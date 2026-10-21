# =============================================================================
# PIM-Reachability.ps1 -- the PURE, offline-testable plan brain for the three
# things a deployed environment needs in order to be REACHABLE and NOT
# AZURE-BLIND, and which the deploy path did not create:
#
#   1. VNet PEERING     spoke <-> hub, both directions   (BUG-49 residual)
#   2. PRIVATE DNS      the ACA env default domain -> the env's static IP,
#                       linked to the VNets that must resolve it (BUG-49 residual)
#   3. AZURE RBAC       an ARM role for each workload identity   (BUG-51)
#
# WHY THIS EXISTS -- the failure it is written against
#   `New-PimHostingPrerequisites` creates an ISOLATED VNet and nothing ever peers
#   it; `Invoke-PimDeployAll` never passed `-DnsServer`, so no name was ever
#   registered; and `Setup-PimContainers` granted the workload identities their
#   GRAPH app-roles and NO ARM rights at all. Every resource-level check still
#   passes: the app is Succeeded, ingress reports an FQDN, the image is verified.
#   REACHABILITY is the one property that cannot be seen from the resource graph,
#   and "can this identity read Azure" is the one that cannot be seen from the
#   directory. Measured live on the production environment: zero peerings, an
#   FQDN that did not resolve, and a tenant-cache run reporting
#   `azure-scopes=0 azure-rbac-roles=0` next to a perfectly healthy directory half.
#   At 25 customer tenants that is 25 deployed, healthy-looking, unreachable,
#   Azure-blind Managers.
#
# DESIGN TENETS (mirror PIM-DownlinkJob.ps1 / PIM-DeployAll.ps1)
#   * PURE core here: NO az / Graph / SQL / HTTP / file I/O / global mutation.
#     These functions take FACTS and RETURN plans -- resource ids, peering pair
#     names, record sets, role-assignment scopes -- plus an ok/reason verdict.
#     The thin live wrappers (tools/setup/_PimSetupShared.ps1) invoke az with them.
#   * REFUSE EARLY, WITH THE REASON NAMED. A peering to yourself, overlapping
#     address spaces, a missing object id, `Owner` for a workload identity -- all
#     are decided here, offline, where they are unit-testable, instead of being
#     discovered as an az error four steps into a production deploy.
#   * The plan is IDEMPOTENT by construction: it describes the DESIRED state, and
#     the wrapper reconciles to it. Re-running a deploy re-emits the same plan.
#
# PS 5.1 COMPATIBLE: no ?. / ??, no ternary, no PS7-only members.
# =============================================================================

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# The short, human name of a VNet, used to build the peering pair names.
# Convention taken from what the tenant already had -- `vnet-platform` +
# `vnet-pim-mfnpr` peered as `platform-to-pim-mfnpr` / `pim-mfnpr-to-platform`.
# Following the existing convention matters: an operator scanning a portal blade
# should not have to work out which of two naming schemes a peering came from.
# ---------------------------------------------------------------------------
function Get-PimVnetShortName {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$VnetName)
    $n = "$VnetName".Trim().ToLowerInvariant()
    if ($n -like 'vnet-*') { $n = $n.Substring(5) }
    elseif ($n -like '*-vnet') { $n = $n.Substring(0, $n.Length - 5) }
    return $n.Trim('-')
}

function New-PimVnetResourceId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$VnetName
    )
    return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Network/virtualNetworks/$VnetName"
}

# ---------------------------------------------------------------------------
# CIDR overlap (pure). Azure refuses to peer overlapping address spaces, but its
# error arrives mid-deploy and names neither range. Deciding it here means the
# plan can say "10.220.8.0/21 overlaps the hub's 10.220.0.0/16" before anything
# is created. Returns $null when either input is absent/unparseable -- "unknown",
# which the caller must NOT read as "no overlap".
# ---------------------------------------------------------------------------
function Test-PimCidrOverlap {
    [CmdletBinding()] param([string]$CidrA, [string]$CidrB)
    function ConvertTo-PimCidrRange {
        param([string]$Cidr)
        if (-not "$Cidr".Trim()) { return $null }
        $parts = "$Cidr".Trim() -split '/'
        if ($parts.Count -ne 2) { return $null }
        $ipParts = $parts[0] -split '\.'
        if ($ipParts.Count -ne 4) { return $null }
        $prefix = 0
        if (-not [int]::TryParse($parts[1], [ref]$prefix)) { return $null }
        if ($prefix -lt 0 -or $prefix -gt 32) { return $null }
        $addr = [uint64]0
        foreach ($o in $ipParts) {
            $v = 0
            if (-not [int]::TryParse($o, [ref]$v)) { return $null }
            if ($v -lt 0 -or $v -gt 255) { return $null }
            $addr = [uint64](($addr * 256) + $v)
        }
        # 🪤 Deliberately NO bit masking here. Both obvious forms are wrong in PowerShell:
        # `-bnot [uint32]` promotes to a SIGNED type and the result fails to cast back
        # ("Cannot convert value -1 to System.UInt32"), and a /0 mask cannot be written as
        # (0xFFFFFFFF -shl 32) because .NET takes the shift count mod 32 and returns the
        # operand unchanged. Block size + modulo has neither problem and is exact in uint64.
        $size  = [uint64][Math]::Pow(2, (32 - $prefix))
        $start = [uint64]($addr - ($addr % $size))
        $end   = [uint64]($start + $size - 1)
        return @{ start = $start; end = $end }
    }
    $a = ConvertTo-PimCidrRange -Cidr $CidrA
    $b = ConvertTo-PimCidrRange -Cidr $CidrB
    if ($null -eq $a -or $null -eq $b) { return $null }     # unknown, NOT "no overlap"
    return (($a.start -le $b.end) -and ($b.start -le $a.end))
}

# ---------------------------------------------------------------------------
# 1. PEERING PLAN (pure).
#
# Returns @{ ok; reason; spokeVnetId; hubVnetId; pairs = @( ... ) }, where each
# pair is one DIRECTION of the peering:
#   @{ direction; name; resourceGroup; vnetName; subscriptionId; remoteVnetId }
#
# BOTH directions are always emitted. A one-sided peering is the failure mode
# that looks fine in the portal blade you happen to open: the local side reads
# `Initiated` rather than `Connected`, and no traffic flows. The plan therefore
# has no concept of "just the spoke side".
# ---------------------------------------------------------------------------
function Get-PimPeeringPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SpokeVnetName,
        [Parameter(Mandatory)][string]$SpokeResourceGroup,
        [Parameter(Mandatory)][string]$SpokeSubscriptionId,
        [Parameter(Mandatory)][string]$HubVnetName,
        [Parameter(Mandatory)][string]$HubResourceGroup,
        [string]$HubSubscriptionId,
        # OPTIONAL facts. When both are supplied the plan refuses an overlap up
        # front instead of letting Azure refuse it mid-deploy.
        [string]$SpokeAddressSpace,
        [string]$HubAddressSpace
    )
    if (-not "$HubSubscriptionId".Trim()) { $HubSubscriptionId = $SpokeSubscriptionId }

    $spokeId = New-PimVnetResourceId -SubscriptionId $SpokeSubscriptionId -ResourceGroup $SpokeResourceGroup -VnetName $SpokeVnetName
    $hubId   = New-PimVnetResourceId -SubscriptionId $HubSubscriptionId  -ResourceGroup $HubResourceGroup  -VnetName $HubVnetName

    if ($spokeId -eq $hubId) {
        return @{ ok = $false; pairs = @(); spokeVnetId = $spokeId; hubVnetId = $hubId
                  reason = "the hub and the spoke are the SAME VNet ($spokeId) -- a VNet cannot be peered to itself. Pass the hub VNet the clients live on, not the PIM spoke." }
    }

    $overlap = Test-PimCidrOverlap -CidrA $SpokeAddressSpace -CidrB $HubAddressSpace
    if ($overlap -eq $true) {
        return @{ ok = $false; pairs = @(); spokeVnetId = $spokeId; hubVnetId = $hubId
                  reason = "address spaces OVERLAP (spoke $SpokeAddressSpace vs hub $HubAddressSpace) -- Azure cannot peer them. Re-carve the spoke prefix (New-PimHostingPrerequisites derives it from -AddressBase/-Index)." }
    }

    $spokeShort = Get-PimVnetShortName -VnetName $SpokeVnetName
    $hubShort   = Get-PimVnetShortName -VnetName $HubVnetName

    $pairs = @(
        @{ direction = 'hub-to-spoke'; name = "$hubShort-to-$spokeShort"
           resourceGroup = $HubResourceGroup; vnetName = $HubVnetName
           subscriptionId = $HubSubscriptionId; remoteVnetId = $spokeId }
        @{ direction = 'spoke-to-hub'; name = "$spokeShort-to-$hubShort"
           resourceGroup = $SpokeResourceGroup; vnetName = $SpokeVnetName
           subscriptionId = $SpokeSubscriptionId; remoteVnetId = $hubId }
    )
    $crossSub = ($SpokeSubscriptionId -ne $HubSubscriptionId)
    $reason = "bidirectional peering $($pairs[0].name) / $($pairs[1].name)"
    if ($crossSub) { $reason += ' (CROSS-SUBSCRIPTION: the deploying identity needs Network Contributor on BOTH sides)' }
    return @{ ok = $true; reason = $reason; spokeVnetId = $spokeId; hubVnetId = $hubId
              crossSubscription = $crossSub; pairs = $pairs }
}

# ---------------------------------------------------------------------------
# 1b. THE HUB OWNER'S "PREPARE" SCRIPT (pure) -- §95.2 item 9 (2026-10-04); REST rewrite §100.63(c) (2026-10-10).
#
# A private install peers the PIM spoke with the customer's hub, and the hub is very often owned by
# another team (or sits in a subscription the installer cannot write). Today that ends in "Cross-
# subscription peering needs Network Contributor on BOTH sides" and a person who must work out the
# names. This writes the script FOR them: the hub-side peering with EXACTLY the name the deploy looks
# for (Get-PimPeeringPlan), optionally the right for the deploy identity (Network Contributor on the
# hub VNet; Private DNS Zone Contributor on the DNS resource group when the zone goes next to the hub),
# optionally the hub VNet's links to existing private DNS zones, and a check. Idempotent, refuses a
# same-name peering that points elsewhere, never deletes anything.
#
# §100.63(c), framework §12.17 (owner 2026-10-10: "rewrite hub script"): the WRITTEN file uses no Azure
# CLI and no PowerShell module. It is ONE self-contained file: an embedded browser sign-in (auth code +
# PKCE on a loopback port, the Microsoft Azure CLI public client APP ID used over REST -- not the az
# program; the tenant is baked in or found from the hub subscription's sign-in hint; a token from another
# tenant is refused before any call), then Azure Resource Manager REST with Invoke-RestMethod. Plan-first:
# without -Apply it only prints what it would do. PowerShell 7 and Windows PowerShell 5.1.
# The generator stays PURE (it returns text). Returns @{ ok; reason; fileName; text; hubPeeringName; spokePeeringName }.
# ---------------------------------------------------------------------------
function New-PimHubPrepareScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SpokeVnetName,
        [Parameter(Mandatory)][string]$SpokeResourceGroup,
        [Parameter(Mandatory)][string]$SpokeSubscriptionId,
        [Parameter(Mandatory)][string]$HubVnetName,
        [Parameter(Mandatory)][string]$HubResourceGroup,
        [string]$HubSubscriptionId,
        [string]$DeployPrincipalObjectId = '',                    # empty = the hub owner creates the hub side only
        [ValidateSet('ServicePrincipal', 'User', 'Group')][string]$DeployPrincipalType = 'ServicePrincipal',
        [string]$DnsResourceGroup = '',                           # the zone's RG when it is in the HUB subscription
        [string]$EnvironmentLabel = '',
        [string]$TenantId = '',                                   # the hub's tenant; empty = the written script finds it from the hub subscription
        [string[]]$PrivateDnsZoneName = @(),                      # existing private DNS zones (in -DnsResourceGroup) to link to the hub VNet
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $fail = { param($why) return @{ ok = $false; reason = $why; fileName = ''; text = '' } }
    $plan = Get-PimPeeringPlan -SpokeVnetName $SpokeVnetName -SpokeResourceGroup $SpokeResourceGroup -SpokeSubscriptionId $SpokeSubscriptionId `
                -HubVnetName $HubVnetName -HubResourceGroup $HubResourceGroup -HubSubscriptionId $HubSubscriptionId
    if (-not $plan.ok) { return (& $fail $plan.reason) }
    $hub = @($plan.pairs | Where-Object { $_.direction -eq 'hub-to-spoke' })[0]
    $spoke = @($plan.pairs | Where-Object { $_.direction -eq 'spoke-to-hub' })[0]
    $guidRx = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $oid = "$DeployPrincipalObjectId".Trim()
    if ($oid -and $oid -notmatch $guidRx) { return (& $fail "the deploy identity must be an object id (GUID), not '$oid'") }
    $tid = "$TenantId".Trim().ToLowerInvariant()
    if ($tid -and $tid -notmatch $guidRx) { return (& $fail "the tenant must be a tenant id (GUID), not '$tid'") }
    foreach ($s in @($SpokeSubscriptionId, $hub.subscriptionId)) { if ("$s" -notmatch $guidRx) { return (& $fail "a subscription must be a subscription id (GUID), not '$s'") } }
    # Every value goes in as a single-quoted PowerShell literal; Azure names cannot hold a quote, but refuse one anyway.
    foreach ($v in @($SpokeVnetName, $SpokeResourceGroup, $HubVnetName, $HubResourceGroup, $DnsResourceGroup, $EnvironmentLabel)) {
        if ("$v" -match "['`"``\r\n]") { return (& $fail "a name contains a quote or a line break: '$v'") }
    }
    $dnsRg = "$DnsResourceGroup".Trim()
    $zones = @(@($PrivateDnsZoneName) | ForEach-Object { "$_".Trim().ToLowerInvariant().TrimEnd('.') } | Where-Object { $_ } | Select-Object -Unique)
    foreach ($z in $zones) {
        if ($z -notmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$') { return (& $fail "'$z' is not a DNS zone name") }
    }
    if ($zones.Count -and -not $dnsRg) { return (& $fail '-PrivateDnsZoneName needs -DnsResourceGroup (the resource group of the zones, in the hub subscription)') }
    $label = if ("$EnvironmentLabel".Trim()) { "$EnvironmentLabel".Trim() } else { $SpokeVnetName }

    $L = New-Object System.Collections.Generic.List[string]
    [void]$L.Add('#Requires -Version 5.1')
    [void]$L.Add('<#')
    [void]$L.Add('.SYNOPSIS')
    [void]$L.Add("    PIM Manager -- PREPARE THE HUB NETWORK for '$label'. Generated $($NowUtc.ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC by PIM setup.")
    [void]$L.Add('.DESCRIPTION')
    [void]$L.Add('    Run it as someone who may change the hub VNet (Network Contributor on it; Owner or User Access Administrator for the')
    [void]$L.Add('    rights below). PowerShell 7 (or Windows PowerShell 5.1) on any machine, a browser sign-in as the hub owner -- no Azure')
    [void]$L.Add('    CLI, no PowerShell modules, nothing to install. Without -Apply it only shows what it would do.')
    [void]$L.Add('    What it does -- and nothing else (it never deletes anything; running it twice is safe):')
    [void]$L.Add("      1. the hub side of the peering: '$($hub.name)' on '$HubVnetName' -> the PIM network '$SpokeVnetName'")
    if ($oid) {
        [void]$L.Add("      2. lets the PIM deploy identity ($oid) make its own side and link the name: Network Contributor on '$HubVnetName'")
        if ($dnsRg) { [void]$L.Add("         and Private DNS Zone Contributor on the resource group '$dnsRg' (the zone for the Manager's name goes there)") }
    }
    foreach ($z in $zones) { [void]$L.Add("      -  links the private DNS zone '$z' (resource group '$dnsRg') to '$HubVnetName'") }
    [void]$L.Add('      3. shows the state of both sides. "Connected" on both = done; "Initiated" = PIM setup still has to make its side.')
    [void]$L.Add('.PARAMETER Apply')
    [void]$L.Add('    Make the changes. Without it the script only prints its plan and changes nothing.')
    [void]$L.Add('.EXAMPLE')
    [void]$L.Add("    ./prepare-hub-<name>.ps1          # the plan only")
    [void]$L.Add("    ./prepare-hub-<name>.ps1 -Apply   # sign in as the hub owner and make the changes")
    [void]$L.Add('#>')
    [void]$L.Add('[CmdletBinding()] param([switch]$Apply)')
    [void]$L.Add('$ErrorActionPreference = ''Stop''')
    [void]$L.Add("`$Label        = '$label'")
    [void]$L.Add("`$TenantId     = '$tid'")
    [void]$L.Add("`$HubSub       = '$($hub.subscriptionId)'")
    [void]$L.Add("`$HubRg        = '$HubResourceGroup'")
    [void]$L.Add("`$HubVnet      = '$HubVnetName'")
    [void]$L.Add("`$HubPeering   = '$($hub.name)'")
    [void]$L.Add("`$HubId        = '$($plan.hubVnetId)'")
    [void]$L.Add("`$SpokeId      = '$($plan.spokeVnetId)'")
    [void]$L.Add("`$SpokeSub     = '$($spoke.subscriptionId)'")
    [void]$L.Add("`$SpokeRg      = '$($spoke.resourceGroup)'")
    [void]$L.Add("`$SpokeVnet    = '$($spoke.vnetName)'")
    [void]$L.Add("`$SpokePeering = '$($spoke.name)'")
    [void]$L.Add("`$Who          = '$oid'")
    [void]$L.Add("`$WhoType      = '$DeployPrincipalType'")
    [void]$L.Add("`$DnsRg        = '$dnsRg'")
    [void]$L.Add("`$Zones        = @($((@($zones | ForEach-Object { "'$_'" })) -join ', '))")
    [void]$L.Add(((Get-PimHubPrepareBody) -replace "`r`n", "`n"))   # the file may be checked out CRLF; the written script is LF throughout
    $file = "prepare-hub-$((Get-PimVnetShortName -VnetName $SpokeVnetName) -replace '[^A-Za-z0-9-]', '-').ps1"
    return @{ ok = $true; reason = $plan.reason; fileName = $file; text = (($L -join "`n").TrimEnd("`n") + "`n"); hubPeeringName = $hub.name; spokePeeringName = $spoke.name }
}

# The constant part of the written file (everything after the values). Single-quoted: nothing here is expanded by the generator.
function Get-PimHubPrepareBody {
    # Returned from a function, not kept in a $script: variable: a dot-sourced file's script scope is not always the caller's.
    return @'

# ---- constants -------------------------------------------------------------------------------------------------------
$Arm            = 'https://management.azure.com'
$NetApi         = '2023-09-01'
$DnsApi         = '2020-06-01'
$AuthzApi       = '2022-04-01'
# The Microsoft Azure CLI first-party public client APP ID, pre-authorised for Azure Resource Manager in every tenant.
# Used over REST for the browser sign-in -- the Azure CLI program is NOT needed and NOT used.
$SignInClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
$LinkName       = 'link-' + $HubVnet
$NetContribId   = '4d97b98b-1d4f-4787-a291-c67834d212e7'
$DnsContribId   = 'b12aa53e-6015-4669-85d0-8515ebb3ae7f'
$HubMaxAttempts = 6
$HubPollSeconds = 5
$HubToken       = ''
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

# ---- sign-in (browser, auth code + PKCE on a loopback port; never a device code) -------------------------------------
function ConvertTo-HubBase64Url([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

function Get-HubJwtTenant([string]$Jwt) {
    try {
        $p = "$Jwt".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }
        return "$(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json).tid)".Trim().ToLowerInvariant()
    } catch { return '' }
}

function Get-HubHttpFailure($ErrorRecord) {
    # The status, ARM error code / message, Retry-After and sign-in hint of a failed call -- PowerShell 7 and 5.1.
    $status = 0; $retry = 0; $code = ''; $message = "$($ErrorRecord.Exception.Message)"; $auth = ''
    $resp = $null; try { $resp = $ErrorRecord.Exception.Response } catch { $resp = $null }
    if ($resp) {
        try { $status = [int]$resp.StatusCode } catch { $status = 0 }
        try {
            if ($resp.Headers -is [System.Net.WebHeaderCollection]) {
                $ra = "$($resp.Headers['Retry-After'])"; if ($ra -match '^\d+$') { $retry = [int]$ra }
                $auth = "$($resp.Headers['WWW-Authenticate'])"
            } else {
                if ($resp.Headers.RetryAfter -and $resp.Headers.RetryAfter.Delta) { $retry = [int]$resp.Headers.RetryAfter.Delta.TotalSeconds }
                $auth = (@($resp.Headers.WwwAuthenticate) | ForEach-Object { "$_" }) -join ', '
            }
        } catch { }
    }
    $raw = "$($ErrorRecord.ErrorDetails.Message)"
    if ($raw) {
        try {
            $j = $raw | ConvertFrom-Json
            $e = if ($j.error) { $j.error } else { $j }
            if ($e.code) { $code = "$($e.code)" }
            if ($e.message) { $message = "$($e.message)" }
        } catch { $message = $raw }
    }
    return [pscustomobject]@{ status = $status; code = $code; message = $message; retryAfter = $retry; authenticate = $auth }
}

function Find-HubTenant {
    # The tenant baked in by PIM setup, else the one Azure names in its sign-in hint for the hub subscription.
    if ("$TenantId".Trim()) { return "$TenantId".Trim().ToLowerInvariant() }
    $f = $null
    try { $null = Invoke-RestMethod -Method GET -Uri "$Arm/subscriptions/$($HubSub)?api-version=2022-12-01" -ErrorAction Stop } catch { $f = Get-HubHttpFailure $_ }
    if ($f -and $f.authenticate -match 'authorization_uri="?https://login\.(?:windows\.net|microsoftonline\.com)/([0-9a-fA-F-]{36})') { return $Matches[1].ToLowerInvariant() }
    throw "Could not find which tenant the hub subscription $HubSub belongs to$(if ($f) { " (HTTP $($f.status))" }). Ask the PIM installer to write this script again with -TenantId <the hub's tenant id>."
}

function Get-HubAuthCode([string]$Tenant) {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $verifier  = ConvertTo-HubBase64Url $bytes
    $challenge = ConvertTo-HubBase64Url ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    $state     = [guid]::NewGuid().ToString('N')
    $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $tcp.Start(); $tcps = @($tcp); try { if ([System.Net.Sockets.Socket]::OSSupportsIPv6) { $tcp6 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::IPv6Loopback, ([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port); $tcp6.Start(); $tcps += $tcp6 } } catch { }   # a customer 2026-10-21: "localhost" may be [::1] -- BOTH loopbacks, same port
    $redirect = "http://localhost:$(([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port)/"
    $scope = "$Arm/.default offline_access openid profile"
    $url = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize?client_id=$SignInClientId&response_type=code&response_mode=query" +
           "&redirect_uri=$([uri]::EscapeDataString($redirect))&scope=$([uri]::EscapeDataString($scope))&state=$state" +
           "&code_challenge=$challenge&code_challenge_method=S256&prompt=select_account"
    Write-Host ''
    Write-Host "Sign in as the owner of the hub network (tenant $Tenant)." -ForegroundColor Yellow
    Write-Host 'If the browser opens in the wrong profile or account, open this address in the right one:' -ForegroundColor Yellow
    Write-Host "  $url" -ForegroundColor DarkGray
    if ("$env:PIM_SIGNIN_BROWSER".Trim().ToLowerInvariant() -eq 'none') {
        Write-Host '  (PIM_SIGNIN_BROWSER=none: no browser opened -- paste the address above into a browser)' -ForegroundColor Yellow
    } else {
        # An InPrivate window has no saved account, so the sign-in form always appears (a saved account signs in silently).
        $edge = @(${env:ProgramFiles(x86)}, $env:ProgramFiles) | Where-Object { $_ } | ForEach-Object { Join-Path $_ 'Microsoft\Edge\Application\msedge.exe' } |
                Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        try { if ($edge) { Start-Process -FilePath $edge -ArgumentList @('--inprivate', '--new-window', $url) } else { Start-Process $url } }
        catch { Write-Host '  (no browser could be opened -- paste the address above into a browser)' -ForegroundColor Yellow }
    }
    $query = $null
    try {
        $deadline = (Get-Date).AddMinutes(5)
        while (-not $query) {
            if ((Get-Date) -gt $deadline) { throw 'Timed out (5 min) waiting for the sign-in.' }
            $tcpReady = @($tcps | Where-Object { $_.Pending() })[0]; if (-not $tcpReady) { Start-Sleep -Milliseconds 200; continue }
            $client = $tcpReady.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $line = (New-Object System.IO.StreamReader($stream)).ReadLine()
                $html = '<html><body style="font-family:sans-serif"><h3>Sign-in complete.</h3>You can close this tab and return to PowerShell.</body></html>'
                $w = New-Object System.IO.StreamWriter($stream)
                $w.Write("HTTP/1.1 200 OK`r`nContent-Type: text/html`r`nContent-Length: $($html.Length)`r`nConnection: close`r`n`r`n$html"); $w.Flush()
                if ($line -match '^GET /\?(\S+) HTTP') { $query = $Matches[1] }
            } finally { $client.Close() }
        }
    } finally { foreach ($tcpL in $tcps) { try { $tcpL.Stop() } catch { } } }
    $kv = @{}
    foreach ($pair in ($query -split '&')) { $k, $v = $pair -split '=', 2; $kv[$k] = if ($null -ne $v) { [uri]::UnescapeDataString(($v -replace '\+', ' ')) } else { '' } }
    if ($kv['error']) { throw "Sign-in failed: $($kv['error']) -- $($kv['error_description'])" }
    if ($kv['state'] -ne $state) { throw 'The sign-in answer did not match this request -- close the browser windows and run the script again.' }
    if (-not $kv['code']) { throw 'The sign-in answer carried no authorization code.' }
    return @{ code = $kv['code']; redirect = $redirect; verifier = $verifier }
}

function Get-HubArmToken([string]$Tenant) {
    $a = Get-HubAuthCode -Tenant $Tenant
    $r = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop -Body @{
        client_id = $SignInClientId; grant_type = 'authorization_code'; code = $a.code; redirect_uri = $a.redirect; code_verifier = $a.verifier
        scope = "$Arm/.default offline_access openid profile" }
    if (-not "$($r.access_token)") { throw 'The sign-in returned no access token.' }
    # The account must belong to the hub's tenant: a token from another tenant (wrong browser profile / account) stops here,
    # before any call is made with it.
    $tid = Get-HubJwtTenant "$($r.access_token)"
    if ($tid -ne $Tenant) { throw "You signed in to tenant $(if ($tid) { $tid } else { '(unknown)' }), but the hub network is in tenant $Tenant -- nothing was changed. Sign in with an account of $Tenant (use that admin's browser profile)." }
    return "$($r.access_token)"
}

# ---- Azure Resource Manager REST ---------------------------------------------------------------------------------------
function Invoke-HubArm {
    # One ARM call. Throttling (429), a busy resource (409 ...InProgress) and a just-created identity not yet visible
    # (PrincipalNotFound) are retried a bounded number of times, honouring Retry-After. A status in -Accept is returned,
    # anything else stops with the ARM error code and message.
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Path, $Body = $null, [int[]]$Accept = @(), [string]$Hint = '')
    $attempt = 0
    while ($true) {
        $attempt++
        $p = @{ Method = $Method; Uri = ($Arm + $Path); Headers = @{ Authorization = "Bearer $HubToken" }; ErrorAction = 'Stop' }
        if ($null -ne $Body) { $p.ContentType = 'application/json'; $p.Body = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 10 -Compress)) }
        try { return [pscustomobject]@{ status = 200; code = ''; message = ''; body = (Invoke-RestMethod @p) } }
        catch {
            $f = Get-HubHttpFailure $_
            $busy = ($f.status -eq 429) -or ($f.status -ge 500) -or
                    (($f.status -eq 409 -or $f.status -eq 400) -and $f.code -match 'InProgress|AnotherOperation|Retryable|PrincipalNotFound|ReferencedResourceNotProvisioned')
            if ($busy -and $attempt -lt $HubMaxAttempts) {
                $wait = if ($f.retryAfter -gt 0) { [Math]::Min($f.retryAfter, 120) } else { [Math]::Min(5 * $attempt, 30) }
                Write-Host ("  Azure is busy (HTTP {0} {1}) -- trying again in {2} s ({3}/{4})" -f $f.status, $f.code, $wait, $attempt, $HubMaxAttempts) -ForegroundColor DarkYellow
                Start-Sleep -Seconds $wait
                continue
            }
            if ($Accept -contains $f.status) { return [pscustomobject]@{ status = $f.status; code = $f.code; message = $f.message; body = $null } }
            throw ("{0} {1} -> HTTP {2} {3}: {4}{5}" -f $Method, $Path, $f.status, $f.code, $f.message, $(if ($Hint) { " -- $Hint" } else { '' }))
        }
    }
}

function Wait-HubSucceeded([string]$Path, [string]$What) {
    for ($i = 0; $i -lt 60; $i++) {
        $r = Invoke-HubArm -Method GET -Path $Path
        $s = "$($r.body.properties.provisioningState)"
        if ($s -eq 'Succeeded') { return $r.body }
        if ($s -eq 'Failed' -or $s -eq 'Canceled') { throw "$What ended in provisioningState $s -- look at the activity log of $HubVnet." }
        Start-Sleep -Seconds $HubPollSeconds
    }
    throw "$What did not reach provisioningState Succeeded in time -- run the script again."
}

function New-HubStableGuid([string]$Text) {
    # The same scope + identity + role always gives the same role assignment name, so a second run cannot add a duplicate.
    $b = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Text.ToLowerInvariant()))
    $g = New-Object byte[] 16
    [Array]::Copy($b, $g, 16)
    $g[7] = [byte](($g[7] -band 0x0f) -bor 0x50)
    $g[8] = [byte](($g[8] -band 0x3f) -bor 0x80)
    return (New-Object guid (, $g)).ToString()
}

function Grant-HubRole([string]$Scope, [string]$RoleId, [string]$RoleName) {
    $name = New-HubStableGuid "$Scope|$Who|$RoleId"
    $body = @{ properties = @{ roleDefinitionId = "/subscriptions/$HubSub/providers/Microsoft.Authorization/roleDefinitions/$RoleId"; principalId = $Who; principalType = $WhoType } }
    $r = Invoke-HubArm -Method PUT -Path "$Scope/providers/Microsoft.Authorization/roleAssignments/$($name)?api-version=$AuthzApi" -Body $body -Accept @(409) `
            -Hint "granting a role needs Owner or User Access Administrator on $Scope"
    if ($r.status -eq 409) {
        if ($r.code -ne 'RoleAssignmentExists') { throw "$RoleName on $Scope could not be granted: HTTP 409 $($r.code): $($r.message)" }
        Write-Host "  $RoleName on $Scope -- already granted"
    } else { Write-Host "  $RoleName on $Scope -- granted" -ForegroundColor Green }
}

function Set-HubDnsLink([string]$Zone) {
    $zonePath = "/subscriptions/$HubSub/resourceGroups/$DnsRg/providers/Microsoft.Network/privateDnsZones/$Zone"
    $z = Invoke-HubArm -Method GET -Path "$($zonePath)?api-version=$DnsApi" -Accept @(404)
    if ($z.status -eq 404) { Write-Host "  private DNS zone $Zone is not in $DnsRg (yet) -- skipped; PIM setup links the zone it creates, or run this again later" -ForegroundColor Yellow; return }
    $linkPath = "$zonePath/virtualNetworkLinks/$($LinkName)?api-version=$DnsApi"
    $have = Invoke-HubArm -Method GET -Path $linkPath -Accept @(404)
    if ($have.status -ne 404) {
        $vid = "$($have.body.properties.virtualNetwork.id)"
        if ($vid.ToLowerInvariant() -ne $HubId.ToLowerInvariant()) { throw "the link $LinkName on $Zone already exists and points at $vid, not at $HubVnet -- nothing was changed." }
        Write-Host "  $Zone -> $HubVnet -- already linked"
        return
    }
    $body = @{ location = 'global'; properties = @{ virtualNetwork = @{ id = $HubId }; registrationEnabled = $false } }
    $r = Invoke-HubArm -Method PUT -Path $linkPath -Body $body -Accept @(409) -Hint "linking a zone needs Private DNS Zone Contributor on $Zone and Network Contributor on $HubVnet"
    if ($r.status -eq 409) { Write-Host "  $Zone -> $HubVnet -- already linked under another name ($($r.code))"; return }
    $null = Wait-HubSucceeded -Path $linkPath -What "the link of $Zone"
    Write-Host "  $Zone -> $HubVnet -- linked" -ForegroundColor Green
}

# ---- the plan -----------------------------------------------------------------------------------------------------------
$peerPath  = "/subscriptions/$HubSub/resourceGroups/$HubRg/providers/Microsoft.Network/virtualNetworks/$HubVnet/virtualNetworkPeerings/$($HubPeering)?api-version=$NetApi"
$spokePath = "/subscriptions/$SpokeSub/resourceGroups/$SpokeRg/providers/Microsoft.Network/virtualNetworks/$SpokeVnet/virtualNetworkPeerings/$($SpokePeering)?api-version=$NetApi"
$dnsScope  = "/subscriptions/$HubSub/resourceGroups/$DnsRg"
Write-Host ''
Write-Host "PIM Manager -- prepare the hub network for '$Label'" -ForegroundColor Cyan
Write-Host ("  tenant: {0}" -f $(if ($TenantId) { $TenantId } else { "found from the hub subscription $HubSub at sign-in" }))
Write-Host "  PLAN 1. peering '$HubPeering' on the hub VNet '$HubVnet' (resource group $HubRg, subscription $HubSub) -> the PIM network $SpokeId -- created when missing, left as it is when it already points there"
$n = 2
if ($Who) {
    Write-Host "  PLAN $n. role Network Contributor for the PIM deploy identity $Who ($WhoType) on $HubId"; $n++
    if ($DnsRg) { Write-Host "  PLAN $n. role Private DNS Zone Contributor for $Who on $dnsScope"; $n++ }
}
foreach ($z in $Zones) { Write-Host "  PLAN $n. link the private DNS zone '$z' (resource group $DnsRg) to the hub VNet as '$LinkName'"; $n++ }
Write-Host "  PLAN $n. read the state of both sides of the peering"
if (-not $Apply) {
    Write-Host ''
    Write-Host 'Plan only -- nothing was changed. Run it again with -Apply to make these changes (a browser sign-in as the hub owner).' -ForegroundColor Yellow
    return
}

# ---- apply --------------------------------------------------------------------------------------------------------------
$tenant = Find-HubTenant
$HubToken = Get-HubArmToken -Tenant $tenant
Write-Host "signed in (tenant $tenant)" -ForegroundColor Green

# 1. the hub-side peering
$have = Invoke-HubArm -Method GET -Path $peerPath -Accept @(404) -Hint "can you read the hub VNet $HubVnet?"
if ($have.status -eq 404) {
    $body = @{ properties = @{ remoteVirtualNetwork = @{ id = $SpokeId }; allowVirtualNetworkAccess = $true; allowForwardedTraffic = $false; allowGatewayTransit = $false; useRemoteGateways = $false } }
    $null = Invoke-HubArm -Method PUT -Path $peerPath -Body $body -Hint "do you have Network Contributor on $HubVnet?"
    $null = Wait-HubSucceeded -Path $peerPath -What "the peering $HubPeering"
    Write-Host "peering $HubPeering created" -ForegroundColor Green
} else {
    $remote = "$($have.body.properties.remoteVirtualNetwork.id)"
    if ($remote.ToLowerInvariant() -ne $SpokeId.ToLowerInvariant()) {
        throw "a peering named $HubPeering already exists on $HubVnet and points at $remote, not at the PIM network -- nothing was changed. Rename or remove it, then run this again."
    }
    if ("$($have.body.properties.provisioningState)" -ne 'Succeeded') { $null = Wait-HubSucceeded -Path $peerPath -What "the peering $HubPeering" }
    Write-Host "peering $HubPeering exists"
}

# 2. the PIM deploy identity may make its own side (and link the name to the hub)
if ($Who) {
    Grant-HubRole -Scope $HubId -RoleId $NetContribId -RoleName 'Network Contributor'
    if ($DnsRg) { Grant-HubRole -Scope $dnsScope -RoleId $DnsContribId -RoleName 'Private DNS Zone Contributor' }
}

# existing private DNS zones -> the hub VNet
foreach ($z in $Zones) { Set-HubDnsLink -Zone $z }

# 3. the state of both sides
$h = Invoke-HubArm -Method GET -Path $peerPath -Accept @(403, 404)
$s = Invoke-HubArm -Method GET -Path $spokePath -Accept @(400, 401, 403, 404)
$hs = if ($h.status -eq 200) { "$($h.body.properties.peeringState)" } else { '' }
$ss = if ($s.status -eq 200) { "$($s.body.properties.peeringState)" } else { '' }
Write-Host ("hub side   {0}: {1}" -f $HubPeering, $(if ($hs) { $hs } else { 'not readable' }))
Write-Host ("PIM side   {0}: {1}" -f $SpokePeering, $(if ($ss) { $ss } else { 'not readable from here (made by PIM setup)' }))
if ($hs -eq 'Connected') { Write-Host 'Done: the PIM network is reachable from the hub.' -ForegroundColor Green }
else { Write-Host 'Tell the PIM installer to continue: setup makes its side, then both read Connected.' -ForegroundColor Yellow }
'@
}

# ---------------------------------------------------------------------------
# 2. PRIVATE DNS PLAN (pure).
#
# An `--internal-only` ACA environment publishes its apps on the environment's
# DEFAULT DOMAIN at a single static PRIVATE ip. Nothing resolves that name off
# the ACA subnet, so a peered client has a route and still cannot connect.
# The fix, mirroring what the tenant already had for the predecessor
# environment: an Azure Private DNS zone NAMED FOR THE DEFAULT DOMAIN, with
# wildcard + apex + `*.internal` A records at the env static IP, LINKED to every
# VNet whose clients must resolve it.
#
# `*.internal` is not decoration: ACA's internal ingress publishes app names
# under `<app>.internal.<defaultDomain>` for env-internal traffic, so a zone
# with only `*` leaves those unresolvable (a wildcard matches ONE label).
#
# Returns @{ ok; reason; zoneName; resourceGroup; staticIp; records; links; warnings }
# ---------------------------------------------------------------------------
function Get-PimPrivateDnsPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EnvDomain,       # e.g. <name>.westeurope.azurecontainerapps.io
        [Parameter(Mandatory)][string]$StaticIp,        # the ACA env's static (private) IP
        [Parameter(Mandatory)][string]$ResourceGroup,   # where the zone lives (usually the hub's connectivity RG)
        [string[]]$LinkVnetIds = @(),                   # VNets that must RESOLVE the zone
        [string]$ManagerFqdn = ''                       # informational: what this makes reachable
    )
    $warnings = New-Object System.Collections.Generic.List[string]
    $zone = "$EnvDomain".Trim().ToLowerInvariant().TrimEnd('.')
    if (-not $zone -or $zone -notlike '*.*') {
        return @{ ok = $false; zoneName = $zone; records = @(); links = @(); warnings = @()
                  reason = "'$EnvDomain' is not a usable DNS zone name. It comes from `az containerapp env show --query properties.defaultDomain`; an empty value means the environment read failed, so DO NOT create a zone from it." }
    }
    $ip = "$StaticIp".Trim()
    if ($ip -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
        return @{ ok = $false; zoneName = $zone; records = @(); links = @(); warnings = @()
                  reason = "'$StaticIp' is not an IPv4 address -- it comes from `properties.staticIp` on the ACA environment. Refusing to publish a DNS record pointing at nothing." }
    }
    foreach ($o in ($ip -split '\.')) { if ([int]$o -gt 255) {
        return @{ ok = $false; zoneName = $zone; records = @(); links = @(); warnings = @()
                  reason = "'$StaticIp' is not a valid IPv4 address (octet $o > 255)." } } }

    # An internal-only environment MUST have an RFC1918 static IP. A public one means the
    # environment is not internal -- in which case a private zone is the wrong tool, and
    # silently creating one would shadow the real public name for every linked VNet.
    $isPrivate = ($ip -like '10.*') -or ($ip -like '192.168.*') -or ($ip -match '^172\.(1[6-9]|2\d|3[01])\.')
    if (-not $isPrivate) {
        $warnings.Add("static IP $ip is NOT in RFC1918 space -- this environment does not look --internal-only. A private DNS zone for '$zone' would SHADOW the public name inside every linked VNet. Verify the environment shape before relying on this.") | Out-Null
    }

    # '@' = the zone apex. Azure Private DNS names the apex record set '@'.
    $records = @(
        @{ name = '@';         type = 'A'; ipv4Address = $ip; purpose = 'zone apex' }
        @{ name = '*';         type = 'A'; ipv4Address = $ip; purpose = 'every app FQDN in the environment' }
        @{ name = '*.internal'; type = 'A'; ipv4Address = $ip; purpose = 'ACA env-internal ingress names (<app>.internal.<domain>)' }
    )

    $links = New-Object System.Collections.Generic.List[object]
    $seen  = New-Object System.Collections.Generic.List[string]
    foreach ($vid in @($LinkVnetIds)) {
        if (-not "$vid".Trim()) { continue }
        $key = "$vid".Trim().ToLowerInvariant()
        if ($seen -contains $key) { continue }
        $seen.Add($key) | Out-Null
        $short = ($vid -split '/')[-1]
        $links.Add(@{ name = "link-$short"; vnetId = "$vid".Trim(); registrationEnabled = $false }) | Out-Null
    }
    if (-not $links.Count) {
        $warnings.Add("no VNets to link -- the zone would be created and resolve for nobody. Pass the hub VNet (and the spoke) so clients can actually resolve $zone.") | Out-Null
    }

    $what = $zone
    if ("$ManagerFqdn".Trim()) { $what = "$ManagerFqdn (via zone $zone)" }
    return @{ ok = $true; zoneName = $zone; resourceGroup = $ResourceGroup; staticIp = $ip
              records = $records; links = @($links.ToArray()); warnings = @($warnings.ToArray())
              reason = "private DNS zone '$zone' -> $ip, $($records.Count) record set(s), $($links.Count) VNet link(s); makes $what resolvable" }
}

# ---------------------------------------------------------------------------
# 3. AZURE RBAC PLAN (pure).   BUG-51.
#
# The mirror image of framework DOCS/REQUIREMENTS.md §10.0b -- "Global
# Administrator is a directory role and grants nothing in Azure". The deploy
# grants the workload identities their Graph app-roles and stops, so PIM's
# Azure half sees an empty tenant: `azure-scopes=0 azure-rbac-roles=0`, and ARM
# management-group enumeration 403s. Nothing fails; there is simply nothing there.
#
# Returns @{ ok; reason; assignments = @( @{ principalName; principalId; role;
#            scope; scopeKind } ); warnings }
#
# SCOPE IS A DECISION, NOT A DETAIL. Reader at the SUBSCRIPTION lets PIM see that
# subscription's RBAC (measured: azure-scopes=1 azure-rbac-roles=922). Reader at
# a MANAGEMENT GROUP is what makes management-group enumeration work, and it is a
# deliberately wider grant -- so it is opt-in via -ManagementGroupId and never
# implied. Reader can READ Azure RBAC; ASSIGNING it (what PIM ultimately does)
# needs User Access Administrator, which is why that role is allowed but must be
# asked for by name.
# ---------------------------------------------------------------------------
$script:PimAzureRbacAllowedRoles = @('Reader','User Access Administrator','Role Based Access Control Administrator')

function Get-PimAzureRbacPlan {
    [CmdletBinding()]
    param(
        # @( @{ name='ca-pim-tick'; objectId='<oid>' }, ... ) -- the workload identities.
        [Parameter(Mandatory)][object[]]$Principals,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [string[]]$Roles = @('Reader'),
        [string]$ManagementGroupId = ''
    )
    $warnings = New-Object System.Collections.Generic.List[string]

    $roleList = @(@($Roles) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if (-not $roleList.Count) {
        return @{ ok = $false; assignments = @(); warnings = @(); reason = 'no roles requested -- pass at least one (Reader is the intended default).' }
    }
    foreach ($r in $roleList) {
        if ($r -eq 'Owner' -or $r -eq 'Contributor') {
            return @{ ok = $false; assignments = @(); warnings = @()
                      reason = "role '$r' is refused for a WORKLOAD identity. PIM needs to READ Azure RBAC (Reader) and, where it assigns roles, 'User Access Administrator'. '$r' grants standing rights over the resources themselves, which PIM never needs and which would make every deployed environment a subscription-wide write principal." }
        }
        if ($r -notin $script:PimAzureRbacAllowedRoles) {
            $warnings.Add("role '$r' is outside the intended set ($($script:PimAzureRbacAllowedRoles -join ', ')) -- granting it anyway because it was asked for by name, but this is standing privilege on every deployed environment.") | Out-Null
        }
    }

    $scopes = New-Object System.Collections.Generic.List[object]
    $subId = "$SubscriptionId".Trim()
    if (-not $subId) {
        return @{ ok = $false; assignments = @(); warnings = @(); reason = 'no -SubscriptionId -- there is no scope to grant at.' }
    }
    $scopes.Add(@{ kind = 'subscription'; scope = "/subscriptions/$subId" }) | Out-Null
    if ("$ManagementGroupId".Trim()) {
        $scopes.Add(@{ kind = 'managementGroup'; scope = "/providers/Microsoft.Management/managementGroups/$("$ManagementGroupId".Trim())" }) | Out-Null
    } else {
        $warnings.Add('no -ManagementGroupId: management-group enumeration will 403 (`ARM managementGroups list failed`). Subscription-scoped Reader is enough for that subscription and nothing above it -- widen deliberately, not by accident.') | Out-Null
    }

    $assignments = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($Principals)) {
        $pName = ''; $pOid = ''
        if ($p -is [System.Collections.IDictionary]) {
            if ($p.Contains('name'))     { $pName = "$($p['name'])" }
            if ($p.Contains('objectId')) { $pOid  = "$($p['objectId'])" }
        } else {
            if ($p.PSObject.Properties['name'])     { $pName = "$($p.name)" }
            if ($p.PSObject.Properties['objectId']) { $pOid  = "$($p.objectId)" }
        }
        $pName = $pName.Trim(); $pOid = $pOid.Trim()
        if (-not $pOid) {
            # Silently dropping an identity here is how one workload ends up Azure-blind while
            # its siblings work -- the hardest shape of this bug to spot.
            return @{ ok = $false; assignments = @(); warnings = @($warnings.ToArray())
                      reason = "principal '$(if ($pName) { $pName } else { '(unnamed)' })' has no objectId. Refusing to emit a partial RBAC plan -- an identity missing from it is an environment that looks deployed and cannot see Azure." }
        }
        foreach ($s in $scopes) {
            foreach ($r in $roleList) {
                $assignments.Add(@{ principalName = $pName; principalId = $pOid; role = $r
                                    scope = $s.scope; scopeKind = $s.kind }) | Out-Null
            }
        }
    }
    if (-not $assignments.Count) {
        return @{ ok = $false; assignments = @(); warnings = @($warnings.ToArray())
                  reason = 'no principals given -- nothing to grant.' }
    }
    return @{ ok = $true; assignments = @($assignments.ToArray()); warnings = @($warnings.ToArray())
              reason = "$($assignments.Count) role assignment(s): $($roleList -join '+') for $(@($Principals).Count) identity(ies) over $($scopes.Count) scope(s)" }
}
