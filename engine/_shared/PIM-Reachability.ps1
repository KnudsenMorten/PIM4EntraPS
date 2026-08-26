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
