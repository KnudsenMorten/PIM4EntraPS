#Requires -Version 5.1
<#
.SYNOPSIS
    Framework installer rule 11d (2026-11-04) -- THE RETURN ROUTE of a private install.

.DESCRIPTION
    Found live at a customer install: the private PIM Manager timed out from the customer's LAN although DNS was right and the
    hub peering was Connected. The app subnet had no route table, so the REPLIES to the on-premises range took Azure's default
    route (straight out, past the hub firewall the request came in through) and were dropped as asymmetric traffic. The fix
    there was a route table on the app subnet: <internal range> -> the hub firewall's private IP (next hop VirtualAppliance),
    BGP route propagation off (a gateway's learned routes must not override the firewall path).

    THE RULE: a private install whose app subnet sits in a spoke behind a hub firewall gets that return route.
      - the install takes -InternalRanges + -FirewallIp (OPTIONAL, private only, both or neither)
      - a spoke PIM creates: route table 'rt-pim' in the install's resource group, one route per range, BGP propagation off,
        attached to the app subnet (read-modify-write: the subnet keeps every other property), everything READ BACK
      - a network the customer gave (-VnetId): PIM does not write the customer's network -- the network hand-off names it
      - a 401 / 403 writing it (framework rule 16): a warning + the same hand-off line, never a stop
      - the nightly updater only REPORTS a missing return route; it never creates one

      Test-PimReturnRouteRange           PURE: one CIDR is a usable return-route destination ('' = yes, else why not)
      Test-PimReturnRouteFirewallIp      PURE: the next hop is an IPv4 address ('' = yes, else why not)
      Get-PimReturnRouteName             PURE: the route's name for a range (stable, ARM-safe)
      Get-PimReturnRouteTableBody        PURE: the PUT body of rt-pim (an existing table's OTHER routes and tags are kept)
      Get-PimReturnRouteSubnetBody       PURE: the subnet PUT body with the route table attached, every other property kept
      Test-PimReturnRouteInPlace         PURE: does the subnet's route table carry every range -> the firewall, BGP off?
      Get-PimReturnRouteHandoffLine      PURE: the network hand-off line
      Get-PimReturnRouteTags / ConvertFrom-PimReturnRouteTags   PURE: what the install records on its resource group for the
                                         updater's report (the updater has no other way to know the answers)
      Invoke-PimReturnRouteConverge      THIN: the installer's write + read-back (never throws)
      Get-PimReturnRouteReport           THIN: the updater's READ-ONLY report (GET only; never throws)
    No module, no az: -Arm is the caller's ARM client, param([string]$Method, [string]$Path, [object]$Body), the path carries
    its own api-version, and a GET of something that is not there answers $null.
#>

# Literal-returning functions, never script-scope variables: a function called from a CHILD script sees that script's own
# script scope, where a pin set here would be $null.
function Get-PimReturnRouteApi {
    param([ValidateSet('net', 'rg', 'aca')][string]$Kind)
    switch ($Kind) { 'net' { 'api-version=2023-09-01' } 'rg' { 'api-version=2021-04-01' } default { 'api-version=2024-03-01' } }
}
function Get-PimReturnRouteTableName { return 'rt-pim' }   # literal-returning: child-scope safe
function Get-PimReturnRouteTagNames { return @{ ranges = 'pim-return-ranges'; firewall = 'pim-return-firewall' } }

function ConvertTo-PimReturnRouteRangeList {
    <# PURE. Ranges as given (an array, or one text with , ; or spaces) -> a clean, de-duplicated list in the given order. #>
    param([AllowNull()][object]$Ranges)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in @(@($Ranges) | ForEach-Object { "$_" -split '[,;\s]+' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })) {
        if (-not @($out | Where-Object { $_ -ieq $r }).Count) { $out.Add($r) }
    }
    return @($out.ToArray())
}

function ConvertFrom-PimReturnRouteCidr {
    # PURE. 'a.b.c.d/n' (n 1-32, the network address itself) -> @{ Start; End; Length; Text }; $null when not
    param([string]$Cidr)
    if ("$Cidr" -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$') { return $null }
    $m = $Matches; $o = @([int]$m[1], [int]$m[2], [int]$m[3], [int]$m[4]); $len = [int]$m[5]
    if (@($o | Where-Object { $_ -gt 255 }).Count -or $len -lt 1 -or $len -gt 32) { return $null }
    [uint64]$ip = ([uint64]$o[0] * 16777216) + ([uint64]$o[1] * 65536) + ([uint64]$o[2] * 256) + [uint64]$o[3]
    [uint64]$size = [uint64][math]::Pow(2, 32 - $len)
    if ($ip % $size) { return $null }
    return @{ Start = $ip; End = $ip + $size - 1; Length = $len; Text = "$Cidr" }
}

function Test-PimReturnRouteRange {
    <#
      PURE. '' = the CIDR is a usable return-route destination, else the reason. 0.0.0.0/0 is refused: that is a DEFAULT route
      (every reply AND all outbound traffic through the firewall) -- a different decision than a return route, and one this
      answer must not make by accident.
    #>
    param([string]$Cidr)
    $c = "$Cidr".Trim()
    if ($c -match '^0\.0\.0\.0/0$') { return "'$c' is a default route, not one of your internal ranges -- give the ranges your users connect from (e.g. 10.81.0.0/16)" }
    if (-not (ConvertFrom-PimReturnRouteCidr $c)) { return "'$c' is not an IPv4 range (a.b.c.d/n, the network address itself)" }
    return ''
}

function Test-PimReturnRouteFirewallIp {
    <# PURE. '' = an IPv4 address (the hub firewall's PRIVATE address), else the reason. #>
    param([string]$Ip)
    $t = "$Ip".Trim()
    if ($t -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$' -or @($Matches[1..4] | Where-Object { [int]$_ -gt 255 }).Count) { return "'$t' is not an IPv4 address (the hub firewall's private IP, e.g. 10.0.0.4)" }
    if ($t -eq '0.0.0.0' -or $t -eq '255.255.255.255') { return "'$t' is not a firewall address" }
    return ''
}

function Get-PimReturnRouteName {
    <# PURE. The route's name for a range: 'pim-return-10-81-0-0-16' (ARM-safe, stable -- the same range keeps its route). #>
    param([Parameter(Mandatory)][string]$Range)
    return ('pim-return-' + ("$Range".Trim() -replace '[./]', '-'))
}

function Get-PimReturnRouteTableBody {
    <#
      PURE. The PUT body of the route table: one route per range -> -FirewallIp (VirtualAppliance) and
      disableBgpRoutePropagation = true. -Existing (the table as ARM answered, $null when new): its OTHER routes (another
      prefix -- e.g. a 0.0.0.0/0 the network team added) and its tags are kept, its location too; a route for one of our ranges
      is REPLACED by ours (same prefix, our next hop).
    #>
    param([Parameter(Mandatory)][string[]]$InternalRanges, [Parameter(Mandatory)][string]$FirewallIp, [string]$Location = '', [AllowNull()][object]$Existing)
    $ranges = @(ConvertTo-PimReturnRouteRangeList $InternalRanges)
    $fw = "$FirewallIp".Trim()
    $routes = New-Object System.Collections.Generic.List[object]
    if ($Existing -and $Existing.properties) {
        foreach ($r in @(@($Existing.properties.routes) | Where-Object { $_ })) {
            $pfx = "$($r.properties.addressPrefix)".Trim()
            if (@($ranges | Where-Object { $_ -ieq $pfx }).Count) { continue }
            $rp = [ordered]@{ addressPrefix = $pfx; nextHopType = "$($r.properties.nextHopType)" }
            if ("$($r.properties.nextHopIpAddress)".Trim()) { $rp.nextHopIpAddress = "$($r.properties.nextHopIpAddress)".Trim() }
            $routes.Add([ordered]@{ name = "$($r.name)"; properties = $rp })
        }
    }
    foreach ($g in $ranges) { $routes.Add([ordered]@{ name = (Get-PimReturnRouteName -Range $g); properties = [ordered]@{ addressPrefix = $g; nextHopType = 'VirtualAppliance'; nextHopIpAddress = $fw } }) }
    $loc = if ($Existing -and "$($Existing.location)".Trim()) { "$($Existing.location)".Trim() } else { "$Location".Trim() }
    $body = [ordered]@{ location = $loc; properties = [ordered]@{ disableBgpRoutePropagation = $true; routes = @($routes.ToArray()) } }
    if ($Existing -and $Existing.tags) { $body.tags = $Existing.tags }
    return $body
}

function Get-PimReturnRouteSubnetBody {
    <#
      PURE. The subnet PUT body with -RouteTableId attached. READ-MODIFY-WRITE: every property the subnet has is kept
      (addressPrefix, the Microsoft.App/environments delegation, NSG, service endpoints, defaultOutboundAccess, ...) except the
      read-only ones ARM refuses in a PUT -- the same list Set-PimArmSubnet (PIM-ArmSetup.ps1) drops.
    #>
    param([Parameter(Mandatory)][object]$Subnet, [Parameter(Mandatory)][string]$RouteTableId)
    $props = [ordered]@{}
    if ($Subnet.properties) {
        foreach ($p in $Subnet.properties.PSObject.Properties) {
            if ($p.Name -notin @('provisioningState', 'ipConfigurations', 'purpose', 'privateEndpoints', 'serviceAssociationLinks', 'resourceNavigationLinks', 'ipConfigurationProfiles')) { $props[$p.Name] = $p.Value }
        }
    }
    $props['routeTable'] = @{ id = "$RouteTableId".Trim() }
    return @{ properties = $props }
}

function Test-PimReturnRouteInPlace {
    <#
      PURE. Does the subnet carry the return route? -Subnet / -RouteTable as ARM answered. @{ ok; missing (ranges); reason }.
        the subnet has no route table, or another table than -RouteTable  -> not ok
        a range with no route, or a route that does not go VirtualAppliance -> -FirewallIp -> missing
        BGP route propagation on -> not ok (a gateway's learned routes would override the firewall path)
    #>
    param([AllowNull()][object]$Subnet, [AllowNull()][object]$RouteTable, [Parameter(Mandatory)][string[]]$InternalRanges, [Parameter(Mandatory)][string]$FirewallIp)
    $ranges = @(ConvertTo-PimReturnRouteRangeList $InternalRanges); $fw = "$FirewallIp".Trim()
    if (-not $Subnet) { return @{ ok = $false; missing = $ranges; reason = 'the app subnet could not be read' } }
    $rtId = "$($Subnet.properties.routeTable.id)".Trim()
    if (-not $rtId) { return @{ ok = $false; missing = $ranges; reason = "the app subnet '$($Subnet.name)' has no route table" } }
    if (-not $RouteTable) { return @{ ok = $false; missing = $ranges; reason = "the app subnet's route table $($rtId -replace '^.*/', '') could not be read" } }
    if ("$($RouteTable.id)".Trim() -and "$($RouteTable.id)".Trim() -ine $rtId) { return @{ ok = $false; missing = $ranges; reason = "the app subnet carries route table $($rtId -replace '^.*/', ''), not $($RouteTable.name)" } }
    $have = @(@($RouteTable.properties.routes) | Where-Object { $_ })
    $missing = @($ranges | Where-Object { $g = $_; -not @($have | Where-Object { "$($_.properties.addressPrefix)".Trim() -ieq $g -and "$($_.properties.nextHopType)" -ieq 'VirtualAppliance' -and "$($_.properties.nextHopIpAddress)".Trim() -eq $fw }).Count })
    $bgpOff = "$($RouteTable.properties.disableBgpRoutePropagation)" -eq 'True'
    $why = @()
    if ($missing.Count) { $why += "no route $($missing -join ', ') -> $fw (VirtualAppliance) in $($RouteTable.name)" }
    if (-not $bgpOff) { $why += "BGP route propagation is on in $($RouteTable.name)" }
    return @{ ok = (-not $missing.Count -and $bgpOff); missing = $missing; reason = ($why -join '; ') }
}

function Get-PimReturnRouteHandoffLine {
    <# PURE. The network hand-off line ('' without ranges). One route per range, as the network team types it. #>
    param([AllowNull()][string[]]$InternalRanges, [string]$FirewallIp, [string]$SubnetName = '')
    $ranges = @(ConvertTo-PimReturnRouteRangeList $InternalRanges); $fw = "$FirewallIp".Trim()
    if (-not $ranges.Count -or -not $fw) { return '' }
    $on = if ("$SubnetName".Trim()) { "the app subnet $("$SubnetName".Trim())" } else { 'the app subnet' }
    return ("Return route: $(@($ranges | ForEach-Object { "$_ -> $fw (VirtualAppliance)" }) -join ', ') on $on, BGP route propagation off " +
            '-- replies to your network time out without it')
}

function Get-PimReturnRouteTags {
    <# PURE. The tags the install merges onto ITS OWN resource group, so the nightly updater knows what to check. #>
    param([AllowNull()][string[]]$InternalRanges, [string]$FirewallIp)
    $n = Get-PimReturnRouteTagNames; $ranges = @(ConvertTo-PimReturnRouteRangeList $InternalRanges)
    if (-not $ranges.Count -or -not "$FirewallIp".Trim()) { return @{} }
    return @{ $n.ranges = ($ranges -join ' '); $n.firewall = "$FirewallIp".Trim() }
}

function ConvertFrom-PimReturnRouteTags {
    <# PURE. A resource group's tags -> @{ ranges; firewallIp } ($null when the install recorded no return route). #>
    param([AllowNull()][object]$Tags)
    if (-not $Tags) { return $null }
    $n = Get-PimReturnRouteTagNames
    $get = { param($k) if ($Tags -is [System.Collections.IDictionary]) { $Tags[$k] } elseif ($Tags.PSObject.Properties[$k]) { $Tags.$k } else { $null } }
    $r = @(ConvertTo-PimReturnRouteRangeList (& $get $n.ranges)); $f = "$(& $get $n.firewall)".Trim()
    if (-not $r.Count -or -not $f) { return $null }
    return @{ ranges = $r; firewallIp = $f }
}

function Test-PimReturnRouteRefusal {
    <# PURE. Is this failure a 401 / 403 (framework rule 16: outside rights = a customer task, never a stop)? #>
    param([AllowEmptyString()][string]$Text)
    return [bool]("$Text" -match '\b(401|403)\b|Forbidden|Unauthorized|AuthorizationFailed|LinkedAuthorizationFailed')
}

function Invoke-PimReturnRouteConverge {
    <#
      THIN. The installer's step. NEVER THROWS -- a missing return route makes the PIM Manager unreachable from the LAN, but
      everything else works, and the hand-off says exactly what to add; stopping the install would leave the customer with
      less, not more. Returns @{ state; lines (@{ level = ok|changed|warn; text }); handoff (the line, '' when done) }.
        state none      no ranges (nothing asked)
        state handoff   -CustomerNetwork: the app subnet is in a network the customer gave -- NOTHING is written there
        state done      rt-pim carries every route, BGP off, attached to the app subnet -- READ BACK
        state refused   a 401 / 403 (framework rule 16): warning + hand-off
        state failed    anything else (a policy denial, the subnet already on ANOTHER route table, a read-back that
                        disagrees): warning + hand-off
      -SubnetId  the app subnet (/subscriptions/../virtualNetworks/<vnet>/subnets/<name>); -ResourceGroupId the install's group
      (rt-pim lives there).
    #>
    param([AllowNull()][string[]]$InternalRanges, [string]$FirewallIp, [string]$SubnetId, [string]$ResourceGroupId, [string]$Location = '',
          [switch]$CustomerNetwork, [Parameter(Mandatory)][scriptblock]$Arm)
    $ranges = @(ConvertTo-PimReturnRouteRangeList $InternalRanges); $fw = "$FirewallIp".Trim()
    $lines = New-Object System.Collections.Generic.List[object]
    $say = { param($l, $t) $lines.Add(@{ level = $l; text = $t }) }
    $snName = "$SubnetId".Trim() -replace '^.*/', ''
    $hand = Get-PimReturnRouteHandoffLine -InternalRanges $ranges -FirewallIp $fw -SubnetName $snName
    if (-not $ranges.Count -or -not $fw) { return @{ state = 'none'; lines = @(); handoff = '' } }
    if ($CustomerNetwork) {
        & $say 'warn' "the app subnet is in your own network: PIM does not write it -- NETWORK HAND-OFF: $hand"
        return @{ state = 'handoff'; lines = @($lines.ToArray()); handoff = $hand }
    }
    $rtId = "$("$ResourceGroupId".Trim().TrimEnd('/'))/providers/Microsoft.Network/routeTables/$(Get-PimReturnRouteTableName)"
    $state = 'done'
    # (no `return` inside the try: Windows PowerShell 5.1's compiler fails such a body -- see Invoke-PimSetupRest)
    try {
        $cur = & $Arm 'GET' "$rtId`?$(Get-PimReturnRouteApi net)" $null
        $sn = & $Arm 'GET' "$("$SubnetId".Trim())?$(Get-PimReturnRouteApi net)" $null
        if (-not $sn) { throw "the app subnet $snName could not be read" }
        $other = "$($sn.properties.routeTable.id)".Trim()
        # the subnet already on ANOTHER route table (the network team's own): never replaced -- that table may carry routes we
        # cannot see the reason for; the routes go there instead (hand-off). Nothing is written.
        if ($other -and $other -ine $rtId) {
            $state = 'failed'
            & $say 'warn' "the app subnet $snName already uses route table $($other -replace '^.*/', '') -- it is not replaced; NETWORK HAND-OFF: add there: $hand"
        } else {
            $body = Get-PimReturnRouteTableBody -InternalRanges $ranges -FirewallIp $fw -Location $Location -Existing $cur
            [void](& $Arm 'PUT' "$rtId`?$(Get-PimReturnRouteApi net)" $body)
            $back = & $Arm 'GET' "$rtId`?$(Get-PimReturnRouteApi net)" $null
            if (-not $other) {
                [void](& $Arm 'PUT' "$("$SubnetId".Trim())?$(Get-PimReturnRouteApi net)" (Get-PimReturnRouteSubnetBody -Subnet $sn -RouteTableId $rtId))
                & $say 'changed' "route table $(Get-PimReturnRouteTableName) attached to the app subnet $snName"
            }
            $sn2 = & $Arm 'GET' "$("$SubnetId".Trim())?$(Get-PimReturnRouteApi net)" $null
            $v = Test-PimReturnRouteInPlace -Subnet $sn2 -RouteTable $back -InternalRanges $ranges -FirewallIp $fw
            if ($v.ok) { & $say 'ok' "return route: $(@($ranges | ForEach-Object { "$_ -> $fw" }) -join ', ') (VirtualAppliance) on $snName, BGP route propagation off -- read back" }
            else { $state = 'failed'; & $say 'warn' "the return route was written but does not read back ($($v.reason)) -- NETWORK HAND-OFF: $hand" }
        }
    } catch {
        $m = (("$($_.Exception.Message)") -split "`n")[0]
        if (Test-PimReturnRouteRefusal -Text $m) { $state = 'refused'; & $say 'warn' "the installer may not write the return route (refused: $m) -- CUSTOMER TASK, the install goes on: $hand" }
        else { $state = 'failed'; & $say 'warn' "the return route could not be made ($m) -- NETWORK HAND-OFF: $hand" }
    }
    return @{ state = $state; lines = @($lines.ToArray()); handoff = $(if ($state -eq 'done') { '' } else { $hand }) }
}

function Get-PimReturnRouteReport {
    <#
      THIN, READ ONLY -- the nightly updater's check (it NEVER creates or changes a route: the route is a network decision the
      install made with the customer's answers, and a wrong next hop would cut the LAN off). -Arm is called with 'GET' only.
      The install's answers come from its resource group's tags (Get-PimReturnRouteTags); no tags = nothing was asked = nothing
      to check. Then: the Manager app -> its environment -> infrastructureSubnetId -> the subnet -> its route table.
      Never throws: @{ state = none|ok|missing|unknown; text }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$ManagerApp = 'ca-pim-manager',
          [Parameter(Mandatory)][scriptblock]$Arm)
    # (one result, returned once below: no `return` inside the try -- the PS 5.1 compile trap)
    $res = $null
    try {
        $rg = & $Arm 'GET' "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup`?$(Get-PimReturnRouteApi rg)" $null
        $want = ConvertFrom-PimReturnRouteTags -Tags $(if ($rg) { $rg.tags } else { $null })
        if (-not $want) { $res = @{ state = 'none'; text = 'return route: no internal ranges were given at install -- nothing to check' } }
        else {
            $app = & $Arm 'GET' "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$ManagerApp`?$(Get-PimReturnRouteApi aca)" $null
            $envId = "$($app.properties.managedEnvironmentId)".Trim(); if (-not $envId) { $envId = "$($app.properties.environmentId)".Trim() }
            $snId = ''
            if ($envId) { $env1 = & $Arm 'GET' "$envId`?$(Get-PimReturnRouteApi aca)" $null; $snId = "$($env1.properties.vnetConfiguration.infrastructureSubnetId)".Trim() }
            if (-not $snId) { $res = @{ state = 'unknown'; text = 'return route: not checked -- the app subnet could not be read from the Container Apps environment' } }
            else {
                $sn = & $Arm 'GET' "$snId`?$(Get-PimReturnRouteApi net)" $null
                $rtId = "$($sn.properties.routeTable.id)".Trim()
                $rt = if ($rtId) { & $Arm 'GET' "$rtId`?$(Get-PimReturnRouteApi net)" $null } else { $null }
                $v = Test-PimReturnRouteInPlace -Subnet $sn -RouteTable $rt -InternalRanges $want.ranges -FirewallIp $want.firewallIp
                $snName = $snId -replace '^.*/', ''
                if ($v.ok) { $res = @{ state = 'ok'; text = "return route: in place on $snName ($(@($want.ranges) -join ', ') -> $($want.firewallIp))" } }
                else {
                    $res = @{ state = 'missing'; text = ("return route MISSING: $($v.reason) -- the updater never creates it. NETWORK HAND-OFF: " +
                                                         (Get-PimReturnRouteHandoffLine -InternalRanges $want.ranges -FirewallIp $want.firewallIp -SubnetName $snName)) }
                }
            }
        }
    } catch { $res = @{ state = 'unknown'; text = "return route: not checked -- $((("$($_.Exception.Message)") -split "`n")[0])" } }
    return $res
}
