#Requires -Version 5.1
<#
.SYNOPSIS
    KV-POLICY-DENIED-PRIVATE / framework installer rule 11 (Invardia 2026-11-03) -- a PRIVATE install's Key Vault is private.

.DESCRIPTION
    Owner rule (Invardia DESIGN ch 12, 2026-10-19): "when we say it is private, it stays that way". THE SHAPE (rule 11, the
    common setting SI and EPS build):
      publicNetworkAccess Disabled + networkAcls { defaultAction Deny, bypass AzureServices, no ipRules, no virtualNetworkRules }
      + a vault private endpoint (groupId 'vault') registered in privatelink.vaultcore.azure.net.
    bypass is AzureServices, NEVER None: EPS measured bypass None -> ARM key GET / PUT 400 ForbiddenByConnection.
    RULE 11 ADDITION (EPS live run 3): a re-install can RECOVER a soft-deleted vault, and a recover IGNORES networkAcls (it comes
    back with bypass None). So the vault is PATCHED to the shape and READ BACK before any key step -- whether it was made,
    recovered or found. The same call moves an existing private install's vault over (the updater).

    The private endpoint goes where the install's SQL endpoint is (pe-<sql server>: its subnet, its location) and its zone
    follows the SQL endpoint's zone: a CENTRAL zone (another resource group) is used and never created; the install's own
    resource group gets the zone + a link to the network when missing -- the as-built storage endpoint's rule (PIM-AsBuilt.ps1).

      Get-PimKeyVaultRule11Drift   PURE: the vault answer -> the fields that are not the shape ('' list = private)
      New-PimKeyVaultRule11Patch   PURE: the PATCH body
      Invoke-PimKeyVaultRule11     THIN: PATCH + read back, then the endpoint, the zone, the zone group -> @{ ok; changed; reason; lines }
    No module, no az: -Arm is the caller's ARM client, param([string]$Method, [string]$Path, [object]$Body) with the path's own
    api-version; a GET of something that is not there answers $null.
#>

$script:PimKvRule11Zone = 'privatelink.vaultcore.azure.net'
$script:PimKvApi = 'api-version=2023-07-01'
$script:PimKvNetApi = 'api-version=2023-09-01'
$script:PimKvDnsApi = 'api-version=2020-06-01'

function Get-PimKeyVaultRule11Drift {
    <# PURE. The vault (ARM GET answer) -> the rule-11 fields it misses, in plain words. Empty = the shape holds. #>
    param([AllowNull()][object]$Vault)
    if ($null -eq $Vault) { return @('the vault could not be read') }
    $p = $Vault.properties
    $acl = $p.networkAcls
    $d = New-Object System.Collections.Generic.List[string]
    if ("$($p.publicNetworkAccess)" -ine 'Disabled') { $d.Add("publicNetworkAccess is '$($p.publicNetworkAccess)', not Disabled") }
    if ("$($acl.defaultAction)" -ine 'Deny') { $d.Add("networkAcls.defaultAction is '$($acl.defaultAction)', not Deny") }
    if ("$($acl.bypass)" -ine 'AzureServices') { $d.Add("networkAcls.bypass is '$($acl.bypass)', not AzureServices") }
    if (@(@($acl.ipRules) | Where-Object { $_ }).Count) { $d.Add("$(@(@($acl.ipRules) | Where-Object { $_ }).Count) IP rule(s)") }
    if (@(@($acl.virtualNetworkRules) | Where-Object { $_ }).Count) { $d.Add("$(@(@($acl.virtualNetworkRules) | Where-Object { $_ }).Count) virtual network rule(s)") }
    return @($d.ToArray())
}

function New-PimKeyVaultRule11Patch {
    <# PURE. The PATCH body that sets the rule-11 shape (and nothing else). #>
    return [ordered]@{ properties = [ordered]@{ publicNetworkAccess = 'Disabled'
        networkAcls = [ordered]@{ defaultAction = 'Deny'; bypass = 'AzureServices'; ipRules = @(); virtualNetworkRules = @() } } }
}

function Invoke-PimKeyVaultRule11 {
    <#
      THIN. -VaultId /subscriptions/../resourceGroups/../providers/Microsoft.KeyVault/vaults/<name>; -SqlServerName the install's
      SQL server (its pe-<name> gives the subnet + the zone's resource group). -Sleep param($s) (test seam). Never throws:
      @{ ok; changed (bool); reason (why not ok); lines (@{ level = ok|changed|warn; text }) }.
      ok = the vault holds the shape (read back) AND has its endpoint in the zone. The CALLER decides: the installer stops before
      the key step on ok = $false; the updater reports it.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$VaultId, [string]$SqlServerName = '',
          [scriptblock]$Sleep, [int]$ReadBackTries = 6)
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $res = @{ ok = $false; changed = $false; reason = ''; customerTask = ''; lines = (New-Object System.Collections.Generic.List[object]) }
    $add = { param($lvl, $t) $res.lines.Add(@{ level = $lvl; text = $t }) | Out-Null; if ($lvl -eq 'changed') { $res.changed = $true } }
    $vid = "$VaultId".Trim().TrimEnd('/')
    $vName = ($vid -split '/')[-1]
    $rg = ($vid -replace '(?i)/providers/Microsoft\.KeyVault/vaults/[^/]+$', '')
    try {
        # ---- 1. the shape: PATCH whenever it is not there, then READ BACK (a recovered vault ignores networkAcls) ------------
        $v = & $Arm 'GET' "$vid`?$script:PimKvApi" $null
        if (-not $v) { $res.reason = "the Key Vault $vName was not found"; return $res }
        $drift = @(Get-PimKeyVaultRule11Drift -Vault $v)
        if ($drift.Count) {
            [void](& $Arm 'PATCH' "$vid`?$script:PimKvApi" (New-PimKeyVaultRule11Patch))
            & $add 'changed' "Key Vault $vName set private (rule 11): $($drift -join '; ')"
            for ($i = 0; $i -lt $ReadBackTries; $i++) {
                $v = & $Arm 'GET' "$vid`?$script:PimKvApi" $null
                $drift = @(Get-PimKeyVaultRule11Drift -Vault $v)
                if (-not $drift.Count) { break }
                & $Sleep 5
            }
            if ($drift.Count) { $res.reason = "the Key Vault $vName did not take the private shape (read back: $($drift -join '; '))"; & $add 'warn' $res.reason; return $res }
            & $add 'ok' "Key Vault $vName read back private: publicNetworkAccess Disabled, Deny, bypass AzureServices, no IP / network rules"
        } else { & $add 'ok' "Key Vault $vName is private (rule 11 shape read back)" }

        # ---- 2. the vault's private endpoint, beside the SQL endpoint ------------------------------------------------------
        $peName = "pe-$vName"
        $pePath = "$rg/providers/Microsoft.Network/privateEndpoints/$peName"
        $sqlPe = $null
        if ("$SqlServerName".Trim()) { $sqlPe = & $Arm 'GET' "$rg/providers/Microsoft.Network/privateEndpoints/pe-$("$SqlServerName".Trim())`?$script:PimKvNetApi" $null }
        $pe = & $Arm 'GET' "$pePath`?$script:PimKvNetApi" $null
        # an endpoint someone else made (another name) that the vault has APPROVED is kept: never a second one
        $otherPe = @(@($v.properties.privateEndpointConnections) | Where-Object { $_ -and "$($_.properties.privateLinkServiceConnectionState.status)" -ieq 'Approved' })
        if (-not $pe -and $otherPe.Count) {
            & $add 'ok' "Key Vault $vName already has an approved private endpoint ($((("$($otherPe[0].properties.privateEndpoint.id)") -split '/')[-1])) -- kept, none added"
            $res.ok = $true
            return $res
        }
        if (-not $pe) {
            $subnetId = "$($sqlPe.properties.subnet.id)".Trim()
            if (-not $subnetId) { $res.reason = "no private endpoint for the vault, and the install's SQL endpoint (pe-$SqlServerName) gives no subnet to put one in"; & $add 'warn' $res.reason; return $res }
            $loc = "$($sqlPe.location)".Trim(); if (-not $loc) { $loc = "$($v.location)".Trim() }
            [void](& $Arm 'PUT' "$pePath`?$script:PimKvNetApi" @{ location = $loc; properties = @{ subnet = @{ id = $subnetId }
                privateLinkServiceConnections = @(@{ name = 'vault'; properties = @{ privateLinkServiceId = $vid; groupIds = @('vault') } }) } })
            & $add 'changed' "private endpoint $peName for $vName (vault) created in $(($subnetId -split '/')[-1])"
            $pe = & $Arm 'GET' "$pePath`?$script:PimKvNetApi" $null
        }
        $vnetId = ("$($pe.properties.subnet.id)".Trim() -replace '(?i)/subnets/[^/]+$', '')

        # ---- 3. the zone: the SQL endpoint's zone resource group (central = used, never created), else this resource group --
        $zoneRg = $rg
        if ($sqlPe) {
            $zg = & $Arm 'GET' "$rg/providers/Microsoft.Network/privateEndpoints/pe-$("$SqlServerName".Trim())/privateDnsZoneGroups`?$script:PimKvNetApi" $null
            $sqlZoneId = "$(@(@(@($zg.value)[0].properties.privateDnsZoneConfigs))[0].properties.privateDnsZoneId)".Trim()
            if ($sqlZoneId -match '(?i)^(/subscriptions/[^/]+/resourceGroups/[^/]+)/') { $zoneRg = $Matches[1] }
        }
        $own = ($zoneRg -ieq $rg)
        $zonePath = "$zoneRg/providers/Microsoft.Network/privateDnsZones/$script:PimKvRule11Zone"
        # framework installer rules 14 + 16 (2026-11-04): the customer's CENTRAL zone (outside the install's resource group) that
        # is missing, or that the caller may not read (401 / 403), is a CUSTOMER TASK with a warning -- the vault is already in
        # the private shape and has its endpoint, so ok = $true with .customerTask set; never a stop
        $z = $null; $zRefused = $false
        try { $z = & $Arm 'GET' "$zonePath`?$script:PimKvDnsApi" $null }
        catch { if (-not $own -and "$($_.Exception.Message)" -match '\b(401|403)\b|Forbidden|AuthorizationFailed') { $zRefused = $true } else { throw } }
        if (-not $z) {
            if (-not $own) {
                $res.customerTask = $(if ($zRefused) { "the central zone $script:PimKvRule11Zone in $(($zoneRg -split '/')[-1]) may not be read by this sign-in (refused)" } else { "the central zone $script:PimKvRule11Zone is not in $(($zoneRg -split '/')[-1])" }) +
                    " -- CUSTOMER TASK: the network team creates / links it and registers $peName in it (PIM never writes a central zone)"
                & $add 'warn' $res.customerTask
                $res.ok = $true
                return $res
            }
            [void](& $Arm 'PUT' "$zonePath`?$script:PimKvDnsApi" @{ location = 'global' })
            & $add 'changed' "private DNS zone $script:PimKvRule11Zone created"
        }
        if ($own -and $vnetId) {
            $links = & $Arm 'GET' "$zonePath/virtualNetworkLinks`?$script:PimKvDnsApi" $null
            if (-not @(@($links.value) | Where-Object { $_ -and "$($_.properties.virtualNetwork.id)" -ieq $vnetId }).Count) {
                [void](& $Arm 'PUT' "$zonePath/virtualNetworkLinks/link-$(($vnetId -split '/')[-1])`?$script:PimKvDnsApi" @{ location = 'global'; properties = @{ virtualNetwork = @{ id = $vnetId }; registrationEnabled = $false } })
                & $add 'changed' "$script:PimKvRule11Zone linked to $(($vnetId -split '/')[-1])"
            }
        }
        # ---- 4. the endpoint registered in the zone -------------------------------------------------------------------------
        $zgMine = & $Arm 'GET' "$pePath/privateDnsZoneGroups/default`?$script:PimKvNetApi" $null
        if (-not $zgMine) {
            [void](& $Arm 'PUT' "$pePath/privateDnsZoneGroups/default`?$script:PimKvNetApi" @{ properties = @{ privateDnsZoneConfigs = @(@{ name = 'vault'; properties = @{ privateDnsZoneId = $zonePath } }) } })
            & $add 'changed' "$peName registered in $script:PimKvRule11Zone"
        }
        $res.ok = $true
    } catch {
        $res.reason = "the private Key Vault could not be set: $((("$($_.Exception.Message)") -split "`n")[0])"
        & $add 'warn' $res.reason
    }
    return $res
}
