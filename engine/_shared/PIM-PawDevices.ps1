# PIM4EntraPS -- PAW (Privileged Access Workstation) device tagging + group.
# Dot-sourced by PIM-Functions.psm1 + the pim-manager.
#
# The tier-0 network gate (PIM-PortalAccess.ps1) consumes a resolved zone; PAW
# detection is environment-specific. This module lets the solution OWN that: make
# a PAW security group, tag devices into it (group membership is the reliable
# signal; an extensionAttribute is supported where the tenant populates it), and
# decide if a device is a PAW. Pure body-builders + decision (testable); live
# Graph calls are thin wrappers.

Set-StrictMode -Off

# PAW LEVELS (match the admin-level model): L0 = high-priv (manages tier-0 any
# level), L1 = consultants (tier-0 L1/L2), L2 = helpdesk (tier-0 L2 only). One PAW
# security group per level.
function Get-PimPawGroupName {
    # Name comes from the NAMING CONVENTION config (never hardcode per customer):
    # $global:PIM_NamingConventions['PawGroupPattern'] with a {Level} token; falls
    # back to a sensible default only when the convention doesn't define one.
    param([Parameter(Mandatory)][ValidateRange(0,2)][int]$Level)
    $pat = $null
    if ($global:PIM_NamingConventions -is [hashtable] -and $global:PIM_NamingConventions.ContainsKey('PawGroupPattern')) { $pat = "$($global:PIM_NamingConventions['PawGroupPattern'])" }
    if (-not "$pat".Trim()) { $pat = 'PIM-PAW-L{Level}-Devices' }
    return ($pat -replace '\{Level\}', "$Level")
}

function Get-PimPawAuName {
    param()
    if ($global:PIM_NamingConventions -is [hashtable] -and $global:PIM_NamingConventions.ContainsKey('PawAuName') -and "$($global:PIM_NamingConventions['PawAuName'])".Trim()) {
        return "$($global:PIM_NamingConventions['PawAuName'])"
    }
    return 'PIM-PAW-Devices-Restricted'
}

function New-PimPawGroupBody {
    # Graph body to create a per-LEVEL PAW security group (membership = PAW devices
    # of that level).
    param([Parameter(Mandatory)][ValidateRange(0,2)][int]$Level, [string]$DisplayName, [string]$Description, [string]$MailNickname)
    $name = if ("$DisplayName".Trim()) { $DisplayName } else { Get-PimPawGroupName -Level $Level }
    $desc = if ("$Description".Trim()) { $Description } else { "Privileged Access Workstations level $Level (L0=high-priv, L1=consultant, L2=helpdesk)" }
    $nick = if ("$MailNickname".Trim()) { $MailNickname } else { ($name -replace '[^A-Za-z0-9]', '') }
    return [ordered]@{ displayName = $name; description = $desc; mailEnabled = $false; mailNickname = $nick; securityEnabled = $true }
}

function Get-PimDevicePawLevel {
    # The device's PAW LEVEL (0/1/2, lowest/most-privileged wins) or $null. By
    # group membership (PawGroupIds = @{ 0='id0'; 1='id1'; 2='id2' }) and/or an
    # extensionAttribute holding 'PAW-L<n>'.
    param([Parameter(Mandatory)][object]$Device, [hashtable]$PawGroupIds = @{}, [int]$ExtensionAttribute)
    $best = $null
    $memberIds = New-Object System.Collections.Generic.List[string]
    foreach ($prop in 'transitiveMemberOf','memberOf') {
        $mo = $Device.PSObject.Properties[$prop]; if ($mo -and $mo.Value) { foreach ($g in @($mo.Value)) { $memberIds.Add("$($g.id)") } }
    }
    $gi = $Device.PSObject.Properties['groupIds']; if ($gi) { foreach ($x in @($gi.Value)) { $memberIds.Add("$x") } }
    foreach ($lvl in @($PawGroupIds.Keys)) {
        if ($memberIds -contains "$($PawGroupIds[$lvl])") { $n = [int]$lvl; if ($null -eq $best -or $n -lt $best) { $best = $n } }
    }
    if ($ExtensionAttribute -ge 1) {
        $ea = $Device.PSObject.Properties['extensionAttributes']
        if ($ea -and $ea.Value) {
            $v = $ea.Value.PSObject.Properties["extensionAttribute$ExtensionAttribute"]
            if ($v) { $m = [regex]::Match("$($v.Value)", '(?i)PAW-?L([012])'); if ($m.Success) { $n = [int]$m.Groups[1].Value; if ($null -eq $best -or $n -lt $best) { $best = $n } } }
        }
    }
    return $best
}

function New-PimPawDeviceTagBody {
    # PATCH body to tag a device via an extension attribute (where the tenant
    # populates device extensionAttributes, e.g. via Intune). Group membership is
    # the primary signal; this is the secondary one.
    param([Parameter(Mandatory)][ValidateRange(1,15)][int]$ExtensionAttribute, [string]$Value = 'PAW')
    return [ordered]@{ extensionAttributes = [ordered]@{ ("extensionAttribute$ExtensionAttribute") = $Value } }
}

function Test-PimDeviceIsPaw {
    # PURE decision: is this device a PAW? TRUE when it is a member of the PAW
    # group (primary; checks memberOf / transitiveMemberOf ids) OR carries the
    # configured PAW extensionAttribute value (secondary).
    param(
        [Parameter(Mandatory)][object]$Device,
        [string]$PawGroupId,
        [int]$ExtensionAttribute,
        [string]$ExpectedValue = 'PAW'
    )
    if ("$PawGroupId".Trim()) {
        foreach ($prop in 'transitiveMemberOf','memberOf') {
            $mo = $Device.PSObject.Properties[$prop]
            if ($mo -and $mo.Value) { foreach ($g in @($mo.Value)) { if ("$($g.id)" -eq "$PawGroupId") { return $true } } }
        }
        # also accept a plain id array
        $gm = $Device.PSObject.Properties['groupIds']
        if ($gm -and (@($gm.Value) -contains "$PawGroupId")) { return $true }
    }
    if ($ExtensionAttribute -ge 1) {
        $ea = $Device.PSObject.Properties['extensionAttributes']
        if ($ea -and $ea.Value) {
            $v = $ea.Value.PSObject.Properties["extensionAttribute$ExtensionAttribute"]
            if ($v -and "$($v.Value)" -ieq "$ExpectedValue") { return $true }
        }
    }
    return $false
}

# --- protection: restricted-management AU (like the high-priv PIM AUs) ----------
function New-PimPawAuBody {
    # A RESTRICTED-MANAGEMENT administrative unit body. Groups placed in it can be
    # managed ONLY by admins with roles scoped to this AU (i.e. by this tool's
    # service principal) -- not by general Group/User admins. Same protection model
    # as the high-priv PIM AUs, applied to the PAW device groups so they can't be
    # tampered with outside this solution.
    param([string]$DisplayName, [string]$Description = 'Restricted-management AU protecting the PAW device groups (managed only by this tool).')
    if (-not "$DisplayName".Trim()) { $DisplayName = Get-PimPawAuName }
    return [ordered]@{
        displayName                  = $DisplayName
        description                  = $Description
        isMemberManagementRestricted = $true
    }
}

# --- live Graph wrappers (thin) -------------------------------------------------
function New-PimPawAu {
    param([string]$DisplayName = 'PIM-PAW-Devices-Restricted')
    return Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/administrativeUnits' -Body ((New-PimPawAuBody -DisplayName $DisplayName) | ConvertTo-Json -Depth 6) -ContentType 'application/json' -ErrorAction Stop
}

function Add-PimGroupToAu {
    # Place a group under an AU (membership). For the restricted-management AU this
    # is what locks the PAW group down to scoped management only.
    param([Parameter(Mandatory)][string]$AuId, [Parameter(Mandatory)][string]$GroupId)
    [void](Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/administrativeUnits/$AuId/members/`$ref" -Body (@{ "@odata.id" = "https://graph.microsoft.com/v1.0/groups/$GroupId" } | ConvertTo-Json) -ContentType 'application/json' -ErrorAction Stop)
}

function Get-PimPawGroupId {
    # Resolve a per-level PAW group's object id by displayName (PIM-PAW-L<n>-Devices).
    param([Parameter(Mandatory)][ValidateRange(0,2)][int]$Level)
    $name = Get-PimPawGroupName -Level $Level
    $r = Invoke-MgGraphRequest -Method GET -Uri ("https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '" + $name.Replace("'","''") + "'&`$select=id") -ErrorAction Stop
    $first = @($r.value) | Select-Object -First 1
    if ($first) { return "$($first.id)" }
    return $null
}

function Get-PimPawGroupIds {
    # Resolve all three level groups -> @{ 0=id; 1=id; 2=id } (missing levels omitted).
    $map = @{}
    foreach ($lvl in 0,1,2) { $id = Get-PimPawGroupId -Level $lvl; if ($id) { $map[$lvl] = $id } }
    return $map
}

function New-PimPawGroup {
    # Create one per-level PAW group and (when -RestrictedAuId given) place it in
    # the restricted-management AU so it can't be managed outside this tool. Run
    # for each of L0/L1/L2 to stand up all three.
    param([Parameter(Mandatory)][ValidateRange(0,2)][int]$Level, [string]$RestrictedAuId)
    $body = New-PimPawGroupBody -Level $Level
    $g = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/groups' -Body ($body | ConvertTo-Json -Depth 6) -ContentType 'application/json' -ErrorAction Stop
    if ("$RestrictedAuId".Trim() -and $g.id) { Add-PimGroupToAu -AuId $RestrictedAuId -GroupId "$($g.id)" }
    return $g
}

function Add-PimPawDevice {
    # Tag a device as a PAW at a LEVEL: add it to that level's PAW group (primary)
    # and optionally set the extensionAttribute to 'PAW-L<n>' (-ExtensionAttribute).
    param(
        [Parameter(Mandatory)][string]$DeviceObjectId,
        [Parameter(Mandatory)][ValidateRange(0,2)][int]$Level,
        [string]$PawGroupId,
        [int]$ExtensionAttribute
    )
    $gid = if ("$PawGroupId".Trim()) { $PawGroupId } else { Get-PimPawGroupId -Level $Level }
    if (-not $gid) { throw "Add-PimPawDevice: PAW L$Level group not found (create it first with New-PimPawGroup -Level $Level)." }
    [void](Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/groups/$gid/members/`$ref" -Body (@{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$DeviceObjectId" } | ConvertTo-Json) -ContentType 'application/json' -ErrorAction Stop)
    if ($ExtensionAttribute -ge 1) {
        [void](Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/devices/$DeviceObjectId" -Body ((New-PimPawDeviceTagBody -ExtensionAttribute $ExtensionAttribute -Value "PAW-L$Level") | ConvertTo-Json -Depth 6) -ContentType 'application/json' -ErrorAction Stop)
    }
}
