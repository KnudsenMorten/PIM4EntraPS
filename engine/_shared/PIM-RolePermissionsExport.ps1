# PIM-RolePermissionsExport.ps1 -- pure CSV export of the Role Lookup surfaces
# (REQUIREMENTS.md s28 [L5] "copy/export of role permissions for least-privilege
#  tickets" + [H5] "export/print on operational views").
#
# The Role Lookup tab answers four read-only questions and, until now, NONE of its
# four modes could lift its result into a least-privilege ticket / auditor trail
# without retyping:
#   1. PERMISSIONS  -- what a role can do  (allowedResourceActions, grouped by ns)
#   2. BY-ACTION    -- which roles grant operation X (ranked least-privilege first)
#   3. REVERSE      -- who can activate a role, with the granting path
#   4. COMPARE      -- who can activate role A vs B vs both
#
# This dependency-free, PS-5.1-safe library turns each of those result shapes into
# RFC-4180 CSV with the SAME spreadsheet formula-injection guard the rest of the
# Manager uses (the audit export's ConvertTo-PimAuditCsvCell, the GUI's csvCell):
# a cell that begins with = + - @ (or a tab/CR) is prefixed with a single quote so
# Excel/Sheets never evaluate it as a formula. The GUI exports CLIENT-SIDE from the
# already-rendered data (same downloadCsv/printTable pattern as Reports/Map/Validate);
# this shared core makes the SAME flattening offline-unit-testable and gives any
# tooling/test one place that resolves a Role Lookup export identically to the screen.
#
# Pure: no module deps, no SQL, no network, no global state. Nothing here writes.

function ConvertTo-PimRolePermCsvCell {
    # RFC-4180 quoting + CSV formula-injection guard. Identical contract to the GUI
    # csvCell and ConvertTo-PimAuditCsvCell so an export reads the same everywhere.
    param([object]$Value)
    $s = if ($null -eq $Value) { '' } else { "$Value" }
    if ($s -match '^[=+\-@\t\r]') { $s = "'" + $s }
    if ($s -match '[",\r\n]') { $s = '"' + ($s -replace '"', '""') + '"' }
    return $s
}

function ConvertTo-PimRolePermCsv {
    <#
    .SYNOPSIS
        Render a header + rows to RFC-4180 CSV text (CRLF, formula-guarded).
    .DESCRIPTION
        Shared by every Role Lookup export. Headers and each row are arrays of
        scalars; every cell is passed through ConvertTo-PimRolePermCsvCell. Returns
        a string; the caller (GUI) prepends the UTF-8 BOM at download time. Pure.
    .PARAMETER Headers
        Column headers (array of strings).
    .PARAMETER Rows
        Array of rows; each row an array of cell values (any scalar, $null -> '').
    #>
    [CmdletBinding()]
    param(
        [object[]]$Headers = @(),
        [object[]]$Rows = @()
    )
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(($Headers | ForEach-Object { ConvertTo-PimRolePermCsvCell $_ }) -join ',')
    foreach ($r in @($Rows)) {
        $cells = @($r) | ForEach-Object { ConvertTo-PimRolePermCsvCell $_ }
        $lines.Add(($cells -join ','))
    }
    return ($lines -join "`r`n")
}

function Get-PimRolePermResourceActions {
    # Flatten a role definition's rolePermissions[] into a de-duped, ORDER-PRESERVING
    # list of action records: { action; kind = allowed|excluded|allowedData|excludedData }.
    # Accepts the Graph roleDefinition shape (object OR hashtable) the Role Lookup
    # "what a role can do" view drills into. Pure, no fetch.
    param([object]$Role)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Role) { return $out.ToArray() }
    $perms = $null
    if ($Role -is [System.Collections.IDictionary]) {
        if ($Role.Contains('rolePermissions')) { $perms = $Role['rolePermissions'] }
        elseif ($Role.Contains('allowedResourceActions')) { $perms = @($Role) }
    } else {
        if ($Role.PSObject.Properties['rolePermissions']) { $perms = $Role.PSObject.Properties['rolePermissions'].Value }
        elseif ($Role.PSObject.Properties['allowedResourceActions']) { $perms = @($Role) }
    }
    if ($null -eq $perms) { return $out.ToArray() }
    $seen = New-Object System.Collections.Generic.HashSet[string]
    $kinds = @(
        @{ prop = 'allowedResourceActions';  kind = 'allowed' },
        @{ prop = 'excludedResourceActions'; kind = 'excluded' },
        @{ prop = 'allowedDataActions';      kind = 'allowedData' },
        @{ prop = 'excludedDataActions';     kind = 'excludedData' }
    )
    foreach ($p in @($perms)) {
        if ($null -eq $p) { continue }
        foreach ($k in $kinds) {
            # Inline property read (no nested function -- PS 5.1's enumerable binder
            # throws "Argument types do not match" on `foreach (x in (nestedFn ...))`).
            $vals = @()
            if ($p -is [System.Collections.IDictionary]) {
                if ($p.Contains($k.prop)) { $vals = @($p[$k.prop]) }
            } else {
                $prop = $p.PSObject.Properties[$k.prop]
                if ($prop) { $vals = @($prop.Value) }
            }
            foreach ($a in $vals) {
                $act = "$a".Trim()
                if (-not $act) { continue }
                $key = "$($k.kind)|$act"
                if (-not $seen.Add($key)) { continue }
                $ns = ''
                $slash = $act.IndexOf('/')
                if ($slash -gt 0) { $ns = $act.Substring(0, $slash) }
                $out.Add([pscustomobject]@{ action = $act; kind = $k.kind; namespace = $ns }) | Out-Null
            }
        }
    }
    # .ToArray() not @($list) -- @() over a List[object] throws "Argument types do
    # not match" on PS 5.1 (the enumerable-binder bug). Same below for the early returns.
    return $out.ToArray()
}

function ConvertTo-PimRolePermissionsCsv {
    <#
    .SYNOPSIS
        [L5] -- export a single role's concrete permissions for a least-privilege
        ticket. CSV columns: Role, Permission, Namespace, Action.
    .DESCRIPTION
        Flattens the role's allowed/excluded resource + data actions (the same set
        the Role Lookup "what a role can do" view shows) into one CSV row per action,
        each labelled by kind and namespace so the ticket carries the full grant.
    .PARAMETER Role
        The Graph roleDefinition (object/hashtable) with rolePermissions[].
    .PARAMETER RoleName
        Display name to stamp in the Role column (defaults to $Role.displayName).
    #>
    [CmdletBinding()]
    param([object]$Role, [string]$RoleName = '')
    $name = "$RoleName".Trim()
    if (-not $name -and $null -ne $Role) {
        if ($Role -is [System.Collections.IDictionary]) { if ($Role.Contains('displayName')) { $name = "$($Role['displayName'])" } }
        elseif ($Role.PSObject.Properties['displayName']) { $name = "$($Role.PSObject.Properties['displayName'].Value)" }
    }
    $kindLabel = @{ allowed = 'Allowed action'; excluded = 'Excluded action'; allowedData = 'Allowed data action'; excludedData = 'Excluded data action' }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($a in (Get-PimRolePermResourceActions -Role $Role)) {
        $label = if ($kindLabel.ContainsKey($a.kind)) { $kindLabel[$a.kind] } else { $a.kind }
        $rows.Add(@($name, $label, $a.namespace, $a.action)) | Out-Null
    }
    return (ConvertTo-PimRolePermCsv -Headers @('Role', 'Permission', 'Namespace', 'Action') -Rows $rows.ToArray())
}

function ConvertTo-PimRolesByActionCsv {
    <#
    .SYNOPSIS
        [L5]/[H9a] -- export the "which roles grant action X, least-privilege first"
        result. CSV columns: Rank, Role, TotalActions, Broad, MatchedActions.
    .DESCRIPTION
        Takes the matches[] array (each { role; totalActions; viaWildcard;
        matchedActions[] }) Find-PimRolesByAction returns, in the order given (already
        ranked narrowest-first), and emits one row per role. MatchedActions is joined
        with '; ' so the narrowest fit for a least-privilege ticket is one cell.
    .PARAMETER Matches
        The ranked matches array from the by-action lookup.
    #>
    [CmdletBinding()]
    param([object[]]$Matches = @())
    $rows = New-Object System.Collections.Generic.List[object]
    $rank = 0
    foreach ($m in @($Matches)) {
        if ($null -eq $m) { continue }
        $rank++
        $role  = ''; $total = ''; $wild = $false; $matched = @()
        if ($m -is [System.Collections.IDictionary]) {
            if ($m.Contains('role'))           { $role = "$($m['role'])" }
            if ($m.Contains('totalActions'))   { $total = "$($m['totalActions'])" }
            if ($m.Contains('viaWildcard'))    { $wild = [bool]$m['viaWildcard'] }
            if ($m.Contains('matchedActions')) { $matched = @($m['matchedActions']) }
        } else {
            if ($m.PSObject.Properties['role'])           { $role = "$($m.role)" }
            if ($m.PSObject.Properties['totalActions'])   { $total = "$($m.totalActions)" }
            if ($m.PSObject.Properties['viaWildcard'])    { $wild = [bool]$m.viaWildcard }
            if ($m.PSObject.Properties['matchedActions']) { $matched = @($m.matchedActions) }
        }
        $matchedStr = (@($matched) | ForEach-Object { "$_" }) -join '; '
        $rows.Add(@($rank, $role, $total, $(if ($wild) { 'yes' } else { 'no' }), $matchedStr)) | Out-Null
    }
    return (ConvertTo-PimRolePermCsv -Headers @('Rank', 'Role', 'TotalActions', 'Broad', 'MatchedActions') -Rows $rows.ToArray())
}

function ConvertTo-PimRoleReachersCsv {
    <#
    .SYNOPSIS
        [H5]/[L5] -- export "who can activate a role, with the granting path" (the
        reverse lookup). CSV columns: Role, Who, Purpose, Path.
    .DESCRIPTION
        One row per principal who can reach the role; Path is the exact grant chain
        so the export is genuine audit evidence, not a flat name list.
    .PARAMETER Role
        The role/target name to stamp in the Role column.
    .PARAMETER Reachers
        The reachers[] array (each { displayName/person; purpose; pathText }).
    #>
    [CmdletBinding()]
    param([string]$Role = '', [object[]]$Reachers = @())
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Reachers)) {
        if ($null -eq $r) { continue }
        $who = ''; $purpose = ''; $path = ''
        if ($r -is [System.Collections.IDictionary]) {
            if ($r.Contains('displayName')) { $who = "$($r['displayName'])" } elseif ($r.Contains('person')) { $who = "$($r['person'])" }
            if ($r.Contains('purpose'))     { $purpose = "$($r['purpose'])" }
            if ($r.Contains('pathText'))    { $path = "$($r['pathText'])" }
        } else {
            if ($r.PSObject.Properties['displayName']) { $who = "$($r.displayName)" } elseif ($r.PSObject.Properties['person']) { $who = "$($r.person)" }
            if ($r.PSObject.Properties['purpose'])     { $purpose = "$($r.purpose)" }
            if ($r.PSObject.Properties['pathText'])    { $path = "$($r.pathText)" }
        }
        $rows.Add(@($Role, $who, $purpose, $path)) | Out-Null
    }
    return (ConvertTo-PimRolePermCsv -Headers @('Role', 'Who', 'Purpose', 'Path') -Rows $rows.ToArray())
}

function ConvertTo-PimRoleCompareCsv {
    <#
    .SYNOPSIS
        [H5] -- export the two-role comparison (who can activate both / only A /
        only B). CSV columns: Bucket, Who.
    .DESCRIPTION
        Takes the comparison object ({ both[]; onlyA[]; onlyB[] } of principals) and
        emits one row per person per bucket, labelled with the role name for A/B-only.
    .PARAMETER Comparison
        The comparison object/hashtable with both/onlyA/onlyB principal arrays.
    .PARAMETER RoleA / RoleB
        Display names used to label the only-A / only-B buckets.
    #>
    [CmdletBinding()]
    param([object]$Comparison, [string]$RoleA = 'A', [string]$RoleB = 'B')
    # Resolve a bucket array off the comparison object (dict or PSObject).
    $getArr = {
        param($o, $name)
        if ($null -eq $o) { return @() }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($name)) { return @($o[$name]) } else { return @() } }
        $pp = $o.PSObject.Properties[$name]; if ($pp) { return @($pp.Value) }
        return @()
    }
    # Resolve a principal's display name (string OR object with displayName/person).
    $getName = {
        param($x)
        if ($null -eq $x) { return '' }
        if ($x -is [string]) { return $x }
        if ($x -is [System.Collections.IDictionary]) { if ($x.Contains('displayName')) { return "$($x['displayName'])" } elseif ($x.Contains('person')) { return "$($x['person'])" } else { return '' } }
        if ($x.PSObject.Properties['displayName']) { return "$($x.displayName)" }
        if ($x.PSObject.Properties['person'])      { return "$($x.person)" }
        return "$x"
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($p in (& $getArr $Comparison 'both'))  { $n = (& $getName $p); if ($n) { $rows.Add(@('Both roles', $n)) | Out-Null } }
    foreach ($p in (& $getArr $Comparison 'onlyA')) { $n = (& $getName $p); if ($n) { $rows.Add(@("Only $RoleA", $n)) | Out-Null } }
    foreach ($p in (& $getArr $Comparison 'onlyB')) { $n = (& $getName $p); if ($n) { $rows.Add(@("Only $RoleB", $n)) | Out-Null } }
    return (ConvertTo-PimRolePermCsv -Headers @('Bucket', 'Who') -Rows $rows.ToArray())
}
