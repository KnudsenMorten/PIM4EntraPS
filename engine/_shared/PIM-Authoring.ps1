# PIM4EntraPS -- Manager authoring / governance helpers (pure, testable).
# Dot-sourced by PIM-Functions.psm1 and standalone by the pim-manager
# (same pattern as PIM-PermissionWizard.ps1: no I/O, fully unit-testable).
#
# These functions take ROW SETS (ordered dictionaries / pscustomobjects, the same
# shape Read-PimRows returns) and RETURN new row sets. The Manager turns the result
# into a normal Review & Save change (the engine stays the only writer to Entra/Azure).
# Nothing here connects, writes a file, or mutates its input in place.

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Shared row helpers (mirror _validator.ps1 / Open-PimManager.ps1 cell access so
# the same row shapes work whether they come from CSV, SQL, or a JSON POST).
# ---------------------------------------------------------------------------
function Get-PimAuthoringCell {
    param([AllowNull()][object]$Row, [Parameter(Mandatory)][string]$Column)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) {
        if ($Row.Contains($Column)) { return "$($Row[$Column])" }
        return ''
    }
    $p = $Row.PSObject.Properties[$Column]
    if ($p) { return "$($p.Value)" }
    return ''
}

function New-PimAuthoringRow {
    # Build an ordered row from a header list + a values hashtable. Columns not in
    # the values map are emitted blank, so every row matches the CSV/SQL schema.
    param(
        [Parameter(Mandatory)][string[]]$Header,
        [hashtable]$Values = @{}
    )
    $d = [ordered]@{}
    foreach ($h in $Header) {
        if ($Values.ContainsKey($h)) { $d[$h] = "$($Values[$h])" } else { $d[$h] = '' }
    }
    # Carry any extra keys the caller supplied that aren't in the header (the
    # writer appends new columns at the end, same as Write-PimCsvCustom does).
    foreach ($k in $Values.Keys) { if (-not $d.Contains($k)) { $d[$k] = "$($Values[$k])" } }
    return $d
}

function Split-PimList {
    # Split a semicolon/comma/pipe-separated string into trimmed, non-empty parts.
    param([AllowNull()][string]$Value)
    if (-not "$Value".Trim()) { return @() }
    return @("$Value" -split '[;,|]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# ---------------------------------------------------------------------------
# 1. BULK-ATTACH WIZARD (REQUIREMENTS §23 "Bulk attach wizard", ROADMAP #4)
#    Pick N Entra roles + N Azure scopes (+ N AUs) and attach them all to one
#    role/org/task GroupTag in a single action. Returns the row sets to append
#    to PIM-Assignments-Roles-Groups / -Azure-Resources / -Roles-AUs.
# ---------------------------------------------------------------------------
function New-PimBulkAttachRows {
    param(
        [Parameter(Mandatory)][string]$GroupTag,            # the permission group everything attaches to
        [string[]]$EntraRoles = @(),                        # role display names
        [object[]]$AzureScopes = @(),                       # @{ scope; permission } objects/dicts
        [object[]]$AuScopes = @(),                          # @{ auTag; role } objects/dicts (AU-scoped entra role)
        [ValidateSet('Eligible','Active')][string]$AssignmentType = 'Eligible',
        [string]$Action = '',                               # blank = engine default (Add)
        [int]$NumOfDaysWhenExpire = 0,
        [string]$Permanent = ''
    )
    $tag = "$GroupTag".Trim()
    if (-not $tag) { throw "New-PimBulkAttachRows: GroupTag is required." }

    $rolesGroupsHdr = @('GroupTag','RoleDefinitionName','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform')
    $azureHdr       = @('GroupTag','AzScope','AzScopePermission','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform')
    $rolesAusHdr    = @('GroupTag','AdministrativeUnitTag','RoleDefinitionName','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform')

    $common = @{ AssignmentType = $AssignmentType; Action = $Action }
    if ($NumOfDaysWhenExpire -gt 0) { $common.NumOfDaysWhenExpire = $NumOfDaysWhenExpire }
    if ($Permanent)                 { $common.Permanent = $Permanent }

    $rolesGroups = New-Object System.Collections.ArrayList
    foreach ($r in @($EntraRoles | Where-Object { "$_".Trim() })) {
        $v = @{ GroupTag = $tag; RoleDefinitionName = "$r".Trim() } + $common
        [void]$rolesGroups.Add((New-PimAuthoringRow -Header $rolesGroupsHdr -Values $v))
    }

    $azure = New-Object System.Collections.ArrayList
    foreach ($s in @($AzureScopes)) {
        $scope = (Get-PimAuthoringCell $s 'scope'); if (-not $scope) { $scope = (Get-PimAuthoringCell $s 'AzScope') }
        $perm  = (Get-PimAuthoringCell $s 'permission'); if (-not $perm) { $perm = (Get-PimAuthoringCell $s 'AzScopePermission') }
        if (-not "$scope".Trim()) { continue }
        $v = @{ GroupTag = $tag; AzScope = "$scope".Trim(); AzScopePermission = "$perm".Trim() } + $common
        [void]$azure.Add((New-PimAuthoringRow -Header $azureHdr -Values $v))
    }

    $aus = New-Object System.Collections.ArrayList
    foreach ($a in @($AuScopes)) {
        $auTag = (Get-PimAuthoringCell $a 'auTag'); if (-not $auTag) { $auTag = (Get-PimAuthoringCell $a 'AdministrativeUnitTag') }
        $role  = (Get-PimAuthoringCell $a 'role');  if (-not $role)  { $role  = (Get-PimAuthoringCell $a 'RoleDefinitionName') }
        if (-not "$auTag".Trim() -or -not "$role".Trim()) { continue }
        $v = @{ GroupTag = $tag; AdministrativeUnitTag = "$auTag".Trim(); RoleDefinitionName = "$role".Trim() } + $common
        [void]$aus.Add((New-PimAuthoringRow -Header $rolesAusHdr -Values $v))
    }

    return [pscustomobject]@{
        groupTag           = $tag
        rolesGroupsRows    = $rolesGroups.ToArray()
        azureResourceRows  = $azure.ToArray()
        rolesAusRows       = $aus.ToArray()
        totalRows          = $rolesGroups.Count + $azure.Count + $aus.Count
    }
}

# ---------------------------------------------------------------------------
# 2. CLONE (REQUIREMENTS §23 ROADMAP #3/#5)
#    (a) Copy-PimDefinitionRows  -- clone any row(s) to N new GroupTags
#        (cross-entity: a role-group / permission-group / definition row template
#         applied to multiple new target tags at once).
#    (b) Copy-PimAzureRbacToRole -- clone an Azure-RBAC delegation row to a
#        DIFFERENT role at the SAME scope (incl. clone-to-N roles).
# ---------------------------------------------------------------------------
function Copy-PimDefinitionRows {
    # Clone a template row to N new GroupTags. The tag column is whichever of
    # GroupTag/TargetGroupTag/SourceGroupTag is present (assignment rows reuse
    # this for cross-entity clone too). Optional -SetColumns overrides per clone.
    param(
        [Parameter(Mandatory)][object]$TemplateRow,
        [Parameter(Mandatory)][string[]]$NewTags,
        [string]$TagColumn = 'GroupTag',
        [hashtable]$SetColumns = @{}
    )
    $tags = @(@($NewTags) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($tags.Count -eq 0) { throw "Copy-PimDefinitionRows: at least one NewTag is required." }
    # Recover the template's column order.
    $cols = @()
    if ($TemplateRow -is [System.Collections.IDictionary]) { $cols = @($TemplateRow.Keys) }
    elseif ($null -ne $TemplateRow) { $cols = @($TemplateRow.PSObject.Properties.Name) }
    if ($cols.Count -eq 0) { throw "Copy-PimDefinitionRows: template row has no columns." }

    $out = New-Object System.Collections.ArrayList
    foreach ($t in $tags) {
        $d = [ordered]@{}
        foreach ($c in $cols) {
            if ($c -eq $TagColumn)            { $d[$c] = $t }
            elseif ($SetColumns.ContainsKey($c)) { $d[$c] = "$($SetColumns[$c])" }
            else                              { $d[$c] = (Get-PimAuthoringCell $TemplateRow $c) }
        }
        # GroupName usually mirrors the tag; if present and not explicitly set, follow the new tag.
        if ($d.Contains('GroupName') -and -not $SetColumns.ContainsKey('GroupName') -and $TagColumn -eq 'GroupTag') { $d['GroupName'] = $t }
        [void]$out.Add($d)
    }
    return $out.ToArray()
}

function Copy-PimAzureRbacToRole {
    # Clone an Azure-RBAC assignment row to one or more DIFFERENT RBAC roles at
    # the SAME scope. Keeps GroupTag + AzScope; swaps AzScopePermission per role.
    param(
        [Parameter(Mandatory)][object]$SourceRow,
        [Parameter(Mandatory)][string[]]$NewRoles
    )
    $roles = @(@($NewRoles) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($roles.Count -eq 0) { throw "Copy-PimAzureRbacToRole: at least one NewRole is required." }
    $scope = (Get-PimAuthoringCell $SourceRow 'AzScope')
    if (-not "$scope".Trim()) { throw "Copy-PimAzureRbacToRole: SourceRow has no AzScope." }
    $cols = @()
    if ($SourceRow -is [System.Collections.IDictionary]) { $cols = @($SourceRow.Keys) }
    else { $cols = @($SourceRow.PSObject.Properties.Name) }

    $out = New-Object System.Collections.ArrayList
    foreach ($r in $roles) {
        $d = [ordered]@{}
        foreach ($c in $cols) {
            if ($c -eq 'AzScopePermission') { $d[$c] = $r }
            else { $d[$c] = (Get-PimAuthoringCell $SourceRow $c) }
        }
        if (-not $d.Contains('AzScopePermission')) { $d['AzScopePermission'] = $r }
        [void]$out.Add($d)
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------------------
# 3. AU WIZARD (REQUIREMENTS §23 ROADMAP #8)
#    Create a new Administrative Unit definition row (+ optional roles-AU rows
#    binding permission groups to entra roles scoped to that AU).
# ---------------------------------------------------------------------------
function New-PimAuRows {
    param(
        [Parameter(Mandatory)][string]$AuDisplayName,
        [Parameter(Mandatory)][string]$AdministrativeUnitTag,
        [string]$AuDescription = '',
        [string]$Workload = '',
        [string]$Level = '',
        [string]$TierLevel = '',
        [ValidateSet('Public','HiddenMembership','')][string]$Visibility = 'Public',
        [object[]]$RoleBindings = @()   # @{ groupTag; role } -> rows for PIM-Assignments-Roles-AUs
    )
    $name = "$AuDisplayName".Trim(); $tag = "$AdministrativeUnitTag".Trim()
    if (-not $name) { throw "New-PimAuRows: AuDisplayName is required." }
    if (-not $tag)  { throw "New-PimAuRows: AdministrativeUnitTag is required." }

    $auHdr = @('AUDisplayName','AUDescription','AdministrativeUnitTag','Workload','Level','TierLevel','Visibility')
    $auRow = New-PimAuthoringRow -Header $auHdr -Values @{
        AUDisplayName = $name; AUDescription = $AuDescription; AdministrativeUnitTag = $tag
        Workload = $Workload; Level = $Level; TierLevel = $TierLevel; Visibility = $Visibility
    }

    $rolesAusHdr = @('GroupTag','AdministrativeUnitTag','RoleDefinitionName','AssignmentType','Action','UpdateExisting','AutoExtend','NumOfDaysWhenExpire','Permanent','CPPlatform','Plane','TierLevel','PermissionScope','SyncPlatform')
    $bindings = New-Object System.Collections.ArrayList
    foreach ($b in @($RoleBindings)) {
        $gt = (Get-PimAuthoringCell $b 'groupTag'); if (-not $gt) { $gt = (Get-PimAuthoringCell $b 'GroupTag') }
        $rl = (Get-PimAuthoringCell $b 'role');     if (-not $rl) { $rl = (Get-PimAuthoringCell $b 'RoleDefinitionName') }
        if (-not "$gt".Trim() -or -not "$rl".Trim()) { continue }
        [void]$bindings.Add((New-PimAuthoringRow -Header $rolesAusHdr -Values @{
            GroupTag = "$gt".Trim(); AdministrativeUnitTag = $tag; RoleDefinitionName = "$rl".Trim(); AssignmentType = 'Eligible'
        }))
    }

    return [pscustomobject]@{
        auRow        = $auRow
        rolesAusRows = $bindings.ToArray()
        auTag        = $tag
    }
}

# ---------------------------------------------------------------------------
# 4. ADMIN CSV IMPORT (REQUIREMENTS §23 ROADMAP #9)
#    Parse a pasted/uploaded list (FirstName/LastName/Initials [+ optional
#    Department/UserName]) and expand each row against a chosen admin template's
#    prefill into a full Account-Definitions-Admins row. Pure: takes the template
#    object (already loaded) + the parsed people, returns rows.
# ---------------------------------------------------------------------------
function ConvertFrom-PimAdminImportCsv {
    # Parse delimited text (semicolon, comma, or tab) into person records.
    # Required logical columns: FirstName, LastName, Initials. Extra columns
    # (Department, UserName, DisplayName, ...) are carried through.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $lines = @("$Text" -split "(`r`n|`n|`r)" | Where-Object { $_ -and $_ -notmatch '^(\r\n|\n|\r)$' -and "$_".Trim() })
    if ($lines.Count -lt 1) { return @() }
    # Detect delimiter from the header.
    $header = $lines[0]
    $delim = if ($header -match "`t") { "`t" } elseif ($header.Contains(';')) { ';' } else { ',' }
    $cols = @($header -split [regex]::Escape($delim) | ForEach-Object { $_.Trim() })
    $records = New-Object System.Collections.ArrayList
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $cells = @($lines[$i] -split [regex]::Escape($delim))
        $rec = [ordered]@{}
        for ($c = 0; $c -lt $cols.Count; $c++) {
            $rec[$cols[$c]] = if ($c -lt $cells.Count) { "$($cells[$c])".Trim() } else { '' }
        }
        # Skip fully-blank lines.
        $hasAny = $false; foreach ($k in $rec.Keys) { if ("$($rec[$k])".Trim()) { $hasAny = $true; break } }
        if ($hasAny) { [void]$records.Add($rec) }
    }
    return $records.ToArray()
}

function New-PimAdminRowsFromImport {
    # Expand parsed people against a chosen admin template into full admin rows.
    # $Template is the .admintemplate.json object (has .prefill). Initials are
    # derived (First+Last initial) when absent. UserName defaults to
    # 'Admin-<Initials>-<DomainCode>' style only if not supplied (left to the
    # caller / engine routing otherwise).
    param(
        [Parameter(Mandatory)][object[]]$People,
        [object]$Template = $null
    )
    $hdr = @('FirstName','LastName','Initials','Purpose','TargetUsage','TargetPlatform','UserType','UserName','DisplayName','UserPrincipalName','UsageLocation','ForwardMailsToContact','MailForwardAddress','CreateTAP','TAPStartDate','Ring')
    $prefill = @{}
    if ($Template -and $Template.prefill) {
        foreach ($p in $Template.prefill.PSObject.Properties) { $prefill[$p.Name] = "$($p.Value)" }
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($person in @($People)) {
        $first = (Get-PimAuthoringCell $person 'FirstName')
        $last  = (Get-PimAuthoringCell $person 'LastName')
        $init  = (Get-PimAuthoringCell $person 'Initials')
        if (-not "$init".Trim()) {
            $fi = if ("$first".Length -gt 0) { "$first".Substring(0,1) } else { '' }
            $li = if ("$last".Length  -gt 0) { "$last".Substring(0,1) }  else { '' }
            $init = ("$fi$li").ToUpperInvariant()
        }
        $disp = (Get-PimAuthoringCell $person 'DisplayName')
        if (-not "$disp".Trim()) { $disp = ("$first $last").Trim() }
        $values = @{}
        foreach ($k in $prefill.Keys) { $values[$k] = $prefill[$k] }   # template prefill first
        $values['FirstName'] = "$first".Trim()
        $values['LastName']  = "$last".Trim()
        $values['Initials']  = "$init".Trim()
        $values['DisplayName'] = $disp
        # carry any extra import columns that map to known admin columns
        foreach ($extra in @('Department','UserName','UserPrincipalName','UsageLocation','TargetPlatform','Purpose')) {
            $v = (Get-PimAuthoringCell $person $extra)
            if ("$v".Trim()) { $values[$extra] = "$v".Trim() }
        }
        [void]$out.Add((New-PimAuthoringRow -Header $hdr -Values $values))
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------------------
# 5. REPLACE-MODE ADMIN MOVE (REQUIREMENTS §23 ROADMAP #27)
#    Transactional (all-or-nothing within one Commit) move of an admin from one
#    role-group to another: REMOVE every PIM-Assignments-Admins row for
#    (admin -> FromTag) and ADD the matching (admin -> ToTag) rows. Returns the
#    new full row set for PIM-Assignments-Admins plus a summary of the move.
# ---------------------------------------------------------------------------
function New-PimAdminMovePlan {
    param(
        [Parameter(Mandatory)][object[]]$AssignmentRows,    # current PIM-Assignments-Admins rows
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][string]$FromTag,
        [Parameter(Mandatory)][string]$ToTag
    )
    $u = "$Username".Trim().ToLowerInvariant()
    $from = "$FromTag".Trim().ToLowerInvariant()
    $to   = "$ToTag".Trim()
    if (-not $u)    { throw "New-PimAdminMovePlan: Username is required." }
    if (-not $from) { throw "New-PimAdminMovePlan: FromTag is required." }
    if (-not $to)   { throw "New-PimAdminMovePlan: ToTag is required." }

    $newRows = New-Object System.Collections.ArrayList
    $removed = New-Object System.Collections.ArrayList
    $added   = New-Object System.Collections.ArrayList
    foreach ($r in @($AssignmentRows)) {
        $ru = (Get-PimAuthoringCell $r 'Username').ToLowerInvariant()
        $rt = (Get-PimAuthoringCell $r 'GroupTag').ToLowerInvariant()
        if ($ru -eq $u -and $rt -eq $from) {
            # Drop the old row; emit a replacement pointing at ToTag (same other columns).
            $removed.Add((Get-PimAuthoringCell $r 'GroupTag')) | Out-Null
            $cols = if ($r -is [System.Collections.IDictionary]) { @($r.Keys) } else { @($r.PSObject.Properties.Name) }
            $clone = [ordered]@{}
            foreach ($c in $cols) { $clone[$c] = if ($c -eq 'GroupTag') { $to } else { (Get-PimAuthoringCell $r $c) } }
            [void]$newRows.Add($clone)
            [void]$added.Add($to)
        } else {
            # keep untouched
            $keep = [ordered]@{}
            $cols = if ($r -is [System.Collections.IDictionary]) { @($r.Keys) } else { @($r.PSObject.Properties.Name) }
            foreach ($c in $cols) { $keep[$c] = (Get-PimAuthoringCell $r $c) }
            [void]$newRows.Add($keep)
        }
    }
    if ($removed.Count -eq 0) {
        throw "New-PimAdminMovePlan: no assignment of '$Username' to '$FromTag' was found to move."
    }
    # NEVER SILENTLY DROP ROWS ([M3]). The move is a per-row RE-POINT (matched rows
    # get a new GroupTag; every other row is carried through verbatim), so the output
    # row count MUST equal the input row count. A mismatch means a row was lost in the
    # transform -- abort the whole plan rather than hand the operator a row set that
    # would delete data on save. (Belt-and-braces guard around the loop above.)
    $inCount  = @($AssignmentRows).Count
    $outCount = $newRows.Count
    if ($outCount -ne $inCount) {
        throw "New-PimAdminMovePlan: row-count changed ($inCount -> $outCount); refusing to drop rows. This is a bug -- no plan produced."
    }
    return [pscustomobject]@{
        rows          = $newRows.ToArray()
        movedCount    = $removed.Count
        preservedCount = ($inCount - $removed.Count)   # rows carried through untouched
        inputCount    = $inCount
        outputCount   = $outCount
        fromTag       = $FromTag
        toTag         = $ToTag
        username      = $Username
    }
}

# ---------------------------------------------------------------------------
# 6. MULTI-SELECT DELETE (REQUIREMENTS §23 "Multi-select delete of assignments")
#    Remove rows by 0-based index from a row set. Idempotent + bounds-safe.
# ---------------------------------------------------------------------------
function Remove-PimRowsByIndex {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][AllowEmptyCollection()][int[]]$Indexes
    )
    $drop = @{}
    foreach ($i in @($Indexes)) { if ($i -ge 0) { $drop[[int]$i] = $true } }
    $out = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        if (-not $drop.ContainsKey($i)) { [void]$out.Add($Rows[$i]) }
    }
    return [pscustomobject]@{
        rows         = $out.ToArray()
        removedCount = ($Rows.Count - $out.Count)
    }
}

# ---------------------------------------------------------------------------
# 7. ROLE-PERMISSION DRILL-DOWN (REQUIREMENTS §23 ROADMAP #2/#25)
#    Pure formatter: given a Graph roleDefinition object (or its rolePermissions
#    array), flatten allowedResourceActions into a clean, sorted list grouped by
#    resource namespace -- for the side panel + CSV export. The live fetch is the
#    caller's job; this is the testable shaping.
# ---------------------------------------------------------------------------
function Format-PimRolePermissions {
    param([Parameter(Mandatory)][AllowNull()][object]$RoleDefinition)
    $actions = New-Object System.Collections.ArrayList
    $perms = $null
    if ($RoleDefinition -is [System.Collections.IDictionary]) {
        if ($RoleDefinition.Contains('rolePermissions')) { $perms = $RoleDefinition['rolePermissions'] }
    } elseif ($null -ne $RoleDefinition) {
        $rp = $RoleDefinition.PSObject.Properties['rolePermissions']
        if ($rp) { $perms = $rp.Value }
        elseif ($RoleDefinition.PSObject.Properties['allowedResourceActions']) { $perms = @($RoleDefinition) }
    }
    foreach ($p in @($perms)) {
        $ara = $null
        if ($p -is [System.Collections.IDictionary]) { if ($p.Contains('allowedResourceActions')) { $ara = $p['allowedResourceActions'] } }
        else { $prop = $p.PSObject.Properties['allowedResourceActions']; if ($prop) { $ara = $prop.Value } }
        foreach ($a in @($ara)) { if ("$a".Trim()) { [void]$actions.Add("$a".Trim()) } }
    }
    $unique = @($actions | Sort-Object -Unique)
    # Group by the leading namespace (everything up to the last '/').
    $groups = [ordered]@{}
    foreach ($a in $unique) {
        $ns = if ($a.Contains('/')) { $a.Substring(0, $a.LastIndexOf('/')) } else { '(root)' }
        if (-not $groups.Contains($ns)) { $groups[$ns] = New-Object System.Collections.ArrayList }
        [void]$groups[$ns].Add($a)
    }
    $grouped = New-Object System.Collections.ArrayList
    foreach ($ns in $groups.Keys) {
        [void]$grouped.Add([pscustomobject]@{ namespace = $ns; actions = @($groups[$ns].ToArray()) })
    }
    return [pscustomobject]@{
        totalActions = $unique.Count
        actions      = $unique
        byNamespace  = $grouped.ToArray()
    }
}

# ---------------------------------------------------------------------------
# 7b. ROLE LOOKUP MATCHING + COMPARE (REQUIREMENTS §28 [H9])
#     Pure, offline, PS 5.1-safe helpers behind the Role Lookup tab:
#       Get-PimStringSimilarity  -- 0..1 closeness of two short strings
#                                   (case-insensitive Levenshtein ratio).
#       Resolve-PimRoleQuery     -- typo-tolerant role resolution: exact-name hit
#                                   when one exists, otherwise RANKED candidates
#                                   ("did you mean...") -- never a 5xx/throw. An
#                                   empty query returns an empty candidate list.
#       Compare-PimReachSets     -- role compare: take two reacher result sets and
#                                   return overlap + each-only principal sets.
#     No I/O, no Graph, no module use -- the Manager calls these over the live
#     role catalog / Get-PimRoleReachers output; the same calls are unit-tested.
# ---------------------------------------------------------------------------
function Get-PimStringSimilarity {
    # Case-insensitive similarity in [0,1] between two short strings, derived from
    # the Levenshtein edit distance: 1 = identical, 0 = nothing in common. Used to
    # RANK near-miss role-name candidates (the "did you mean..." order). Pure; no
    # ?./?? (PS 5.1). Empty-vs-empty = 1; empty-vs-nonempty = 0.
    [CmdletBinding()]
    param([AllowNull()][string]$A, [AllowNull()][string]$B)
    $a = "$A"; $b = "$B"
    if ($a -eq $b) { return 1.0 }
    $al = $a.ToLowerInvariant(); $bl = $b.ToLowerInvariant()
    if ($al -eq $bl) { return 1.0 }
    $la = $al.Length; $lb = $bl.Length
    if ($la -eq 0 -or $lb -eq 0) { return 0.0 }
    # Classic two-row Levenshtein (O(la*lb) time, O(lb) space).
    $prev = New-Object 'int[]' ($lb + 1)
    $cur  = New-Object 'int[]' ($lb + 1)
    for ($j = 0; $j -le $lb; $j++) { $prev[$j] = $j }
    for ($i = 1; $i -le $la; $i++) {
        $cur[0] = $i
        $ca = $al[$i - 1]
        for ($j = 1; $j -le $lb; $j++) {
            $cost = if ($ca -eq $bl[$j - 1]) { 0 } else { 1 }
            $del = $prev[$j] + 1
            $ins = $cur[$j - 1] + 1
            $sub = $prev[$j - 1] + $cost
            $min = $del; if ($ins -lt $min) { $min = $ins }; if ($sub -lt $min) { $min = $sub }
            $cur[$j] = $min
        }
        $tmp = $prev; $prev = $cur; $cur = $tmp
    }
    $dist = $prev[$lb]
    $maxLen = [Math]::Max($la, $lb)
    return [Math]::Round((1.0 - ($dist / [double]$maxLen)), 4)
}

function Resolve-PimRoleQuery {
    # Typo-tolerant role resolution. Given a free-text query and the list of known
    # role names (the live tenant catalog), return one of:
    #   matched=$true  + role=<exact name>            (case-insensitive exact hit)
    #   matched=$false + candidates=[{role,score,reason}...]  ("did you mean...")
    #   matched=$false + candidates=[]                (empty query, or nothing close)
    # NEVER throws and NEVER signals a 5xx-shaped failure -- a near-miss is data,
    # not an error. Ranking: exact > substring (query in name / name in query) >
    # fuzzy (Levenshtein ratio >= MinScore). PS 5.1-safe.
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Query,
        [AllowNull()][object[]]$RoleNames,
        [int]$Max = 8,
        [double]$MinScore = 0.55
    )
    $q = "$Query".Trim()
    $names = @()
    foreach ($n in @($RoleNames)) { $s = "$n".Trim(); if ($s) { $names += $s } }
    $names = @($names | Sort-Object -Unique)
    if (-not $q) {
        return [ordered]@{ query = ''; matched = $false; role = ''; candidates = @() }
    }
    $ql = $q.ToLowerInvariant()
    # 1. Exact (case-insensitive) match wins outright.
    foreach ($n in $names) {
        if ($n.ToLowerInvariant() -eq $ql) {
            return [ordered]@{ query = $q; matched = $true; role = $n; candidates = @() }
        }
    }
    # 2. Score every known name; keep substring + fuzzy near-misses.
    $scored = New-Object System.Collections.ArrayList
    foreach ($n in $names) {
        $nl = $n.ToLowerInvariant()
        $reason = ''
        $score = 0.0
        if ($nl.Contains($ql) -or $ql.Contains($nl)) {
            $reason = 'substring'
            # Longer shared coverage ranks higher; bounded to (0,1).
            $shorter = [Math]::Min($nl.Length, $ql.Length)
            $longer  = [Math]::Max($nl.Length, $ql.Length)
            $score = 0.8 + (0.2 * ($shorter / [double]$longer))
        } else {
            $sim = Get-PimStringSimilarity -A $ql -B $nl
            if ($sim -ge $MinScore) { $reason = 'fuzzy'; $score = $sim }
        }
        if ($reason) {
            [void]$scored.Add([ordered]@{ role = $n; score = [Math]::Round($score, 4); reason = $reason })
        }
    }
    $ranked = @($scored | Sort-Object @{ e = { [double]$_.score }; Descending = $true }, @{ e = { "$($_.role)" } })
    if (@($ranked).Count -gt $Max) { $ranked = @($ranked[0..($Max - 1)]) }
    return [ordered]@{ query = $q; matched = $false; role = ''; candidates = @($ranked) }
}

function Compare-PimReachSets {
    # Role compare: given two "who can activate" reacher sets (each = the array of
    # principal objects Get-PimRoleReachers returns under .reachers, OR any objects
    # carrying a person/id field), return who/what BOTH roles reach (overlap), who
    # reaches ONLY the first, and who reaches ONLY the second. Identity = the
    # principal's UPN/id (case-insensitive). Pure, set-based, PS 5.1-safe.
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$ReachersA,
        [AllowNull()][object[]]$ReachersB,
        [string]$LabelA = 'A',
        [string]$LabelB = 'B'
    )
    $key = {
        param($r)
        $v = Get-PimAuthoringCell $r 'person'
        if (-not "$v".Trim()) { $v = Get-PimAuthoringCell $r 'id' }
        if (-not "$v".Trim()) { $v = Get-PimAuthoringCell $r 'displayName' }
        return "$v".Trim()
    }
    $indexA = [ordered]@{}; $indexB = [ordered]@{}
    foreach ($r in @($ReachersA)) { $k = (& $key $r); if ($k -and -not $indexA.Contains($k.ToLowerInvariant())) { $indexA[$k.ToLowerInvariant()] = $r } }
    foreach ($r in @($ReachersB)) { $k = (& $key $r); if ($k -and -not $indexB.Contains($k.ToLowerInvariant())) { $indexB[$k.ToLowerInvariant()] = $r } }
    $both = New-Object System.Collections.ArrayList
    $onlyA = New-Object System.Collections.ArrayList
    $onlyB = New-Object System.Collections.ArrayList
    foreach ($k in $indexA.Keys) {
        if ($indexB.Contains($k)) { [void]$both.Add($indexA[$k]) } else { [void]$onlyA.Add($indexA[$k]) }
    }
    foreach ($k in $indexB.Keys) {
        if (-not $indexA.Contains($k)) { [void]$onlyB.Add($indexB[$k]) }
    }
    $sortFn = { @($args[0] | Sort-Object @{ e = { "$(Get-PimAuthoringCell $_ 'displayName')$(Get-PimAuthoringCell $_ 'person')" } }) }
    return [ordered]@{
        labelA    = $LabelA
        labelB    = $LabelB
        both      = @(& $sortFn $both)
        onlyA     = @(& $sortFn $onlyA)
        onlyB     = @(& $sortFn $onlyB)
        countBoth = @($both).Count
        countA    = @($onlyA).Count
        countB    = @($onlyB).Count
    }
}

# ---------------------------------------------------------------------------
# 8. AUDIT TO LOG ANALYTICS (REQUIREMENTS §23 ROADMAP #26)
#    Pure builder: turn a PIM audit event into the flat record AzLogDcrIngestPS
#    sends to a DCR/Log Analytics custom table. The actual Send-... call is done
#    by the engine when $global:PIM_AuditLogAnalytics is enabled; this shaping is
#    testable offline (CollectionTime stamping convention + flattening).
# ---------------------------------------------------------------------------
function ConvertTo-PimLaAuditRecord {
    param(
        [Parameter(Mandatory)][object]$Event,
        [datetime]$CollectionTime = ([datetime]::UtcNow)
    )
    function _ev([string]$k) { Get-PimAuthoringCell $Event $k }
    $rec = [ordered]@{
        CollectionTime = $CollectionTime.ToString('o')   # AzLogDcrIngestPS naming, identical across one execution
        TimeGenerated  = (_ev 'ts')
        Actor          = (_ev 'actor')
        Action         = (_ev 'action')
        Target         = (_ev 'target')
        Result         = (_ev 'result')
        RunId          = (_ev 'runId')
        CorrelationId  = (_ev 'correlationId')
        WhatIf         = (_ev 'whatIf')
    }
    # Flatten the 'after' detail object to a compact JSON string (LA columns are scalar-friendly).
    $after = $null
    if ($Event -is [System.Collections.IDictionary]) { if ($Event.Contains('after')) { $after = $Event['after'] } }
    else { $ap = $Event.PSObject.Properties['after']; if ($ap) { $after = $ap.Value } }
    if ($null -ne $after) {
        try { $rec['Details'] = ($after | ConvertTo-Json -Depth 6 -Compress) } catch { $rec['Details'] = "$after" }
    } else { $rec['Details'] = '' }
    return [pscustomobject]$rec
}

# ---------------------------------------------------------------------------
# 9. AUTHORING PREVIEW / DIFF BEFORE COMMIT (REQUIREMENTS §28 [M3])
#    Every authoring action -- Move admin, clone-azure-role, clone-au,
#    delete-rows, bulk-attach, import-admins, etc. -- COMPUTES a new row set.
#    Before that set is staged into pending (let alone committed), the operator
#    must see EXACTLY what changes: which rows are added, modified (with the
#    changed columns), or REMOVED, matched by their STABLE natural key (not by
#    position), plus a loud flag when the action is DESTRUCTIVE (removes rows).
#
#    This is the pure, offline core behind the inline preview the Manager shows.
#    It reuses the store's own key derivation (Get-PimStoreRowKey) when that
#    function is loaded, so the preview keys rows IDENTICALLY to the keyed
#    Review & Save diff and to the SQL store -- no parallel keying scheme. When
#    the key helper isn't available (pure-unit context) it falls back to a
#    per-base key map, then to a content fingerprint, so it NEVER crashes and a
#    reorder of identical rows is NEVER reported as a change.
#
#    No I/O, no Graph, no module use. The Manager calls Get-PimAuthoringPreview
#    on each authoring action's computed rows; the same call is unit-tested.
# ---------------------------------------------------------------------------

# Bases whose stage operation is a WHOLE-FILE REPLACE (the computed rows become
# the new full row set for that base). For these, a key only in Before = a REMOVE.
# Bases whose stage operation is an APPEND (computed rows are added on top of the
# current set) never remove anything, so they are previewed as add-only.
function Get-PimAuthoringActionShape {
    # Map an authoring action to (base, mode). mode = 'replace' | 'append'.
    # Pure lookup; unknown actions default to a safe 'replace' (worst case shows
    # the most -- removes are surfaced rather than hidden).
    param([Parameter(Mandatory)][string]$Action, [string]$Base = '')
    $a = "$Action".Trim().ToLowerInvariant()
    switch ($a) {
        'move-admin'        { return [ordered]@{ base = 'PIM-Assignments-Admins'; mode = 'replace'; destructiveByDesign = $false } }
        'delete-rows'       { return [ordered]@{ base = "$Base"; mode = 'replace'; destructiveByDesign = $true } }
        'clone'             { return [ordered]@{ base = "$Base"; mode = 'append';  destructiveByDesign = $false } }
        'clone-azure-role'  { return [ordered]@{ base = 'PIM-Assignments-Azure-Resources'; mode = 'append'; destructiveByDesign = $false } }
        'clone-au'          { return [ordered]@{ base = 'PIM-Definitions-AU'; mode = 'append'; destructiveByDesign = $false } }
        'au'                { return [ordered]@{ base = 'PIM-Definitions-AU'; mode = 'append'; destructiveByDesign = $false } }
        'bulk-attach'       { return [ordered]@{ base = "$Base"; mode = 'append'; destructiveByDesign = $false } }
        'import-admins'     { return [ordered]@{ base = 'Account-Definitions-Admins'; mode = 'append'; destructiveByDesign = $false } }
        default             { return [ordered]@{ base = "$Base"; mode = 'replace'; destructiveByDesign = $false } }
    }
}

function Get-PimAuthoringRowKey {
    # Natural (stable) key for a row under a base. Prefers the store's own
    # derivation (Get-PimStoreRowKey) so the preview keys identically to the
    # keyed Review & Save diff + the SQL store; falls back to a built-in per-base
    # map (mirrors Get-PimStoreRowKey's contract) so the core is unit-testable
    # without the store loaded. Returns '' when no key can be derived.
    param([Parameter(Mandatory)][string]$Base, [AllowNull()][object]$Row)
    if ($null -eq $Row) { return '' }
    if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) {
        try {
            $k = "$(Get-PimStoreRowKey -Base $Base -Row $Row)".Trim()
            if ($k) { return $k }
        } catch {
            # Store helper threw (unexpected row shape) -- fall through to the
            # built-in derivation below rather than failing the preview.
            Write-Verbose "Get-PimStoreRowKey failed for base '$Base'; using built-in key. $($_.Exception.Message)"
        }
    }
    # Built-in fallback (same key shapes as Get-PimStoreRowKey).
    $g = { param($n) (Get-PimAuthoringCell $Row $n) }
    $k = ''
    switch -Wildcard ("$Base") {
        'PIM-Definitions-AU'               { $k = (& $g 'AdministrativeUnitTag'); break }
        'PIM-Definitions-Departments'      {
            $d = (& $g 'Department'); if (-not "$d".Trim()) { $d = (& $g 'DepartmentName') }
            if (-not "$d".Trim()) { $d = (& $g 'GroupTag') }; if (-not "$d".Trim()) { $d = (& $g 'GroupName') }
            $k = $d; break
        }
        'PIM-Definitions-*'                { $k = (& $g 'GroupTag'); break }
        'Account-Definitions-Admins'       { $k = (& $g 'UserName'); break }
        'PIM-Assignments-Admins'           { $k = ((& $g 'Username') + '|' + (& $g 'GroupTag')); break }
        'PIM-Assignments-Groups'           { $k = ((& $g 'TargetGroupTag') + '|' + (& $g 'SourceGroupTag')); break }
        'PIM-Assignments-Roles-Groups'     { $k = ((& $g 'GroupTag') + '|' + (& $g 'RoleDefinitionName')); break }
        'PIM-Assignments-Roles-AUs'        { $k = ((& $g 'GroupTag') + '|' + (& $g 'AdministrativeUnitTag') + '|' + (& $g 'RoleDefinitionName')); break }
        'PIM-Assignments-Azure-Resources'  { $k = ((& $g 'GroupTag') + '|' + (& $g 'AzScope') + '|' + (& $g 'AzScopePermission')); break }
        default                            { $x = (& $g 'GroupTag'); if (-not "$x".Trim()) { $x = (& $g 'GroupName') }; $k = $x }
    }
    $k = "$k".Trim()
    if ($k -eq '' -or $k -match '^\|+$') { return '' }
    return $k
}

function Get-PimAuthoringPreview {
    # KEYED add/modify/remove preview of an authoring action, BEFORE it is staged
    # or committed. Matches rows by natural key (Get-PimAuthoringRowKey) so a pure
    # reorder is ZERO change; same key + different field values = a modify (with the
    # changed columns); key only in After = an add; key only in Before = a remove.
    #
    #   $Base    -- the entity the rows belong to (drives the natural key).
    #   $Before  -- the CURRENT row set for that base (the committed/store state).
    #   $After   -- the PROPOSED row set the authoring action computed.
    #   $Mode    -- 'replace' (After becomes the whole set; missing keys = removes)
    #               or 'append' (After is added; no removes possible). When omitted,
    #               'replace' (the safe default: surfaces removes rather than hiding).
    #   $Action  -- optional label carried into the result for the UI.
    #
    # Rows with a blank/colliding natural key fall back to a content fingerprint so
    # the preview never crashes. Returns an ordered result: adds/modifies/removes
    # arrays, counts, unchanged, destructive flag (=removes > 0), and the keyed
    # 'summary' an operator reads ("+2 / ~1 / -3"). Pure; PS 5.1-safe.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Base,
        [AllowNull()][AllowEmptyCollection()][object[]]$Before = @(),
        [AllowNull()][AllowEmptyCollection()][object[]]$After = @(),
        [ValidateSet('replace','append')][string]$Mode = 'replace',
        [string]$Action = ''
    )
    $before = @($Before); $after = @($After)

    function _ContentKey([object]$row) {
        if ($null -eq $row) { return '' }
        $kvs = @()
        if ($row -is [System.Collections.IDictionary]) {
            foreach ($kk in ($row.Keys | Sort-Object)) { $kvs += "$kk=$($row[$kk])" }
        } else {
            foreach ($p in ($row.PSObject.Properties | Sort-Object Name)) { $kvs += "$($p.Name)=$($p.Value)" }
        }
        return ($kvs -join ([char]1))
    }
    function _DiffCols([object]$b, [object]$a) {
        $cols = New-Object System.Collections.ArrayList
        $all = @()
        if ($b -is [System.Collections.IDictionary]) { $all += @($b.Keys) } else { $all += @($b.PSObject.Properties.Name) }
        if ($a -is [System.Collections.IDictionary]) { $all += @($a.Keys) } else { $all += @($a.PSObject.Properties.Name) }
        $all = @($all | Select-Object -Unique)
        foreach ($c in $all) {
            $bv = Get-PimAuthoringCell $b $c
            $av = Get-PimAuthoringCell $a $c
            if ($bv -ne $av) { [void]$cols.Add($c) }
        }
        return $cols.ToArray()
    }

    $adds      = New-Object System.Collections.ArrayList
    $removes   = New-Object System.Collections.ArrayList
    $modifies  = New-Object System.Collections.ArrayList
    $unchanged = 0

    # Bucket each side by natural key; only keys unique on each side are keyed.
    $bByKey = @{}; foreach ($r in $before) { $nk = Get-PimAuthoringRowKey -Base $Base -Row $r; if (-not $nk) { continue }; if (-not $bByKey.ContainsKey($nk)) { $bByKey[$nk] = New-Object System.Collections.ArrayList }; [void]$bByKey[$nk].Add($r) }
    $aByKey = @{}; foreach ($r in $after)  { $nk = Get-PimAuthoringRowKey -Base $Base -Row $r; if (-not $nk) { continue }; if (-not $aByKey.ContainsKey($nk)) { $aByKey[$nk] = New-Object System.Collections.ArrayList }; [void]$aByKey[$nk].Add($r) }

    $keyedHandled = @{}
    $allKeys = @{}
    foreach ($k in $bByKey.Keys) { $allKeys[$k] = $true }
    foreach ($k in $aByKey.Keys) { $allKeys[$k] = $true }
    foreach ($k in @($allKeys.Keys)) {
        $bc = if ($bByKey.ContainsKey($k)) { $bByKey[$k].Count } else { 0 }
        $ac = if ($aByKey.ContainsKey($k)) { $aByKey[$k].Count } else { 0 }
        if ($bc -gt 1 -or $ac -gt 1) { continue }   # collision -> content fallback
        $keyedHandled[$k] = $true
        if ($bc -eq 1 -and $ac -eq 1) {
            $b = $bByKey[$k][0]; $a = $aByKey[$k][0]
            $cols = _DiffCols $b $a
            if (@($cols).Count -eq 0) { $unchanged++ }
            else { [void]$modifies.Add([ordered]@{ key = $k; before = $b; after = $a; diffCols = @($cols) }) }
        } elseif ($ac -eq 1) {
            [void]$adds.Add([ordered]@{ key = $k; row = $aByKey[$k][0] })
        } else {
            [void]$removes.Add([ordered]@{ key = $k; row = $bByKey[$k][0] })
        }
    }

    # Content fallback for blank/colliding keys.
    $bLeft = New-Object System.Collections.ArrayList
    foreach ($r in $before) { $nk = Get-PimAuthoringRowKey -Base $Base -Row $r; if ($nk -and $keyedHandled.ContainsKey($nk)) { continue }; [void]$bLeft.Add($r) }
    $aLeft = New-Object System.Collections.ArrayList
    foreach ($r in $after)  { $nk = Get-PimAuthoringRowKey -Base $Base -Row $r; if ($nk -and $keyedHandled.ContainsKey($nk)) { continue }; [void]$aLeft.Add($r) }
    $bMap = @{}
    foreach ($r in $bLeft) { $ck = _ContentKey $r; if (-not $bMap.ContainsKey($ck)) { $bMap[$ck] = New-Object System.Collections.ArrayList }; [void]$bMap[$ck].Add($r) }
    $legacyAdds = New-Object System.Collections.ArrayList
    foreach ($r in $aLeft) {
        $ck = _ContentKey $r
        if ($bMap.ContainsKey($ck) -and $bMap[$ck].Count -gt 0) { $bMap[$ck].RemoveAt(0); $unchanged++ }
        else { [void]$legacyAdds.Add($r) }
    }
    $legacyRemoves = New-Object System.Collections.ArrayList
    foreach ($ck in $bMap.Keys) { foreach ($r in $bMap[$ck]) { [void]$legacyRemoves.Add($r) } }
    foreach ($r in $legacyAdds)    { [void]$adds.Add([ordered]@{ key = ''; row = $r }) }
    foreach ($r in $legacyRemoves) { [void]$removes.Add([ordered]@{ key = ''; row = $r }) }

    # In 'append' mode the action only adds rows on top of the current set; nothing
    # the action computed can REMOVE an existing row, so drop any spurious removes
    # (a row present in Before but not in the small computed After is simply not
    # part of this append -- it is untouched, not deleted).
    if ($Mode -eq 'append') {
        $unchanged += $removes.Count
        $removes = New-Object System.Collections.ArrayList
    }

    $addCount = $adds.Count; $modCount = $modifies.Count; $remCount = $removes.Count
    $summary = ("+{0} / ~{1} / -{2}" -f $addCount, $modCount, $remCount)
    return [ordered]@{
        action       = "$Action"
        base         = "$Base"
        mode         = $Mode
        adds         = $adds.ToArray()
        modifies     = $modifies.ToArray()
        removes      = $removes.ToArray()
        unchanged    = $unchanged
        addCount     = $addCount
        modifyCount  = $modCount
        removeCount  = $remCount
        destructive  = ($remCount -gt 0)
        summary      = $summary
    }
}
