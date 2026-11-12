<#
  ACCESS PACKAGES -- the Manager half (Access > Access packages). Functions only; Open-PimManager.ps1 dot-sources this file and
  routes the paths of Get-PimManagerAccessPackageRoutePaths here.

  🔒 OWNER 2026-11-12: "we dont rename anything existing. we add new groups locked for access packages. we dont touch existing groups.
  if in doubt then pause access package." + "-ap group ends with as agreed".
    * Create access package = NEW group definitions only (the normal direct-group tag / name with '-AP' at the end, column
      AccessPackage = the package), each nested into the permission groups it grants, plus the AccessPackage row. A tag or name that
      is already defined anywhere is REFUSED -- an existing group is never reused, renamed or bound.
    * NOTHING IS WRITTEN HERE. Every route answers rows; the page stages them in Pending changes (wuxStage) and the normal audited
      commit writes them (SuperAdmin / Admin, the commit approvals, the validator's PIM-AP-* rules).
    * Pause / resume = the package row's State column (Paused / blank) + PauseReason, staged the same way. The engine writes nothing
      for a paused package (PIM-AccessPackages.ps1), and pauses by itself on any doubt -- its reason is in pim.Settings
      'AccessPackageStatus', which the list shows.

  Routes (every edition; nothing here is Pro-gated -- the engine half is not either):
    GET  /api/access-packages            Reader+  the packages, their new groups, what they grant, state + reason, the licence line
    POST /api/access-packages/plan       Admin+   { name; description; groups[{ type; shortName; grants[] }]; requestScope; ... } -> rows to stage
    POST /api/access-packages/pause      Admin+   { name; reason } -> the row change to stage (State=Paused)
    POST /api/access-packages/resume     Admin+   { name }         -> the row change to stage (State cleared)
  Test seams: -Seams @{ ReadRows = { param($base) rows }; ReadSetting = { param($name) value }; RoleAtLeast = { param($min) bool }; Enabled = { bool } }.
#>
Set-StrictMode -Off

function Get-PimManagerAccessPackageRoutePaths { @('/api/access-packages', '/api/access-packages/plan', '/api/access-packages/pause', '/api/access-packages/resume') }
function Get-PimManagerAccessPackageBase { 'AccessPackage' }
function Get-PimManagerAccessPackageGroupEntities { @('PIM-Definitions-Roles', 'PIM-Definitions-Departments', 'PIM-Definitions-Organization', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg') }
function Get-PimManagerAccessPackageAllGroupEntities {
    @('PIM-Definitions-Roles', 'PIM-Definitions-Tasks', 'PIM-Definitions-Services', 'PIM-Definitions-Processes', 'PIM-Definitions-Resources',
      'PIM-Definitions-Departments', 'PIM-Definitions-Organization', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg')
}

function Get-PimManagerApCell {
    param($Row, [string]$Col)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Col)) { return "$($Row[$Col])".Trim() }; return '' }
    $p = $Row.PSObject.Properties[$Col]; if ($p -and $null -ne $p.Value) { return "$($p.Value)".Trim() }; return ''
}

function Get-PimManagerApSeams {
    param([hashtable]$Seams)
    $s = @{}
    if ($Seams) { foreach ($k in @($Seams.Keys)) { $s[$k] = $Seams[$k] } }
    if (-not $s.ContainsKey('ReadRows')) { $s['ReadRows'] = { param($base) @((Read-PimRows -BaseName $base -NoScope).rows) } }
    if (-not $s.ContainsKey('ReadSetting')) { $s['ReadSetting'] = { param($name) Get-PimManagerSettingObject -Name $name } }
    if (-not $s.ContainsKey('RoleAtLeast')) { $s['RoleAtLeast'] = { param($min) Test-PimManagerRoleAtLeast -Minimum $min } }
    if (-not $s.ContainsKey('Enabled')) { $s['Enabled'] = { if (Get-Command Get-PimFeatureSetting -ErrorAction SilentlyContinue) { [bool](Get-PimFeatureSetting -Name 'AccessPackagesEnabled') } else { $true } } }
    return $s
}

function Get-PimManagerApRowIsGone {
    <# PURE. A row the list never shows (REMOVED-HIDDEN-EVERYWHERE): Action=Remove (retired / being retired) or Action=ReturnToEngine (a one-time instruction). #>
    param($Row)
    return ((Get-PimManagerApCell $Row 'Action') -match '^(?i)(remove|returntoengine)$')
}

function Get-PimManagerAccessPackageGroupIndex {
    <# Every group definition (all nine entities): tag (lower) -> @{ tag; name; entity; tier; lockedTo; locked; retired }, plus name (lower) -> tag. #>
    param([hashtable]$S)
    $byTag = @{}; $byName = @{}
    foreach ($e in @(Get-PimManagerAccessPackageAllGroupEntities)) {
        $rows = @(); try { $rows = @(& $S.ReadRows $e) } catch { throw "the group definitions ($e) could not be read: $($_.Exception.Message)" }
        foreach ($r in $rows) {
            $t = Get-PimManagerApCell $r 'GroupTag'; $n = Get-PimManagerApCell $r 'GroupName'
            if (-not $t -and -not $n) { continue }
            $o = [pscustomobject]@{ tag = $t; name = $n; entity = $e; tier = (Get-PimManagerApCell $r 'TierLevel'); lockedTo = (Get-PimManagerApCell $r 'AccessPackage')
                locked = [bool](Get-PimManagerApCell $r 'AccessPackage'); retired = ((Get-PimManagerApCell $r 'Lifecycle') -match '^(?i)retire')
                direct = (@(Get-PimManagerAccessPackageGroupEntities) -contains $e) }
            if ($t -and -not $byTag.ContainsKey($t.ToLowerInvariant())) { $byTag[$t.ToLowerInvariant()] = $o }
            if ($n -and -not $byName.ContainsKey($n.ToLowerInvariant())) { $byName[$n.ToLowerInvariant()] = $o }
        }
    }
    return @{ byTag = $byTag; byName = $byName }
}

function Get-PimManagerAccessPackageList {
    <# GET /api/access-packages. Read-only: the store rows + the engine's recorded state. Never throws (a read that fails = 503 with the reason). #>
    param([hashtable]$Seams)
    $S = Get-PimManagerApSeams -Seams $Seams
    if (-not [bool](& $S.RoleAtLeast 'Reader')) { return @{ status = 403; body = [ordered]@{ ok = $false; error = 'Reader role required to see the access packages.' } } }
    try {
        $rows = @(& $S.ReadRows (Get-PimManagerAccessPackageBase))
        $idx = Get-PimManagerAccessPackageGroupIndex -S $S
        $nest = @(& $S.ReadRows 'PIM-Assignments-Groups')
    } catch { return @{ status = 503; body = [ordered]@{ ok = $false; error = "the access packages could not be read: $($_.Exception.Message)" } } }
    $status = $null; $statusErr = ''
    try { $status = & $S.ReadSetting 'AccessPackageStatus' } catch { $statusErr = "$($_.Exception.Message)" }
    $bindings = $null; try { $bindings = & $S.ReadSetting 'AccessPackageBindings' } catch { $bindings = $null }
    $enabled = $true; try { $enabled = [bool](& $S.Enabled) } catch { $enabled = $true }
    $stOf = @{}
    if ($status -and $status.packages) {
        foreach ($p in @($status.packages.PSObject.Properties)) { $stOf["$($p.Name)".ToLowerInvariant()] = $p.Value }
    }
    $boundTags = @{}
    if ($bindings -and $bindings.bindings) { foreach ($b in @($bindings.bindings.PSObject.Properties)) { if ("$($b.Value.tag)".Trim()) { $boundTags["$($b.Value.tag)".Trim().ToLowerInvariant()] = $true } } }
    $grantsOf = @{}
    foreach ($r in $nest) {
        if ((Get-PimManagerApCell $r 'Action') -ieq 'Remove') { continue }
        $m = (Get-PimManagerApCell $r 'TargetGroupTag').ToLowerInvariant(); $c = Get-PimManagerApCell $r 'SourceGroupTag'
        if ($m -and $c) { if (-not $grantsOf.ContainsKey($m)) { $grantsOf[$m] = New-Object System.Collections.Generic.List[string] }; $grantsOf[$m].Add($c) }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        if (Get-PimManagerApRowIsGone $r) { continue }
        $name = Get-PimManagerApCell $r 'AccessPackageName'; if (-not $name) { continue }
        $groups = @(foreach ($t in @(Split-PimAccessPackageList (Get-PimManagerApCell $r 'DirectGroupTags'))) {
            $g = $idx.byTag["$t".ToLowerInvariant()]
            [ordered]@{ tag = "$t"; name = $(if ($g) { $g.name } else { '' }); defined = [bool]$g; dedicated = [bool]($g -and $g.lockedTo -ieq $name -and "$($g.name)" -match '(?i)-AP$')
                bound = $boundTags.ContainsKey("$t".ToLowerInvariant()); grants = @(if ($grantsOf.ContainsKey("$t".ToLowerInvariant())) { $grantsOf["$t".ToLowerInvariant()].ToArray() }) }
        })
        $adminPaused = ((Get-PimManagerApCell $r 'State') -ieq 'Paused')
        $es = $stOf[$name.ToLowerInvariant()]
        $state = 'pending'; $reason = 'waiting for the engine''s next run'
        if (-not $enabled) { $state = 'off'; $reason = 'access packages are switched off in Settings' }
        elseif ($adminPaused) { $state = 'paused'; $reason = $(if (Get-PimManagerApCell $r 'PauseReason') { "paused by an administrator: $(Get-PimManagerApCell $r 'PauseReason')" } else { 'paused by an administrator' }) }
        elseif ($es) { $state = "$($es.state)"; $reason = "$($es.reason)" }
        # Doubts the page can see by itself: a group that is not one created for this package pauses it (the engine does the same).
        if ($enabled -and -not $adminPaused -and @($groups | Where-Object { $_.defined -and -not $_.dedicated }).Count) { $state = 'paused'; $reason = 'a group of this package was not created for it -- an access package never uses an existing group' }
        $out.Add([ordered]@{
            name = $name; description = (Get-PimManagerApCell $r 'Notes'); groups = $groups
            requestScope = (Get-PimManagerApCell $r 'RequestScope'); requestGroupTag = (Get-PimManagerApCell $r 'RequestGroupTag')
            approval = (Get-PimManagerApCell $r 'Approval'); approvalStage1 = (Get-PimManagerApCell $r 'ApprovalStage1'); approvalStage2 = (Get-PimManagerApCell $r 'ApprovalStage2')
            requireJustification = ((Get-PimManagerApCell $r 'RequireJustification') -match '^(?i)(true|1|yes)$'); allowExtension = ((Get-PimManagerApCell $r 'AllowExtension') -match '^(?i)(true|1|yes)$')
            maxDays = (Get-PimManagerApCell $r 'MaxDays'); reviewCadence = (Get-PimManagerApCell $r 'ReviewCadence'); reviewers = (Get-PimManagerApCell $r 'Reviewers'); reviewNoResponse = (Get-PimManagerApCell $r 'ReviewNoResponse')
            state = $state; reason = $reason; adminPaused = $adminPaused })
    }
    $lic = $null
    if ($status -and $status.licence) { $lic = [ordered]@{ ok = [bool]$status.licence.ok; reason = "$($status.licence.reason)" } }
    return @{ status = 200; body = [ordered]@{ ok = $true; enabled = $enabled; marker = (Get-PimAccessPackageGroupMarker); catalog = (Get-PimAccessPackageCatalogName)
        licence = $lic; statusUpdatedUtc = $(if ($status) { "$($status.updatedUtc)" } else { '' }); statusError = $statusErr; packages = $out.ToArray()
        canWrite = [bool](& $S.RoleAtLeast 'Admin') } }
}

function New-PimManagerAccessPackagePlan {
    <#
      POST /api/access-packages/plan. Validates and answers the rows to stage: @{ status; body = { ok; rows = { <entity> = @(row...) }; groups; problems } }.
      Nothing is written. A taken tag or name, a grant that is not a permission group, or a locked group anywhere = refused (422) with the reason.
    #>
    param([AllowNull()]$Body, [hashtable]$Seams)
    $S = Get-PimManagerApSeams -Seams $Seams
    if (-not [bool](& $S.RoleAtLeast 'Admin')) { return @{ status = 403; body = [ordered]@{ ok = $false; error = 'Admin role required to create an access package.' } } }
    if ($null -eq $Body) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'no request body' } } }
    $name = "$($Body.name)".Trim()
    $problems = New-Object System.Collections.Generic.List[string]
    try {
        $rows = @(& $S.ReadRows (Get-PimManagerAccessPackageBase))
        $idx = Get-PimManagerAccessPackageGroupIndex -S $S
    } catch { return @{ status = 503; body = [ordered]@{ ok = $false; error = "nothing was planned -- the store could not be read: $($_.Exception.Message)" } } }
    if (-not $name) { $problems.Add('give the access package a name') }
    elseif (@($rows | Where-Object { (Get-PimManagerApCell $_ 'AccessPackageName') -ieq $name }).Count) { $problems.Add("an access package named '$name' already exists -- pick another name") }
    $reqGroups = @($Body.groups | Where-Object { $null -ne $_ })
    if (-not $reqGroups.Count) { $problems.Add('add at least one new group to the package') }
    if ($reqGroups.Count -gt 10) { $problems.Add('a package can have at most 10 groups') }
    $defRows = @{}; $nestRows = New-Object System.Collections.Generic.List[object]; $newTags = New-Object System.Collections.Generic.List[string]
    $seen = @{}; $planned = New-Object System.Collections.Generic.List[object]
    foreach ($g in $reqGroups) {
        $id = New-PimAccessPackageGroupIdentity -Type "$($g.type)" -ShortName "$($g.shortName)"
        if (-not $id.ok) { $problems.Add($id.error); continue }
        # OWNER 2026-11-12: a NEW group only. A tag or a name already defined (any entity, retired included) is never reused.
        if ($idx.byTag.ContainsKey($id.tag.ToLowerInvariant())) { $problems.Add("the tag '$($id.tag)' is already used by an existing group -- an access package always gets a NEW group; pick another short name"); continue }
        if ($idx.byName.ContainsKey($id.name.ToLowerInvariant())) { $problems.Add("the name '$($id.name)' is already used by an existing group -- an access package always gets a NEW group; pick another short name"); continue }
        if ($seen.ContainsKey($id.tag.ToLowerInvariant())) { $problems.Add("'$($id.tag)' is in this package twice"); continue }
        $seen[$id.tag.ToLowerInvariant()] = $true
        $grants = @(@($g.grants) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
        if (-not $grants.Count) { $problems.Add("'$($id.tag)' grants nothing -- pick the permission groups (roles and delegations) it carries") }
        $tiers = New-Object System.Collections.Generic.List[int]
        foreach ($t in $grants) {
            $p = $idx.byTag["$t".ToLowerInvariant()]
            if (-not $p) { $problems.Add("'$t' is not a group defined in PIM Manager"); continue }
            if ($p.direct) { $problems.Add("'$t' is a direct group -- a package's group is nested into PERMISSION groups (the roles and delegations it carries)"); continue }
            if ($p.locked) { $problems.Add("'$t' belongs to an access package -- it cannot be granted by another one"); continue }
            if ($p.retired) { $problems.Add("'$t' is being retired"); continue }
            $tn = $null; if ("$($p.tier)" -match '(\d+)') { $tn = [int]$Matches[1] }
            if ($null -ne $tn) { $tiers.Add($tn) }
        }
        # The new group takes the MOST privileged tier it reaches (the lowest number); unknown = left blank, so the engine treats it as not stated.
        $tier = if ($tiers.Count -and $tiers.Count -eq @($grants).Count) { 'T' + (@($tiers | Sort-Object)[0]) } else { '' }
        $desc = "Access package '$name'" + $(if ("$($Body.description)".Trim()) { ": $("$($Body.description)".Trim())" } else { '' })
        if (-not $defRows.ContainsKey($id.entity)) { $defRows[$id.entity] = New-Object System.Collections.Generic.List[object] }
        $defRows[$id.entity].Add([ordered]@{ GroupName = $id.name; GroupDescription = $desc; GroupTag = $id.tag; AdministrativeUnitTag = ''; TierLevel = $tier; AccessPackage = $name; Lifecycle = '' })
        foreach ($t in $grants) {
            $nestRows.Add([ordered]@{ TargetGroupTag = $id.tag; SourceGroupTag = "$t"; AssignmentType = 'Eligible'; Action = 'Assign'; UpdateExisting = 'FALSE'; AutoExtend = 'TRUE'; NumOfDaysWhenExpire = '365'; Permanent = 'FALSE' })
        }
        $newTags.Add($id.tag)
        $planned.Add([ordered]@{ tag = $id.tag; name = $id.name; entity = $id.entity; tier = $tier; grants = $grants })
    }
    $flag = { param($v) if ($v -is [bool]) { if ($v) { 'true' } else { 'false' } } elseif ("$v" -match '^(?i)(true|1|yes|on)$') { 'true' } else { 'false' } }
    $apRow = [ordered]@{
        AccessPackageName = $name; Notes = "$($Body.description)".Trim(); DirectGroupTags = ($newTags -join '; ')
        RequestScope = "$($Body.requestScope)".Trim(); RequestGroupTag = "$($Body.requestGroupTag)".Trim()
        Approval = "$($Body.approval)".Trim(); ApprovalStage1 = "$($Body.approvalStage1)".Trim(); ApprovalStage2 = "$($Body.approvalStage2)".Trim()
        RequireJustification = (& $flag $Body.requireJustification); AllowExtension = (& $flag $Body.allowExtension)
        MaxDays = "$($Body.maxDays)".Trim(); ReviewCadence = $(if ("$($Body.reviewCadence)".Trim()) { "$($Body.reviewCadence)".Trim() } else { 'None' })
        Reviewers = "$($Body.reviewers)".Trim(); ReviewNoResponse = "$($Body.reviewNoResponse)".Trim(); State = ''; PauseReason = ''; Action = ''
    }
    # The engine's own definition check, so the page refuses what the engine would refuse.
    $check = ConvertTo-PimAccessPackageDefinition -Row ([pscustomobject]$apRow)
    foreach ($p in @($check.problems)) { if ("$p" -notmatch 'names no direct group|has no AccessPackageName') { $problems.Add("$p") } }
    if ("$($apRow.RequestScope)" -ieq 'Group') {
        $rg = $idx.byTag["$($apRow.RequestGroupTag)".ToLowerInvariant()]
        if (-not $rg) { $problems.Add("the group that may request ('$($apRow.RequestGroupTag)') is not a group defined in PIM Manager") }
    }
    if ("$($apRow.Approval)" -ieq 'None' -and @($planned | Where-Object { -not "$($_.tier)" -or [int]("$($_.tier)" -replace '\D', '') -le 1 }).Count) {
        $problems.Add('no approval is refused when a group of the package reaches Tier 0 or Tier 1, or a tier that is not stated -- choose approval stages')
    }
    if ($problems.Count) { return @{ status = 422; body = [ordered]@{ ok = $false; problems = $problems.ToArray(); error = ($problems.ToArray() -join '; ') } } }
    $outRows = [ordered]@{}
    $outRows[(Get-PimManagerAccessPackageBase)] = @($apRow)
    foreach ($e in @($defRows.Keys | Sort-Object)) { $outRows[$e] = $defRows[$e].ToArray() }
    $outRows['PIM-Assignments-Groups'] = $nestRows.ToArray()
    return @{ status = 200; body = [ordered]@{ ok = $true; name = $name; groups = $planned.ToArray(); rows = $outRows
        summary = ("Access package '{0}' with {1} new group(s) ({2}). Staged in Pending changes; nothing is written until you commit." -f $name, $planned.Count, ((@($planned | ForEach-Object { $_.name })) -join ', ')) } }
}

function Get-PimManagerAccessPackageStateChange {
    <# POST /api/access-packages/pause | resume. The row change to stage (key = AccessPackageName). Nothing is written. #>
    param([Parameter(Mandatory)][ValidateSet('pause', 'resume')][string]$Verb, [AllowNull()]$Body, [hashtable]$Seams)
    $S = Get-PimManagerApSeams -Seams $Seams
    if (-not [bool](& $S.RoleAtLeast 'Admin')) { return @{ status = 403; body = [ordered]@{ ok = $false; error = "Admin role required to $Verb an access package." } } }
    $name = "$($Body.name)".Trim()
    if (-not $name) { return @{ status = 400; body = [ordered]@{ ok = $false; error = 'name the access package' } } }
    $rows = @(); try { $rows = @(& $S.ReadRows (Get-PimManagerAccessPackageBase)) } catch { return @{ status = 503; body = [ordered]@{ ok = $false; error = "the access packages could not be read: $($_.Exception.Message)" } } }
    $row = @($rows | Where-Object { (Get-PimManagerApCell $_ 'AccessPackageName') -ieq $name -and -not (Get-PimManagerApRowIsGone $_) } | Select-Object -First 1)
    if (-not $row.Count) { return @{ status = 404; body = [ordered]@{ ok = $false; error = "no access package named '$name'" } } }
    $reason = "$($Body.reason)".Trim()
    if ($reason.Length -gt 300) { $reason = $reason.Substring(0, 300) }
    $changes = if ($Verb -eq 'pause') { [ordered]@{ State = 'Paused'; PauseReason = $reason } } else { [ordered]@{ State = ''; PauseReason = '' } }
    return @{ status = 200; body = [ordered]@{ ok = $true; base = (Get-PimManagerAccessPackageBase); keyColumn = 'AccessPackageName'; key = (Get-PimManagerApCell $row[0] 'AccessPackageName'); changes = $changes
        summary = $(if ($Verb -eq 'pause') { "Pause '$name': nothing is changed for it until it is resumed. Staged in Pending changes." } else { "Resume '$name': the engine builds it again at its next run. Staged in Pending changes." }) } }
}

function Invoke-PimManagerAccessPackageRoute {
    <# The one entry Open-PimManager.ps1 calls. Returns @{ status; body }. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Method, [AllowNull()]$Body, [hashtable]$Seams)
    if ($Path -eq '/api/access-packages' -and $Method -eq 'GET') { return (Get-PimManagerAccessPackageList -Seams $Seams) }
    if ($Path -eq '/api/access-packages/plan' -and $Method -eq 'POST') { return (New-PimManagerAccessPackagePlan -Body $Body -Seams $Seams) }
    if ($Path -eq '/api/access-packages/pause' -and $Method -eq 'POST') { return (Get-PimManagerAccessPackageStateChange -Verb pause -Body $Body -Seams $Seams) }
    if ($Path -eq '/api/access-packages/resume' -and $Method -eq 'POST') { return (Get-PimManagerAccessPackageStateChange -Verb resume -Body $Body -Seams $Seams) }
    return @{ status = 405; body = [ordered]@{ ok = $false; error = "$Method $Path is not an access package route" } }
}

function Get-PimManagerAccessPackageLockedTags {
    <# tag (lower) -> package of every STORED group definition locked by its AccessPackage column (the five direct-group entities). #>
    param([hashtable]$Seams)
    $S = Get-PimManagerApSeams -Seams $Seams
    $h = @{}
    foreach ($e in @(Get-PimManagerAccessPackageGroupEntities)) {
        foreach ($r in @(& $S.ReadRows $e)) {
            $t = Get-PimManagerApCell $r 'GroupTag'; $p = Get-PimManagerApCell $r 'AccessPackage'
            if ($t -and $p) { $h[$t.ToLowerInvariant()] = $p }
        }
    }
    return $h
}

function Test-PimManagerAccessPackageCommitGate {
    <#
      PURE. THE COMMIT GATE OF THE LOCK (owner 2026-11-12). -Diff = Compare-PimRowSets output for -Base; -LockedTags = Get-PimManagerAccessPackageLockedTags.
        PIM-Assignments-Admins  a new / changed row (not Action=Remove) giving membership of a package group        -> refused
        PIM-Assignments-Groups  a new / changed row nesting anything INTO a package group (SourceGroupTag)          -> refused
        a direct-group entity   a package group's GroupName / GroupTag / AccessPackage changed (never renamed)      -> refused
                                a new group with only one of the two markers ('-AP' name, AccessPackage column)     -> refused
      Removals are always allowed (taking access away never needs the package). Returns @{ allowed; refused = @(@{ op; key; why }); reason }.
    #>
    param([Parameter(Mandatory)][object]$Diff, [string]$Base = '', [hashtable]$LockedTags = @{})
    $out = New-Object System.Collections.Generic.List[object]
    $side = { param($m, $s) if ($m -is [System.Collections.IDictionary]) { $m[$s] } elseif ($m.PSObject.Properties[$s]) { $m.PSObject.Properties[$s].Value } }
    $after = @(@($Diff.adds) | Where-Object { $null -ne $_ } | ForEach-Object { @{ op = 'add'; row = $_; before = $null } }) +
             @(@($Diff.modifies) | Where-Object { $null -ne $_ } | ForEach-Object { @{ op = 'modify'; row = (& $side $_ 'after'); before = (& $side $_ 'before') } })
    $isAp = { param($n) "$n".Trim() -match '(?i)-AP$' }
    switch -Regex ("$Base") {
        '^PIM-Assignments-Admins$' {
            foreach ($x in $after) {
                if ((Get-PimManagerApCell $x.row 'Action') -ieq 'Remove') { continue }
                $t = (Get-PimManagerApCell $x.row 'GroupTag').ToLowerInvariant()
                if ($t -and $LockedTags.ContainsKey($t)) { $out.Add([ordered]@{ op = $x.op; key = "$(Get-PimManagerApCell $x.row 'Username')|$t"; why = "'$t' belongs to access package '$($LockedTags[$t])' -- its members come from the access package only" }) }
            }
        }
        '^PIM-Assignments-Groups$' {
            foreach ($x in $after) {
                if ((Get-PimManagerApCell $x.row 'Action') -ieq 'Remove') { continue }
                $t = (Get-PimManagerApCell $x.row 'SourceGroupTag').ToLowerInvariant()
                if ($t -and $LockedTags.ContainsKey($t)) { $out.Add([ordered]@{ op = $x.op; key = "$(Get-PimManagerApCell $x.row 'TargetGroupTag')>$t"; why = "'$t' belongs to access package '$($LockedTags[$t])' -- nothing is nested into an access package group" }) }
            }
        }
        '^PIM-Definitions-(Roles|Departments|Organization|Projects|CrossOrg)$' {
            foreach ($x in $after) {
                $tag = Get-PimManagerApCell $x.row 'GroupTag'; $gn = Get-PimManagerApCell $x.row 'GroupName'; $pk = Get-PimManagerApCell $x.row 'AccessPackage'
                if ($x.before) {
                    $bt = Get-PimManagerApCell $x.before 'GroupTag'; $bn = Get-PimManagerApCell $x.before 'GroupName'; $bp = Get-PimManagerApCell $x.before 'AccessPackage'
                    if ($bp) {   # a package group (the column; an existing group that merely ends with -AP is not one)
                        if ($bt -cne $tag -or $bn -cne $gn -or $bp -cne $pk) { $out.Add([ordered]@{ op = 'modify'; key = $bt; why = "'$bn' is an access package group -- it is never renamed, re-tagged or moved to another package" }) }
                        continue
                    }
                    if ($pk) { $out.Add([ordered]@{ op = 'modify'; key = $bt; why = "'$bn' is an existing group -- it is never given to an access package (a package always gets a NEW group)" }); continue }
                }
                if ($pk -and -not (& $isAp $gn)) { $out.Add([ordered]@{ op = $x.op; key = $tag; why = "'$gn' is marked for access package '$pk' but its name does not end with '-AP'" }) }
                elseif ((& $isAp $gn) -and -not $pk -and $x.op -eq 'add') { $out.Add([ordered]@{ op = 'add'; key = $tag; why = "'$gn' ends with '-AP', kept for the groups an access package creates -- create the package under Access > Access packages" }) }
            }
        }
    }
    if (-not $out.Count) { return @{ allowed = $true; refused = @(); reason = '' } }
    return @{ allowed = $false; refused = $out.ToArray(); reason = ("Not committed -- access package groups are locked to their package: " + ((@($out | ForEach-Object { $_.why }) | Select-Object -Unique) -join '; ') + '. Nothing was saved.') }
}

function Test-PimManagerAccessPackageAdoptLocked {
    <#
      The adopt lock: is -Name the name of a group DEFINED FOR an access package (the AccessPackage column)? Then only the group PIM
      created for the package is used -- another group is never adopted under that name. An unreadable store = $true (no write in doubt).
    #>
    param([AllowNull()][string]$Name, [hashtable]$Seams)
    $n = "$Name".Trim(); if (-not $n) { return $false }
    $S = Get-PimManagerApSeams -Seams $Seams
    try {
        foreach ($e in @(Get-PimManagerAccessPackageGroupEntities)) {
            foreach ($r in @(& $S.ReadRows $e)) { if ((Get-PimManagerApCell $r 'GroupName') -ieq $n -and (Get-PimManagerApCell $r 'AccessPackage')) { return $true } }
        }
    } catch { return $true }
    return $false
}

function Test-PimManagerAccessPackageLockedName {
    <# PURE. The lock for the adopt and drift-delete routes: a group name ending '-AP' belongs to an access package. #>
    param([AllowNull()][string]$Name)
    return ("$Name".Trim() -match '(?i)-AP$')
}
