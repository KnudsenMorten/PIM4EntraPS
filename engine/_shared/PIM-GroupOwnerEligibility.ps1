<#
  PIM 95.2l (owner 2026-10-07 / approved 2026-10-29) -- GROUP OWNERS AS PIM-ELIGIBLE OWNERS.

  Microsoft's practice for privileged groups: people are ELIGIBLE owners (PIM for Groups, accessId = owner) -- they
  activate ownership with MFA + justification for a short time -- and nobody holds standing ownership except service
  identities. The GroupOwners scope used to attach every defined owner as a permanent DIRECTORY owner
  (POST /groups/{id}/owners/$ref). This file holds the switches and the decisions that make it attach PEOPLE as
  eligible owners instead, and move existing permanent owners over -- only when the operator switches it on.

  THE SWITCHES (pim.Settings, hydrated into $global:PIM_NamingConventions; also $global:PIM_<name> / env PIM_<name>):
    GroupOwnersEligible      off by default. On: a defined owner who is a PERSON becomes an owner eligibility
                             (eligibilityScheduleRequests, accessId owner) -- never a directory owner POST. With it off
                             the GroupOwners scope does exactly what it did before (tests/Test-PimGroupOwnerEligibility.ps1
                             holds that).
    GroupOwnerMigration      off by default; read only while GroupOwnersEligible is on. Off: the run LISTS every defined
                             person who is still a permanent directory owner (the migration plan) and changes nothing for
                             them. On: for each of them the eligibility is created (or found), READ BACK from the tenant,
                             and only then the permanent ownership is removed -- under the removal budget.
    GroupOwnerEligibleDays   how long an owner eligibility lasts (default 365, 1..3650). AutoExtend renews it the same
                             way it renews member eligibilities (Get-PimAssignmentMaintenance, policy lead days).

  WHAT IS NEVER TOUCHED
    * an owner the definitions do not name (only defined group+person pairs are ever planned or moved);
    * a service identity (a service principal -- the engine's own identity among them -- or anything the engine cannot
      confirm is a user): it keeps the directory path, exactly as today;
    * a directory owner that holds an ACTIVE PIM owner schedule (an activated eligible owner, or an active PIM owner
      assignment): that ownership is PIM's own, not a standing one;
    * the last owner Entra refuses to remove: kept, and the run says so.

  ASCII only. Windows PowerShell 5.1 and pwsh 7. REST only (Invoke-PimGraph), no module.
#>

Set-StrictMode -Off

function Get-PimGroupOwnerSettingRaw {
    <# The raw value of -Name: the store (NamingConventions) -> $global:PIM_<Name> -> env PIM_<Name> -> $null. #>
    param([Parameter(Mandatory)][string]$Name)
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($Name)) {
        $s = $global:PIM_NamingConventions[$Name]
        if ($null -ne $s -and "$s".Trim() -ne '') { return $s }
    }
    $g = Get-Variable -Name "PIM_$Name" -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $g -and "$g".Trim() -ne '') { return $g }
    $e = [Environment]::GetEnvironmentVariable("PIM_$Name", 'Process')
    if ($null -ne $e -and "$e".Trim() -ne '') { return $e }
    return $null
}

function Test-PimGroupOwnerSwitchOn {
    <# PURE on its input. Only true / 1 / yes / on is ON -- never [bool] on text (the stored text "false" would be TRUE). #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    return ("$Value".Trim() -match '^(?i)(true|1|yes|on)$')
}

function Test-PimGroupOwnersEligibleEnabled {
    <# The 95.2l switch: defined people become ELIGIBLE owners. Default OFF. #>
    Test-PimGroupOwnerSwitchOn (Get-PimGroupOwnerSettingRaw -Name 'GroupOwnersEligible')
}

function Test-PimGroupOwnerMigrationEnabled {
    <# The migration switch: existing permanent owners are moved. Default OFF, and never on without GroupOwnersEligible. #>
    (Test-PimGroupOwnersEligibleEnabled) -and (Test-PimGroupOwnerSwitchOn (Get-PimGroupOwnerSettingRaw -Name 'GroupOwnerMigration'))
}

function Get-PimGroupOwnerEligibleDays {
    <# Days an owner eligibility lasts. Default 365; a value outside 1..3650 or not a whole number gives the default. #>
    $v = Get-PimGroupOwnerSettingRaw -Name 'GroupOwnerEligibleDays'
    $n = 0
    if ($null -ne $v -and "$v".Trim() -match '^\d{1,4}$') { $n = [int]("$v".Trim()) }
    if ($n -ge 1 -and $n -le 3650) { return $n }
    return 365
}

function Test-PimGroupOwnerIsUserType {
    <# PURE. Is this @odata.type a user? #>
    param([AllowNull()][string]$ODataType)
    return ("$ODataType".Trim() -match '(?i)^#?microsoft\.graph\.user$')
}

function Resolve-PimGroupOwnerEntryKind {
    <#
      What a defined owner entry is: 'user' (a person), 'service' (a service principal or any non-user object), or
      'unknown'. An entry written as a UPN resolves through /users, so it is a person. An entry written as an object id is
      a person only when the directory says so (the user cache, else one GET of the object's type); anything the engine
      cannot confirm is NOT a person and keeps the directory path (today's behaviour).
    #>
    param([string]$Entry, [string]$Id)
    $e = "$Entry".Trim()
    if (-not $e -or -not "$Id".Trim()) { return 'unknown' }
    if ($e -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return 'user' }
    foreach ($u in @($Global:Users_All_ID)) { if ($u -and "$($u.Id)" -ieq "$Id") { return 'user' } }
    try {
        $o = Invoke-PimGraph -Path "/directoryObjects/$Id"
        $t = if ($o -and $o.PSObject.Properties['@odata.type']) { "$($o.'@odata.type')" } else { '' }
        if (Test-PimGroupOwnerIsUserType $t) { return 'user' }
        if ($t) { return 'service' }
    } catch { }
    return 'unknown'
}

function Merge-PimGroupOwnerLive {
    <#
      PURE. One live row per group + owner, from the directory owners (-Directory: { GroupName; groupId; OwnerId;
      ODataType }) and the PIM owner schedules (-Schedules: Get-PimLiveGroupMembership rows of accessId owner, each with
      GroupName). Fields: GroupName; OwnerId; groupId; directoryOwner; directoryType; eligible (the schedule row or $null);
      active (the active owner schedules); permanentDirectory = a directory owner with NO active PIM owner schedule.
    #>
    param([object[]]$Directory = @(), [object[]]$Schedules = @())
    $map = [ordered]@{}
    $get = {
        param($gn, $oid, $gid)
        $k = ("$gn".ToLowerInvariant() + '|' + "$oid".ToLowerInvariant())
        if (-not $map.Contains($k)) {
            $map[$k] = [pscustomobject]@{ GroupName = "$gn"; OwnerId = "$oid"; groupId = "$gid"; directoryOwner = $false; directoryType = ''
                                          eligible = $null; active = (New-Object System.Collections.Generic.List[object]); permanentDirectory = $false }
        }
        $r = $map[$k]
        if (-not $r.groupId -and "$gid") { $r.groupId = "$gid" }
        return $r
    }
    foreach ($d in @($Directory)) {
        if ($null -eq $d -or -not "$($d.OwnerId)" -or -not "$($d.GroupName)") { continue }
        $r = & $get $d.GroupName $d.OwnerId $d.groupId
        $r.directoryOwner = $true; $r.directoryType = "$($d.ODataType)"
    }
    foreach ($s in @($Schedules)) {
        if ($null -eq $s -or -not "$($s.principalId)" -or -not "$($s.GroupName)") { continue }
        if ("$($s.accessId)".Trim() -ine 'owner') { continue }
        $r = & $get $s.GroupName $s.principalId $s.groupId
        if ("$($s.AssignmentType)" -eq 'Eligible') { if ($null -eq $r.eligible) { $r.eligible = $s } }
        else { $r.active.Add($s) }
    }
    foreach ($r in $map.Values) {
        $r.permanentDirectory = [bool]($r.directoryOwner -and $r.active.Count -eq 0)
        $r.active = @($r.active.ToArray())
    }
    return @($map.Values)
}

function Get-PimGroupOwnerMode {
    <#
      PURE. How THIS defined owner is held: 'eligible' (the switch is on and the owner is a person) or 'directory' (the
      switch is off, or a service identity / an object the engine cannot confirm is a person -- today's behaviour).
    #>
    param([object]$Desired, [object]$Live, [bool]$EligibleOn)
    if (-not $EligibleOn -or $null -eq $Desired) { return 'directory' }
    $kind = if ($Desired.PSObject.Properties['OwnerKind']) { "$($Desired.OwnerKind)" } else { '' }
    if ($kind -eq 'user') { return 'eligible' }
    if ($kind -eq 'service') { return 'directory' }
    if ($Live -and $Live.PSObject.Properties['directoryType'] -and (Test-PimGroupOwnerIsUserType "$($Live.directoryType)")) { return 'eligible' }
    return 'directory'
}

function New-PimGroupOwnerMaintenanceRow {
    <# PURE. The assignment-shaped row the AutoExtend / expiry machinery reads for one owner eligibility. #>
    param([Parameter(Mandatory)][object]$Desired, [int]$Days = 365)
    $who = if ($Desired.PSObject.Properties['OwnerRef'] -and "$($Desired.OwnerRef)".Trim()) { "$($Desired.OwnerRef)" } else { "$($Desired.OwnerId)" }
    $ae = if ($Desired.PSObject.Properties['AutoExtend']) { "$($Desired.AutoExtend)" } else { '' }
    [pscustomobject]@{ UserPrincipalName = $who; GroupTag = "$($Desired.GroupName)"; AssignmentType = 'Eligible'
                       NumOfDaysWhenExpire = "$Days"; Permanent = 'FALSE'; AutoExtend = $ae; AccessId = 'owner' }
}

function Get-PimGroupOwnerAction {
    <#
      PURE except the maintenance decision (Get-PimAssignmentMaintenance, which reads the AutoExtend policy). What the
      GroupOwners scope does for ONE defined owner. Returns
        @{ mode; createEligible; maintain (a maintenance decision or $null); removePermanent; planMove; none; reason }
      Rules, in eligible mode:
        * no eligibility live            -> create it, EXCEPT for a permanent directory owner while the migration switch is
                                            off: that one is only LISTED (planMove) and nothing is written for it;
        * an eligibility live            -> AutoExtend / expiry exactly like a member eligibility;
        * a permanent directory owner    -> planMove; with the migration switch on also removePermanent (after read-back).
    #>
    param([object]$Desired, [object]$Live, [bool]$EligibleOn, [bool]$MigrateOn, [int]$Days = 365, [datetime]$NowUtc = [datetime]::UtcNow, $AutoExtendContext = $null)
    $mode = Get-PimGroupOwnerMode -Desired $Desired -Live $Live -EligibleOn $EligibleOn
    $out = [pscustomobject]@{ mode = $mode; createEligible = $false; maintain = $null; removePermanent = $false; planMove = $false; none = $true; reason = '' }
    if ($mode -ne 'eligible') { $out.reason = 'directory owner (today''s behaviour)'; return $out }
    $el = if ($Live -and $Live.PSObject.Properties['eligible']) { $Live.eligible } else { $null }
    $perm = [bool]($Live -and $Live.PSObject.Properties['permanentDirectory'] -and $Live.permanentDirectory)
    $out.planMove = $perm
    if ($null -eq $el) {
        $out.createEligible = (-not $perm) -or $MigrateOn
    } else {
        $mrow = New-PimGroupOwnerMaintenanceRow -Desired $Desired -Days $Days
        $m = Get-PimAssignmentMaintenance -Desired $mrow -Live $el -NowUtc $NowUtc -AutoExtendContext $AutoExtendContext
        if ($m -and "$($m.action)" -ne 'none') { $out.maintain = $m }
    }
    $out.removePermanent = ($perm -and $MigrateOn)
    $out.none = -not ($out.createEligible -or $out.maintain -or $out.removePermanent)
    $out.reason = if ($out.none -and $perm) { 'permanent owner -- listed in the migration plan (migration switch off)' } elseif ($out.none) { 'eligible owner in place' } else { 'due' }
    return $out
}

function Get-PimGroupOwnerMigrationPlan {
    <#
      PURE. The migration plan: every DEFINED person (eligible mode) who is still a permanent directory owner.
      -Desired: the scope's desired rows; -LiveByKey: key -> merged live row. Each move: { key; group; ownerId; owner;
      eligibleExists }. Owners the definitions do not name are never in it.
    #>
    param([object[]]$Desired = @(), [hashtable]$LiveByKey = @{}, [bool]$EligibleOn, [bool]$MigrateOn)
    $moves = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($d in @($Desired)) {
        if ($null -eq $d) { continue }
        $k = ("$($d.GroupName)".ToLowerInvariant() + '|' + "$($d.OwnerId)".ToLowerInvariant())
        if ($seen.ContainsKey($k)) { continue }; $seen[$k] = $true
        $l = $LiveByKey[$k]
        if ($null -eq $l -or -not $l.permanentDirectory) { continue }
        if ((Get-PimGroupOwnerMode -Desired $d -Live $l -EligibleOn $EligibleOn) -ne 'eligible') { continue }
        $who = if ($d.PSObject.Properties['OwnerRef'] -and "$($d.OwnerRef)".Trim()) { "$($d.OwnerRef)" } else { "$($d.OwnerId)" }
        $moves.Add([pscustomobject]@{ key = $k; group = "$($d.GroupName)"; ownerId = "$($d.OwnerId)"; owner = $who; eligibleExists = ($null -ne $l.eligible) })
    }
    return [pscustomobject]@{ eligibleOn = [bool]$EligibleOn; migrateOn = [bool]$MigrateOn; count = $moves.Count; moves = @($moves.ToArray())
                              budget = $null; held = $false; moved = 0; kept = 0 }
}

function Format-PimGroupOwnerMigrationRunSummary {
    <# PURE. One plain line for the run detail: what the migration plan holds and what this run did with it. '' = nothing to say. #>
    param([object]$Plan, [int]$Show = 5)
    if ($null -eq $Plan -or -not $Plan.eligibleOn) { return '' }
    $n = [int]$Plan.count
    if ($n -le 0) { return 'eligible owners: no permanent owner left to move' }
    $list = (@(@($Plan.moves) | Select-Object -First $Show | ForEach-Object { "$($_.group) -> $($_.owner)" }) -join ', ')
    if ($n -gt $Show) { $list += (", +{0} more" -f ($n - $Show)) }
    if (-not $Plan.migrateOn) { return ("owner migration plan (switch off, nothing changed): {0} permanent owner(s) would become eligible owners: {1}" -f $n, $list) }
    if ($Plan.held) { return ("owner migration HELD by the removal budget: {0} permanent owner(s) to move, nothing removed: {1}" -f $n, $list) }
    return ("owner migration: {0} permanent owner(s) planned, {1} moved to eligible, {2} kept: {3}" -f $n, [int]$Plan.moved, [int]$Plan.kept, $list)
}

function Get-PimGroupOwnersEligibleLive {
    <#
      GetLive of the GroupOwners scope with GroupOwnersEligible ON. The SAME directory-owner read as before (every group,
      $expand=owners, now with each owner's type), plus the PIM owner schedules of the groups the definitions name, merged
      into one row per group + owner (Merge-PimGroupOwnerLive). Then the migration plan is made and listed.
      FAIL CLOSED: either read failing = the scope is NOT CHECKED (__pimLiveReadError) -- a short read would hide a
      permanent owner, and an eligibility would be created for a planned move while the migration switch is off.
    #>
    param([Parameter(Mandatory)][hashtable]$Ctx)
    $dir = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($grp in @(Invoke-PimGraph -Path "/groups?`$select=id,displayName&`$expand=owners" -All)) {
            $gn = "$($grp.displayName)"; if (-not $gn) { continue }
            foreach ($o in @($grp.owners)) {
                if ($o -and $o.id) {
                    $t = if ($o.PSObject.Properties['@odata.type']) { "$($o.'@odata.type')" } else { '' }
                    $dir.Add([pscustomobject]@{ GroupName = $gn; groupId = "$($grp.id)"; OwnerId = "$($o.id)"; ODataType = $t })
                }
            }
        }
    } catch {
        $Ctx['__pimLiveReadError'] = "GroupOwners: the owners read failed ($($_.Exception.Message))"
        return @()
    }
    $sched = New-Object System.Collections.Generic.List[object]
    $groups = @{}
    foreach ($d in @($Ctx['GroupOwners.desired'])) { if ($d -and "$($d.GroupName)") { $groups["$($d.GroupName)".ToLowerInvariant()] = "$($d.GroupName)" } }
    Clear-PimGroupScheduleReadError
    foreach ($gn in @($groups.Values)) {
        $gid = Resolve-PimLiveGroupIdByName $gn
        if (-not $gid) { continue }   # not created yet: its owners are creates
        foreach ($m in @(Get-PimLiveGroupMembership -GroupId $gid -GroupTag $gn)) {
            if ($null -eq $m -or "$($m.accessId)".Trim() -ine 'owner') { continue }
            $c = $m | Select-Object *
            Add-Member -InputObject $c -NotePropertyName GroupName -NotePropertyValue $gn -Force
            if (-not "$($c.groupId)") { $c.groupId = $gid }
            $sched.Add($c)
        }
    }
    $ge = "$(Get-PimGroupScheduleReadError)".Trim()
    if ($ge) { $Ctx['__pimLiveReadError'] = "GroupOwners: the owner schedule read was INCOMPLETE ($ge)"; return @() }
    $live = @(Merge-PimGroupOwnerLive -Directory @($dir.ToArray()) -Schedules @($sched.ToArray()))
    $byKey = @{}; foreach ($l in $live) { $byKey[("$($l.GroupName)".ToLowerInvariant() + '|' + "$($l.OwnerId)".ToLowerInvariant())] = $l }
    $migOn = Test-PimGroupOwnerMigrationEnabled
    $plan = Get-PimGroupOwnerMigrationPlan -Desired @($Ctx['GroupOwners.desired']) -LiveByKey $byKey -EligibleOn $true -MigrateOn $migOn
    $Ctx['GroupOwners.ownerMigration'] = $plan
    if ($plan.count -gt 0) {
        Write-Host ("[engine] GroupOwners          owner migration plan ({0}): {1} permanent owner(s) of defined groups would become eligible owners" -f $(if ($migOn) { 'switch ON -- applied this run, under the removal budget' } else { 'switch OFF -- nothing is changed for them' }), $plan.count) -ForegroundColor DarkYellow
        foreach ($mv in @($plan.moves)) { Write-Host ("    [plan] {0} -> {1} ({2})" -f $mv.group, $mv.owner, $(if ($mv.eligibleExists) { 'eligible owner already in place' } else { 'eligible owner to create' })) -ForegroundColor DarkGray }
    }
    return $live
}

function Add-PimGroupOwnerScopeWarning {
    param([hashtable]$Ctx, [string]$Message)
    try { Write-Warning ("  [GroupOwners] {0}" -f $Message) } catch { }
    if ($Ctx -and $Ctx['__pimScopeWarnings'] -is [System.Collections.IList]) { try { [void]$Ctx['__pimScopeWarnings'].Add($Message) } catch { } }
}

function Invoke-PimGroupOwnerEligibleCreate {
    <# Create ONE owner eligibility (PIM for Groups, accessId owner). The duration ladder lands it at the policy maximum. #>
    param([Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$OwnerId, [int]$Days = 365)
    $body = New-PimGroupMembershipBody -PrincipalId $OwnerId -GroupId $GroupId -AccessId 'owner' -Days $Days
    $r = Invoke-PimScheduleCreate -Path '/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests' -Body $body
    Reset-PimAssignmentLiveCaches -GroupId $GroupId
    return $r
}

function Test-PimGroupOwnerEligibilityLive {
    <#
      READ-BACK: a FRESH read of the group's PIM schedules (the cache entry is dropped first). $true only when an owner
      eligibility for this owner is there and the read was complete; a failed read is $false (never assume).
    #>
    param([Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$OwnerId, [string]$GroupName = '')
    try {
        Reset-PimAssignmentLiveCaches -GroupId $GroupId
        Clear-PimGroupScheduleReadError
        $rows = @(Get-PimLiveGroupMembership -GroupId $GroupId -GroupTag $GroupName)
        if ("$(Get-PimGroupScheduleReadError)".Trim()) { return $false }
        foreach ($r in $rows) {
            if ($null -eq $r) { continue }
            if ("$($r.principalId)" -ieq $OwnerId -and "$($r.accessId)" -ieq 'owner' -and "$($r.AssignmentType)" -eq 'Eligible') { return $true }
        }
    } catch { }
    return $false
}

function Test-PimGroupLastOwnerRefusal {
    <# PURE. Did Entra refuse to remove the owner because the group must keep one? #>
    param([string]$Message)
    return ("$Message" -match '(?i)last owner|at least one owner|must have (at least )?one owner|cannot remove .*only owner|without an owner')
}

function Get-PimGroupOwnerMigrationBudget {
    <#
      The removal budget for this run's permanent-owner removals, decided ONCE per pass and cached in the context. Uses the
      engine's own G4 (Test-PimRemoveBudgetAllowed) and its release on Operations > Guards (Resolve-PimRemoveBudgetRelease,
      scope 'GroupOwners-Migration'). Over the budget and not released: NOTHING is removed (never a partial pick), the
      alert goes out, and every move is held. Returns @{ allowed; reason }.
    #>
    param([hashtable]$Ctx)
    $c = $Ctx['GroupOwners.migrationBudget']; if ($c) { return $c }
    $plan = $Ctx['GroupOwners.ownerMigration']
    $moves = if ($plan) { @($plan.moves) } else { @() }
    $scope = 'GroupOwners-Migration'
    $res = [pscustomobject]@{ allowed = $true; reason = 'nothing to remove' }
    if ($moves.Count -gt 0) {
        if (-not (Get-Command Test-PimRemoveBudgetAllowed -ErrorAction SilentlyContinue)) {
            $res = [pscustomobject]@{ allowed = $false; reason = 'the removal budget could not be checked (the guard is not loaded) -- nothing is removed' }
        } else {
            $rb = Test-PimRemoveBudgetAllowed -ToRemove $moves.Count -Scope $scope -Scanned $moves.Count -Operation 'remove a permanent owner from'
            if (Get-Command Resolve-PimRemoveBudgetRelease -ErrorAction SilentlyContinue) {
                $items = @($moves | ForEach-Object { [pscustomobject]@{ key = "permanent-owner|$($_.key)" } })
                $g = Resolve-PimRemoveBudgetRelease -Decision $rb -Scope $scope -Remove $items -Scanned $moves.Count -RunKind "$($Ctx['__pimRunKind'])"
                if ($g) { $rb = $g.decision }
            }
            if (-not $rb.allowed) {
                if (Get-Command Write-PimRemoveBudgetAlert -ErrorAction SilentlyContinue) { try { Write-PimRemoveBudgetAlert -Decision $rb } catch { } }
                Add-PimGroupOwnerScopeWarning -Ctx $Ctx -Message ("owner migration HELD: {0} permanent owner(s) to remove is over the removal budget of {1} -- nothing was removed and no eligibility was created for them. Release the plan on Operations > Guards, or move fewer at a time. [GROUP-OWNER-MIGRATION-HELD]" -f $moves.Count, $rb.budget)
                if ($plan) { $plan.held = $true; $plan.budget = $rb.budget }
            } elseif ($plan) { $plan.budget = $rb.budget }
            $res = [pscustomobject]@{ allowed = [bool]$rb.allowed; reason = "$($rb.reason)" }
        }
    }
    $Ctx['GroupOwners.migrationBudget'] = $res
    return $res
}

function Invoke-PimGroupOwnerUpdate {
    <#
      ApplyUpdate of the GroupOwners scope in eligible mode, for ONE defined owner. Order (95.2l, never another):
        1. a permanent owner under migration: the removal budget first -- held = nothing at all is written for it;
        2. no eligibility yet: create it;  an eligibility: AutoExtend / expiry, like a member eligibility;
        3. a permanent owner under migration: READ BACK the eligibility from the tenant -- not there = the permanent owner
           is KEPT (a later run completes it); there = remove the permanent ownership. Entra refusing the last owner =
           KEPT and reported. "Already gone" = done.
      Returns a result object; pimApplied = $false when nothing was written.
    #>
    param([Parameter(Mandatory)][object]$Item, [Parameter(Mandatory)][hashtable]$Ctx, [datetime]$NowUtc = [datetime]::UtcNow)
    $d = $Item.desired; $l = $Item.live
    $eligOn = Test-PimGroupOwnersEligibleEnabled; $migOn = Test-PimGroupOwnerMigrationEnabled; $days = Get-PimGroupOwnerEligibleDays
    $a = Get-PimGroupOwnerAction -Desired $d -Live $l -EligibleOn $eligOn -MigrateOn $migOn -Days $days -NowUtc $NowUtc
    if ($a.none) { return [pscustomobject]@{ pimApplied = $false; reason = "nothing due: $($a.reason)" } }
    $gid = if ($l -and "$($l.groupId)") { "$($l.groupId)" } else { Resolve-PimLiveGroupIdByName "$($d.GroupName)" }
    if (-not $gid) { throw "GroupOwners: group '$($d.GroupName)' not found" }
    $oid = "$($d.OwnerId)"
    $plan = $Ctx['GroupOwners.ownerMigration']
    if ($a.removePermanent) {
        $b = Get-PimGroupOwnerMigrationBudget -Ctx $Ctx
        if (-not $b.allowed) { return [pscustomobject]@{ pimApplied = $false; reason = "owner migration held by the removal budget: $($b.reason)" } }
    }
    $wrote = $false
    if ($a.createEligible) {
        try { [void](Invoke-PimGroupOwnerEligibleCreate -GroupId $gid -OwnerId $oid -Days $days); $wrote = $true }
        catch { if ("$($_.Exception.Message)" -notmatch '(?i)already exist|RoleAssignmentExists|existing assignment') { throw } }
    } elseif ($a.maintain) {
        $mrow = New-PimGroupOwnerMaintenanceRow -Desired $d -Days $days
        $r = Invoke-PimAssignmentMaintenanceApply -Kind GroupMember -Item ([pscustomobject]@{ key = "$($Item.key)|owner-eligible"; desired = $mrow; live = $l.eligible }) -NowUtc $NowUtc
        $notApplied = $false; foreach ($o in @($r)) { if ($o -and $o.PSObject.Properties['pimApplied'] -and -not $o.pimApplied) { $notApplied = $true } }
        if (-not $notApplied) { $wrote = $true }
    }
    if ($a.removePermanent) {
        if (-not (Test-PimGroupOwnerEligibilityLive -GroupId $gid -OwnerId $oid -GroupName "$($d.GroupName)")) {
            if ($plan) { $plan.kept = 1 + [int]$plan.kept }
            Add-PimGroupOwnerScopeWarning -Ctx $Ctx -Message ("'{0}' -> {1}: the eligible owner could not be read back yet -- the permanent owner is KEPT; a later run completes the move. [GROUP-OWNER-READBACK-PENDING]" -f $d.GroupName, $oid)
            if ($wrote) { return [pscustomobject]@{ ownerMigration = 'eligible-created-permanent-kept' } }
            return [pscustomobject]@{ pimApplied = $false; reason = 'the eligible owner is not readable yet -- the permanent owner is kept' }
        }
        try {
            Invoke-PimGraph -Method DELETE -Path "/groups/$gid/owners/$oid/`$ref" | Out-Null
            $wrote = $true
            if ($plan) { $plan.moved = 1 + [int]$plan.moved }
            Write-Host ("    [~] {0}: permanent owner {1} moved to an eligible owner" -f $d.GroupName, $oid) -ForegroundColor Green
        } catch {
            $m = "$($_.Exception.Message)"
            if ($_.ErrorDetails -and "$($_.ErrorDetails.Message)".Trim()) { $m = "$m $($_.ErrorDetails.Message)" }
            if (Test-PimGroupLastOwnerRefusal $m) {
                if ($plan) { $plan.kept = 1 + [int]$plan.kept }
                Add-PimGroupOwnerScopeWarning -Ctx $Ctx -Message ("'{0}' -> {1}: Microsoft Entra refuses to remove the group's last owner -- the permanent owner is KEPT (the eligible owner is in place). Add another owner, or keep this one. [GROUP-OWNER-LAST-OWNER-KEPT]" -f $d.GroupName, $oid)
            } elseif ((Get-Command Test-PimAssignmentAbsentError -ErrorAction SilentlyContinue) -and (Test-PimAssignmentAbsentError $m)) {
                $wrote = $true; if ($plan) { $plan.moved = 1 + [int]$plan.moved }
            } else { throw }
        }
    }
    Reset-PimAssignmentLiveCaches -GroupId $gid
    if ($wrote) { return [pscustomobject]@{ ownerMigration = 'applied' } }
    return [pscustomobject]@{ pimApplied = $false; reason = 'nothing was written' }
}
