#Requires -Version 5.1
<#
.SYNOPSIS
  PIM 100.72 (7) / framework DOCS/REQUIREMENTS.md 12.21: BLOCK (+ APPROVE) any change that would remove the LAST Global
  Administrator of the tenant, or the LAST PIM Manager SuperAdmin. Damage that does not heal: nobody could undo it.

.DESCRIPTION
  GLOBAL ADMINISTRATOR (guard 'engine.last-global-admin', engine, releasable like the other engine guards)
    Who holds Global Administrator now (Get-PimGlobalAdminHolders, REST only): every ENABLED USER with an active or eligible
    Global Administrator assignment at the directory scope -- directly, or through a group that holds it (its members and its
    PIM-for-Groups eligible members). Service principals are not counted: they cannot sign in to repair a tenant.
    What a run would take away (Get-PimLastGlobalAdminDecision, PURE):
      EntraRoles / EntraRolesDirect  a removal of a Global Administrator assignment = that PATH (group or user) is gone
      AdminMembers                   a removal of a user from a group = that user's path through that group is gone
      Admins (row-driven disables)   a disable (or delete) = that user is gone
    When the tenant has at least one holder now and would have NONE after the run, the GA-relevant items are HELD (the rest
    of the run goes ahead): guard trip (refused, critical), the hold on the Guards page, and a SuperAdmin may release EXACTLY
    that plan for one run (second person when GuardReleaseSecondPerson is on). FAIL CLOSED: when the holders cannot be read,
    every item that could matter is held this run (it heals: the next run reads again).
  PIM MANAGER SUPERADMIN (guard 'manager.last-superadmin', the Manager's role map)
    Test-PimLastSuperAdminRemoval (PURE): a role map that ends with no SuperAdmin is refused -- never releasable (with no
    SuperAdmin left nobody could release it, approve it or undo it). Add another SuperAdmin first.
  ASCII only (PS 5.1 reads a file without a BOM as CP1252).
#>

Set-StrictMode -Off

$script:PimGlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
$script:PimLastGaGuardId     = 'engine.last-global-admin'
$script:PimLastGaScopes      = @('EntraRoles', 'EntraRolesDirect', 'AdminMembers')

function Test-PimIsGlobalAdminRole {
    <# PURE. Does a live role item name the Global Administrator role (by template id, a definition path ending in it, or its name)? #>
    param([AllowNull()][object]$Live)
    if ($null -eq $Live) { return $false }
    $rid = ''
    foreach ($n in 'roleDefinitionId', 'RoleDefinitionId', 'roleTemplateId') { if ($Live.PSObject.Properties[$n] -and "$($Live.$n)".Trim()) { $rid = "$($Live.$n)".Trim(); break } }
    if ($rid -and ($rid.TrimEnd('/') -split '/')[-1].ToLowerInvariant() -eq $script:PimGlobalAdminRoleId) { return $true }
    foreach ($n in 'RoleDefinitionName', 'roleDefinitionName', 'RoleName') { if ($Live.PSObject.Properties[$n] -and "$($Live.$n)".Trim() -ieq 'Global Administrator') { return $true } }
    return $false
}

function Get-PimLastGlobalAdminDecision {
    <#
      PURE. -Holders: @( @{ userId; upn; paths = @(<principal id the role is held through: the user itself or a group>) } ).
      -RemovePaths: principal ids whose Global Administrator assignment goes; -RemoveMemberships: @( @{ userId; pathId } );
      -RemoveUsers: user ids disabled / deleted. Returns @{ block; before; after; losing (upn); remaining (upn); reason }.
      block = there is at least one holder now and none after.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Holders = @(), [AllowNull()][AllowEmptyCollection()][string[]]$RemovePaths = @(),
          [AllowNull()][AllowEmptyCollection()][object[]]$RemoveMemberships = @(), [AllowNull()][AllowEmptyCollection()][string[]]$RemoveUsers = @())
    $rp = @{}; foreach ($p in @($RemovePaths)) { if ("$p".Trim()) { $rp["$p".Trim().ToLowerInvariant()] = $true } }
    $ru = @{}; foreach ($u in @($RemoveUsers)) { if ("$u".Trim()) { $ru["$u".Trim().ToLowerInvariant()] = $true } }
    $rm = @{}; foreach ($m in @($RemoveMemberships)) { if ($m -and "$($m.userId)".Trim() -and "$($m.pathId)".Trim()) { $rm[("{0}|{1}" -f "$($m.userId)".Trim(), "$($m.pathId)".Trim()).ToLowerInvariant()] = $true } }
    $before = 0; $remaining = New-Object System.Collections.Generic.List[string]; $losing = New-Object System.Collections.Generic.List[string]
    foreach ($h in @($Holders)) {
        if ($null -eq $h) { continue }
        $uid = "$($h.userId)".Trim().ToLowerInvariant(); if (-not $uid) { continue }
        $paths = @(@($h.paths) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Select-Object -Unique)
        if (-not $paths.Count) { continue }
        $before++
        $name = if ("$($h.upn)".Trim()) { "$($h.upn)".Trim() } else { $uid }
        if ($ru.ContainsKey($uid)) { $losing.Add($name); continue }
        $left = @($paths | Where-Object { -not $rp.ContainsKey($_) -and -not $rm.ContainsKey("$uid|$_") })
        if ($left.Count) { $remaining.Add($name) } else { $losing.Add($name) }
    }
    $block = ($before -gt 0 -and $remaining.Count -eq 0)
    $reason = if ($block) { "this run would remove the LAST Global Administrator ($before now, 0 after: $(@($losing) -join ', '))" }
              elseif ($before -eq 0) { 'no Global Administrator is known to PIM in this tenant -- nothing to protect' }
              else { "$($remaining.Count) Global Administrator(s) remain after this run" }
    return [pscustomobject]@{ block = $block; before = $before; after = $remaining.Count; losing = @($losing.ToArray()); remaining = @($remaining.ToArray()); reason = $reason }
}

function Get-PimGlobalAdminHolders {
    <#
      Who holds Global Administrator now: @{ ok; holders = @( @{ userId; upn; paths } ); error }. NEVER throws (ok = $false +
      error). -Get { param($Path) } returns a collection's items (an array) or a single object; default Invoke-PimGraph.
    #>
    param([scriptblock]$Get = $null)
    if (-not $Get) {
        $Get = { param($p)
            if ($p -match '^/(directoryObjects|users)/[^/?]+(\?|$)') { Invoke-PimGraph -Path $p } else { @(Invoke-PimGraph -All -Path $p) } }
    }
    $ga = $script:PimGlobalAdminRoleId
    try {
        $f = [uri]::EscapeDataString("roleDefinitionId eq '$ga'")
        $princ = @{}
        foreach ($src in @("/roleManagement/directory/roleAssignments?`$filter=$f", "/roleManagement/directory/roleEligibilitySchedules?`$filter=$f")) {
            foreach ($a in @(& $Get $src)) {
                if ($null -eq $a) { continue }
                $ds = "$($a.directoryScopeId)".Trim(); if ($ds -and $ds -ne '/') { continue }
                $pid0 = "$($a.principalId)".Trim(); if ($pid0) { $princ[$pid0.ToLowerInvariant()] = $pid0 }
            }
        }
        $users = @{}   # userId(lower) -> @{ userId; upn; enabled; paths(List) }
        $addUser = { param($u, $path)
            if ($null -eq $u) { return }
            $id = "$($u.id)".Trim(); if (-not $id) { return }
            $k = $id.ToLowerInvariant()
            if (-not $users.ContainsKey($k)) { $users[$k] = @{ userId = $id; upn = "$($u.userPrincipalName)"; enabled = $(if ($u.PSObject.Properties['accountEnabled']) { [bool]$u.accountEnabled } else { $true }); paths = (New-Object System.Collections.Generic.List[string]) } }
            if (-not $users[$k].paths.Contains($path)) { $users[$k].paths.Add($path) }
        }
        $sel = '$select=id,userPrincipalName,accountEnabled'
        foreach ($pk in @($princ.Keys)) {
            $p = $princ[$pk]
            $obj = & $Get "/directoryObjects/$p"
            $t = "$($obj.'@odata.type')".ToLowerInvariant()
            if ($t -match 'user$') {
                $u = & $Get "/users/$p`?$sel"
                & $addUser $u $p
            } elseif ($t -match 'group$') {
                foreach ($m in @(& $Get "/groups/$p/members/microsoft.graph.user?$sel")) { & $addUser $m $p }
                $ef = [uri]::EscapeDataString("groupId eq '$p' and accessId eq 'member'")
                foreach ($e in @(& $Get "/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=$ef")) {
                    $eid = "$($e.principalId)".Trim(); if (-not $eid) { continue }
                    $eu = $null; try { $eu = & $Get "/users/$eid`?$sel" } catch { $eu = $null }   # a group / service principal is not a person
                    if ($eu -and "$($eu.id)") { & $addUser $eu $p }
                }
            }
            # service principals (and anything else) are not people who can repair a tenant -- not counted
        }
        $hold = @($users.Values | Where-Object { $_.enabled } | ForEach-Object { [pscustomobject]@{ userId = $_.userId; upn = $_.upn; paths = @($_.paths.ToArray()) } })
        return [pscustomobject]@{ ok = $true; holders = $hold; error = '' }
    } catch {
        return [pscustomobject]@{ ok = $false; holders = @(); error = "$($_.Exception.Message)" }
    }
}

function Get-PimLastGaCandidates {
    <#
      PURE. The items of one scope's removals that could take Global Administrator away, and what each removes:
      @( @{ key; kind = path|membership|user; userId; pathId } ). -Remove: the engine's remove items ({ key; live });
      -DisableUsers: @( @{ key; userId } ) (the Admins disables).
    #>
    param([string]$Scope = '', [AllowNull()][AllowEmptyCollection()][object[]]$Remove = @(), [AllowNull()][AllowEmptyCollection()][object[]]$DisableUsers = @())
    $out = New-Object System.Collections.Generic.List[object]
    $sc = "$Scope".Trim()
    foreach ($i in @($Remove)) {
        if ($null -eq $i) { continue }
        $l = if ($i.PSObject.Properties['live'] -and $i.live) { $i.live } else { $null }
        if ($null -eq $l) { continue }
        if ($sc -in @('EntraRoles', 'EntraRolesDirect')) {
            if ((Test-PimIsGlobalAdminRole -Live $l) -and "$($l.principalId)".Trim()) { $out.Add([pscustomobject]@{ key = "$($i.key)"; kind = 'path'; userId = ''; pathId = "$($l.principalId)".Trim() }) }
        } elseif ($sc -eq 'AdminMembers') {
            if ("$($l.principalId)".Trim() -and "$($l.groupId)".Trim()) { $out.Add([pscustomobject]@{ key = "$($i.key)"; kind = 'membership'; userId = "$($l.principalId)".Trim(); pathId = "$($l.groupId)".Trim() }) }
        }
    }
    foreach ($d in @($DisableUsers)) { if ($d -and "$($d.userId)".Trim()) { $out.Add([pscustomobject]@{ key = "$($d.key)"; kind = 'user'; userId = "$($d.userId)".Trim(); pathId = '' }) } }
    return @($out.ToArray())
}

function Invoke-PimLastGlobalAdminGuard {
    <#
      Engine. One scope's removals (or the Admins disables) against the Global Administrators that hold the role now.
      Returns @{ checked; blocked; heldKeys (lower-case item keys held this run); released; reason }. NEVER throws: an error
      here holds every candidate (fail closed). -WhatIf (a plan) holds the same items but records no hold / trip / release.
      Seams: -GetHolders { } -> Get-PimGlobalAdminHolders shape; -HoldOrRelease { param($a) } -> @{ released; release; planHash };
      -Trip { param($a) }.
    #>
    param([Parameter(Mandatory)][string]$Scope, [AllowNull()][AllowEmptyCollection()][object[]]$Remove = @(), [AllowNull()][AllowEmptyCollection()][object[]]$DisableUsers = @(),
          [string]$RunKind = '', [switch]$WhatIf, [bool]$CanRelease = $true,
          [scriptblock]$GetHolders = $null, [scriptblock]$HoldOrRelease = $null, [scriptblock]$Trip = $null)
    $res = [pscustomobject]@{ checked = $false; blocked = $false; heldKeys = @(); released = $false; reason = ''; used = $null }
    $cand = @()
    try { $cand = @(Get-PimLastGaCandidates -Scope $Scope -Remove $Remove -DisableUsers $DisableUsers) } catch { $cand = @() }
    if (-not $cand.Count) { return $res }
    $res.checked = $true
    if (-not $GetHolders) { $GetHolders = { Get-PimGlobalAdminHolders } }
    if (-not $HoldOrRelease) { $HoldOrRelease = { param($a) if (Get-Command Invoke-PimGuardHoldOrRelease -ErrorAction SilentlyContinue) { Invoke-PimGuardHoldOrRelease @a } else { [pscustomobject]@{ released = $false; release = $null; planHash = '' } } } }
    if (-not $Trip) { $Trip = { param($a) if (Get-Command Invoke-PimGuardTrip -ErrorAction SilentlyContinue) { [void](Invoke-PimGuardTrip @a) } } }
    $held = @(); $reason = ''; $losing = @()
    try {
        $h = & $GetHolders
        if (-not $h -or -not $h.ok) {
            $held = @($cand); $reason = "the Global Administrators could not be read ($(if ($h) { $h.error } else { 'no answer' })) -- every item that could remove one is held this run (fail closed)"
        } else {
            $dec = Get-PimLastGlobalAdminDecision -Holders @($h.holders) `
                    -RemovePaths @($cand | Where-Object { $_.kind -eq 'path' } | ForEach-Object { $_.pathId }) `
                    -RemoveMemberships @($cand | Where-Object { $_.kind -eq 'membership' } | ForEach-Object { @{ userId = $_.userId; pathId = $_.pathId } }) `
                    -RemoveUsers @($cand | Where-Object { $_.kind -eq 'user' } | ForEach-Object { $_.userId })
            if (-not $dec.block) {
                if (-not $WhatIf -and $CanRelease -and (Get-Command Clear-PimGuardHold -ErrorAction SilentlyContinue)) { [void](Clear-PimGuardHold -GuardId $script:PimLastGaGuardId -Scope $Scope -RunKind $RunKind) }
                $res.reason = $dec.reason; return $res
            }
            # Hold only what touches a holder: a GA path / a holder's membership in a GA path / a holder's account.
            $hp = @{}; $hu = @{}
            foreach ($x in @($h.holders)) { $hu["$($x.userId)".ToLowerInvariant()] = $true; foreach ($p in @($x.paths)) { $hp["$p".ToLowerInvariant()] = $true } }
            $held = @($cand | Where-Object {
                ($_.kind -eq 'path' -and $hp.ContainsKey("$($_.pathId)".ToLowerInvariant())) -or
                ($_.kind -eq 'membership' -and $hu.ContainsKey("$($_.userId)".ToLowerInvariant()) -and $hp.ContainsKey("$($_.pathId)".ToLowerInvariant())) -or
                ($_.kind -eq 'user' -and $hu.ContainsKey("$($_.userId)".ToLowerInvariant())) })
            if (-not $held.Count) { $held = @($cand) }
            $reason = $dec.reason; $losing = @($dec.losing)
        }
    } catch { $held = @($cand); $reason = "the last-Global-Administrator check failed ($($_.Exception.Message)) -- held this run (fail closed)" }
    $keys = @($held | ForEach-Object { "$($_.key)".Trim().ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $WhatIf -and $CanRelease) {
        $g = $null
        try { $g = & $HoldOrRelease @{ GuardId = $script:PimLastGaGuardId; Scope = $Scope; Keys = @($keys); Count = $keys.Count; RunKind = $RunKind; Measured = @{ held = $keys.Count; losing = @($losing).Count } } } catch { $g = $null }
        if ($g -and $g.released) {
            $res.released = $true; $res.reason = "RELEASED for this run by $($g.release.createdBy): $reason"
            $res.used = [pscustomobject]@{ guardId = $script:PimLastGaGuardId; releaseId = "$($g.release.id)"; planHash = "$($g.planHash)" }
            try { Write-Host ("[engine] {0,-20} last Global Administrator guard RELEASED for this run (plan {1})" -f $Scope, "$($g.planHash)".Substring(0, [Math]::Min(12, "$($g.planHash)".Length))) -ForegroundColor Magenta } catch { }
            return $res
        }
        try {
            & $Trip @{ GuardId = $script:PimLastGaGuardId; Outcome = 'refused'; Area = $Scope; Job = 'engine'; HeldCount = $keys.Count
                Title = ("{0}: {1} change(s) held -- they would remove the last Global Administrator" -f $Scope, $keys.Count)
                Detail = ("{0}. Held: {1}. The rest of the run went ahead." -f $reason, (@($keys | Select-Object -First 10) -join ', '))
                ActionText = 'Make sure another person holds Global Administrator first (an emergency account is best). If this is really intended, a SuperAdmin can release exactly this plan for one run on Operations > Guards.'
                Measured = @{ held = $keys.Count; losing = @($losing).Count } }
        } catch { }
    }
    try { Write-Host ("[engine] {0,-20} LAST GLOBAL ADMINISTRATOR guard: {1} item(s) HELD -- {2}" -f $Scope, $keys.Count, $reason) -ForegroundColor Red } catch { }
    $res.blocked = $true; $res.heldKeys = @($keys); $res.reason = $reason
    return $res
}

function Test-PimLastSuperAdminRemoval {
    <#
      PURE. Would this PIM Manager role map leave NO SuperAdmin? -Before / -After: the map ({ managerAccess = [ {identity; role} ] }
      or the bare list). @{ block; before; after; removed (identities); reason }. A map that ends empty is refused too (almost
      always a failed read upstream). Never releasable: with no SuperAdmin nobody could undo it.
    #>
    param([AllowNull()][object]$Before, [AllowNull()][object]$After)
    $list = { param($v)
        if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { $v = $null } }
        if ($v -and -not ($v -is [array]) -and $v.PSObject.Properties['managerAccess']) { $v = $v.managerAccess }
        @(@($v) | Where-Object { $_ -and "$($_.role)".Trim() -eq 'SuperAdmin' -and "$($_.identity)".Trim() } | ForEach-Object { "$($_.identity)".Trim().ToLowerInvariant() } | Select-Object -Unique) }
    $b = @(& $list $Before); $a = @(& $list $After)
    $removed = @($b | Where-Object { $a -notcontains $_ })
    $block = ($a.Count -eq 0)
    [pscustomobject]@{ block = $block; before = $b.Count; after = $a.Count; removed = @($removed)
        reason = $(if ($block) { 'At least one SuperAdmin is required -- saving this map would remove the last PIM Manager SuperAdmin and lock everyone out. Add another SuperAdmin first.' } else { '' }) }
}
