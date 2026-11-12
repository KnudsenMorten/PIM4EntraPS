<#
  Entra Access Package support -- the ENGINE half (docs/REQUIREMENTS.md "Entra Access Package support", owner 2026-11-09).

  THE MODEL. The access package decides WHO GETS ONTO a delegation; PIM decides HOW IT IS USED (activation, unchanged).
  A package grants ELIGIBLE MEMBERSHIP of one or more DIRECT groups -- never of a permission group, never a role.

  🔒 OWNER 2026-11-12 (supersedes the '-AP rename' plan): "we dont rename anything existing. we add new groups locked for access packages.
  we dont touch existing groups. if in doubt then pause access package." + "-ap group ends with as agreed". A package only delivers groups
  CREATED FOR IT (definition column AccessPackage = the package, GroupName ending '-AP'); they are LOCKED to it (Split-PimAccessPackageOwnedMembers,
  Test-PimAccessPackageGroupStillPackaged, the Manager's adopt / drift-delete refusals, the validator's PIM-AP-* rules); any doubt PAUSES the
  package (no write, reason in pim.Settings 'AccessPackageStatus'). Nothing here ever renames a group or binds an existing one.

  ON BY DEFAULT, ACTS ONLY WHEN DEFINED. Setting AccessPackagesEnabled (default on) can stop the provider. With no 'AccessPackage'
  row and no binding the feature is inert: no Graph call of any kind, no right asked for, member reconciliation unchanged.

  GROUP OWNERSHIP IS A DURABLE BINDING, ONE pim.Settings RECORD (AccessPackageBindings), KEYED BY GROUP ID, NOT DERIVED EACH RUN.
    * written only after the provider READ BACK a package in PIM's own catalog with an eligible member scope on that group AND its policy,
      and only for direct groups a valid definition names;
    * ended only when that package's retirement (or that group's removal from it) was read back, or a complete read-back confirmed the package is gone;
    * a group is set aside if and only if it has a binding AND the feature is on. Not the licence, not a parsable row. Handing a group back is by
      retiring the package, by the package being confirmed gone, or (owner 2026-11-10 "off hands members back") by switching the feature
      OFF: then every bound group is the engine's again, the bindings record kept untouched for when it is switched on.
    * WHEN A BINDING ENDS the group enters the RELEASED state (the same record): the engine's CREATES for it stay suppressed and reported, so a retirement
      never quietly re-grants access from old rows. It ends when no row names the group any more, or by an Action=ReturnToEngine row.
    * the record ALSO holds what this install created (catalog id, package ids) and the intent recorded BEFORE a create, so a crash between the create
      and the save is adopted by exactly that object. Only those are adopted; a name match is not ownership.
    * saved with compare-and-swap; never restored from a configuration backup.
    * a binding record that cannot be read: the member scope applies nothing. Corrupt, unconfigured or any other non-connection failure, or bindings known to THIS process: NOT CHECKED and
      not ok. A connection-class read failure with no binding known to this process (a fresh process knows none, so this also covers an install whose first read fails with bindings
      present): the pass is skipped with a warning, nothing is applied and the job stays green. A connection failure that never ends also fails the engine's own store reads, so it is
      not silent (Split-PimAccessPackageOwnedMembers -> Invoke-PimEngineScope).

  THE ONLY PLACE THE ENGINE STOPS RECONCILING A GROUP'S MEMBERS is Split-PimAccessPackageOwnedMembers, called from one block in
  Invoke-PimEngineScope. Roles and settings are other scopes: not touched.

  A REMOVAL REALLY ENDS PEOPLE'S ACCESS, so it is planned per person (Expand-PimAccessPackageRemovals, the provider's ExpandRemovals
  hook, before the removal budget, the guards and the per-item audit). The last Global Administrator guard only sees people who hold the role through
  a path it can read (it does not follow every nested group), so it is NOT relied on here: a retire or group drop on a package whose group is on a chain
  reaching Global Administrator is ALWAYS held for release (Select-PimAccessPackageHeldRemovals). Removing a group from a package is all-or-nothing.

  FOLLOWS: New-PimAdminMembersProvider / New-PimGroupMembersProvider (GetDesired / GetLive / Apply*, Action=Remove through GetRemoveRows),
  Split-PimDuplicateNameItems + $__dupHeld (held items as failure items), the pimApplied = $false convention, Get-PimFeatureSetting.

  REST ONLY (Invoke-PimGraph): no PowerShell module, no az. Windows PowerShell 5.1 and pwsh 7.
  NOT VERIFIED LIVE (no tenant holds the licence yet): every Graph shape in this file comes from learn.microsoft.com, read 2026-11-09;
  none has been sent to a tenant. The riskiest one is isolated in Select-PimAccessPackageEligibleRole.
#>

Set-StrictMode -Off

function Get-PimAccessPackageEntityName { return 'AccessPackage' }
function Get-PimAccessPackageCatalogName { return 'PIM Manager' }
function Get-PimAccessPackagePolicyName { return 'PIM Manager policy' }
function Get-PimAccessPackageRightName { return 'EntitlementManagement.ReadWrite.All' }
function Get-PimAccessPackageBindingSetting { return 'AccessPackageBindings' }
function Get-PimEntitlementManagementPath { return '/identityGovernance/entitlementManagement' }

# ---- the switch and the definition rows ----------------------------------------------------------------------------------
function Test-PimAccessPackagesEnabled {
    <# The switch. On by default (it still acts only when something is defined); a reader that cannot answer = off. Stops the provider only. #>
    if (-not (Get-Command Get-PimFeatureSetting -ErrorAction SilentlyContinue)) { return $false }
    try { return [bool](Get-PimFeatureSetting -Name 'AccessPackagesEnabled') } catch { return $false }
}

function Get-PimAccessPackageRows {
    <# The 'AccessPackage' rows of pim.Rows. A failed read is reported and treated as none: nothing is built, bindings stand. #>
    if (-not (Get-Command Get-PimDesiredRowsFromStore -ErrorAction SilentlyContinue)) { return @() }
    $entity = Get-PimAccessPackageEntityName
    $rows = @(Get-PimDesiredRowsFromStore -Entity $entity -AbsentIsResolved | Where-Object { $null -ne $_ })
    if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey($entity) -and -not $global:PIM_DesiredResolved[$entity]) {
        Write-Warning '  [AccessPackages] the access package definitions could not be read -- nothing is built this run; every existing binding stands.'
    }
    return $rows
}

function Get-PimAccessPackageRightDemand {
    <#
      PURE. THE ONE PLACE THAT SAYS WHETHER THE RIGHT IS ASKED FOR (framework RIGHTS-1.7: no right until enabled). 0 definitions = nothing,
      so updating can never add it. Same shape as a Get-PimRequiredGraphCapabilities row, tier optional.
    #>
    param([int]$DefinedCount = 0)
    if ($DefinedCount -le 0) { return @() }
    return @(@{ role = (Get-PimAccessPackageRightName); capability = 'Access packages (only because at least one is defined)'; tier = 'optional'; connector = 'access-packages' })
}

# ---- the durable binding record --------------------------------------------------------------------------------------------
function New-PimAccessPackageBindingRecord {
    <#
      PURE. An empty record. catalogId / packages = what this install created; bindings = groupId (lower) -> @{ groupId; tag; packages[] }, keyed by id, the tag is
      for reports only; released = groupId (lower) -> @{ groupId; tag; reason; releasedUtc }; intent = the create about to be made (@{ kind; name; atUtc });
      returnsConsumed = Action=ReturnToEngine rows already acted on (row name -> utc): a row applies once, never to a later binding; goneSeen = the first read that found a
      package or a group's scope missing (key -> utc): the second read 10 minutes later is what ends a binding.
    #>
    return @{ catalogId = ''; packages = @{}; bindings = @{}; released = @{}; intent = $null; returnsConsumed = @{}; goneSeen = @{} }
}

function ConvertFrom-PimAccessPackageBindingJson {
    <# PURE. The stored JSON -> the record. Blank = an empty record; anything else that is not a record THROWS a specific error (a corrupt record is never read as "no bindings"). #>
    param([AllowNull()][string]$Json)
    $rec = New-PimAccessPackageBindingRecord
    if ($null -eq $Json -or "$Json".Trim() -eq '') { return $rec }
    $o = $null
    try { $o = "$Json" | ConvertFrom-Json } catch { throw "CORRUPT: pim.Settings 'AccessPackageBindings' is not valid JSON ($($_.Exception.Message))" }
    if ($null -eq $o -or -not (@($o.PSObject.Properties | ForEach-Object { $_.Name }) -contains 'bindings')) { throw "CORRUPT: pim.Settings 'AccessPackageBindings' has no 'bindings' field, so it is not a binding record; repair or remove that row" }
    $rec.catalogId = "$($o.catalogId)"
    if ($o.packages) { foreach ($p in $o.packages.PSObject.Properties) { $rec.packages["$($p.Name)".ToLowerInvariant()] = @{ id = "$($p.Value.id)"; name = "$($p.Value.name)" } } }
    if ($o.bindings) {
        foreach ($b in $o.bindings.PSObject.Properties) {
            $rec.bindings["$($b.Name)".ToLowerInvariant()] = @{ groupId = "$($b.Value.groupId)"; tag = "$($b.Value.tag)"; packages = @(@($b.Value.packages) | ForEach-Object { "$_" } | Where-Object { $_ }); boundUtc = "$($b.Value.boundUtc)" }
        }
    }
    if ($o.released) { foreach ($b in $o.released.PSObject.Properties) { $rec.released["$($b.Name)".ToLowerInvariant()] = @{ groupId = "$($b.Value.groupId)"; tag = "$($b.Value.tag)"; reason = "$($b.Value.reason)"; releasedUtc = "$($b.Value.releasedUtc)" } } }
    if ($o.intent -and "$($o.intent.name)".Trim()) { $rec.intent = @{ kind = "$($o.intent.kind)"; name = "$($o.intent.name)"; atUtc = "$($o.intent.atUtc)" } }
    if ($o.returnsConsumed) { foreach ($b in $o.returnsConsumed.PSObject.Properties) { $rec.returnsConsumed["$($b.Name)".ToLowerInvariant()] = "$($b.Value)" } }
    if ($o.goneSeen) { foreach ($b in $o.goneSeen.PSObject.Properties) { $rec.goneSeen["$($b.Name)".ToLowerInvariant()] = "$($b.Value)" } }
    return $rec
}

function Get-PimAccessPackageStoreConnection {
    <#
      The SQL store's connection string. '' ONLY when this process has no store configured at all (an offline run: no store, no binding can exist). A store that is
      configured but whose connection string cannot be resolved THROWS: a connection failure is never read as "no bindings". Every engine host sets one of these signals
      (Invoke-PimEngineCore, the scheduler and the job entries: $global:PIM_EngineSqlCs, PIM_SqlConnectionString, or PIM_SqlServer / PIM_SqlDatabase / PIM_SqlConnStringVault, or the same in the process environment).
    #>
    if ("$($global:PIM_EngineSqlCs)".Trim()) { return "$($global:PIM_EngineSqlCs)" }
    if ("$($global:PIM_SqlConnectionString)".Trim()) { return "$($global:PIM_SqlConnectionString)" }
    $configured = "$($global:PIM_SqlServer)$($global:PIM_SqlConnStringVault)$($global:PIM_SqlDatabase)$($env:PIM_SqlServer)$($env:PIM_SqlConnectionString)".Trim()
    if (-not $configured) { return '' }
    if (-not (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue)) { throw 'CONFIG: a SQL store is configured but its connection code is not loaded in this process' }
    $cs = "$(Get-PimSqlConnectionString)"
    if (-not $cs.Trim()) { throw 'CONFIG: a SQL store is configured but no connection string could be resolved' }
    return $cs
}

function Get-PimAccessPackageBindingRecord {
    <#
      The record: @{ ok; record; error; corrupt; raw }. ok = $false means it could NOT be read (a missing row is ok + empty); corrupt = it was read and is not a record.
      raw = the stored text, for the compare-and-swap. Test seam: $global:PIM_AccessPackageBindingStore = @{ json = '...'; failRead; failWrite; failCas }.
    #>
    $bad = { param($m, $c) [pscustomobject]@{ ok = $false; record = $null; error = "$m"; corrupt = [bool]$c; raw = $null } }
    $seam = $global:PIM_AccessPackageBindingStore
    $raw = $null
    try {
        if ($seam -is [hashtable]) {
            if ($seam['failRead']) { throw 'the store is unreachable (test seam)' }
            $raw = $seam['json']
        } else {
            $cs = Get-PimAccessPackageStoreConnection
            if (-not $cs) { return [pscustomobject]@{ ok = $true; record = (New-PimAccessPackageBindingRecord); error = ''; corrupt = $false; raw = $null } }
            if (-not (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue)) { throw 'CONFIG: a SQL store is configured but its settings reader is not loaded in this process' }
            $raw = Get-PimSqlSettingRaw -ConnectionString $cs -Name (Get-PimAccessPackageBindingSetting)
        }
    } catch {
        # Only a connection-class failure can be transient; anything else (not configured, a setting nobody may read) is a real failure, so a skip can never hide it.
        $msg = "$($_.Exception.Message)"
        $hard = (($msg -match '(?i)^CONFIG:|not configured') -or ($msg -notmatch '(?i)timeout|timed out|network|transport|unreachable|connection|could not open|deadlock'))
        return (& $bad $msg $hard)
    }
    try {
        $rec = ConvertFrom-PimAccessPackageBindingJson -Json $raw
        $script:PimAccessPackageBindingsKnown = [int]($rec.bindings.Count + $rec.released.Count)
        return [pscustomobject]@{ ok = $true; record = $rec; error = ''; corrupt = $false; raw = $raw }
    } catch { return (& $bad "$($_.Exception.Message)" $true) }
}

function Save-PimAccessPackageBindingState {
    <#
      Writes the record with COMPARE-AND-SWAP against what -State read, so two runs cannot lose each other's bindings. THROWS on any failure (a caller never believes an
      unsaved binding) and when another run changed it first. -State is updated, so a flow can save more than once.
    #>
    param([Parameter(Mandatory)][object]$State)
    $json = ConvertTo-Json -InputObject $State.record -Depth 8 -Compress
    $seam = $global:PIM_AccessPackageBindingStore
    if ($seam -is [hashtable]) {
        if ($seam['failWrite']) { throw 'the store refused the write (test seam)' }
        if ($seam['failCas'] -or "$($seam['json'])" -cne "$($State.raw)") { throw 'CAS: the binding record was changed by another run; nothing was saved, the next run retries' }
        $seam['json'] = $json; $State.raw = $json; return
    }
    $cs = Get-PimAccessPackageStoreConnection
    if (-not $cs) { throw 'no SQL store to record the binding in' }
    $won = Set-PimSqlSettingIfUnchanged -ConnectionString $cs -Name (Get-PimAccessPackageBindingSetting) -NewValueJson $json -ExpectedValueJson "$($State.raw)"
    if ([int]$won -lt 1) { throw 'CAS: the binding record was changed by another run; nothing was saved, the next run retries' }
    $State.raw = $json
}

function Add-PimAccessPackageBindingEntry {
    <# PURE. Adds group -> package to a record (a released group becomes bound). Returns $true when the record changed. #>
    param([Parameter(Mandatory)][hashtable]$Record, [Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$Tag, [Parameter(Mandatory)][string]$PackageId)
    $k = $GroupId.ToLowerInvariant()
    $changed = $false
    if ($Record.released.ContainsKey($k)) { $Record.released.Remove($k); $changed = $true }
    $e = $Record.bindings[$k]
    if (-not $e) { $Record.bindings[$k] = @{ groupId = $GroupId; tag = $Tag; packages = @($PackageId); boundUtc = (Get-Date).ToUniversalTime().ToString('o') }; return $true }
    if (@($e.packages) -contains $PackageId) { return $changed }
    $e.packages = @(@($e.packages) + $PackageId); return $true
}

function Remove-PimAccessPackageBindingEntry {
    <# PURE. Takes one package off a group (or off every group). A group with no package left moves to RELEASED (its rows need review). Returns $true when it changed. #>
    param([Parameter(Mandatory)][hashtable]$Record, [Parameter(Mandatory)][string]$PackageId, [string]$GroupId = '', [string]$Reason = 'the package was retired')
    $changed = $false
    foreach ($k in @($Record.bindings.Keys)) {
        if ($GroupId -and $k -ne $GroupId.ToLowerInvariant()) { continue }
        $e = $Record.bindings[$k]
        if (@($e.packages) -contains $PackageId) {
            $e.packages = @(@($e.packages) | Where-Object { $_ -ne $PackageId }); $changed = $true
            if (-not @($e.packages).Count) {
                $Record.released[$k] = @{ groupId = "$($e.groupId)"; tag = "$($e.tag)"; reason = $Reason; releasedUtc = (Get-Date).ToUniversalTime().ToString('o') }
                $Record.bindings.Remove($k)
            }
        }
    }
    return $changed
}

function Split-PimAccessPackageOwnedMembers {
    <#
      THE MEMBER-RECONCILIATION GUARD. A group gets members only from the package when, and only when, it has a binding (by group id). A RELEASED group keeps its members and
      Remove rows handled normally, but a row that would CREATE a member is suppressed and reported until the row is gone or the group is explicitly returned (-KeyOf: to tell a create).
      AdminMembers and GroupMembers only. The CONTAINER is the group the membership is IN: GroupTag, or SourceGroupTag for a nesting (a package-bound direct group that is a
      MEMBER of a permission group keeps that nesting). A live item is matched by its group id, a row through the id its tag resolves to, so a tag rename cannot split them.
      failed = $true: nothing is to be applied. soft = $true: a transient read failure with no binding known, the pass is skipped without failing the job.
    #>
    param([string]$Scope, [object[]]$Desired = @(), [object[]]$Live = @(), [scriptblock]$KeyOf = $null)
    $none = [pscustomobject]@{ active = $false; failed = $false; soft = $false; reason = ''; desired = @($Desired); live = @($Live); droppedDesired = 0; droppedLive = 0; heldDesired = @(); heldLive = @(); groups = @(); suppressed = 0; suppressedGroups = @() }
    if ($Scope -notin @('AdminMembers', 'GroupMembers')) { return $none }
    # OWNER 2026-11-10 (decision b3430fd4: "Yes, but off hands members back"): with the feature switched OFF nothing is set
    # aside -- every bound or released group's members are the engine's again (its rows, the removal budget, the guards and
    # the per-item audit decide what happens to the people the package added). The bindings record is kept untouched, so
    # switching it on again sets the same groups aside. The provider says it (ACCESS-PACKAGE-OFF-HANDED-BACK).
    if (-not (Test-PimAccessPackagesEnabled)) { $none.reason = 'access packages are switched off: bound groups are handed back to the engine'; return $none }
    $state = Get-PimAccessPackageBindingRecord
    $failure = { param($why, [bool]$soft) [pscustomobject]@{ active = $false; failed = $true; soft = $soft; reason = "$why"; desired = @($Desired); live = @($Live); droppedDesired = 0; droppedLive = 0; heldDesired = @(); heldLive = @(); groups = @(); suppressed = 0; suppressedGroups = @() } }
    if (-not $state.ok) { return (& $failure "$($state.error)" ((-not $state.corrupt) -and -not ([int]$script:PimAccessPackageBindingsKnown -gt 0))) }
    $rec = $state.record
    # THE LOCK (owner 2026-11-12 "new groups locked for access packages"): a group CREATED FOR a package (its definition names the
    # package in the AccessPackage column -- never the name alone, so an existing '...-AP' group is not touched) gets its members from the package only, also before its binding is written --
    # admin rows and nestings INTO it are set aside like a bound group's. Switched OFF it is handed back like every bound group.
    $lockedTags = @{}
    if (Get-Command Get-PimGroupDefinitionRows -ErrorAction SilentlyContinue) {
        try { $lockedTags = Get-PimAccessPackageLockedTags -ColumnOnly -GroupDefinitions @(Get-PimGroupDefinitionRows -IncludeRetired) } catch { return (& $failure "the group definitions could not be read: $($_.Exception.Message)" $false) }
    }
    if (-not $rec.bindings.Count -and -not $rec.released.Count -and -not $lockedTags.Count) { return $none }
    $owned = $null
    try { $owned = Get-PimSolutionOwnedGroups } catch { return (& $failure "the groups PIM manages could not be resolved: $($_.Exception.Message)" $false) }
    $lockedIds = @{}
    foreach ($lt in @($lockedTags.Keys)) {
        foreach ($k in @($owned.byTag.Keys)) { if ("$k".ToLowerInvariant() -eq $lt -and "$($owned.byTag[$k])".Trim()) { $lockedIds["$($owned.byTag[$k])".ToLowerInvariant()] = $lt } }
    }
    $names = if ($Scope -eq 'GroupMembers') { @('SourceGroupTag', 'GroupTag') } else { @('GroupTag') }
    # GroupMembers applies a row through the group NAME of its tag (Get-PimTagToGroupName + Resolve-PimLiveGroupIdByName), which can differ from the owned set: both are candidates, so whichever the row would hit is checked.
    $tagToName = $null
    if ($Scope -eq 'GroupMembers') { try { $tagToName = Get-PimTagToGroupName } catch { return (& $failure "the group definitions could not be read: $($_.Exception.Message)" $false) } }
    $resolved = @{}
    $idsOf = {
        param($r)
        if ($null -eq $r) { return @() }
        $g = "$($r.groupId)".Trim().ToLowerInvariant(); if ($g) { return @($g) }
        $t = "$(Get-PimRowProp -Row $r -Names $names)".Trim().ToLowerInvariant()
        if (-not $t) { return @() }
        if ($resolved.ContainsKey($t)) { return @($resolved[$t]) }
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($k in @($owned.byTag.Keys)) { if ("$k".ToLowerInvariant() -eq $t) { $found.Add("$($owned.byTag[$k])".ToLowerInvariant()) } }
        if ($tagToName -is [hashtable] -and $tagToName.ContainsKey($t) -and "$($tagToName[$t])".Trim()) {
            $byName = Resolve-PimLiveGroupIdByName "$($tagToName[$t])"
            if ($byName -and -not $found.Contains("$byName".ToLowerInvariant())) { $found.Add("$byName".ToLowerInvariant()) }
        }
        $resolved[$t] = $found.ToArray()
        return @($found.ToArray())
    }
    $tagName = { param($g) if ($rec.bindings.ContainsKey($g)) { "$($rec.bindings[$g].tag)" } elseif ($lockedIds.ContainsKey($g)) { "$($lockedIds[$g])" } elseif ($rec.released.ContainsKey($g)) { "$($rec.released[$g].tag)" } else { $g } }
    $boundOf = { param($ids) foreach ($i in @($ids)) { if ($rec.bindings.ContainsKey("$i") -or $lockedIds.ContainsKey("$i")) { return "$i" } }; return '' }
    $liveKeys = @{}
    if ($KeyOf) { foreach ($l in @($Live)) { if ($null -ne $l) { try { $liveKeys["$(& $KeyOf $l)".Trim().ToLowerInvariant()] = $true } catch { } } } }
    $isCreate = { param($d) $k = ''; try { $k = "$(& $KeyOf $d)".Trim().ToLowerInvariant() } catch { $k = '' }; (-not $k -or -not $liveKeys.ContainsKey($k)) }
    $keepD = New-Object System.Collections.Generic.List[object]; $heldD = New-Object System.Collections.Generic.List[object]
    $suppressed = 0; $sg = @{}; $hit = @{}; $unresolved = 0; $ug = @{}
    foreach ($d in @($Desired)) {
        if ($null -eq $d) { continue }
        $ids = @(& $idsOf $d)
        $b = & $boundOf $ids
        if ($b) { $heldD.Add($d); $hit[(& $tagName $b)] = $true; continue }
        if ($KeyOf) {
            # A row that cannot be resolved to a group could be for a bound or released one: it never reaches a create.
            if (-not $ids.Count -and (& $isCreate $d)) { $unresolved++; $ug["$(Get-PimRowProp -Row $d -Names $names)"] = $true; continue }
            $rel = @($ids | Where-Object { $rec.released.ContainsKey("$_") })
            if ($rel.Count -and (& $isCreate $d)) { $suppressed++; $sg[(& $tagName "$($rel[0])")] = $true; continue }
        }
        $keepD.Add($d)
    }
    $keepL = @($Live | Where-Object { -not (& $boundOf @(& $idsOf $_)) })
    $heldL = @($Live | Where-Object { [bool](& $boundOf @(& $idsOf $_)) })
    foreach ($r in $heldL) { $hit[(& $tagName (& $boundOf @(& $idsOf $r)))] = $true }
    return [pscustomobject]@{ active = $true; failed = $false; soft = $false; reason = ''; desired = $keepD.ToArray(); live = $keepL; droppedDesired = ($heldD.Count + $suppressed + $unresolved); droppedLive = $heldL.Count; heldDesired = $heldD.ToArray(); heldLive = $heldL
        groups = @($hit.Keys | Sort-Object); suppressed = $suppressed; suppressedGroups = @($sg.Keys | Sort-Object); unresolved = $unresolved; unresolvedTags = @($ug.Keys | Sort-Object) }
}

function Select-PimAccessPackageHeldRemovals {
    <#
      After the budget and the last Global Administrator guard. Two rules the guards cannot express:
        * a removal of a group from a package is ALL-OR-NOTHING: if any person on it was held, none of its items runs;
        * a retire or group drop whose group is on a chain reaching Global Administrator is ALWAYS held for a release (never relied on the guard to find the holder).
      Returns @{ remove; warnings; used }. A release in the Guards page releases exactly this plan for one run. -DriftRead lists, holds nothing.
    #>
    param([object[]]$Remove = @(), [string]$Scope, [string]$RunKind = '', [switch]$WhatIf, [switch]$DriftRead, [bool]$CanRelease = $true)
    $items = @($Remove | Where-Object { $null -ne $_ })
    $warnings = New-Object System.Collections.Generic.List[string]
    $used = $null
    $hold = @($items | Where-Object { $_.PSObject.Properties['requiresRelease'] -and $_.requiresRelease })
    if ($hold.Count -and -not $DriftRead) {
        $guardId = 'engine.last-global-admin'
        $keys = @($hold | ForEach-Object { "$($_.key)".Trim().ToLowerInvariant() } | Select-Object -Unique)
        $g = $null
        if (-not $WhatIf -and $CanRelease -and (Get-Command Invoke-PimGuardHoldOrRelease -ErrorAction SilentlyContinue)) {
            try { $g = Invoke-PimGuardHoldOrRelease -GuardId $guardId -Scope $Scope -Keys @($keys) -Count $keys.Count -RunKind $RunKind -Measured @{ held = $keys.Count; accessPackage = $true } } catch { $g = $null }
        }
        if ($g -and $g.released) {
            $used = [pscustomobject]@{ guardId = $guardId; releaseId = "$($g.release.id)"; planHash = "$($g.planHash)" }
        } else {
            $heldSet = @{}; foreach ($k in $keys) { $heldSet[$k] = $true }
            $items = @($items | Where-Object { -not $heldSet.ContainsKey("$($_.key)".Trim().ToLowerInvariant()) })
            $warnings.Add(("{0} removal(s) HELD for release: the package's group is on a chain reaching Global Administrator. A SuperAdmin can release exactly this plan for one run on Operations > Guards. [LAST-GLOBAL-ADMIN]" -f $keys.Count))
            if (-not $WhatIf -and $CanRelease -and (Get-Command Invoke-PimGuardTrip -ErrorAction SilentlyContinue)) {
                try { [void](Invoke-PimGuardTrip -GuardId $guardId -Outcome refused -Area $Scope -Job 'engine' -HeldCount $keys.Count -Title ("{0}: {1} change(s) held -- the group is on a chain reaching Global Administrator" -f $Scope, $keys.Count) -Detail 'A retired or changed access package would end access on a chain that reaches Global Administrator.' -ActionText 'Check that another person holds Global Administrator, then release exactly this plan for one run on Operations > Guards.' -Measured @{ held = $keys.Count }) } catch { }
            }
        }
    }
    $present = @{}
    foreach ($i in $items) { if ($i.PSObject.Properties['atomicGroup'] -and "$($i.atomicGroup)") { $present["$($i.atomicGroup)"] = 1 + [int]$present["$($i.atomicGroup)"] } }
    $broken = @{}
    foreach ($i in $items) { if ($i.PSObject.Properties['atomicGroup'] -and "$($i.atomicGroup)" -and [int]$present["$($i.atomicGroup)"] -lt [int]$i.atomicSize) { $broken["$($i.atomicGroup)"] = $true } }
    if ($broken.Count) {
        $items = @($items | Where-Object { -not ($_.PSObject.Properties['atomicGroup'] -and $broken.ContainsKey("$($_.atomicGroup)")) })
        $warnings.Add(("{0} group removal(s) from a package NOT applied: someone on it is held, and removing a group from a package is all-or-nothing. [ACCESS-PACKAGE-SCOPE-HELD]" -f $broken.Count))
    }
    return [pscustomobject]@{ remove = $items; warnings = $warnings.ToArray(); used = $used }
}

function New-PimAccessPackageRemoveHeld {
    <# PURE. The failure item for a Remove row on a package-delivered group (Invoke-PimEngineScope's $__dupHeld path). #>
    param([string]$Scope, [AllowNull()][object]$Row)
    $names = if ($Scope -eq 'GroupMembers') { @('SourceGroupTag', 'GroupTag') } else { @('GroupTag') }
    $tag = "$(Get-PimRowProp -Row $Row -Names $names)".Trim()
    return [pscustomobject]@{ row = $Row; kind = 'group'; name = $tag; ids = @(); code = 'ACCESS-PACKAGE-REMOVE-HELD'
        message = ("ACCESS-PACKAGE-REMOVE-HELD: group '{0}' is delivered by an access package, so this Remove row was NOT applied. End the person's assignment in the package, then delete this row." -f $tag) }
}

# ---- definitions -------------------------------------------------------------------------------------------------------------
function Split-PimAccessPackageList {
    <# PURE. 'a; b,c' -> @('a','b','c'), trimmed, blanks dropped, duplicates (any case) dropped. #>
    param([AllowNull()][object]$Value)
    $seen = @{}
    return @(foreach ($p in @("$Value" -split '[;,]')) {
        $t = "$p".Trim(); if (-not $t) { continue }
        $k = $t.ToLowerInvariant(); if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true; $t
    })
}

function ConvertTo-PimAccessPackageDefinition {
    <#
      PURE. One 'AccessPackage' row -> a checked definition. Columns:
        AccessPackageName  the package's display name, and the store key
        DirectGroupTags    the DIRECT groups it grants membership of ('tagA; tagB')
        RequestScope       REQUIRED: AllMembers | Group       RequestGroupTag  the PIM group that may request (Group only)
        Approval           REQUIRED: Stages | None -- no approval must be stated, it is never what an empty column means
        ApprovalStage1 / ApprovalStage2             approvers: UPNs or PIM group tags ('a@x; TAG'); Stage1 required with Stages
        RequireJustification, AllowExtension        true / false
        MaxDays            days until an assignment ends; blank or 0 = no end date
        ReviewCadence      None | Monthly | Quarterly | SemiAnnually | Annually     Reviewers  as approvers
        ReviewNoResponse   KeepAccess (default) | RemoveAccess: what happens when a reviewer does not answer. Removing access on no response must be stated
        Notes, Action      Action=Remove retires the package; Action=ReturnToEngine returns the released groups in DirectGroupTags to the engine
        State, PauseReason State=Paused: an administrator paused the package -- nothing is written for it (not even a retirement) until it is resumed
      DirectGroupTags may only name groups CREATED FOR THIS PACKAGE (owner 2026-11-12): see Get-PimAccessPackageGroupProblems.
    #>
    param([Parameter(Mandatory)][object]$Row)
    $g = { param($n) if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { "$($Row[$n])".Trim() } else { '' } } else { $p = $Row.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { "$($p.Value)".Trim() } else { '' } } }
    $flag = { param($v) "$v" -match '^(?i)(true|1|yes|y|on)$' }
    $problems = New-Object System.Collections.Generic.List[string]
    $name = & $g 'AccessPackageName'
    if (-not $name) { $problems.Add('it has no AccessPackageName') }
    elseif ($name -match "[`r`n]" -or $name.Length -gt 256) { $problems.Add('its AccessPackageName is not usable') }
    $groups = @(Split-PimAccessPackageList (& $g 'DirectGroupTags'))
    if (-not $groups.Count) { $problems.Add('it names no direct group') }
    $scope = & $g 'RequestScope'
    $scopeOk = @('AllMembers', 'Group') | Where-Object { $_ -ieq $scope } | Select-Object -First 1
    if (-not $scope) { $problems.Add('RequestScope is required (AllMembers or Group): who may request must be stated') }
    elseif (-not $scopeOk) { $problems.Add("RequestScope '$scope' is not AllMembers or Group") }
    $reqTag = & $g 'RequestGroupTag'
    if ($scopeOk -ieq 'Group' -and -not $reqTag) { $problems.Add('RequestScope is Group but RequestGroupTag is empty') }
    $appr = & $g 'Approval'
    $apprOk = @('Stages', 'None') | Where-Object { $_ -ieq $appr } | Select-Object -First 1
    if (-not $appr) { $problems.Add('Approval is required (Stages or None): no approval must be stated explicitly') }
    elseif (-not $apprOk) { $problems.Add("Approval '$appr' is not Stages or None") }
    $stages = New-Object System.Collections.Generic.List[object]
    foreach ($c in @('ApprovalStage1', 'ApprovalStage2')) {
        $a = @(Split-PimAccessPackageList (& $g $c))
        if ($a.Count) { $stages.Add($a) }
    }
    if ((& $g 'ApprovalStage2') -and -not (& $g 'ApprovalStage1')) { $problems.Add('ApprovalStage2 is set but ApprovalStage1 is empty') }
    if ($apprOk -ieq 'Stages' -and -not $stages.Count) { $problems.Add('Approval is Stages but ApprovalStage1 is empty') }
    if ($apprOk -ieq 'None' -and $stages.Count) { $problems.Add('Approval is None but approvers are named') }
    $days = 0
    $rawDays = & $g 'MaxDays'
    if ($rawDays -and (-not [int]::TryParse($rawDays, [ref]$days) -or $days -lt 0 -or $days -gt 3650)) { $problems.Add("MaxDays '$rawDays' is not a whole number from 0 to 3650"); $days = 0 }
    $cad = & $g 'ReviewCadence'; if (-not $cad) { $cad = 'None' }
    $cadOk = @('None', 'Monthly', 'Quarterly', 'SemiAnnually', 'Annually') | Where-Object { $_ -ieq $cad } | Select-Object -First 1
    if (-not $cadOk) { $problems.Add("ReviewCadence '$cad' is not None, Monthly, Quarterly, SemiAnnually or Annually"); $cadOk = 'None' }
    $reviewers = @(Split-PimAccessPackageList (& $g 'Reviewers'))
    if ($cadOk -ne 'None' -and -not $reviewers.Count) { $problems.Add('a review cadence is set but Reviewers is empty') }
    $nrRaw = & $g 'ReviewNoResponse'
    $nrOk = if ($nrRaw) { @('KeepAccess', 'RemoveAccess') | Where-Object { $_ -ieq $nrRaw } | Select-Object -First 1 } else { 'KeepAccess' }
    if (-not $nrOk) { $problems.Add("ReviewNoResponse '$nrRaw' is not KeepAccess or RemoveAccess"); $nrOk = 'KeepAccess' }
    return [pscustomobject]@{
        name = $name; groupTags = $groups; requestScope = "$(if ($scopeOk) { $scopeOk } else { $scope })"; requestGroupTag = $reqTag; approval = "$(if ($apprOk) { $apprOk } else { $appr })"; stages = $stages.ToArray()
        requireJustification = [bool](& $flag (& $g 'RequireJustification')); allowExtension = [bool](& $flag (& $g 'AllowExtension'))
        maxDays = $days; reviewCadence = "$cadOk"; reviewers = $reviewers; reviewNoResponse = "$nrOk"; notes = (& $g 'Notes')
        isRemove = ((& $g 'Action') -ieq 'Remove'); isReturn = ((& $g 'Action') -ieq 'ReturnToEngine'); problems = $problems.ToArray()
        paused = ((& $g 'State') -ieq 'Paused'); pauseReason = (& $g 'PauseReason')
    }
}

# ---- NEW, DEDICATED, LOCKED GROUPS (owner 2026-11-12) ----------------------------------------------------------------------------
# "we dont rename anything existing. we add new groups locked for access packages. we dont touch existing groups. if in doubt then
# pause access package." + the naming pick the same day: "-ap group ends with as agreed".
#   * A package only ever delivers groups CREATED FOR IT: a group definition whose AccessPackage column names the package AND whose
#     GroupName ends with '-AP' (the normal PIM name for what it grants, '-AP' appended). An existing group is never bound or renamed.
#   * Such a group is LOCKED to its package: every other path (admin rows, nesting INTO it, adopt, retire, drift delete) leaves it.
#   * Any doubt (a group not created for this package, a name taken by a group PIM did not create, an admin pause, an unreadable
#     state) PAUSES the package: nothing is written for it, the reason is recorded in pim.Settings 'AccessPackageStatus'.
function Get-PimAccessPackageGroupMarker { return '-AP' }
function Get-PimAccessPackageStatusSetting { return 'AccessPackageStatus' }

function Test-PimAccessPackageGroupName {
    <# PURE. Does a group NAME carry the access-package marker (ends with '-AP', any case)? #>
    param([AllowNull()][string]$Name)
    $n = "$Name".Trim()
    return [bool]($n -and $n.EndsWith((Get-PimAccessPackageGroupMarker), [System.StringComparison]::OrdinalIgnoreCase))
}

function Get-PimAccessPackageDefinitionOwner {
    <# PURE. The package a group definition row is dedicated to ('' = none). Reads the AccessPackage column of a definition row or projection. #>
    param([AllowNull()][object]$Definition)
    if ($null -eq $Definition) { return '' }
    if ($Definition -is [System.Collections.IDictionary]) { if ($Definition.Contains('AccessPackage')) { return "$($Definition['AccessPackage'])".Trim() }; return '' }
    $p = $Definition.PSObject.Properties['AccessPackage']
    if ($p -and $null -ne $p.Value) { return "$($p.Value)".Trim() }
    return ''
}

function Test-PimAccessPackageLockedDefinition {
    <# PURE. Is this group definition LOCKED to an access package? Either marker is enough (a name ending '-AP', or the AccessPackage column): other paths leave it. #>
    param([AllowNull()][object]$Definition)
    if ($null -eq $Definition) { return $false }
    return ([bool](Get-PimAccessPackageDefinitionOwner -Definition $Definition) -or (Test-PimAccessPackageGroupName -Name "$($Definition.GroupName)"))
}

function Test-PimAccessPackageDedicatedDefinition {
    <# PURE. Was this definition created FOR this package? BOTH markers: the AccessPackage column names the package and the name ends with '-AP'. #>
    param([AllowNull()][object]$Definition, [string]$PackageName)
    if ($null -eq $Definition -or -not "$PackageName".Trim()) { return $false }
    return ((Get-PimAccessPackageDefinitionOwner -Definition $Definition) -ieq "$PackageName".Trim() -and (Test-PimAccessPackageGroupName -Name "$($Definition.GroupName)"))
}

function Get-PimAccessPackageLockedTags {
    <#
      PURE. tag (lower) -> package name ('' when only the name marker says so) of every LOCKED group definition.
      -ColumnOnly: only definitions that NAME a package (the AccessPackage column, which exists only since 2026-11-12). The engine's member
      guard uses it, so an EXISTING group whose name happens to end with '-AP' is never taken from the engine ("we dont touch existing groups").
    #>
    param([object[]]$GroupDefinitions = @(), [switch]$ColumnOnly)
    $h = @{}
    foreach ($d in @($GroupDefinitions)) {
        if ($null -eq $d -or -not "$($d.GroupTag)".Trim()) { continue }
        $locked = if ($ColumnOnly) { [bool](Get-PimAccessPackageDefinitionOwner -Definition $d) } else { Test-PimAccessPackageLockedDefinition -Definition $d }
        if ($locked) { $h["$($d.GroupTag)".Trim().ToLowerInvariant()] = (Get-PimAccessPackageDefinitionOwner -Definition $d) }
    }
    return $h
}

function Get-PimAccessPackageGroupEntity {
    <# PURE. The definition entity of a direct-group type (the types the Create access package screen offers). '' = not a direct-group type. #>
    param([string]$Type)
    switch ("$Type".Trim().ToLowerInvariant()) {
        'role' { 'PIM-Definitions-Roles' } 'department' { 'PIM-Definitions-Departments' } 'organisation' { 'PIM-Definitions-Organization' }
        'organization' { 'PIM-Definitions-Organization' } 'project' { 'PIM-Definitions-Projects' } 'crossorg' { 'PIM-Definitions-CrossOrg' } default { '' }
    }
}

function New-PimAccessPackageGroupIdentity {
    <#
      The tag and name of a NEW group for a package (owner 2026-11-12 "-ap group ends with as agreed"): the normal direct-group tag
      ({GroupTypePrefix}{ShortName}) and the tenant's group name around it (PimGroupPattern), each with '-AP' appended at the END.
      Example: department + Finance -> tag DEPT-Finance-AP, name PIM-DEPT-Finance-AP. Returns @{ ok; tag; name; entity; error }.
    #>
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$ShortName)
    $entity = Get-PimAccessPackageGroupEntity -Type $Type
    if (-not $entity) { return [pscustomobject]@{ ok = $false; tag = ''; name = ''; entity = ''; error = "'$Type' is not a direct-group type (role, department, organisation, project, crossorg)" } }
    $short = ConvertTo-PimNamePart $ShortName
    $mk = Get-PimAccessPackageGroupMarker
    if ($short.EndsWith($mk, [System.StringComparison]::OrdinalIgnoreCase)) { $short = $short.Substring(0, $short.Length - $mk.Length).TrimEnd('-') }
    if (-not $short) { return [pscustomobject]@{ ok = $false; tag = ''; name = ''; entity = $entity; error = 'the group needs a short name (letters, digits, dot or dash)' } }
    $key = "$Type".Trim().ToLowerInvariant(); if ($key -eq 'organization') { $key = 'organisation' }
    $prefix = Get-PimNamingMapValue -Map 'GroupTypePrefixes' -Key $key
    $baseTag = "$prefix$short"
    $aff = Get-PimGroupNameAffixes
    $baseName = ("$($aff.prefix)$baseTag$($aff.suffix)" -replace '-{2,}', '-').Trim('-')
    return [pscustomobject]@{ ok = $true; tag = "$baseTag$mk"; name = "$baseName$mk"; entity = $entity; error = '' }
}

function Test-PimAccessPackageRowPaused {
    <# PURE. Did an administrator pause this package (State = Paused on its row)? #>
    param([AllowNull()][object]$Row)
    return ("$(Get-PimRowProp -Row $Row -Names @('State'))".Trim() -ieq 'Paused')
}

function Get-PimAccessPackageGroupDoubt {
    <#
      The doubt about ONE resolved group of a package, or '' when there is none. Read-only (never pins, never holds):
        * the name is in the run's duplicate / adopt-held register: a group PIM did not create carries it;
        * the adopted-group record (GroupObjectPins) is readable and does not pin this name to this id: PIM cannot prove it created it.
      No store, or the one-time pin migration still running = no record to judge by: no doubt from it (the engine's own rule).
    #>
    param([string]$Name, [string]$Id)
    $k = "$Name".Trim().ToLowerInvariant()
    $reg = $global:PIM_DuplicateLiveNames
    if ($k -and $reg -is [hashtable] -and $reg['group'] -is [hashtable] -and $reg['group'].ContainsKey($k)) {
        return "the name '$Name' is already taken by a group PIM Manager did not create for this package"
    }
    if ($k -and "$Id".Trim() -and (Get-Command Get-PimGroupPinState -ErrorAction SilentlyContinue)) {
        $st = $null; try { $st = Get-PimGroupPinState } catch { return "the record of the groups PIM Manager created could not be read ($($_.Exception.Message))" }
        if ($st -and $st.available -and -not $st.migrating) {
            $pin = "$($st.pins[$k])"
            if (-not $pin) { return "PIM Manager has no record that it created the group '$Name' -- a group of that name is not used for a package" }
            if ($pin -ine "$Id".Trim()) { return "the group '$Name' in Entra ID is not the one PIM Manager created for this package" }
        }
    }
    return ''
}

function Save-PimAccessPackageStatus {
    <#
      Report-only: pim.Settings 'AccessPackageStatus' = @{ updatedUtc; licence = @{ ok; reason }; packages = name(lower) -> @{ name; state; reason } } for the Manager.
      Written only when it changed (the timestamp is not compared) and never on a plan. A failed write never fails the scope.
    #>
    param([hashtable]$Context, [hashtable]$Packages = @{}, [AllowNull()][object]$Licence)
    if ($Context -and $Context['__pimWhatIf']) { return }
    if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { return }
    $pk = [ordered]@{}; foreach ($k in @($Packages.Keys | Sort-Object)) { $pk[$k] = [ordered]@{ name = "$($Packages[$k].name)"; state = "$($Packages[$k].state)"; reason = "$($Packages[$k].reason)" } }
    $lic = if ($null -ne $Licence) { [ordered]@{ ok = [bool]$Licence.ok; reason = "$($Licence.reason)" } } else { $null }
    $sig = ConvertTo-Json -InputObject ([ordered]@{ licence = $lic; packages = $pk }) -Depth 6 -Compress
    if ("$($script:PimAccessPackageStatusSig)" -ceq $sig) { return }
    try {
        Set-PimSetting -Name (Get-PimAccessPackageStatusSetting) -Value ([pscustomobject]@{ updatedUtc = (Get-Date).ToUniversalTime().ToString('o'); licence = $lic; packages = [pscustomobject]$pk })
        $script:PimAccessPackageStatusSig = $sig
    } catch { Write-Warning "  [AccessPackages] the package status for the Manager could not be saved: $($_.Exception.Message)" }
}

function Test-PimAccessPackageGroupStillPackaged {
    <#
      The LOCK for retirement: is the group of this NAME (a locked one) still delivered by a defined package (a row that is not Action=Remove names its tag)?
      $true also when that cannot be read (doubt = keep the group). Not a locked name = $false (the lock does not apply).
    #>
    param([string]$GroupName)
    if (-not (Test-PimAccessPackageGroupName -Name $GroupName)) {
        $lockedByCol = $false
        try { foreach ($d in @(Get-PimGroupDefinitionRows -IncludeRetired)) { if ("$($d.GroupName)" -ieq "$GroupName" -and (Get-PimAccessPackageDefinitionOwner -Definition $d)) { $lockedByCol = $true } } } catch { return $false }   # not a '-AP' name: the retirement's own checks decide
        if (-not $lockedByCol) { return $false }
    }
    try {
        $tags = @{}
        foreach ($d in @(Get-PimGroupDefinitionRows -IncludeRetired)) { if ("$($d.GroupName)" -ieq "$GroupName" -and "$($d.GroupTag)".Trim()) { $tags["$($d.GroupTag)".Trim().ToLowerInvariant()] = $true } }
        $rows = @(Get-PimAccessPackageRows)
        $entity = Get-PimAccessPackageEntityName
        if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey($entity) -and -not $global:PIM_DesiredResolved[$entity]) { return $true }
        foreach ($r in $rows) {
            if ("$(Get-PimRowProp -Row $r -Names @('Action'))".Trim() -ieq 'Remove') { continue }
            foreach ($t in @(Split-PimAccessPackageList "$(Get-PimRowProp -Row $r -Names @('DirectGroupTags'))")) { if ($tags.ContainsKey("$t".ToLowerInvariant())) { return $true } }
        }
        return $false
    } catch { return $true }
}

function Get-PimAccessPackageChainTags {
    <# PURE. Every tag on a group's chain, walked UPWARD through every level of nesting (a member's containers, then theirs), lowercase. Cycles are safe. #>
    param([string]$Tag, [object[]]$Nestings = @())
    $seen = @{}
    $queue = New-Object System.Collections.Generic.Queue[string]
    $queue.Enqueue("$Tag".Trim().ToLowerInvariant())
    while ($queue.Count) {
        $t = $queue.Dequeue()
        if (-not $t -or $seen.ContainsKey($t)) { continue }
        $seen[$t] = $true
        foreach ($n in @($Nestings)) {
            if ($null -eq $n) { continue }
            $target = "$(Get-PimRowProp -Row $n -Names @('TargetGroupTag'))".Trim().ToLowerInvariant()
            $source = "$(Get-PimRowProp -Row $n -Names @('SourceGroupTag'))".Trim().ToLowerInvariant()
            if ($target -eq $t -and $source -and -not $seen.ContainsKey($source)) { $queue.Enqueue($source) }
        }
    }
    return @($seen.Keys)
}

function Get-PimAccessPackageChainTiers {
    <# PURE. The tier numbers on a direct group's WHOLE chain upward ('unknown' = not stated, kept). #>
    param([string]$Tag, [object[]]$GroupDefinitions = @(), [object[]]$Nestings = @())
    $tierOf = @{}
    foreach ($d in @($GroupDefinitions)) { if ($null -ne $d -and "$($d.GroupTag)".Trim()) { $tierOf["$($d.GroupTag)".Trim().ToLowerInvariant()] = "$($d.TierLevel)" } }
    return @(foreach ($t in @(Get-PimAccessPackageChainTags -Tag $Tag -Nestings $Nestings)) { $n = ConvertTo-PimTierNumber $tierOf[$t]; if ($null -eq $n) { 'unknown' } else { [int]$n } })
}

function Test-PimAccessPackageTagReachesGlobalAdmin {
    <# PURE. Does a group's whole chain upward hold the Global Administrator role? -RoleRows: rows of PIM-Assignments-Roles-Groups. #>
    param([string]$Tag, [object[]]$Nestings = @(), [object[]]$RoleRows = @())
    $chain = @{}
    foreach ($t in @(Get-PimAccessPackageChainTags -Tag $Tag -Nestings $Nestings)) { $chain[$t] = $true }
    foreach ($r in @($RoleRows)) {
        if ($null -eq $r) { continue }
        $g = "$(Get-PimRowProp -Row $r -Names @('GroupTag'))".Trim().ToLowerInvariant()
        $n = "$(Get-PimRowProp -Row $r -Names @('RoleDefinitionName', 'RoleName'))".Trim()
        if ($g -and $chain.ContainsKey($g) -and $n -ieq 'Global Administrator') { return $true }
    }
    return $false
}

function Get-PimAccessPackageGroupProblems {
    <#
      PURE. Why this definition may not name these groups. Refused, not warned: only a DIRECT group defined exactly once, not being retired and
      not owned by a managing tenant can be delivered by a package; no approval is refused on a Tier-0 / Tier-1 chain (the design's risk rule),
      and on a chain whose tier nobody stated, because a Tier-0 chain cannot be ruled out.
      -GroupDefinitions: rows of Get-PimGroupDefinitionRows -IncludeRetired. -Nestings: rows of PIM-Assignments-Groups.
    #>
    param([Parameter(Mandatory)][object]$Definition, [object[]]$GroupDefinitions = @(), [object[]]$Nestings = @())
    $byTag = @{}
    foreach ($d in @($GroupDefinitions)) {
        if ($null -eq $d -or -not "$($d.GroupTag)".Trim()) { continue }
        $k = "$($d.GroupTag)".Trim().ToLowerInvariant()
        if (-not $byTag.ContainsKey($k)) { $byTag[$k] = New-Object System.Collections.Generic.List[object] }
        $byTag[$k].Add($d)
    }
    return @(foreach ($t in @($Definition.groupTags)) {
        $rows = $byTag["$t".ToLowerInvariant()]
        if ($null -eq $rows) { "'$t' is not a group defined in PIM Manager"; continue }
        if (@($rows | ForEach-Object { "$($_.SourceEntity)".ToLowerInvariant() } | Select-Object -Unique).Count -gt 1 -or $rows.Count -gt 1) { "'$t' is defined more than once -- a package may only name a group with one definition"; continue }
        $d = $rows[0]
        if (-not (Test-PimDirectGroupEntity -Entity "$($d.SourceEntity)")) { "'$t' is a permission group -- a package may only grant membership of a direct group"; continue }
        if ("$($d.Lifecycle)".Trim() -match '(?i)^retire') { "'$t' is being retired -- a package may not deliver it"; continue }
        if ("$($d.Owner)".Trim() -ieq 'msp') { "'$t' is owned by the managing tenant -- a managed tenant's package may not deliver it"; continue }
        # OWNER 2026-11-12: "we dont touch existing groups" -- only a group created FOR this package (AccessPackage column = this package,
        # name ending '-AP'). An existing group, or one locked to ANOTHER package, pauses the package; it is never bound or renamed.
        if (-not (Test-PimAccessPackageDedicatedDefinition -Definition $d -PackageName "$($Definition.name)")) {
            $o = Get-PimAccessPackageDefinitionOwner -Definition $d
            if ($o -and $o -ine "$($Definition.name)") { "'$t' belongs to access package '$o' -- a group is locked to the one package it was created for" }
            else { "'$t' is not a group created for this access package (its definition must name the package and its name must end with '$(Get-PimAccessPackageGroupMarker)') -- an access package never uses an existing group" }
            continue
        }
        if ("$($Definition.approval)" -ieq 'None') {
            $tiers = @(Get-PimAccessPackageChainTiers -Tag "$t" -GroupDefinitions $GroupDefinitions -Nestings $Nestings)
            if (@($tiers | Where-Object { "$_" -eq 'unknown' -or [int]$_ -le 1 }).Count) { "'$t' sits on a Tier-0 or Tier-1 chain, or on a chain whose tier is not stated -- no approval is refused there" }
        }
    })
}

# ---- licence --------------------------------------------------------------------------------------------------------------------
function Test-PimAccessPackageLicenceSkus {
    <# PURE. Entra ID Governance: the service plan Entra_Identity_Governance of an enabled subscription, or a product whose string id names it. P2 alone is not enough. #>
    param([object[]]$Skus = @())
    foreach ($s in @($Skus)) {
        if ($null -eq $s) { continue }
        if ("$($s.capabilityStatus)".Trim() -and "$($s.capabilityStatus)" -ine 'Enabled') { continue }
        if ("$($s.skuPartNumber)" -match '^(?i)(Microsoft_Entra_ID_Governance|Microsoft_Entra_Suite|MICROSOFT_365_E7)') { return $true }
        foreach ($p in @($s.servicePlans)) {
            if ($null -ne $p -and "$($p.servicePlanName)" -ieq 'Entra_Identity_Governance' -and "$($p.provisioningStatus)" -ine 'Disabled') { return $true }
        }
    }
    return $false
}

function Clear-PimAccessPackageLicenceCache { $script:PimAccessPackageLicence = $null }

function Get-PimAccessPackageLicence {
    <# @{ ok; reason }. One read per process per hour, only ever when a package is defined. Decides whether the provider builds; never decides a binding. #>
    $c = $script:PimAccessPackageLicence
    if ($c -and $c.at -and ((Get-Date) - $c.at).TotalMinutes -lt 60) { return $c }
    $r = $null
    try {
        $skus = @(Invoke-PimGraph -All -Path '/subscribedSkus?$select=skuPartNumber,capabilityStatus,servicePlans')
        if (Test-PimAccessPackageLicenceSkus -Skus $skus) { $r = [pscustomobject]@{ ok = $true; reason = ''; at = (Get-Date) } }
        else { $r = [pscustomobject]@{ ok = $false; reason = 'this tenant has no Microsoft Entra ID Governance (or Entra Suite) licence, which eligible group membership in an access package requires'; at = (Get-Date) } }
    } catch { $r = [pscustomobject]@{ ok = $false; reason = "the tenant's licences could not be read ($($_.Exception.Message))"; at = (Get-Date) } }
    $script:PimAccessPackageLicence = $r
    return $r
}

# ---- Graph shapes -------------------------------------------------------------------------------------------------------------------
function Select-PimAccessPackageEligibleRole {
    <#
      NOT VERIFIED LIVE -- no tenant holds the licence yet. This one function decides what "eligible member" means to Graph.
      Documented (learn.microsoft.com, read 2026-11-09): the admin center offers "Eligible Member" for a PIM-managed group; the Graph BETA example
      sends originId "EligibleMember_<guid>", displayName "Eligible Member", originSystem AadGroup; the role comes from the catalog's list of
      resource roles. The v1.0 page shows no eligible example for a group. So nothing is constructed: the role is PICKED from the catalog's list.
      No such role = $null, and the caller REFUSES -- no fallback to "Member", that would hand out ACTIVE membership of a group that holds roles.
    #>
    param([object[]]$Roles = @())
    foreach ($r in @($Roles)) {
        if ($null -eq $r) { continue }
        if ("$($r.displayName)".Trim() -ieq 'Eligible Member' -or "$($r.originId)" -like 'EligibleMember_*') { return $r }
    }
    return $null
}

function Test-PimAccessPackageRoleIsEligible {
    param([AllowNull()][object]$Role)
    return ($null -ne $Role -and ("$($Role.displayName)".Trim() -ieq 'Eligible Member' -or "$($Role.originId)" -like 'EligibleMember_*'))
}

function Get-PimAccessPackageFingerprint {
    <# PURE. One comparable text for a desired or a live package: every setting this provider owns, sorted, lowercase. #>
    param([string[]]$GroupIds = @(), [string]$RequestScope = 'AllMembers', [string]$RequestGroupId = '', [object[]]$Stages = @(), [bool]$RequireJustification = $false,
          [int]$MaxDays = 0, [bool]$AllowExtension = $false, [string]$ReviewCadence = 'None', [string[]]$Reviewers = @(), [string]$ReviewNoResponse = 'KeepAccess')
    $norm = { param($a) (@(@($a) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)) -join ',' }
    $st = @(foreach ($s in @($Stages)) { & $norm $s }) -join ';'
    return ('groups={0}|scope={1}|rg={2}|stages={3}|just={4}|days={5}|ext={6}|cad={7}|rev={8}|nr={9}' -f (& $norm $GroupIds), "$RequestScope".ToLowerInvariant(), "$RequestGroupId".ToLowerInvariant(), $st, [int]$RequireJustification, $MaxDays, [int]$AllowExtension, "$ReviewCadence".ToLowerInvariant(), (& $norm $Reviewers), $(if ("$ReviewCadence" -ieq 'None') { 'none' } else { "$ReviewNoResponse".ToLowerInvariant() }))
}

function Get-PimAccessPackageDesiredFingerprint {
    <# PURE. A desired package's fingerprint, optionally over other group ids (groups whose removal is still planned stay in place until it runs). #>
    param([Parameter(Mandatory)][object]$Desired, [string[]]$GroupIds)
    if (-not $PSBoundParameters.ContainsKey('GroupIds')) { $GroupIds = @($Desired.GroupIds) }
    return (Get-PimAccessPackageFingerprint -GroupIds $GroupIds -RequestScope "$($Desired.RequestScope)" -RequestGroupId "$($Desired.RequestGroupId)" `
        -Stages @(foreach ($st in @($Desired.StageSubjects)) { , @(@($st) | ForEach-Object { "$($_.id)" }) }) -RequireJustification ([bool]$Desired.RequireJustification) -MaxDays ([int]$Desired.MaxDays) `
        -AllowExtension ([bool]$Desired.AllowExtension) -ReviewCadence "$($Desired.ReviewCadence)" -Reviewers @(@($Desired.ReviewerSubjects) | ForEach-Object { "$($_.id)" }) -ReviewNoResponse "$($Desired.ReviewNoResponse)")
}

function New-PimAccessPackageSubjectSet {
    <# PURE. Resolved ids -> the Graph approver / reviewer objects. @{ type = user|group; id }. #>
    param([object[]]$Subjects = @())
    return @(foreach ($s in @($Subjects)) {
        if ("$($s.type)" -eq 'group') { [ordered]@{ '@odata.type' = '#microsoft.graph.groupMembers'; groupId = "$($s.id)" } }
        else { [ordered]@{ '@odata.type' = '#microsoft.graph.singleUser'; userId = "$($s.id)" } }
    })
}

function New-PimAccessPackagePolicyBody {
    <# PURE. The accessPackageAssignmentPolicy for one resolved definition (learn.microsoft.com, read 2026-11-09; not sent to a tenant yet). An extension is approved like a request. #>
    param([Parameter(Mandatory)][object]$Desired, [string]$PackageId = '')
    $stages = @($Desired.StageSubjects)
    $bodyStages = @(foreach ($st in $stages) {
        [ordered]@{ durationBeforeAutomaticDenial = 'P14D'; isApproverJustificationRequired = $false; isEscalationEnabled = $false; durationBeforeEscalation = 'PT0S'
                    primaryApprovers = @(New-PimAccessPackageSubjectSet -Subjects @($st)); fallbackPrimaryApprovers = @(); escalationApprovers = @(); fallbackEscalationApprovers = @() }
    })
    $allMembers = ("$($Desired.RequestScope)" -ieq 'AllMembers')
    $body = [ordered]@{
        displayName = (Get-PimAccessPackagePolicyName)
        description = 'Managed by PIM Manager.'
        allowedTargetScope = $(if ($allMembers) { 'allMemberUsers' } else { 'specificDirectoryUsers' })
        specificAllowedTargets = @(if (-not $allMembers) { [ordered]@{ '@odata.type' = '#microsoft.graph.groupMembers'; groupId = "$($Desired.RequestGroupId)" } })
        expiration = $(if ([int]$Desired.MaxDays -gt 0) { [ordered]@{ type = 'afterDuration'; duration = "P$([int]$Desired.MaxDays)D" } } else { [ordered]@{ type = 'noExpiration' } })
        requestorSettings = [ordered]@{
            enableTargetsToSelfAddAccess = $true; enableTargetsToSelfUpdateAccess = [bool]$Desired.AllowExtension; enableTargetsToSelfRemoveAccess = $true
            allowCustomAssignmentSchedule = $false; enableOnBehalfRequestorsToAddAccess = $false; enableOnBehalfRequestorsToUpdateAccess = $false; enableOnBehalfRequestorsToRemoveAccess = $false; onBehalfRequestors = @()
        }
        requestApprovalSettings = [ordered]@{ isApprovalRequiredForAdd = [bool]($stages.Count -gt 0); isApprovalRequiredForUpdate = [bool]($stages.Count -gt 0); isRequestorJustificationRequired = [bool]$Desired.RequireJustification; stages = @($bodyStages) }
        reviewSettings = [ordered]@{ isEnabled = $false }
        accessPackage = [ordered]@{ id = "$PackageId" }
    }
    if ("$($Desired.ReviewCadence)" -ine 'None') {
        $interval = switch ("$($Desired.ReviewCadence)".ToLowerInvariant()) { 'monthly' { 1 } 'quarterly' { 3 } 'semiannually' { 6 } 'annually' { 12 } default { 3 } }
        $body['reviewSettings'] = [ordered]@{
            isEnabled = $true; expirationBehavior = $(if ("$($Desired.ReviewNoResponse)" -ieq 'RemoveAccess') { 'removeAccess' } else { 'keepAccess' }); isRecommendationEnabled = $true; isReviewerJustificationRequired = $true; isSelfReview = $false
            schedule = [ordered]@{ startDateTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); expiration = [ordered]@{ duration = 'P14D'; type = 'afterDuration' }
                                   recurrence = [ordered]@{ pattern = [ordered]@{ type = 'absoluteMonthly'; interval = $interval }; range = [ordered]@{ type = 'noEnd' } } }
            primaryReviewers = @(New-PimAccessPackageSubjectSet -Subjects @($Desired.ReviewerSubjects)); fallbackReviewers = @()
        }
    }
    return $body
}

function ConvertFrom-PimAccessPackageLive {
    <# PURE. One Graph accessPackage (expanded) -> the live row. Only ELIGIBLE group scopes and PIM's own policy are read as ours. #>
    param([Parameter(Mandatory)][object]$Package)
    $scopes = @(@($Package.resourceRoleScopes) | Where-Object { $null -ne $_ -and "$($_.role.originSystem)" -ieq 'AadGroup' -and (Test-PimAccessPackageRoleIsEligible -Role $_.role) })
    $groupIds = @($scopes | ForEach-Object { "$($_.scope.originId)" })
    $pol = @(@($Package.assignmentPolicies) | Where-Object { $null -ne $_ -and "$($_.displayName)" -ieq (Get-PimAccessPackagePolicyName) } | Select-Object -First 1)
    $p = if ($pol.Count) { $pol[0] } else { $null }
    $subjectIds = { param($list) @(@($list) | Where-Object { $null -ne $_ } | ForEach-Object { if ("$($_.userId)".Trim()) { "$($_.userId)" } else { "$($_.groupId)" } }) }
    $stages = @(); $reqScope = 'AllMembers'; $reqGroup = ''; $just = $false; $days = 0; $ext = $false; $cad = 'None'; $rev = @(); $nr = 'KeepAccess'
    if ($p) {
        if ("$($p.allowedTargetScope)" -ine 'allMemberUsers') { $reqScope = 'Group'; $t = @(@($p.specificAllowedTargets) | Where-Object { $null -ne $_ } | Select-Object -First 1); if ($t.Count) { $reqGroup = "$($t[0].groupId)" } }
        $stages = @(foreach ($st in @($p.requestApprovalSettings.stages)) { if ($null -ne $st) { , @(& $subjectIds $st.primaryApprovers) } })
        $just = [bool]$p.requestApprovalSettings.isRequestorJustificationRequired
        if ("$($p.expiration.type)" -ieq 'afterDuration' -and "$($p.expiration.duration)" -match '^P(\d+)D$') { $days = [int]$Matches[1] }
        $ext = [bool]$p.requestorSettings.enableTargetsToSelfUpdateAccess
        if ($p.reviewSettings -and $p.reviewSettings.isEnabled) {
            $cad = switch ([int]$p.reviewSettings.schedule.recurrence.pattern.interval) { 1 { 'Monthly' } 3 { 'Quarterly' } 6 { 'SemiAnnually' } 12 { 'Annually' } default { 'Other' } }
            $rev = @(& $subjectIds $p.reviewSettings.primaryReviewers)
            $nr = if ("$($p.reviewSettings.expirationBehavior)" -ieq 'removeAccess') { 'RemoveAccess' } else { 'KeepAccess' }
        }
    }
    return [pscustomobject]@{
        PackageName = "$($Package.displayName)"; Id = "$($Package.id)"; CatalogId = "$($Package.catalog.id)"; GroupIds = $groupIds
        ScopesByGroup = $scopes; PolicyId = $(if ($p) { "$($p.id)" } else { '' })
        Fingerprint = (Get-PimAccessPackageFingerprint -GroupIds $groupIds -RequestScope $reqScope -RequestGroupId $reqGroup -Stages $stages -RequireJustification $just -MaxDays $days -AllowExtension $ext -ReviewCadence $cad -Reviewers $rev -ReviewNoResponse $nr)
    }
}

function Assert-PimAccessPackageOwned {
    <# Every write path starts here: nothing this install did not create is ever changed -- its catalog id AND its package id, as recorded when they were made. #>
    param([string]$LiveCatalogId, [string]$PackageId, [hashtable]$Context, [string]$What = 'this package')
    $state = Get-PimAccessPackageBindingRecord
    if (-not $state.ok) { throw "AccessPackages: REFUSED -- the record of what this install created could not be read ($($state.error)), so nothing is changed." }
    $rec = $state.record
    if (-not "$($rec.catalogId)".Trim() -or "$LiveCatalogId" -ine "$($rec.catalogId)") { throw ("AccessPackages: REFUSED -- {0} is not in the catalog this install created; nothing outside it is ever changed." -f $What) }
    if ($PackageId -and -not $rec.packages.ContainsKey("$PackageId".ToLowerInvariant())) { throw ("AccessPackages: REFUSED -- {0} was not created by this install; a name match is not ownership." -f $What) }
}

function Resolve-PimAccessPackageSubject {
    <# 'user@x' -> a user id; anything else -> a PIM-defined group tag. Only PIM's own groups can ever be named. #>
    param([string]$Token, [hashtable]$ByTag)
    $t = "$Token".Trim()
    if ($t -match '@') {
        $id = Resolve-PimPrincipalId $t
        if (-not $id) { return $null }
        return [pscustomobject]@{ type = 'user'; id = "$id"; token = $t }
    }
    $gid = $ByTag[$t.ToLowerInvariant()]
    if (-not $gid) { return $null }
    return [pscustomobject]@{ type = 'group'; id = "$gid"; token = $t }
}

function Add-PimAccessPackageWarning {
    param([hashtable]$Context, [string]$Message)
    Write-Warning "  [AccessPackages] $Message"
    if ($Context -and $Context['__pimScopeWarnings'] -is [System.Collections.IList]) { try { [void]$Context['__pimScopeWarnings'].Add($Message) } catch { } }
}

function Invoke-PimAccessPackageReturnRows {
    <#
      Action=ReturnToEngine rows: the named RELEASED groups go back to the engine (SQL only). A group that is still bound stays bound: only retiring its package hands it back.
      A row applies ONCE: it is recorded as consumed (by row name) as soon as it has been acted on, including when it matched nothing, so a later binding of the same group is never returned by
      an old row. A return decision needs a new row name. A tag that cannot be resolved while something is released leaves the row unconsumed for the next run.
    #>
    param([hashtable]$Context, [Parameter(Mandatory)][object]$State, [object[]]$Rows = @())
    if (-not @($Rows).Count) { return }
    $rec = $State.record
    $owned = if ($rec.released.Count) { Get-PimSolutionOwnedGroups } else { $null }
    $changed = $false
    foreach ($r in @($Rows)) {
        $name = "$(Get-PimRowProp -Row $r -Names @('AccessPackageName'))".Trim().ToLowerInvariant()
        if (-not $name) { Add-PimAccessPackageWarning -Context $Context -Message 'an Action=ReturnToEngine row has no AccessPackageName; it was ignored. [ACCESS-PACKAGE-DEFINITION]'; continue }
        if ($rec.returnsConsumed.ContainsKey($name)) { continue }
        $pending = $false; $applied = $false
        foreach ($t in @(Split-PimAccessPackageList "$(Get-PimRowProp -Row $r -Names @('DirectGroupTags'))")) {
            if (-not $rec.released.Count) { continue }
            $g = "$($owned.byTag["$t".ToLowerInvariant()])".ToLowerInvariant()
            if (-not $g) { $pending = $true; continue }
            if ($rec.released.ContainsKey($g)) {
                $rec.released.Remove($g); $applied = $true; $changed = $true
                Write-Host "  [AccessPackages] released group '$t' returned to the engine by an Action=ReturnToEngine row." -ForegroundColor DarkYellow
                if (Get-Command Write-PimEngineChangeAudit -ErrorAction SilentlyContinue) { Write-PimEngineChangeAudit -Scope 'AccessPackages' -Entity (Get-PimAccessPackageEntityName) -Op 'Update' -Item ([pscustomobject]@{ key = "return|$t"; desired = $r }) -Result 'ok' }
            }
        }
        if ($pending) { Add-PimAccessPackageWarning -Context $Context -Message "Action=ReturnToEngine row '$name' names a group that cannot be resolved; it was not applied and is retried. [ACCESS-PACKAGE-DEFINITION]"; continue }
        $rec.returnsConsumed[$name] = (Get-Date).ToUniversalTime().ToString('o'); $changed = $true
        Add-PimAccessPackageWarning -Context $Context -Message ("Action=ReturnToEngine row '{0}' {1} and is now used up; delete it. A later release needs a new row with a new name." -f $name, $(if ($applied) { 'returned its group' } else { 'matched no released group' }))
    }
    if ($changed) { Save-PimAccessPackageBindingState -State $State }
}

function Update-PimAccessPackageReleasedState {
    <#
      A released group whose rows are PROVEN gone needs no review any more: the state ends. Proven means every read succeeded (the group definitions behind the ids and both assignment entities) and every
      row was matched to a resolved group. Anything unread or unresolved: every entry stays.
    #>
    param([hashtable]$Context, [Parameter(Mandatory)][object]$State)
    if (-not $State.record.released.Count) { return }
    [void](Get-PimGroupDefinitionRows -IncludeRetired)
    foreach ($e in @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks', 'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg')) {
        if (-not ($global:PIM_DesiredResolved -is [hashtable]) -or -not $global:PIM_DesiredResolved.ContainsKey($e) -or -not $global:PIM_DesiredResolved[$e]) { return }
    }
    $owned = Get-PimSolutionOwnedGroups
    $named = @{}
    foreach ($pair in @(@{ e = 'PIM-Assignments-Admins'; n = @('GroupTag') }, @{ e = 'PIM-Assignments-Groups'; n = @('SourceGroupTag', 'GroupTag') })) {
        $rows = @(Get-PimDesiredRows -Entity $pair.e)
        if (-not ($global:PIM_DesiredResolved -is [hashtable]) -or -not $global:PIM_DesiredResolved.ContainsKey($pair.e) -or -not $global:PIM_DesiredResolved[$pair.e]) { return }
        foreach ($r in $rows) {
            if ($null -eq $r -or (Test-PimRowIsRemove $r)) { continue }
            $g = "$($owned.byTag["$(Get-PimRowProp -Row $r -Names $pair.n)".Trim().ToLowerInvariant()])".ToLowerInvariant()
            if (-not $g) { return }   # a row that cannot be matched to a group could be one of these: nothing is proven
            $named[$g] = $true
        }
    }
    $changed = $false
    foreach ($k in @($State.record.released.Keys)) { if (-not $named.ContainsKey($k)) { $State.record.released.Remove($k); $changed = $true } }
    if ($changed) { Save-PimAccessPackageBindingState -State $State }
}

function Get-PimAccessPackageReleasedSteps {
    <# PURE. The step that actually works for a released group, for the warning. #>
    return "delete the member rows that name it (PIM-Assignments-Admins, PIM-Assignments-Groups), or add an AccessPackage row with Action=ReturnToEngine and DirectGroupTags set to it"
}

function Get-PimAccessPackageDesired {
    <#
      GetDesired. The binding record is read first: it is reported whatever the switch, the licence or the rows say. Return rows and the released state are handled first (SQL only).
      Then, stopping at the first no: switched off -> no rows -> the licence. No definition and no binding = no Graph call of any kind. With the licence missing a retirement still
      runs (Action=Remove rows only), because retiring the package is the way to hand a group back.
    #>
    param([hashtable]$Context)
    $Context['apActive'] = $false; $Context['apRemoveRows'] = @(); $Context['apCatalogId'] = ''; $Context['apHeldNames'] = @{}; $Context['apUnnamedInvalid'] = $false
    $Context['apDesiredByName'] = @{}; $Context['apNamedGroupIds'] = @{}; $Context['apOnlyNames'] = $null
    $state = Get-PimAccessPackageBindingRecord
    if (-not $state.ok) { Add-PimAccessPackageWarning -Context $Context -Message "the binding record could not be read ($($state.error)); nothing was built and no member of a possibly bound group was changed. [ACCESS-PACKAGE-BINDING-UNREADABLE]" ; return @() }
    $allRows = @(Get-PimAccessPackageRows)
    $returnRows = @($allRows | Where-Object { "$(Get-PimRowProp -Row $_ -Names @('Action'))".Trim() -ieq 'ReturnToEngine' })
    $rows = @($allRows | Where-Object { "$(Get-PimRowProp -Row $_ -Names @('Action'))".Trim() -ine 'ReturnToEngine' })
    if (-not $Context['__pimWhatIf']) {
        try { Invoke-PimAccessPackageReturnRows -Context $Context -State $state -Rows $returnRows; Update-PimAccessPackageReleasedState -Context $Context -State $state }
        catch { Add-PimAccessPackageWarning -Context $Context -Message "the released groups could not be updated: $($_.Exception.Message). [ACCESS-PACKAGE-BINDING-WRITE]" }
        # An intent older than its window, or whose definition went away, can never be adopted: it is cleared.
        if ($state.record.intent) {
            $i = $state.record.intent
            $at = ConvertTo-PimAssignmentUtc $i.atUtc
            $still = if ("$($i.kind)" -eq 'package') { [bool](@($rows | Where-Object { -not (Test-PimRowIsRemove $_) -and "$(Get-PimRowProp -Row $_ -Names @('AccessPackageName'))".Trim() -ceq "$($i.name)" }).Count) } else { [bool]$rows.Count }
            if (-not $still -or $null -eq $at -or ([datetime]::UtcNow - $at).TotalMinutes -gt 15) {
                $state.record.intent = $null
                try { Save-PimAccessPackageBindingState -State $state } catch { Add-PimAccessPackageWarning -Context $Context -Message "an expired create intent could not be cleared: $($_.Exception.Message). [ACCESS-PACKAGE-BINDING-WRITE]" }
            }
        }
    }
    if ($state.record.released.Count) {
        $names = @($state.record.released.Keys | ForEach-Object { "$($state.record.released[$_].tag)" } | Sort-Object)
        Add-PimAccessPackageWarning -Context $Context -Message ("{0} group(s) were released from an access package and their old rows have not been reviewed ({1}); the engine creates nothing for them. To hand one back: {2}. [ACCESS-PACKAGE-RELEASED]" -f $names.Count, ($names -join ', '), (Get-PimAccessPackageReleasedSteps))
    }
    $bound = [int]$state.record.bindings.Count
    # The state of every package for the Manager (report-only, pim.Settings 'AccessPackageStatus'): active / waiting / paused / off.
    $status = @{}
    $setStatus = { param($n, $s, $why) $nn = "$n".Trim(); if ($nn) { $status[$nn.ToLowerInvariant()] = @{ name = $nn; state = $s; reason = "$why" } } }
    $rowName = { param($r) "$(Get-PimRowProp -Row $r -Names @('AccessPackageName'))".Trim() }
    if (-not (Test-PimAccessPackagesEnabled)) {
        if ($bound) { Add-PimAccessPackageWarning -Context $Context -Message ("access packages are switched off (AccessPackagesEnabled): the {0} bound group(s) are handed back to the engine -- their members follow the group rows again (removals go through the removal budget and the guards). The bindings are kept: switching it on again gives the groups back to their packages. [ACCESS-PACKAGE-OFF-HANDED-BACK]" -f $bound) }
        foreach ($r in $rows) { & $setStatus (& $rowName $r) 'off' 'access packages are switched off in Settings' }
        Save-PimAccessPackageStatus -Context $Context -Packages $status -Licence $null
        return @()
    }
    if (-not $rows.Count) {
        if ($bound) { Add-PimAccessPackageWarning -Context $Context -Message ("{0} group(s) are bound to access packages that have no definition any more; the members stay with the packages. To hand a group back, add an Action=Remove row for its package. [ACCESS-PACKAGE-BINDING-ORPHAN]" -f $bound) }
        Save-PimAccessPackageStatus -Context $Context -Packages $status -Licence $null
        return @()
    }
    $lic = Get-PimAccessPackageLicence
    $removalOnly = $false
    if (-not $lic.ok) {
        foreach ($r in $rows) { if (-not (Test-PimRowIsRemove $r)) { & $setStatus (& $rowName $r) 'paused' "nothing is built: $($lic.reason)" } }
        Save-PimAccessPackageStatus -Context $Context -Packages $status -Licence $lic
        $removes = @($rows | Where-Object { Test-PimRowIsRemove $_ })
        if (-not $removes.Count) {
            Add-PimAccessPackageWarning -Context $Context -Message ("{0} access package(s) are defined but nothing was built: {1}. Existing bindings stand. To hand a group back, add an Action=Remove row for its package: retiring does not wait for the licence. [ACCESS-PACKAGE-LICENCE]" -f $rows.Count, $lic.reason)
            return @()
        }
        Add-PimAccessPackageWarning -Context $Context -Message ("{0} access package(s) are defined but nothing is built: {1}. Only the {2} Action=Remove row(s) are carried out. [ACCESS-PACKAGE-LICENCE]" -f $rows.Count, $lic.reason, $removes.Count)
        $removalOnly = $true
    }
    Ensure-PimContextLoaded
    $defs = @(Get-PimGroupDefinitionRows -IncludeRetired)
    $nest = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Groups')
    $owned = Get-PimSolutionOwnedGroups
    $ByTag = @{}; foreach ($t in @($owned.byTag.Keys)) { $ByTag["$t".ToLowerInvariant()] = "$($owned.byTag[$t])" }
    $out = New-Object System.Collections.Generic.List[object]
    $remove = New-Object System.Collections.Generic.List[object]
    if ($removalOnly) { $Context['apOnlyNames'] = @{} }
    foreach ($r in $rows) {
        $d = ConvertTo-PimAccessPackageDefinition -Row $r
        foreach ($t in @($d.groupTags)) { $g = $ByTag["$t".ToLowerInvariant()]; if ($g) { $Context['apNamedGroupIds']["$g".ToLowerInvariant()] = $true } }
        # PAUSED BY AN ADMINISTRATOR: nothing at all is written for it (not even a retirement) and its live package is left out whole.
        if ($d.paused) {
            if ($d.name) { $Context['apHeldNames'][$d.name.ToLowerInvariant()] = $true } else { $Context['apUnnamedInvalid'] = $true }
            & $setStatus $d.name 'paused' $(if ("$($d.pauseReason)".Trim()) { "paused by an administrator: $($d.pauseReason)" } else { 'paused by an administrator' })
            Add-PimAccessPackageWarning -Context $Context -Message ("package '{0}' is paused by an administrator; nothing is changed for it until it is resumed. [ACCESS-PACKAGE-PAUSED]" -f $(if ($d.name) { $d.name } else { '(no name)' }))
            continue
        }
        if ($d.isRemove) { if ($d.name) { $remove.Add($r); & $setStatus $d.name 'retiring' 'an Action=Remove row retires it'; if ($removalOnly) { $Context['apOnlyNames'][$d.name.ToLowerInvariant()] = $true } } else { $Context['apUnnamedInvalid'] = $true }; continue }
        if ($removalOnly) { continue }
        $bad = @(@($d.problems) + @(Get-PimAccessPackageGroupProblems -Definition $d -GroupDefinitions $defs -Nestings $nest))
        $gids = New-Object System.Collections.Generic.List[string]
        $waiting = New-Object System.Collections.Generic.List[string]
        foreach ($t in @($d.groupTags)) {
            $g = $ByTag["$t".ToLowerInvariant()]
            if ($g) {
                # IN DOUBT = PAUSE: a group of that name PIM did not create (or cannot prove it created) is never used for a package.
                $dn = "$(@($defs | Where-Object { "$($_.GroupTag)" -ieq "$t" } | Select-Object -First 1 | ForEach-Object { $_.GroupName }))"
                if (-not $dn) { $dn = "$($owned.byId["$g"].name)" }
                $doubt = Get-PimAccessPackageGroupDoubt -Name $dn -Id "$g"
                if ($doubt) { $bad += $doubt } else { $gids.Add($g) }
            } elseif (-not @($bad | Where-Object { "$_" -like "*'$t'*" }).Count) {
                $nm = "$(@($defs | Where-Object { "$($_.GroupTag)" -ieq "$t" } | Select-Object -First 1 | ForEach-Object { $_.GroupName }))"
                $doubt = if ($nm) { Get-PimAccessPackageGroupDoubt -Name $nm -Id '' } else { '' }
                if ($doubt) { $bad += $doubt } else { $bad += "group '$t' does not exist in the tenant yet"; $waiting.Add("$t") }
            }
        }
        $reqGroup = ''
        if ($d.requestScope -ieq 'Group') { $reqGroup = "$($ByTag["$($d.requestGroupTag)".ToLowerInvariant()])"; if (-not $reqGroup) { $bad += "RequestGroupTag '$($d.requestGroupTag)' is not a PIM group that exists" } }
        $stageSubjects = New-Object System.Collections.Generic.List[object]
        foreach ($st in @($d.stages)) {
            $sub = @(foreach ($x in @($st)) { $s = Resolve-PimAccessPackageSubject -Token "$x" -ByTag $ByTag; if ($s) { $s } else { $bad += "approver '$x' could not be resolved" } })
            $stageSubjects.Add($sub)
        }
        $revSubjects = @(foreach ($x in @($d.reviewers)) { $s = Resolve-PimAccessPackageSubject -Token "$x" -ByTag $ByTag; if ($s) { $s } else { $bad += "reviewer '$x' could not be resolved" } })
        if (@($bad).Count) {
            # Only "its new group is not created yet" is waiting (the Groups scope creates it first); every other reason is a PAUSE.
            $onlyWaiting = ($waiting.Count -gt 0 -and @($bad).Count -eq $waiting.Count)
            Add-PimAccessPackageWarning -Context $Context -Message ("package '{0}' is {1}: {2} [{3}]" -f $(if ($d.name) { $d.name } else { '(no name)' }), $(if ($onlyWaiting) { 'not applied yet' } else { 'PAUSED -- nothing is written for it' }), (@($bad) -join '; '), $(if ($onlyWaiting) { 'ACCESS-PACKAGE-DEFINITION' } else { 'ACCESS-PACKAGE-PAUSED' }))
            & $setStatus $d.name $(if ($onlyWaiting) { 'waiting' } else { 'paused' }) (@($bad) -join '; ')
            # An invalid definition must never read as "gone": its live package is left out of this run, whole.
            if ($d.name) { $Context['apHeldNames'][$d.name.ToLowerInvariant()] = $true } else { $Context['apUnnamedInvalid'] = $true }
            continue
        }
        & $setStatus $d.name 'active' ''
        $row = [pscustomobject]@{
            PackageName = $d.name; GroupIds = $gids.ToArray(); RequestScope = $d.requestScope; RequestGroupId = $reqGroup; StageSubjects = $stageSubjects.ToArray()
            RequireJustification = $d.requireJustification; MaxDays = $d.maxDays; AllowExtension = $d.allowExtension; ReviewCadence = $d.reviewCadence; ReviewerSubjects = $revSubjects; ReviewNoResponse = $d.reviewNoResponse; Notes = $d.notes
            Fingerprint = ''
        }
        $row.Fingerprint = Get-PimAccessPackageDesiredFingerprint -Desired $row
        $Context['apDesiredByName'][$d.name.ToLowerInvariant()] = $row
        $out.Add($row)
    }
    $Context['apRemoveRows'] = $remove.ToArray()
    $Context['apActive'] = $true
    Save-PimAccessPackageStatus -Context $Context -Packages $status -Licence $lic
    return $out.ToArray()
}

function Resolve-PimAccessPackageIntent {
    <#
      PURE. The create recorded in the intent, if exactly one object answers it: same kind, the exact name, created within 5 minutes either side of the intent. The ONLY way an object this
      install did not record the id of can be adopted, and only the object of that one interrupted create. Anything else is $null. An object that does not carry createdDateTime is NEVER adopted.
      UNVERIFIED: that Graph returns createdDateTime on a catalog and a package (documented, not observed on a tenant); if it does not, adoption simply never happens and the object is refused as foreign.
    #>
    param([Parameter(Mandatory)][hashtable]$Record, [string]$Kind, [object[]]$Candidates = @())
    $i = $Record.intent
    if ($null -eq $i -or "$($i.kind)" -ne $Kind) { return $null }
    $at = ConvertTo-PimAssignmentUtc $i.atUtc
    if ($null -eq $at) { return $null }
    $hits = @(@($Candidates) | Where-Object {
        if ($null -eq $_ -or "$($_.displayName)" -cne "$($i.name)") { return $false }
        $c = ConvertTo-PimAssignmentUtc $_.createdDateTime
        return ($null -ne $c -and $c -ge $at.AddMinutes(-5) -and $c -le $at.AddMinutes(5)) })
    if ($hits.Count -eq 1) { return $hits[0] }
    return $null
}

function Update-PimAccessPackageGone {
    <#
      A package this install created that a COMPLETE read-back confirms is gone, or a group that is no longer a scope of its recorded package, ends the binding into the released state. Confirmed means the same
      as the Remove-row rule: found missing by a second read at least 10 minutes after the first (Test-PimAccessPackageGoneConfirmed); a 404 on the package itself, never an empty list. A read that cannot
      confirm it changes nothing. Also how a group removal whose save lost a compare-and-swap converges by itself. -LiveRows: the complete read of this install's packages.
    #>
    param([hashtable]$Context, [object]$State, [hashtable]$LiveIds = @{}, [object[]]$LiveRows = @())
    $em = Get-PimEntitlementManagementPath
    $rec = $State.record
    $before = [int]$rec.goneSeen.Count
    $changed = $false
    foreach ($k in @($rec.packages.Keys)) {
        $key = "pkg:$k"
        if ($LiveIds.ContainsKey($k)) { $rec.goneSeen.Remove($key); continue }
        $p = $rec.packages[$k]
        $gone = $false; $read = $false
        try { [void](Invoke-PimGraph -Path "$em/accessPackages/$($p.id)"); $read = $true } catch { $gone = [bool](Test-PimNotFoundAnswer -Message "$($_.Exception.Message)"); if (-not $gone) { Add-PimAccessPackageWarning -Context $Context -Message "package '$($p.name)' could not be confirmed gone ($($_.Exception.Message)); its binding stands." } }
        if ($read) { $rec.goneSeen.Remove($key); continue }
        if (-not $gone) { continue }
        if (-not (Test-PimAccessPackageGoneConfirmed -Record $rec -Key $key)) { continue }
        if (Remove-PimAccessPackageBindingEntry -Record $rec -PackageId "$($p.id)" -Reason 'the package no longer exists') { $changed = $true }
        $rec.packages.Remove($k); $changed = $true
        Add-PimAccessPackageWarning -Context $Context -Message ("package '{0}' no longer exists in Entra; its bound groups are released and the engine creates nothing for them until they are reviewed. {1}. [ACCESS-PACKAGE-RELEASED]" -f $p.name, "To hand one back: $(Get-PimAccessPackageReleasedSteps)")
    }
    foreach ($row in @($LiveRows)) {
        $pid2 = "$($row.Id)"
        $liveGroups = @{}; foreach ($g in @($row.GroupIds)) { $liveGroups["$g".ToLowerInvariant()] = $true }
        foreach ($gk in @($rec.bindings.Keys)) {
            if (-not (@($rec.bindings[$gk].packages) -contains $pid2)) { continue }
            $key = "scope:$($pid2.ToLowerInvariant()):$gk"
            if ($liveGroups.ContainsKey($gk)) { $rec.goneSeen.Remove($key); continue }
            if (-not (Test-PimAccessPackageGoneConfirmed -Record $rec -Key $key)) { continue }
            $tag = "$($rec.bindings[$gk].tag)"
            if (Remove-PimAccessPackageBindingEntry -Record $rec -PackageId $pid2 -GroupId $gk -Reason 'the group is no longer a scope of its package') { $changed = $true }
            Add-PimAccessPackageWarning -Context $Context -Message ("group '{0}' is no longer part of package '{1}'; it is released and the engine creates nothing for it until it is reviewed. {2}. [ACCESS-PACKAGE-RELEASED]" -f $tag, $row.PackageName, "To hand it back: $(Get-PimAccessPackageReleasedSteps)")
        }
    }
    if ($changed -or [int]$rec.goneSeen.Count -ne $before) { Save-PimAccessPackageBindingState -State $State }
}

function Test-PimAccessPackageGoneConfirmed {
    <# PURE on -Record. The first read that finds it missing is recorded; the second, at least 10 minutes later (the rule Select-PimConfirmedAbsentRemoveRows uses), confirms it. #>
    param([Parameter(Mandatory)][hashtable]$Record, [Parameter(Mandatory)][string]$Key, [datetime]$NowUtc = [datetime]::UtcNow)
    $first = ConvertTo-PimAssignmentUtc $Record.goneSeen[$Key]
    if ($null -eq $first) { $Record.goneSeen[$Key] = $NowUtc.ToString('o'); return $false }
    if (($NowUtc - $first).TotalMinutes -lt 10) { return $false }
    $Record.goneSeen.Remove($Key)
    return $true
}

function Get-PimAccessPackageLive {
    <#
      GetLive. Only runs against Graph when definitions exist and the licence holds (or for retirements). Only PIM's own: the catalog this install recorded, the packages it recorded, or the single object
      of a recorded interrupted create. A same-named catalog it did not create = NOT CHECKED, nothing done, said so. A package it did not create is not read as its own, and a definition of that name is
      refused (Invoke-PimAccessPackageCreate). A definition that is invalid leaves its live package out: never "gone".
    #>
    param([hashtable]$Context)
    if (-not $Context['apActive']) { return @() }
    if ($Context['apUnnamedInvalid']) { $Context['__pimLiveReadError'] = 'an access package row has no usable AccessPackageName, so what is "gone" cannot be told; nothing is compared this run'; return @() }
    $em = Get-PimEntitlementManagementPath
    $name = (Get-PimAccessPackageCatalogName)
    $state = Get-PimAccessPackageBindingRecord
    if (-not $state.ok) { $Context['__pimLiveReadError'] = "the record of what this install created could not be read: $($state.error)"; return @() }
    $rec = $state.record
    $write = (-not $Context['__pimWhatIf'])
    $cats = @()
    try { $cats = @(Invoke-PimGraph -All -Path "$em/catalogs?`$filter=displayName eq '$name'" | Where-Object { $null -ne $_ -and "$($_.displayName)" -ieq $name }) }
    catch { $Context['__pimLiveReadError'] = "the access package catalog could not be read (the engine needs $(Get-PimAccessPackageRightName), granted only when a package is defined): $($_.Exception.Message)"; return @() }
    $mine = @($cats | Where-Object { "$($rec.catalogId)".Trim() -and "$($_.id)" -ieq "$($rec.catalogId)" })
    if ($cats.Count -and -not $mine.Count) {
        $adopt = Resolve-PimAccessPackageIntent -Record $rec -Kind 'catalog' -Candidates $cats
        if ($adopt) {
            if ($write) { $rec.catalogId = "$($adopt.id)"; $rec.intent = $null; try { Save-PimAccessPackageBindingState -State $state } catch { $Context['__pimLiveReadError'] = "the recorded catalog could not be saved: $($_.Exception.Message)"; return @() } }
            $mine = @($adopt)
        } else {
            $Context['__pimLiveReadError'] = ("a catalog named '{0}' exists that this install did not create (a name match is not ownership); nothing was done. Rename or remove that catalog. [ACCESS-PACKAGE-CATALOG-NOT-OURS]" -f $name)
            return @()
        }
    }
    if (-not $mine.Count) {
        $Context['apCatalogId'] = ''
        if ($write -and "$($rec.catalogId)".Trim() -and $rec.packages.Count) {
            try { Update-PimAccessPackageGone -Context $Context -State $state -LiveIds @{} } catch { Add-PimAccessPackageWarning -Context $Context -Message "bindings of a gone catalog could not be ended: $($_.Exception.Message). [ACCESS-PACKAGE-BINDING-WRITE]" }
        }
        return @()
    }
    $cid = "$($mine[0].id)"
    $Context['apCatalogId'] = $cid
    $pkgs = @()
    try {
        $pkgs = @(Invoke-PimGraph -All -Path "$em/accessPackages?`$filter=catalog/id eq '$cid'&`$expand=catalog,resourceRoleScopes(`$expand=role,scope),assignmentPolicies" | Where-Object { $null -ne $_ -and "$($_.catalog.id)" -ieq $cid })
    } catch { $Context['__pimLiveReadError'] = "the access packages could not be read: $($_.Exception.Message)"; return @() }
    if ($rec.intent -and "$($rec.intent.kind)" -eq 'package') {
        $adopt = Resolve-PimAccessPackageIntent -Record $rec -Kind 'package' -Candidates @($pkgs | Where-Object { -not $rec.packages.ContainsKey("$($_.id)".ToLowerInvariant()) })
        if ($adopt -and $write) {
            $rec.packages["$($adopt.id)".ToLowerInvariant()] = @{ id = "$($adopt.id)"; name = "$($adopt.displayName)" }; $rec.intent = $null
            try { Save-PimAccessPackageBindingState -State $state } catch { $Context['__pimLiveReadError'] = "the recorded package could not be saved: $($_.Exception.Message)"; return @() }
        }
    }
    $live = New-Object System.Collections.Generic.List[object]
    $foreign = @{}; $liveIds = @{}
    foreach ($p in $pkgs) {
        if (-not $rec.packages.ContainsKey("$($p.id)".ToLowerInvariant())) { $foreign["$($p.displayName)".ToLowerInvariant()] = $true; continue }
        $liveIds["$($p.id)".ToLowerInvariant()] = $true
        $lr = ConvertFrom-PimAccessPackageLive -Package $p
        if ($Context['apHeldNames'].ContainsKey("$($lr.PackageName)".ToLowerInvariant())) { continue }
        if ($Context['apOnlyNames'] -is [hashtable] -and -not $Context['apOnlyNames'].ContainsKey("$($lr.PackageName)".ToLowerInvariant())) { continue }
        $live.Add($lr)
    }
    $Context['apForeignNames'] = $foreign
    $rows = $live.ToArray()
    [void](Add-PimAccessPackageDriftFindings -Context $Context -LiveRows $rows)
    foreach ($k in @($rec.bindings.Keys)) {
        if (-not $Context['apNamedGroupIds'].ContainsKey($k)) { Add-PimAccessPackageWarning -Context $Context -Message ("group '{0}' is bound to an access package but no definition names it; its members stay with the package. To hand it back, add an Action=Remove row for the package. [ACCESS-PACKAGE-BINDING-ORPHAN]" -f "$($rec.bindings[$k].tag)") }
    }
    if ($write) {
        Sync-PimAccessPackageBindingsFromLive -Context $Context -LiveRows $rows
        $state2 = Get-PimAccessPackageBindingRecord
        if ($state2.ok) { try { Update-PimAccessPackageGone -Context $Context -State $state2 -LiveIds $liveIds -LiveRows $rows } catch { Add-PimAccessPackageWarning -Context $Context -Message "bindings of a gone package could not be ended: $($_.Exception.Message). [ACCESS-PACKAGE-BINDING-WRITE]" } }
    }
    return $rows
}

function Write-PimAccessPackageBindingsReadBack {
    <#
      The ONLY path that writes a binding: this live row is a read-back of a package in PIM's catalog with an eligible member scope on each group, AND a policy. Only groups in -AllowedGroupIds (the direct groups a
      valid definition names) are bound. THROWS when it cannot be saved.
    #>
    param([Parameter(Mandatory)][object]$LiveRow, [string[]]$AllowedGroupIds = @(), [string]$PackageName = '')
    if (-not "$($LiveRow.PolicyId)".Trim()) { return }   # the policy was not read back: no binding yet
    $state = Get-PimAccessPackageBindingRecord
    if (-not $state.ok) { throw "the binding record could not be read: $($state.error)" }
    $allowed = @{}; foreach ($g in @($AllowedGroupIds)) { $allowed["$g".ToLowerInvariant()] = $true }
    $owned = Get-PimSolutionOwnedGroups
    # OWNER 2026-11-12: a binding is written ONLY for a group created for THIS package (both markers) -- never an existing group.
    $pkgName = if ("$PackageName".Trim()) { "$PackageName".Trim() } else { "$($LiveRow.PackageName)".Trim() }
    $dedicated = @{}
    foreach ($def in @(Get-PimGroupDefinitionRows -IncludeRetired)) { if (Test-PimAccessPackageDedicatedDefinition -Definition $def -PackageName $pkgName) { $dedicated["$($def.GroupTag)".Trim().ToLowerInvariant()] = $true } }
    $changed = $false
    foreach ($gid in @($LiveRow.GroupIds)) {
        if (-not $allowed.ContainsKey("$gid".ToLowerInvariant()) -or -not $owned.byId.ContainsKey("$gid")) { continue }
        if (-not $dedicated.ContainsKey("$($owned.byId["$gid"].tag)".Trim().ToLowerInvariant())) { Write-Warning "  [AccessPackages] group '$($owned.byId["$gid"].tag)' was not created for package '$pkgName'; it is NOT bound. [ACCESS-PACKAGE-PAUSED]"; continue }
        if (Add-PimAccessPackageBindingEntry -Record $state.record -GroupId "$gid" -Tag "$($owned.byId["$gid"].tag)" -PackageId "$($LiveRow.Id)") { $changed = $true }
    }
    if ($changed) { Save-PimAccessPackageBindingState -State $state }
}

function Sync-PimAccessPackageBindingsFromLive {
    <# A read-back of this install's packages (a binding whose earlier write failed is written now). Only for what a valid definition names. Never fails the scope. #>
    param([hashtable]$Context, [object[]]$LiveRows = @())
    foreach ($row in @($LiveRows)) {
        $d = $Context['apDesiredByName']["$($row.PackageName)".ToLowerInvariant()]
        if ($null -eq $d) { continue }
        try { Write-PimAccessPackageBindingsReadBack -LiveRow $row -AllowedGroupIds @($d.GroupIds) }
        catch { Add-PimAccessPackageWarning -Context $Context -Message "the binding of package '$($row.PackageName)' could not be recorded: $($_.Exception.Message); the engine keeps managing its group until it is. [ACCESS-PACKAGE-BINDING-WRITE]" }
    }
}

function Get-PimAccessPackageDriftPrincipals {
    <# PURE. A live MEMBER schedule of a package-owned group whose principal holds no delivered assignment of the package: a member added outside it. Reported, never changed. #>
    param([object[]]$Memberships = @(), [object[]]$Assignments = @())
    $have = @{}
    foreach ($a in @($Assignments)) { if ($null -ne $a -and "$($a.target.objectId)".Trim()) { $have["$($a.target.objectId)".Trim().ToLowerInvariant()] = $true } }
    return @($Memberships | Where-Object { $null -ne $_ -and "$($_.graphAssignmentType)" -ine 'activated' -and -not "$($_.accessId)".Trim().Equals('owner', [StringComparison]::OrdinalIgnoreCase) -and -not $have.ContainsKey("$($_.principalId)".Trim().ToLowerInvariant()) })
}

function Add-PimAccessPackageDriftFindings {
    <# Report-only: one finding per owned group that has members from outside its package. Never fails the scope. #>
    param([hashtable]$Context, [object[]]$LiveRows = @())
    if (-not ($Context['__pimLiveFindings'] -is [System.Collections.Generic.List[object]])) { return 0 }
    $em = Get-PimEntitlementManagementPath
    $owned = Get-PimSolutionOwnedGroups
    $n = 0
    foreach ($pkg in @($LiveRows)) {
        try {
            $asg = @(Invoke-PimGraph -All -Path "$em/assignments?`$filter=accessPackage/id eq '$($pkg.Id)' and state eq 'delivered'&`$expand=target")
            foreach ($gid in @($pkg.GroupIds)) {
                if (-not $owned.byId.ContainsKey("$gid")) { continue }
                $tag = "$($owned.byId["$gid"].tag)"
                $extra = @(Get-PimAccessPackageDriftPrincipals -Memberships @(Get-PimLiveGroupMembership -GroupId "$gid" -GroupTag $tag) -Assignments $asg)
                if ($extra.Count) {
                    $msg = ("group '{0}' is delivered by package '{1}' but has {2} member(s) added outside the package; the engine leaves them (report only)." -f $tag, $pkg.PackageName, $extra.Count)
                    $Context['__pimLiveFindings'].Add([pscustomobject]@{ kind = 'access-package-member-drift'; scope = 'AccessPackages'; group = $tag; package = "$($pkg.PackageName)"; members = $extra.Count
                        principals = @($extra | ForEach-Object { "$($_.principalId)" }); label = $msg; message = $msg })
                    $n++
                }
            }
        } catch { Write-Warning "  [AccessPackages] the member-drift check of package '$($pkg.PackageName)' could not be made: $($_.Exception.Message)" }
    }
    return $n
}

# ---- apply --------------------------------------------------------------------------------------------------------------------
function Get-PimAccessPackageRoleScope {
    <#
      A group resource in PIM's catalog, its eligible member role and its scope: adds the group to the catalog first when it is not there, then re-reads it.
      Refuses when the catalog lists no eligible member role (the group is not PIM-managed, or the shape is not what the documentation shows).
    #>
    param([string]$CatalogId, [string]$GroupId)
    $em = Get-PimEntitlementManagementPath
    $read = { @(Invoke-PimGraph -All -Path "$em/catalogs/$CatalogId/resources?`$filter=originId eq '$GroupId'&`$expand=scopes" | Where-Object { $null -ne $_ -and "$($_.originId)" -ieq $GroupId }) }
    $res = @(& $read)
    if (-not $res.Count) {
        Invoke-PimGraph -Method POST -Path "$em/resourceRequests" -Body ([ordered]@{ requestType = 'adminAdd'; resource = [ordered]@{ originId = $GroupId; originSystem = 'AadGroup' }; catalog = [ordered]@{ id = $CatalogId } }) | Out-Null
        foreach ($i in 1..4) { $res = @(& $read); if ($res.Count) { break }; if ($script:PimAccessPackageWaitSeconds -gt 0) { Start-Sleep -Seconds $script:PimAccessPackageWaitSeconds } }
    }
    if (-not $res.Count) { throw "AccessPackages: group $GroupId did not appear in the catalog after it was requested" }
    $r = $res[0]
    $roles = @(Invoke-PimGraph -All -Path "$em/catalogs/$CatalogId/resourceRoles?`$filter=(originSystem eq 'AadGroup' and resource/id eq '$($r.id)')&`$expand=resource")
    $role = Select-PimAccessPackageEligibleRole -Roles $roles
    if ($null -eq $role) { throw "AccessPackages: the catalog lists no 'Eligible Member' role for group $GroupId -- it must be a PIM-managed group. Nothing was granted (never falls back to active membership)." }
    $scope = @(@($r.scopes) | Where-Object { $null -ne $_ -and "$($_.originId)" -ieq $GroupId } | Select-Object -First 1)
    return [pscustomobject]@{ resource = $r; role = $role; scope = $(if ($scope.Count) { $scope[0] } else { $null }) }
}

function New-PimAccessPackageRoleScopeBody {
    <# PURE. The accessPackageResourceRoleScope (v1.0 shape; the role and the scope come from the catalog's own lists). #>
    param([Parameter(Mandatory)][object]$Resource, [Parameter(Mandatory)][object]$Role, [AllowNull()][object]$Scope, [Parameter(Mandatory)][string]$GroupId)
    $roleBody = [ordered]@{ displayName = "$($Role.displayName)"; originSystem = "$($Role.originSystem)"; originId = "$($Role.originId)"; resource = [ordered]@{ id = "$($Resource.id)"; originId = "$($Resource.originId)"; originSystem = "$($Resource.originSystem)" } }
    if ("$($Role.id)".Trim()) { $roleBody['id'] = "$($Role.id)" }
    $scopeBody = [ordered]@{ originId = $GroupId; originSystem = 'AadGroup' }
    if ($Scope -and "$($Scope.id)".Trim()) { $scopeBody['id'] = "$($Scope.id)" }
    return [ordered]@{ role = $roleBody; scope = $scopeBody }
}

function Add-PimAccessPackageGroupScope {
    param([string]$CatalogId, [string]$PackageId, [string]$GroupId)
    $em = Get-PimEntitlementManagementPath
    $rs = Get-PimAccessPackageRoleScope -CatalogId $CatalogId -GroupId $GroupId
    Invoke-PimGraph -Method POST -Path "$em/accessPackages/$PackageId/resourceRoleScopes" -Body (New-PimAccessPackageRoleScopeBody -Resource $rs.resource -Role $rs.role -Scope $rs.scope -GroupId $GroupId) | Out-Null
}

function Get-PimAccessPackageLiveItem {
    <# Read one package back through the expanded read every live row comes from. #>
    param([string]$PackageId, [string]$CatalogId)
    $em = Get-PimEntitlementManagementPath
    $pkg = Invoke-PimGraph -Path "$em/accessPackages/$PackageId`?`$expand=catalog,resourceRoleScopes(`$expand=role,scope),assignmentPolicies"
    if ($pkg -and "$($pkg.catalog.id)" -ine "$CatalogId") { throw 'AccessPackages: read-back found the package outside PIM''s catalog' }
    return (ConvertFrom-PimAccessPackageLive -Package $pkg)
}

function Assert-PimAccessPackageReadBack {
    <# After a write: the package read back must carry what the definition asks for (with -ExtraGroupIds still in place when their removal is planned). Returns the read-back. #>
    param([Parameter(Mandatory)][object]$Desired, [string]$PackageId, [string]$CatalogId, [string[]]$ExtraGroupIds = @())
    $expect = Get-PimAccessPackageDesiredFingerprint -Desired $Desired -GroupIds @(@($Desired.GroupIds) + @($ExtraGroupIds))
    $got = $null
    foreach ($i in 1..4) {
        $got = Get-PimAccessPackageLiveItem -PackageId $PackageId -CatalogId $CatalogId
        if ("$($got.Fingerprint)" -ceq "$expect") { return $got }
        if ($script:PimAccessPackageWaitSeconds -gt 0) { Start-Sleep -Seconds $script:PimAccessPackageWaitSeconds }
    }
    throw "AccessPackages: read-back of '$($Desired.PackageName)' does not match the definition (asked: $expect / found: $($got.Fingerprint))"
}

function Clear-PimAccessPackageIntentOnRefusal {
    <# A POST that Graph definitively refused (HTTP 4xx) created nothing: its intent is cleared so no later object can be adopted under it. A timeout or a 5xx may have created it: the intent stays, within its window. #>
    param([Parameter(Mandatory)][object]$State, [string]$Message)
    if ("$Message" -notmatch 'HTTP 4\d\d') { return }
    $State.record.intent = $null
    try { Save-PimAccessPackageBindingState -State $State } catch { Write-Warning "  [AccessPackages] a refused create's intent could not be cleared: $($_.Exception.Message)" }
}

function Invoke-PimAccessPackageCreate {
    <# ApplyCreate. The intent is saved BEFORE a create, every created id right after it, and the binding only after the read-back. A same-named package this install did not create is refused. #>
    param([Parameter(Mandatory)][object]$Item, [hashtable]$Context)
    $d = $Item.desired
    $em = Get-PimEntitlementManagementPath
    if ($Context['apForeignNames'] -is [hashtable] -and $Context['apForeignNames'].ContainsKey("$($d.PackageName)".ToLowerInvariant())) {
        throw "AccessPackages: REFUSED -- a package named '$($d.PackageName)' exists in the catalog that this install did not create; a name match is not ownership. Rename it or the definition."
    }
    $state = Get-PimAccessPackageBindingRecord
    if (-not $state.ok) { throw "AccessPackages: the record could not be read: $($state.error)" }
    $rec = $state.record
    $cid = "$($Context['apCatalogId'])"
    if (-not $cid) {
        $rec.intent = @{ kind = 'catalog'; name = (Get-PimAccessPackageCatalogName); atUtc = (Get-Date).ToUniversalTime().ToString('o') }
        Save-PimAccessPackageBindingState -State $state
        try { $cat = Invoke-PimGraph -Method POST -Path "$em/catalogs" -Body ([ordered]@{ displayName = (Get-PimAccessPackageCatalogName); description = 'Access packages managed by PIM Manager.'; state = 'published'; isExternallyVisible = $false }) }
        catch { Clear-PimAccessPackageIntentOnRefusal -State $state -Message "$($_.Exception.Message)"; throw }
        $cid = "$($cat.id)"
        if (-not $cid) { throw 'AccessPackages: the catalog could not be created' }
        $rec.catalogId = $cid; $rec.intent = $null
        Save-PimAccessPackageBindingState -State $state
        Register-PimNewObjectThisRun -Id $cid -Kind 'accessPackageCatalog'
        $Context['apCatalogId'] = $cid
    }
    $rec.intent = @{ kind = 'package'; name = "$($d.PackageName)"; atUtc = (Get-Date).ToUniversalTime().ToString('o') }
    Save-PimAccessPackageBindingState -State $state
    try { $pkg = Invoke-PimGraph -Method POST -Path "$em/accessPackages" -Body ([ordered]@{ displayName = "$($d.PackageName)"; description = "$(if ("$($d.Notes)".Trim()) { $d.Notes } else { 'Managed by PIM Manager.' })"; isHidden = $false; catalog = [ordered]@{ id = $cid } }) }
    catch { Clear-PimAccessPackageIntentOnRefusal -State $state -Message "$($_.Exception.Message)"; throw }
    if (-not "$($pkg.id)") { throw "AccessPackages: package '$($d.PackageName)' was not created" }
    $rec.packages["$($pkg.id)".ToLowerInvariant()] = @{ id = "$($pkg.id)"; name = "$($d.PackageName)" }; $rec.intent = $null
    Save-PimAccessPackageBindingState -State $state
    foreach ($g in @($d.GroupIds)) { Add-PimAccessPackageGroupScope -CatalogId $cid -PackageId "$($pkg.id)" -GroupId "$g" }
    Invoke-PimGraph -Method POST -Path "$em/assignmentPolicies" -Body (New-PimAccessPackagePolicyBody -Desired $d -PackageId "$($pkg.id)") | Out-Null
    $got = Assert-PimAccessPackageReadBack -Desired $d -PackageId "$($pkg.id)" -CatalogId $cid
    Write-PimAccessPackageBindingsReadBack -LiveRow $got -AllowedGroupIds @($d.GroupIds)
    Set-PimCreatedThisRunMark -Object $pkg
    return $pkg
}

function Invoke-PimAccessPackageUpdate {
    <# ApplyUpdate. Adds groups and rewrites the policy; NEVER removes a group -- that is a planned, counted removal (Expand-PimAccessPackageRemovals). #>
    param([Parameter(Mandatory)][object]$Item, [hashtable]$Context)
    $d = $Item.desired; $l = $Item.live
    $em = Get-PimEntitlementManagementPath
    $cid = "$($Context['apCatalogId'])"
    Assert-PimAccessPackageOwned -LiveCatalogId "$($l.CatalogId)" -PackageId "$($l.Id)" -Context $Context -What "package '$($l.PackageName)'"
    $want = @{}; foreach ($g in @($d.GroupIds)) { $want["$g".ToLowerInvariant()] = "$g" }
    $have = @{}; foreach ($s in @($l.ScopesByGroup)) { if ($s -and "$($s.scope.originId)".Trim()) { $have["$($s.scope.originId)".ToLowerInvariant()] = "$($s.scope.originId)" } }
    foreach ($k in @($want.Keys)) { if (-not $have.ContainsKey($k)) { Add-PimAccessPackageGroupScope -CatalogId $cid -PackageId "$($l.Id)" -GroupId $want[$k] } }
    $body = New-PimAccessPackagePolicyBody -Desired $d -PackageId "$($l.Id)"
    if ("$($l.PolicyId)".Trim()) { Invoke-PimGraph -Method PUT -Path "$em/assignmentPolicies/$($l.PolicyId)" -Body $body | Out-Null }
    else { Invoke-PimGraph -Method POST -Path "$em/assignmentPolicies" -Body $body | Out-Null }
    $extra = @($have.Keys | Where-Object { -not $want.ContainsKey($_) } | ForEach-Object { $have[$_] })
    $got = Assert-PimAccessPackageReadBack -Desired $d -PackageId "$($l.Id)" -CatalogId $cid -ExtraGroupIds $extra
    Write-PimAccessPackageBindingsReadBack -LiveRow $got -AllowedGroupIds @($d.GroupIds)
    return [pscustomobject]@{ id = "$($l.Id)" }
}

function Get-PimAccessPackageOpenAssignments {
    <# Assignments of one package that have not ended. THROWS when they cannot be read: a removal plan is never made on a guess. #>
    param([string]$PackageId)
    $em = Get-PimEntitlementManagementPath
    return @(Invoke-PimGraph -All -Path "$em/assignments?`$filter=accessPackage/id eq '$PackageId'&`$expand=target" | Where-Object { $null -ne $_ -and "$($_.state)" -ine 'expired' })
}

function Expand-PimAccessPackageRemovals {
    <#
      The provider's ExpandRemovals hook. What Graph would do silently to people is planned here, one item per person, so the removal budget counts each one, a hold holds them all and the audit names each one:
        * a package being retired, while assignments are open -> one item per assignment (the package itself goes once none is left);
        * a group dropped from a package -> one item per assignment that loses it (with none, one item for the scope), all-or-nothing as a group (atomicGroup).
      Update never removes a group; these items do. requiresRelease: the group is on a chain reaching Global Administrator (or the chain cannot be read): held for release by Select-PimAccessPackageHeldRemovals.
    #>
    param([Parameter(Mandatory)][object]$Diff, [hashtable]$Context)
    $out = New-Object System.Collections.Generic.List[object]
    $cache = @{}
    $open = { param($id) if (-not $cache.ContainsKey($id)) { $cache[$id] = @(Get-PimAccessPackageOpenAssignments -PackageId $id) }; , $cache[$id] }
    if (-not @($Diff.remove).Count -and -not @($Diff.update).Count) { return $Diff }
    $nest = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Groups'); $roles = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Roles-Groups')
    $chainReadable = $true
    if ($global:PIM_DesiredResolved -is [hashtable]) { foreach ($e in @('PIM-Assignments-Groups', 'PIM-Assignments-Roles-Groups')) { if ($global:PIM_DesiredResolved.ContainsKey($e) -and -not $global:PIM_DesiredResolved[$e]) { $chainReadable = $false } } }
    $owned = Get-PimSolutionOwnedGroups
    $reach = {
        param($gid)
        if (-not $chainReadable) { return $true }
        $o = $owned.byId["$gid"]
        if ($null -eq $o) { return $true }
        return (Test-PimAccessPackageTagReachesGlobalAdmin -Tag "$($o.tag)" -Nestings $nest -RoleRows $roles)
    }
    foreach ($r in @($Diff.remove)) {
        $l = $r.live
        if ($null -eq $l -or -not "$($l.Id)".Trim()) { $out.Add($r); continue }
        $ga = [bool](@(@($l.GroupIds) | Where-Object { & $reach $_ }).Count -gt 0)
        $asg = @((& $open "$($l.Id)"))
        if (-not $asg.Count) { $r | Add-Member -NotePropertyName requiresRelease -NotePropertyValue $ga -Force; $out.Add($r); continue }
        foreach ($a in $asg) {
            $who = "$($a.target.objectId)"
            $out.Add([pscustomobject]@{ key = ("assignment|{0}|{1}" -f $l.PackageName, $a.id).ToLowerInvariant(); targeted = $true; requiresRelease = $ga
                live = [pscustomobject]@{ apKind = 'assignment'; AssignmentId = "$($a.id)"; PackageId = "$($l.Id)"; PackageName = "$($l.PackageName)"; CatalogId = "$($l.CatalogId)"; principalId = $who; groupIds = @($l.GroupIds) } })
        }
    }
    foreach ($u in @($Diff.update)) {
        $l = $u.live; $d = $u.desired
        if ($null -eq $l -or $null -eq $d) { continue }
        $want = @{}; foreach ($g in @($d.GroupIds)) { $want["$g".ToLowerInvariant()] = $true }
        foreach ($s in @($l.ScopesByGroup)) {
            if ($null -eq $s) { continue }
            $gid = "$($s.scope.originId)".Trim()
            if (-not $gid -or $want.ContainsKey($gid.ToLowerInvariant())) { continue }
            $asg = @((& $open "$($l.Id)"))
            $people = if ($asg.Count) { @($asg) } else { @($null) }
            $ga = [bool](& $reach $gid)
            $atomic = ("scope|{0}|{1}" -f $l.PackageName, $gid).ToLowerInvariant()
            foreach ($a in $people) {
                $who = if ($a) { "$($a.target.objectId)" } else { '' }
                $out.Add([pscustomobject]@{ key = ("scope|{0}|{1}|{2}" -f $l.PackageName, $gid, $(if ($a) { $a.id } else { 'no-assignment' })).ToLowerInvariant(); targeted = $true; requiresRelease = $ga; atomicGroup = $atomic; atomicSize = @($people).Count
                    live = [pscustomobject]@{ apKind = 'scope'; ScopeId = "$($s.id)"; PackageId = "$($l.Id)"; PackageName = "$($l.PackageName)"; CatalogId = "$($l.CatalogId)"; GroupId = $gid; principalId = $who; groupIds = @($gid) } })
            }
        }
    }
    return [pscustomobject]@{ create = @($Diff.create); update = @($Diff.update); remove = $out.ToArray(); nochange = @($Diff.nochange) }
}

function Invoke-PimAccessPackageRemove {
    <#
      ApplyRemove, one planned item:
        assignment  ends one person's assignment (adminRemove)
        scope       removes a group from a package (once; the other people on it are the same removal), reads it back, then ends that group's binding for this package
        (package)   no assignment left: deletes the policies and the package, reads back that it is gone, then ends the binding -- the group moves to RELEASED
      Only ever on what this install created.
    #>
    param([Parameter(Mandatory)][object]$Item, [hashtable]$Context)
    $l = $Item.live
    $em = Get-PimEntitlementManagementPath
    $what = "package '$($l.PackageName)'"
    if ("$($l.apKind)" -eq 'assignment') {
        Assert-PimAccessPackageOwned -LiveCatalogId "$($l.CatalogId)" -PackageId "$($l.PackageId)" -Context $Context -What $what
        try { Invoke-PimGraph -Method POST -Path "$em/assignmentRequests" -Body ([ordered]@{ requestType = 'adminRemove'; assignment = [ordered]@{ id = "$($l.AssignmentId)" } }) | Out-Null }
        catch { if ("$($_.Exception.Message)" -match '(?i)open request|already|pending') { return [pscustomobject]@{ pimApplied = $false; reason = 'an earlier request to end this assignment is still running' } }; throw }
        return [pscustomobject]@{ id = "$($l.AssignmentId)"; ended = $true }
    }
    if ("$($l.apKind)" -eq 'scope') {
        Assert-PimAccessPackageOwned -LiveCatalogId "$($l.CatalogId)" -PackageId "$($l.PackageId)" -Context $Context -What $what
        if (-not ($Context['apDeletedScopes'] -is [hashtable])) { $Context['apDeletedScopes'] = @{} }
        if (-not $Context['apDeletedScopes'].ContainsKey("$($l.ScopeId)")) {
            Invoke-PimGraph -Method DELETE -Path "$em/accessPackages/$($l.PackageId)/resourceRoleScopes/$($l.ScopeId)" | Out-Null
            $got = Get-PimAccessPackageLiveItem -PackageId "$($l.PackageId)" -CatalogId "$($l.CatalogId)"
            if (@($got.GroupIds | Where-Object { "$_" -ieq "$($l.GroupId)" }).Count) { throw "AccessPackages: group $($l.GroupId) is still on $what after its removal" }
            $state = Get-PimAccessPackageBindingRecord
            if (-not $state.ok) { throw "AccessPackages: the binding record could not be read: $($state.error)" }
            if (Remove-PimAccessPackageBindingEntry -Record $state.record -PackageId "$($l.PackageId)" -GroupId "$($l.GroupId)" -Reason 'the group was removed from the package') { Save-PimAccessPackageBindingState -State $state }
            $Context['apDeletedScopes']["$($l.ScopeId)"] = $true
        }
        return [pscustomobject]@{ id = "$($l.ScopeId)"; removedFrom = "$($l.PackageId)" }
    }
    # the package itself
    Assert-PimAccessPackageOwned -LiveCatalogId "$($l.CatalogId)" -PackageId "$($l.Id)" -Context $Context -What $what
    if (@(Get-PimAccessPackageOpenAssignments -PackageId "$($l.Id)").Count) { return [pscustomobject]@{ pimApplied = $false; reason = "assignments of $what are still ending; it is removed on a later run" } }
    $full = Invoke-PimGraph -Path "$em/accessPackages/$($l.Id)?`$expand=assignmentPolicies"
    foreach ($p in @($full.assignmentPolicies)) { if ($null -ne $p -and "$($p.id)".Trim()) { Invoke-PimGraph -Method DELETE -Path "$em/assignmentPolicies/$($p.id)" | Out-Null } }
    Invoke-PimGraph -Method DELETE -Path "$em/accessPackages/$($l.Id)" | Out-Null
    $still = $null
    try { $still = Invoke-PimGraph -Path "$em/accessPackages/$($l.Id)" } catch { if (-not (Test-PimNotFoundAnswer -Message "$($_.Exception.Message)")) { throw } }
    if ($still -and "$($still.id)".Trim()) { throw "AccessPackages: $what is still there after its delete" }
    $state = Get-PimAccessPackageBindingRecord
    if (-not $state.ok) { throw "AccessPackages: the binding record could not be read: $($state.error)" }
    [void](Remove-PimAccessPackageBindingEntry -Record $state.record -PackageId "$($l.Id)" -Reason 'the package was retired')
    $state.record.packages.Remove("$($l.Id)".ToLowerInvariant())
    Save-PimAccessPackageBindingState -State $state
    return [pscustomobject]@{ id = "$($l.Id)"; retired = $true }
}

function Remove-PimAccessPackageAssignmentsOfPrincipal {
    <#
      Offboarding: a person's package assignment would bring their access back, so it ends with the rest, audited. Only this install's packages; none recorded = no call.
      An unreadable record is an error of the offboarding step, never silence. Returns @{ ended; errors }.
    #>
    param([Parameter(Mandatory)][string]$PrincipalId)
    $state = Get-PimAccessPackageBindingRecord
    if (-not $state.ok) { return [pscustomobject]@{ ended = 0; errors = @("the access package record could not be read: $($state.error)") } }
    if (-not $state.record.packages.Count) { return [pscustomobject]@{ ended = 0; errors = @() } }
    $em = Get-PimEntitlementManagementPath
    $ended = 0; $errors = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($state.record.packages.Keys)) {
        $p = $state.record.packages[$k]
        try {
            foreach ($a in @(Invoke-PimGraph -All -Path "$em/assignments?`$filter=accessPackage/id eq '$($p.id)' and target/objectId eq '$PrincipalId'&`$expand=target" | Where-Object { $null -ne $_ -and "$($_.state)" -ine 'expired' -and "$($_.target.objectId)" -ieq $PrincipalId })) {
                $item = [pscustomobject]@{ key = ("assignment|{0}|{1}" -f $p.name, $a.id).ToLowerInvariant(); live = [pscustomobject]@{ apKind = 'assignment'; AssignmentId = "$($a.id)"; PackageId = "$($p.id)"; PackageName = "$($p.name)"; principalId = $PrincipalId } }
                try {
                    Invoke-PimGraph -Method POST -Path "$em/assignmentRequests" -Body ([ordered]@{ requestType = 'adminRemove'; assignment = [ordered]@{ id = "$($a.id)" } }) | Out-Null
                    $ended++
                    if (Get-Command Write-PimEngineChangeAudit -ErrorAction SilentlyContinue) { Write-PimEngineChangeAudit -Scope 'AccessPackages' -Entity (Get-PimAccessPackageEntityName) -Op 'Remove' -Item $item -Result 'ok' }
                } catch {
                    $errors.Add("end assignment $($a.id) of package '$($p.name)': $($_.Exception.Message)")
                    if (Get-Command Write-PimEngineChangeAudit -ErrorAction SilentlyContinue) { Write-PimEngineChangeAudit -Scope 'AccessPackages' -Entity (Get-PimAccessPackageEntityName) -Op 'Remove' -Item $item -Result 'error' -ErrorMessage "$($_.Exception.Message)" }
                }
            }
        } catch { $errors.Add("read assignments of package '$($p.name)': $($_.Exception.Message)") }
    }
    return [pscustomobject]@{ ended = $ended; errors = $errors.ToArray() }
}

function New-PimAccessPackagesProvider {
    @{
        scope = 'AccessPackages'; entity = (Get-PimAccessPackageEntityName); order = 72; refreshBefore = $false
        GetDesired = { param($ctx) @(Get-PimAccessPackageDesired -Context $ctx) }
        GetRemoveRows = { param($ctx) @($ctx['apRemoveRows']) }
        GetLive = { param($ctx) @(Get-PimAccessPackageLive -Context $ctx) }
        KeyOf = { param($r) "$(Get-PimRowProp -Row $r -Names @('PackageName', 'AccessPackageName'))".Trim().ToLowerInvariant() }
        Equal = { param($d, $l) "$($d.Fingerprint)" -ceq "$($l.Fingerprint)" }
        ExpandRemovals = { param($diff, $ctx) Expand-PimAccessPackageRemovals -Diff $diff -Context $ctx }
        ApplyCreate = { param($item, $ctx) Invoke-PimAccessPackageCreate -Item $item -Context $ctx }
        ApplyUpdate = { param($item, $ctx) Invoke-PimAccessPackageUpdate -Item $item -Context $ctx }
        ApplyRemove = { param($item, $ctx) Invoke-PimAccessPackageRemove -Item $item -Context $ctx }
    }
}

$script:PimAccessPackageWaitSeconds = 3
