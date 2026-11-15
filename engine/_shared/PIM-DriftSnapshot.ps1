<#
  PIM4EntraPS -- DRIFT SNAPSHOT (live vs desired), built by the SCHEDULER, served by the Manager.

  🔴 WHY THIS FILE EXISTS (operator, 2026-09-14: "when i click access & drift, i get to something that looks like
  settings, where menu item is hidden as a button. why is this option not its own page and automatically run and why
  does it not show a comparison to expand"). GET /api/drift used to run
      Invoke-PimEngine -Scope All -Mode Full -Prune -WhatIf
  INSIDE the Manager request. The Manager serves ONE request at a time, so a drift check froze every page for every
  user for minutes (§70.1b) -- which is why it had been hidden behind a "slow" button -- and the answer was a flat
  list of keys with no per-area comparison.

  🔑 THE SAME DESIGN AS THE ACTIVE-ASSIGNMENTS SNAPSHOT (engine/_shared/PIM-ActiveAssignments.ps1, §70.1b option 2):
    * the scheduler job 'drift-snapshot' (default every 240 min) runs the plan and stores ONE document in SQL
      pim.TenantCache kind 'drift';
    * the Manager only READS that row (ConvertTo-PimDriftSnapshotView) and asks for a refresh by queueing a trigger
      (Request-PimDriftSnapshotRefresh) -- the page opens instantly and loads by itself;
    * the job handler is registered ONLY by tools/pim-scheduler/Start-PimScheduler.ps1
      (Register-PimDriftSnapshotHandler). The default handler in PIM-Scheduler.ps1 declares the job unimplemented,
      so the Manager -- which initialises the default handlers too -- can never run the plan.

  The stored document (REQ-U wave 2: + counts.warnings, scope.warnings, items of type 'warning' with kind/counted;
  2026-09-22: + excluded / excludedNames -- platform-owned objects, see Get-PimDriftExcludedNames):
    { refreshedUtc; durationSeconds; total; counts{missing,changed,extra,warnings}; excluded; excludedNames;
      scopesFailed; scopesChecked; scopesNotChecked; ok; source; correlationId;
      scopes:[ { scope; entity; desired; live; nochange; missing; changed; extra; excluded; ok; error; skippedFeature;
                 checked; notCheckedReason; truncated; items:[ { type; key; label } ] } ] }
  REQ-U: checked=$false for a failed scope AND for a skipped one (feature gated off, live read refused) -- neither
  is ever counted as "checked, 0 drift".

  Classification is Get-PimDriftReport's (PIM-Governance.ps1) -- create=missing, update=changed, remove=extra -- never
  re-implemented here. Labels come from Get-PimFailureItemLabel (PIM-FailureCatalog.ps1), the same readable sentence
  the engine failures and the audit trail use; the key stays as the technical id.

  Dependencies: PIM-EngineCore.ps1 (Invoke-PimEngine / Resolve-PimEngineScope), PIM-Governance.ps1
  (Get-PimDriftReport), optionally PIM-FailureCatalog.ps1, tools/pim-manager/_tenantSync.ps1 (Set-/Get-
  PimTenantCacheEntry) and, for the trigger, PIM-Scheduler.ps1 (Add-PimJobTrigger). Runs on pwsh 7 and 5.1.
#>

Set-StrictMode -Off

$script:PimDriftSnapshotJobType   = 'drift-snapshot'
$script:PimDriftSnapshotCacheKind = 'drift'
$script:PimDriftSnapshotDefaultCadenceMinutes = 240
# A tenant that has never been reconciled can carry thousands of items in one scope; the document is one SQL row
# the Manager parses on every page open. The counts stay exact; only the item LIST is capped (with `truncated`).
$script:PimDriftSnapshotItemCap = 500

function Get-PimDriftSnapshotField {
    param([AllowNull()][object]$Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { return $Item[$Name] }; return $null }
    $p = $Item.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

# ===========================================================================
# 🔒 PLATFORM-OWNED OBJECTS ARE NOT DELEGATION DRIFT
# Operator, 2026-09-22: "this group is critical for the whole solution so it should be excluded from
# the drift report - grp-pim-sql-admins".
# That group is PIM's OWN SQL admin group: the deploy creates it and the Manager, the tick and the
# updater identities are its members (Initialize-PimSqlAdminGroup.ps1, PIM-MspBuild 'sqlgroup' step).
# PIM never DEFINES it as a delegation, so every comparison sees a live object with no desired row and
# reports it as drift the operator cannot resolve -- on the one group they must never delete.
# 🔑 Excluded by NAME, counted SEPARATELY and named on the page: silently dropping items would make
# this the place a real finding could hide. `excluded` is reported, `total` is not inflated by it.
# ===========================================================================
function Get-PimDriftExcludedNames {
    <# PURE-ish: the platform's own objects, which are never delegation drift. The SQL admin group's
       name is configurable ($global:PIM_SqlAdminGroupName, set by the deploy), so read it and fall
       back to the shipped default rather than hard-coding one spelling. #>
    param([string]$SqlAdminGroupName = '')
    $g = "$SqlAdminGroupName".Trim()
    if (-not $g) { try { $g = "$($global:PIM_SqlAdminGroupName)".Trim() } catch { $g = '' } }
    if (-not $g) { $g = 'grp-pim-sql-admins' }
    # 33.0 item 5 (2026-10-20): every display-name form of it (CR5 item 5: the earlier and the current release's name), so
    # the old and the new naming both match. Get-PimDisplayNameForms answers the name first; not loaded = the name alone.
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add($g)
    if (Get-Command Get-PimDisplayNameForms -ErrorAction SilentlyContinue) {
        try { foreach ($f in @(Get-PimDisplayNameForms -Name $g)) { if ("$f".Trim() -and -not @($out | Where-Object { $_ -ieq "$f".Trim() }).Count) { $out.Add("$f".Trim()) } } } catch { }
    }
    return , @($out.ToArray())
}
function Get-PimDriftItemLabel {
    <#
      The readable label of one drift item. DRIFT-PIM-NAMED (owner 2026-11-10): an item of the AdministrativeUnits area is
      an ADMINISTRATIVE UNIT -- "administrative unit <name>". Get-PimFailureItemLabel read an AU named PIM-... from its key
      ('pim-x') as "PIM for Groups policy of group pim-x". Done here, by scope, so no other area's label changes.
      Every other area: Get-PimFailureItemLabel, as before ('' when it is not loaded or throws).
    #>
    param([string]$Scope, [string]$Key, [AllowNull()][object]$Row, [switch]$LabelFn)
    if ("$Scope" -eq 'AdministrativeUnits') {
        $nm = ''
        foreach ($n in @('AUDisplayName', 'displayName')) { $v = "$(Get-PimDriftSnapshotField $Row $n)".Trim(); if ($v) { $nm = $v; break } }
        if (-not $nm) { $nm = "$Key".Trim() }
        if ($nm) { return "administrative unit $nm" }
    }
    if (-not $LabelFn) { return '' }
    try { return "$(Get-PimFailureItemLabel -Key "$Key" -Row $Row)" } catch { return '' }
}

function Get-PimDriftExcludedIds {
    <# 33.0 item 5 (2026-10-20): the SQL admin group's OBJECT ID(s) when the install sets one ($env:PIM_SQL_ADMIN_GROUP_ID,
       else $global:PIM_SqlAdminGroupId; -SqlAdminGroupId: the caller's / test seam). Optional: none = by name only, as
       before. A renamed group is still excluded by its id. Lower-case, unique. #>
    param([string]$SqlAdminGroupId = '')
    $raw = "$SqlAdminGroupId".Trim()
    if (-not $raw) { $raw = "$($env:PIM_SQL_ADMIN_GROUP_ID)".Trim() }
    if (-not $raw) { try { $raw = "$($global:PIM_SqlAdminGroupId)".Trim() } catch { $raw = '' } }
    return , @(@($raw -split '[,;\s]+') | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Select-Object -Unique)
}
function Test-PimDriftItemExcluded {
    <# PURE. True when this drift item names a platform-owned object. Matches the item's key AND its
       label, because a provider may carry the group in either (an id-keyed item still labels it).
       33.0 item 5 (2026-10-20): -Ids (the SQL admin group's object id) are matched against the key, the label, the group
       AND the item's groupId / id -- a RENAMED group is still excluded when its id is known. #>
    param([AllowNull()][object]$Item, [string[]]$Names = @(), [string[]]$Ids = @())
    if ($null -eq $Item) { return $false }
    $hay = "$(Get-PimDriftSnapshotField $Item 'key') $(Get-PimDriftSnapshotField $Item 'label') $(Get-PimDriftSnapshotField $Item 'group')"
    foreach ($n in @($Names)) {
        $nn = "$n".Trim()
        if (-not $nn) { continue }
        if ($hay.IndexOf($nn, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    $idHay = "$hay $(Get-PimDriftSnapshotField $Item 'groupId') $(Get-PimDriftSnapshotField $Item 'id')"
    foreach ($i in @($Ids)) {
        $ii = "$i".Trim()
        if (-not $ii) { continue }
        if ($idHay.IndexOf($ii, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

# ===========================================================================
# PURE -- engine scope results -> the stored document
# ===========================================================================
function ConvertTo-PimDriftSnapshotDocument {
    <#
      PURE. -ScopeResults: one entry per scope, either an Invoke-PimEngine scope result
      ({ scope; create; update; remove; nochange; plan=[{entity;key;op;payload}]; ok; ... }) or an error record
      ({ scope; ok=$false; error }). Returns the stored document (see the file header).
      🔒 A scope that failed is recorded ok=$false with its error and NO counts -- never as a clean scope.
    #>
    param(
        [object[]]$ScopeResults = @(),
        [datetime]$NowUtc = [datetime]::UtcNow,
        [double]$DurationSeconds = 0,
        [int]$ItemCap = $script:PimDriftSnapshotItemCap
    )
    if ($ItemCap -le 0) { $ItemCap = $script:PimDriftSnapshotItemCap }
    $scopeDocs = New-Object System.Collections.Generic.List[object]
    $diffs     = New-Object System.Collections.Generic.List[object]
    $payloads  = @{}   # "scope|key" -> the row the plan carried (desired for create/update, live for remove)
    $diffOf    = @{}   # §79.3: "scope|key" -> what differs on a CHANGED item, live -> desired (Get-PimChangeFieldDiff)
    $findByScope = @{} # REQ-U wave 2: scope -> its live findings (warnings)
    foreach ($r in @($ScopeResults)) {
        if ($null -eq $r) { continue }
        $scope = "$(Get-PimDriftSnapshotField $r 'scope')".Trim()
        $entity = "$(Get-PimDriftSnapshotField $r 'entity')".Trim()
        $err = "$(Get-PimDriftSnapshotField $r 'error')".Trim()
        $okV = Get-PimDriftSnapshotField $r 'ok'
        $detail = "$(Get-PimDriftSnapshotField $r 'detail')".Trim()
        if (-not $err -and $null -ne $okV -and -not [bool]$okV -and $null -eq (Get-PimDriftSnapshotField $r 'create')) {
            # Invoke-PimEngineScope answers an unserved scope with { ok=$false; detail } and no counts.
            $err = if ($detail) { $detail } else { 'the engine returned no result for this scope' }
        }
        $plan = @(@(Get-PimDriftSnapshotField $r 'plan') | Where-Object { $null -ne $_ })
        if (-not $entity) {
            $pe = @($plan | ForEach-Object { "$(Get-PimDriftSnapshotField $_ 'entity')" } | Where-Object { $_ }) | Select-Object -First 1
            $entity = if ($pe) { "$pe" } else { $scope }
        }
        if ($err) {
            $scopeDocs.Add([ordered]@{ scope = $scope; entity = $entity; desired = $null; live = $null; nochange = $null
                missing = $null; changed = $null; extra = $null; ok = $false; error = $err; skippedFeature = ''
                checked = $false; notCheckedReason = $err; truncated = 0; excluded = 0; items = @() })
            continue
        }
        # 🔴 REQ-U (2026-09-19): a scope the engine SKIPPED (its feature gated off -- e.g. connectors.workload for
        # DefenderXdrRoles / IntuneRoles) returned create=update=remove=nochange=0 and was stored as ok with 0 drift,
        # so the page counted it among the "areas checked" and called it in sync. Nothing was compared. It is now
        # NOT CHECKED, with its reason, and carries no counts (never "checked, 0 drift").
        $skipF = "$(Get-PimDriftSnapshotField $r 'skippedFeature')".Trim()
        $ncV = Get-PimDriftSnapshotField $r 'notChecked'
        if ($skipF -or ($null -ne $ncV -and [bool]$ncV)) {
            $why = "$(Get-PimDriftSnapshotField $r 'skippedReason')".Trim()
            if (-not $why) { $why = if ($skipF) { "the feature '$skipF' is off for this run" } else { 'the engine did not compare this area' } }
            $scopeDocs.Add([ordered]@{ scope = $scope; entity = $entity; desired = $null; live = $null; nochange = $null
                missing = $null; changed = $null; extra = $null; ok = $true; error = ''; skippedFeature = $skipF
                checked = $false; notCheckedReason = $why; truncated = 0; excluded = 0; items = @() })
            continue
        }
        $cre = New-Object System.Collections.Generic.List[object]
        $upd = New-Object System.Collections.Generic.List[object]
        $rem = New-Object System.Collections.Generic.List[object]
        foreach ($pc in $plan) {
            $k = "$(Get-PimDriftSnapshotField $pc 'key')"
            $item = [pscustomobject]@{ key = $k }
            switch ("$(Get-PimDriftSnapshotField $pc 'op')".ToLowerInvariant()) {
                'create' { $cre.Add($item) }
                'update' { $upd.Add($item) }
                'remove' { $rem.Add($item) }
            }
            $payloads["$scope|$k"] = Get-PimDriftSnapshotField $pc 'payload'
            $diffOf["$scope|$k"] = "$(Get-PimDriftSnapshotField $pc 'diff')"
        }
        $diffs.Add([pscustomobject]@{ scope = $scope; entity = $entity; create = @($cre.ToArray()); update = @($upd.ToArray()); remove = @($rem.ToArray()) })
        # REQ-U wave 2: the scope's live FINDINGS (the workload providers' orphan group / unmanaged binding / wrong
        # permissions warnings, Invoke-PimEngineScope `findings`) -- listed as type 'warning' and counted as drift.
        $findByScope[$scope] = @(@(Get-PimDriftSnapshotField $r 'findings') | Where-Object { $null -ne $_ })
        $nC = [int](Get-PimDriftSnapshotField $r 'create'); $nU = [int](Get-PimDriftSnapshotField $r 'update')
        $nR = [int](Get-PimDriftSnapshotField $r 'remove'); $nN = [int](Get-PimDriftSnapshotField $r 'nochange')
        # Invoke-PimEngineScope logs desired=/live= but does NOT return them. Derived from the diff instead:
        #   desired = create + update + nochange  (every desired item is one of those three)
        #   live    = update + remove + nochange  (every live item the comparison matched or would prune)
        # A live item outside the managed comparison is not counted -- the SEC-14 note on the page says so.
        $desiredN = Get-PimDriftSnapshotField $r 'desired'; $liveN = Get-PimDriftSnapshotField $r 'live'
        $scopeDocs.Add([ordered]@{
            scope = $scope; entity = $entity
            desired  = $(if ($desiredN -is [int] -or $desiredN -is [long]) { [int]$desiredN } else { $nC + $nU + $nN })
            live     = $(if ($liveN -is [int] -or $liveN -is [long]) { [int]$liveN } else { $nU + $nR + $nN })
            nochange = $nN
            missing = 0; changed = 0; extra = 0; warnings = 0; excluded = 0
            ok = $true; error = ''
            skippedFeature = ''
            checked = $true; notCheckedReason = ''
            # REQ-AU-DRIFT-1: the scope has no definitions -- every extra here is something PIM has never been told about
            noDefinitions = [bool](Get-PimDriftSnapshotField $r 'noDefinitions')
            # BUG-269: more extras than the removal budget -- all listed; an apply would hold them (the budget guards writes)
            overRemoveBudget = $(if ($ob = Get-PimDriftSnapshotField $r 'overRemoveBudget') { [ordered]@{ toRemove = [int](Get-PimDriftSnapshotField $ob 'toRemove'); budget = [int](Get-PimDriftSnapshotField $ob 'budget') } } else { $null })
            truncated = 0; items = @()
        })
    }

    # Classify through the ONE drift classifier (create=missing, update=changed, remove=extra).
    $report = $null
    if ($diffs.Count) { $report = Get-PimDriftReport -ScopeDiffs @($diffs.ToArray()) -NowUtc $NowUtc }
    $byScope = @{}
    foreach ($it in @(if ($report) { $report.items })) {
        $s = "$($it.scope)"
        if (-not $byScope.ContainsKey($s)) { $byScope[$s] = New-Object System.Collections.Generic.List[object] }
        $byScope[$s].Add($it)
    }
    $labelFn = [bool](Get-Command Get-PimFailureItemLabel -ErrorAction SilentlyContinue)
    $exclNames = Get-PimDriftExcludedNames
    $exclIds = Get-PimDriftExcludedIds   # 33.0 item 5 (2026-10-20): the group's object id, when set (a rename keeps it excluded)
    foreach ($sd in $scopeDocs) {
        if (-not $sd.ok -or -not $sd.checked) { continue }
        # 🪤 `@(...)` AROUND THE WHOLE `if`, and `@($list).Count` -- both are load-bearing, and their
        # absence made the exclusion below a NO-OP ON WINDOWS POWERSHELL 5.1 ONLY.
        # Assigning the result of an `if` unwraps a ONE-element array to the element itself, and a
        # bare PSCustomObject has no .Count in 5.1 (pwsh 7 gives it one). So with exactly one drift
        # item `$list.Count` was $null -> falsy -> the whole exclusion block was skipped, and the
        # platform's own SQL admin group came back as drift. It passed every check on pwsh 7.
        $list = @(if ($byScope.ContainsKey("$($sd.scope)")) { @($byScope["$($sd.scope)"].ToArray()) } else { @() })
        # Platform-owned objects out first, so they are in no count, no item list and no total.
        $exclN = 0
        if (@($list).Count) {
            $keep = New-Object System.Collections.Generic.List[object]
            foreach ($it in $list) {
                $lbl = ''
                $lbl = Get-PimDriftItemLabel -Scope "$($sd.scope)" -Key "$($it.key)" -Row $payloads["$($sd.scope)|$($it.key)"] -LabelFn:$labelFn
                $pl = $payloads["$($sd.scope)|$($it.key)"]
                $plGid = "$(Get-PimDriftSnapshotField $pl 'groupId')"; if (-not $plGid.Trim()) { $plGid = "$(Get-PimDriftSnapshotField $pl 'GroupId')" }
                $probe = [pscustomobject]@{ key = "$($it.key)"; label = $lbl; groupId = $plGid }
                if (Test-PimDriftItemExcluded -Item $probe -Names $exclNames -Ids $exclIds) { $exclN++ } else { $keep.Add($it) }
            }
            $list = @($keep.ToArray())
        }
        $sd.missing = @($list | Where-Object { $_.type -eq 'missing' }).Count
        $sd.changed = @($list | Where-Object { $_.type -eq 'changed' }).Count
        $sd.extra   = @($list | Where-Object { $_.type -eq 'extra' }).Count
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($it in $list) {
            if ($items.Count -ge $ItemCap) { break }
            $label = ''
            $label = Get-PimDriftItemLabel -Scope "$($sd.scope)" -Key "$($it.key)" -Row $payloads["$($sd.scope)|$($it.key)"] -LabelFn:$labelFn
            if (-not $label.Trim()) { $label = "$($it.key)" }
            # §79.3: a changed item says WHAT differs (live -> desired); missing / extra say where the item is.
            $det = switch ("$($it.type)") { 'changed' { "$($diffOf["$($sd.scope)|$($it.key)"])" } 'missing' { 'in PIM, not in the tenant' } 'extra' { 'in the tenant, not in PIM' } default { '' } }
            $row = [ordered]@{ type = "$($it.type)"; key = "$($it.key)"; label = $label; detail = $det }
            # REQ-DRIFT-2: an EXTRA carries what Delete (the revoke row) and Keep (the desired row) would do, from its live row.
            if ("$($it.type)" -eq 'extra') {
                $xa = Get-PimDriftExtraActions -Scope "$($sd.scope)" -Payload $payloads["$($sd.scope)|$($it.key)"]
                $row['revoke'] = $xa.revoke; $row['revokeWhy'] = $xa.revokeWhy; $row['keep'] = $xa.keep; $row['keepWhy'] = $xa.keepWhy
                # DRIFT-EXTRAS (100.12) / PIM 100.22 (d): a group extra's Delete is ONE queued group delete (its own commit), not a revoke.
                if ($xa.Contains('groupDelete') -and $null -ne $xa['groupDelete']) { $row['groupDelete'] = $xa['groupDelete'] }
            }
            $items.Add($row)
        }
        # REQ-U wave 2 (design point 8): the area's live WARNINGS (orphan group, unmanaged binding, wrong permissions).
        # They count toward drift -- EXCEPT a warning that names an item the plan already lists (its key, or one of its
        # relatedKeys: a wrong-permissions warning IS the plan's 'changed' item), which is shown but counted once.
        $wf = @(if ($findByScope.ContainsKey("$($sd.scope)")) { @($findByScope["$($sd.scope)"]) } else { @() })   # see the 5.1 note above
        if (@($wf).Count) {
            $keepW = New-Object System.Collections.Generic.List[object]
            foreach ($f in $wf) { if (Test-PimDriftItemExcluded -Item $f -Names $exclNames -Ids $exclIds) { $exclN++ } else { $keepW.Add($f) } }
            $wf = @($keepW.ToArray())
        }
        $planKeys = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
        foreach ($it in $list) { [void]$planKeys.Add("$($it.key)") }
        $wn = 0
        foreach ($f in $wf) {
            $fk = "$(Get-PimDriftSnapshotField $f 'key')"
            $dup = $planKeys.Contains($fk)
            foreach ($rk in @(Get-PimDriftSnapshotField $f 'relatedKeys')) { if ("$rk" -and $planKeys.Contains("$rk")) { $dup = $true } }
            # Lead decision 2026-09-19 (operator: "you decide"): an UNMANAGED binding -- a workload role held by a principal PIM
            # does not define (hand-made assignments) -- is a REVIEW item, not drift: it is listed, never counted, so it cannot
            # hold drift above zero and re-raise the drift alert every cycle. Orphan groups and wrong permissions still count.
            $kind = "$(Get-PimDriftSnapshotField $f 'kind')"
            $counts = (-not $dup) -and $kind -ne 'unmanaged-binding'
            if ($counts) { $wn++ }
            if ($items.Count -ge $ItemCap) { continue }
            $items.Add([ordered]@{ type = 'warning'; key = $fk; label = "$(Get-PimDriftSnapshotField $f 'label')"; kind = $kind; counted = $counts; review = ($kind -eq 'unmanaged-binding') })
        }
        $sd.warnings = $wn
        $sd.excluded = $exclN
        $sd.items = @($items.ToArray())
        $sd.truncated = [int]([math]::Max(0, ($list.Count + $wf.Count) - $items.Count))
    }

    $okScopes = @($scopeDocs | Where-Object { $_.ok -and $_.checked })
    $m = 0; $c = 0; $x = 0; $w = 0; $ex = 0
    foreach ($sd in $okScopes) {
        $m += [int]$sd.missing; $c += [int]$sd.changed; $x += [int]$sd.extra; $w += [int]$sd.warnings
        if ($sd.Contains('excluded')) { $ex += [int]$sd.excluded }
    }
    $failed = @($scopeDocs | Where-Object { -not $_.ok }).Count
    return [ordered]@{
        refreshedUtc    = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        durationSeconds = [math]::Round([double]$DurationSeconds, 1)
        total           = ($m + $c + $x + $w)
        counts          = [ordered]@{ missing = $m; changed = $c; extra = $x; warnings = $w }
        # Platform-owned items left out of every count above, and WHICH objects they were -- so the
        # page can say it rather than the number simply being smaller.
        excluded        = $ex
        excludedNames   = @($exclNames)
        scopesFailed    = $failed
        # REQ-U: how many areas were really compared, and how many were NOT (failed + skipped), so no summary can
        # present a skipped area as checked.
        scopesChecked    = $okScopes.Count
        scopesNotChecked = @($scopeDocs | Where-Object { -not $_.checked }).Count
        # ok = the check itself worked for every scope (NOT "no drift"). A partly-failed check is ok=$false.
        ok              = ($failed -eq 0 -and $scopeDocs.Count -gt 0)
        scopes          = @($scopeDocs.ToArray())
    }
}

# ===========================================================================
# THE COMPUTE -- runs ONLY in the scheduler (never in the Manager)
# ===========================================================================
function Invoke-PimDriftSnapshot {
    <#
      Run the drift plan once per scope and return the document. The same plan the Manager used to run
      (Clear-PimEngineReadCaches, then Invoke-PimEngine -Mode Full -Prune -WhatIf -- plan only, NO writes), but
      scope by scope, so ONE scope that throws is recorded as failed instead of taking every other scope's answer
      with it (Invoke-PimEngine -Scope All has no per-scope catch).
    #>
    param([datetime]$NowUtc = [datetime]::UtcNow)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (Get-Command Clear-PimEngineReadCaches -ErrorAction SilentlyContinue) { Clear-PimEngineReadCaches }
    $scopes = @()
    if (Get-Command Resolve-PimEngineScope -ErrorAction SilentlyContinue) {
        $res = Resolve-PimEngineScope -Scope 'All'
        if (-not $res.ok) { throw "[drift-snapshot] the engine scopes could not be resolved: $($res.detail)" }
        $scopes = @($res.scopes)
    }
    $results = New-Object System.Collections.Generic.List[object]
    # REQ-AU-DRIFT-1: a scope with no rows still has its live items LISTED as extras (plan only -- see Invoke-PimEngineScope).
    # Set for this read and cleared in finally, so no other engine run in the process ever sees it.
    $global:PIM_DriftReadPlan = $true
    try {
    if ($scopes.Count -eq 0) {
        # No resolver in this process: one call, and a throw is recorded against 'All' (still never "clean").
        try { foreach ($r in @(Invoke-PimEngine -Scope 'All' -Mode 'Full' -Prune -WhatIf)) { $results.Add($r) } }
        catch { $results.Add([pscustomobject]@{ scope = 'All'; ok = $false; error = "$($_.Exception.Message)" }) }
    } else {
        foreach ($s in $scopes) {
            # A plan writes nothing, but it can take minutes: keep the tick's lease alive between scopes.
            if (Get-Command Invoke-PimSchedulerLeaseHeartbeat -ErrorAction SilentlyContinue) { try { [void](Invoke-PimSchedulerLeaseHeartbeat) } catch { } }
            try {
                foreach ($r in @(Invoke-PimEngine -Scope "$s" -Mode 'Full' -Prune -WhatIf)) { if ($null -ne $r) { $results.Add($r) } }
            } catch {
                $results.Add([pscustomobject]@{ scope = "$s"; ok = $false; error = "$($_.Exception.Message)" })
            }
        }
    }
    } finally { $global:PIM_DriftReadPlan = $null }
    try { Add-PimDriftPayloadNames -ScopeResults @($results.ToArray()) } catch { Write-Warning "[drift-snapshot] names for drift items could not be resolved: $($_.Exception.Message)" }
    # 2026-10-07: the live identities the engine MATCHED to a definition, for Delegation overview (All privileged permissions) (managed / not).
    # Kept apart from the drift document (it is large and the Drift page does not need it); complete = every scope read.
    $script:PimLastManagedLive = Get-PimManagedLiveSet -ScopeResults @($results.ToArray()) -NowUtc $NowUtc
    $sw.Stop()
    return (ConvertTo-PimDriftSnapshotDocument -ScopeResults @($results.ToArray()) -NowUtc $NowUtc -DurationSeconds $sw.Elapsed.TotalSeconds)
}

function Get-PimManagedLiveSet {
    <# PURE. { computedUtc; complete; scopes; identities[] } from the drift read's per-scope results (managedLive). #>
    param([object[]]$ScopeResults = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $complete = $true; $scopes = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($ScopeResults)) {
        if ($null -eq $r) { continue }
        if (-not (Get-PimDriftSnapshotField $r 'ok') -or (Get-PimDriftSnapshotField $r 'error')) { $complete = $false }
        $scopes.Add("$(Get-PimDriftSnapshotField $r 'scope')")
        foreach ($i in @(Get-PimDriftSnapshotField $r 'managedLive')) { if ("$i".Trim()) { [void]$set.Add("$i".Trim().ToLowerInvariant()) } }
    }
    return [ordered]@{ computedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); complete = $complete; scopes = @($scopes.ToArray()); identities = @($set) }
}

# ===========================================================================
# NAMES FOR LIVE MEMBERSHIP ROWS -- runs in the scheduler, with the plan
# ===========================================================================
function Resolve-PimDriftPrincipalName {
    <#
      A principal id -> @{ name; kind } (kind = user | group | servicePrincipal | object), or $null when nothing knows it.
      Order: the solution-owned groups (-Owned, no request), the engine context caches ($Global:Users_All_ID /
      $Global:Groups_All_ID), then ONE Graph /directoryObjects read. Answers (misses too) are cached in -Cache, so an
      id is read at most once per drift run.
    #>
    param([string]$Id, [hashtable]$Cache, [AllowNull()][object]$Owned)
    $id = "$Id".Trim(); if (-not $id) { return $null }
    if ($null -eq $Cache) { $Cache = @{} }
    $ck = $id.ToLowerInvariant()
    if ($Cache.ContainsKey($ck)) { return $Cache[$ck] }
    $res = $null
    if ($Owned -and $Owned.byId -and $Owned.byId.ContainsKey($id) -and "$($Owned.byId[$id].name)") {
        $res = @{ name = "$($Owned.byId[$id].name)"; kind = 'group' }
    }
    if (-not $res) {
        $u = @($Global:Users_All_ID) | Where-Object { $_ -and "$($_.Id)" -ieq $id } | Select-Object -First 1
        if ($u) { $n = if ("$($u.UserPrincipalName)") { "$($u.UserPrincipalName)" } else { "$($u.DisplayName)" }; if ($n) { $res = @{ name = $n; kind = 'user' } } }
    }
    if (-not $res) {
        $gr = @($Global:Groups_All_ID) | Where-Object { $_ -and "$($_.Id)" -ieq $id } | Select-Object -First 1
        if ($gr -and "$($gr.DisplayName)") { $res = @{ name = "$($gr.DisplayName)"; kind = 'group' } }
    }
    if (-not $res -and (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) {
        try {
            $o = Invoke-PimGraph -Path "/directoryObjects/$([uri]::EscapeDataString($id))?`$select=id,displayName,userPrincipalName"
            if ($o) {
                $ot = "$($o.'@odata.type')"
                $kind = if ($ot -match '(?i)user$') { 'user' } elseif ($ot -match '(?i)group$') { 'group' } elseif ($ot -match '(?i)servicePrincipal$') { 'servicePrincipal' } else { 'object' }
                $n = if ($kind -eq 'user' -and "$($o.userPrincipalName)") { "$($o.userPrincipalName)" } else { "$($o.displayName)" }
                if ($n) { $res = @{ name = $n; kind = $kind } }
            }
        } catch { Write-Verbose "drift name ($id): $($_.Exception.Message)" }
    }
    $Cache[$ck] = $res
    return $res
}

function Get-PimDriftAuTagMap {
    # AU id (lower-case) -> the PIM tag of the AU PIM defines under that display name. Reads the definitions and the directory
    # cache already loaded in the engine; @{} when either is missing (an AU role is then not Kept -- never a guessed tag).
    $map = @{}
    try {
        $byName = @{}
        if (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue) {
            foreach ($d in @(Get-PimDesiredRows -Entity 'PIM-Definitions-AU')) { $n = "$($d.AUDisplayName)".Trim(); $tg = "$($d.AdministrativeUnitTag)".Trim(); if ($n -and $tg) { $byName[$n.ToLowerInvariant()] = $tg } }
        }
        foreach ($a in @($Global:AU_All_ID | Where-Object { $_ })) {
            $n = "$($a.DisplayName)".Trim().ToLowerInvariant(); $id = "$($a.Id)".Trim().ToLowerInvariant()   # property names are case-insensitive (SDK or REST shape alike)
            if ($n -and $id -and $byName.ContainsKey($n)) { $map[$id] = $byName[$n] }
        }
    } catch { }
    return $map
}

function Add-PimDriftPayloadNames {
    <#
      Operator, 2026-09-14, on the Drift page: "i cannot see what that guid is". An 'extra' item carries the LIVE row,
      and a live membership row is only principalId + groupId + GroupTag + AssignmentType -- Get-PimFailureItemLabel had
      nothing to name, so the page showed the raw key '<principalId>|<tag>|<type>'. This stamps PrincipalName,
      PrincipalKind and GroupName on a COPY of each such payload (the engine's membership cache holds the originals),
      so the label reads "admin-x@contoso.com -> member of group PIM-ROLE-... (Eligible)".
      Only rows with principalId + groupId and no desired-side names are touched; everything else is left as it is.
    #>
    param([object[]]$ScopeResults = @())
    $cache = @{}; $owned = $null; $ownedTried = $false; $auTags = $null
    foreach ($r in @($ScopeResults)) {
        foreach ($pc in @(@(Get-PimDriftSnapshotField $r 'plan') | Where-Object { $null -ne $_ })) {
            $pl = Get-PimDriftSnapshotField $pc 'payload'
            if ($null -eq $pl) { continue }
            $prin = "$(Get-PimDriftSnapshotField $pl 'principalId')".Trim()
            $gid  = "$(Get-PimDriftSnapshotField $pl 'groupId')".Trim()
            # REQ-AU-DRIFT-1 (2.4.455): an AU-scoped role row names its group by id and its AU by the scope path -- stamp the
            # group's tag and the AU's PIM tag, so Keep can stage the Roles-AUs row.
            $dsid = "$(Get-PimDriftSnapshotField $pl 'directoryScopeId')".Trim()
            if ($prin -and -not $gid -and $dsid -match '(?i)^/administrativeUnits/([^/]+)$') {
                $auId = $Matches[1]
                if (-not $ownedTried) { $ownedTried = $true; if (Get-Command Get-PimSolutionOwnedGroups -ErrorAction SilentlyContinue) { try { $owned = Get-PimSolutionOwnedGroups } catch { $owned = $null } } }
                if ($null -eq $auTags) { $auTags = Get-PimDriftAuTagMap }
                $copy = if ($pl -is [System.Collections.IDictionary]) { [pscustomobject]$pl } else { $pl | Select-Object * }
                if ($owned -and $owned.byId -and $owned.byId.ContainsKey($prin) -and "$($owned.byId[$prin].tag)") { Add-Member -InputObject $copy -NotePropertyName PrincipalTag -NotePropertyValue "$($owned.byId[$prin].tag)" -Force }
                if ($auTags.ContainsKey($auId.ToLowerInvariant())) { Add-Member -InputObject $copy -NotePropertyName AuTag -NotePropertyValue "$($auTags[$auId.ToLowerInvariant()])" -Force }
                if ($pc -is [System.Collections.IDictionary]) { $pc['payload'] = $copy } else { $pc.payload = $copy }
                continue
            }
            if (-not $prin -or -not $gid) { continue }
            if ("$(Get-PimDriftSnapshotField $pl 'Username')" -or "$(Get-PimDriftSnapshotField $pl 'TargetGroupTag')" -or "$(Get-PimDriftSnapshotField $pl 'PrincipalName')") { continue }
            if (-not $ownedTried) {
                $ownedTried = $true
                if (Get-Command Get-PimSolutionOwnedGroups -ErrorAction SilentlyContinue) { try { $owned = Get-PimSolutionOwnedGroups } catch { $owned = $null } }
            }
            $who = Resolve-PimDriftPrincipalName -Id $prin -Cache $cache -Owned $owned
            $grpName = "$(Get-PimDriftSnapshotField $pl 'GroupName')"
            if (-not $grpName) {
                if ($owned -and $owned.byId -and $owned.byId.ContainsKey($gid)) { $grpName = "$($owned.byId[$gid].name)" }
                else { $gw = Resolve-PimDriftPrincipalName -Id $gid -Cache $cache -Owned $owned; if ($gw) { $grpName = "$($gw.name)" } }
            }
            if (-not $who -and -not $grpName) { continue }
            $copy = if ($pl -is [System.Collections.IDictionary]) { [pscustomobject]$pl } else { $pl | Select-Object * }
            if ($who) {
                Add-Member -InputObject $copy -NotePropertyName PrincipalName -NotePropertyValue "$($who.name)" -Force
                Add-Member -InputObject $copy -NotePropertyName PrincipalKind -NotePropertyValue "$($who.kind)" -Force
            }
            if ($grpName) { Add-Member -InputObject $copy -NotePropertyName GroupName -NotePropertyValue $grpName -Force }
            # REQ-DRIFT-2: a member that is itself a PIM group carries its tag, so Keep can stage the nesting row.
            if ($owned -and $owned.byId -and $owned.byId.ContainsKey($prin) -and "$($owned.byId[$prin].tag)") { Add-Member -InputObject $copy -NotePropertyName PrincipalTag -NotePropertyValue "$($owned.byId[$prin].tag)" -Force }
            if ($pc -is [System.Collections.IDictionary]) { $pc['payload'] = $copy } else { $pc.payload = $copy }
        }
    }
}

if (-not (Get-Command Get-PimTrustCarryMaxAgeDays -ErrorAction SilentlyContinue)) {
    function Get-PimTrustCarryMaxAgeDays { <# PURE. LITERAL. Framework TRUST-1 point 8 (the same value as PIM-JobLanes.ps1). #> return 7 }
}

function Get-PimDriftCarriedSet {
    <#
      PURE. TRUST-1 round 4 item 5: what the stored drift document holds from an EARLIER run (carried areas -- not compared this
      run): @{ scopes = @{ name -> carriedFromUtc }; keys = <HashSet 'scope|key', case-insensitive>; groupIds = <HashSet> }.
      Every action the Manager offers on drift (ignore, delete, group delete, apply) is refused for these -- in the API.
    #>
    param([AllowNull()][object]$Doc)
    $scopes = @{}
    $keys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $gids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    # Round 5 G2: a KEPT document whose newest run failed on every area (lastRun.trusted = false) ages too -- the areas its lastRun
    # names STALE (DRIFT-SOURCE-STALE, compared longer ago than Get-PimTrustCarryMaxAgeDays) are refused like carried ones.
    $lrStale = @{}
    $lr = Get-PimDriftSnapshotField $Doc 'lastRun'
    if ($null -ne $lr -and "$(Get-PimDriftSnapshotField $lr 'trusted')" -match '^(?i)false$') {
        # round 6 F3 (decided: every action on data not read this run is refused): the areas the newest run could NOT compare
        # (lastRun.failed) are refused AT ONCE, not only once they are stale; their date = when they were last compared
        $prevAtL = "$(ConvertTo-PimDriftIsoStamp (Get-PimDriftSnapshotField $Doc 'refreshedUtc'))"
        foreach ($fn in @(@(Get-PimDriftSnapshotField $lr 'failed') | Where-Object { "$_".Trim() })) { $lrStale["$fn"] = $prevAtL }
        foreach ($x in @(@(Get-PimDriftSnapshotField $lr 'stale') | Where-Object { $null -ne $_ })) { $lrStale["$(Get-PimDriftSnapshotField $x 'scope')"] = "$(ConvertTo-PimDriftIsoStamp (Get-PimDriftSnapshotField $x 'sinceUtc'))" }
    }
    foreach ($s in @(@(Get-PimDriftSnapshotField $Doc 'scopes') | Where-Object { $null -ne $_ })) {
        $name = "$(Get-PimDriftSnapshotField $s 'scope')"
        if (-not [bool](Get-PimDriftSnapshotField $s 'carried') -and -not $lrStale.ContainsKey($name)) { continue }
        $scopes[$name] = $(if ([bool](Get-PimDriftSnapshotField $s 'carried')) { "$(ConvertTo-PimDriftIsoStamp (Get-PimDriftSnapshotField $s 'carriedFromUtc'))" } else { $lrStale[$name] })
        foreach ($it in @(@(Get-PimDriftSnapshotField $s 'items') | Where-Object { $null -ne $_ })) {
            $k = "$(Get-PimDriftSnapshotField $it 'key')"; if ($k) { [void]$keys.Add("$name|$k") }
            $gd = Get-PimDriftSnapshotField $it 'groupDelete'; $g = "$(Get-PimDriftSnapshotField $gd 'groupId')".Trim(); if ($g) { [void]$gids.Add($g) }
            $rv = Get-PimDriftSnapshotField $it 'revoke'; $g2 = "$(Get-PimDriftSnapshotField $rv 'groupId')".Trim(); if ($g2) { [void]$gids.Add($g2) }
        }
    }
    return @{ scopes = $scopes; keys = $keys; groupIds = $gids }
}

function Get-PimDriftActionRefusal {
    <#
      PURE. TRUST-1 round 4 item 5: the plain reason an action on drift is refused (409), or '' -- the scope is carried, the item
      ('scope|key') is in a carried scope, or the group belongs to a carried item. -Set: Get-PimDriftCarriedSet.
    #>
    param([AllowNull()][hashtable]$Set, [string]$Scope = '', [string]$Key = '', [string]$GroupId = '', [string[]]$SelectKeys = @())
    if ($null -eq $Set) { return '' }
    $hit = ''
    if ("$Scope".Trim() -and $Set.scopes.ContainsKey("$Scope".Trim())) { $hit = "$Scope".Trim() }
    elseif ("$Scope".Trim() -and "$Key".Trim() -and $Set.keys.Contains("$("$Scope".Trim())|$("$Key".Trim())")) { $hit = "$Scope".Trim() }
    elseif ("$GroupId".Trim() -and $Set.groupIds.Contains("$GroupId".Trim())) { $hit = 'the group' }
    else { foreach ($sk in @($SelectKeys)) { if ("$sk".Trim() -and $Set.keys.Contains("$sk".Trim())) { $hit = ("$sk" -split '\|')[0]; break } } }
    if (-not $hit) { return '' }
    $when = if ($Set.scopes.ContainsKey($hit)) { " (last compared $($Set.scopes[$hit]))" } else { '' }
    return "This item is not from today: $hit was not compared this run and is shown from the last complete check$when. Nothing was done -- act on it once the area is compared again."
}

function Test-PimDriftScopeFeatureOn {
    <#
      Framework TRUST-1 point 7, checked FIRST (round 3 item 6): is the scope's provider feature on for this install? $true for
      a core scope (no feature key -- it runs on the engine's approved Graph rights, engine\_shared\PIM-RightsList.ps1), $false
      when its feature is off or unlicensed, $true when it cannot be told (no provider registry / feature gate in this process).
    #>
    param([string]$Scope)
    try {
        if (-not (Get-Command Get-PimEngineProvider -ErrorAction SilentlyContinue)) { return $true }
        $p = Get-PimEngineProvider -Scope $Scope
        if ($null -eq $p -or -not "$($p.feature)".Trim()) { return $true }
        if (-not (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue)) { return $true }
        return [bool](Test-PimFeatureAvailable -Key "$($p.feature)" -Quiet)
    } catch { return $true }
}

function Test-PimDriftScopeFeatureGated {
    <#
      TRUST-1 round 5 H5: is the scope BEHIND a feature switch (its provider names a feature key)? Only such a scope can be
      "not part of this install" when it was never compared. $false for a core scope AND when it cannot be told (no provider
      registry in this process) -- fail-closed: a core scope's error is always a failure this time.
    #>
    param([string]$Scope)
    try {
        if (-not (Get-Command Get-PimEngineProvider -ErrorAction SilentlyContinue)) { return $false }
        $p = Get-PimEngineProvider -Scope $Scope
        return [bool]($null -ne $p -and "$($p.feature)".Trim())
    } catch { return $false }
}

function Get-PimDriftStoredRefusal {
    <#
      TRUST-1 round 5 G5 / H7: the 409 reason for an action on drift, from the STORED drift document (Get-PimDriftCarriedSet +
      Get-PimDriftActionRefusal), or ''. FAIL-CLOSED: a document that could not be READ (a failed read -- never "nothing
      stored") refuses the action: "could not check whether this item is current -- try again". -Read { -> document }: test seam.
    #>
    param([string]$Scope = '', [string]$Key = '', [string]$GroupId = '', [string[]]$SelectKeys = @(), [scriptblock]$Read = $null)
    $doc = $null; $err = ''
    try {
        if ($Read) { $doc = & $Read }
        else {
            $doc = Get-PimTenantCacheEntry -Kind 'drift'
            if ($null -eq $doc -and (Get-Command Get-PimTenantCacheReadError -ErrorAction SilentlyContinue)) { $err = "$(Get-PimTenantCacheReadError -Kind 'drift')".Trim() }
        }
    } catch { $err = "$($_.Exception.Message)" }
    if ($err) { return "Could not check whether this item is current ($err) -- nothing was done. Try again." }
    return (Get-PimDriftActionRefusal -Set (Get-PimDriftCarriedSet -Doc $doc) -Scope $Scope -Key $Key -GroupId $GroupId -SelectKeys $SelectKeys)
}

function Merge-PimDriftCarriedScopes {
    <#
      TRUST-1 (points 2, 7, 8; gap 4). Splits the document's scopes the way every job does:
        absent by design  the scope's FEATURE is off for this install -- skippedFeature, or (checked FIRST, round 3 item 6) an
                          erroring scope whose provider feature is off (-FeatureOn) -- or a scope that errors, was NEVER
                          compared before and is not on the approved rights list (-Approved) -> scopesUnknown with the stable
                          code DRIFT-SCOPE-NOT-PRESENT; it blocks nothing. Round 5 H5: "never compared" applies ONLY to a scope
                          behind a feature switch (-Gated, Test-PimDriftScopeFeatureGated); a core scope errors = failed.
        failed this time  any other error, or not compared for a data reason (ok, not checked, NO skippedFeature: a live read
                          refused, unreadable bindings) -> its entry is replaced by the PREVIOUS document's entry of that scope
                          when that one was compared or carried (carried = $true, carriedFromUtc = when it was last compared,
                          carriedReason); none to carry = the entry stays (not checked, no counts).
        stale             a carried scope older than Get-PimTrustCarryMaxAgeDays (point 8): still listed with its date (stale =
                          $true), named in scopesStale with DRIFT-SOURCE-STALE; staleNew = it became stale on THIS run.
      Every engine scope runs on the engine's approved Graph rights, so -Approved defaults to $true (an erroring core scope is
      always failed this time); a scope behind a feature asks -FeatureOn (Test-PimDriftScopeFeatureOn).
      Round 3 item 12: the counters are recomputed -- scopesChecked = compared THIS run, scopesCarried, scopesFailed = failed this
      run, scopesNotChecked = every scope not compared this run; ok = nothing failed this run. Totals over compared + carried.
      Changes -Doc in place; returns @{ failed = [string[]]; carried; unknown; stale; staleNew; reasons }.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Doc, [AllowNull()][object]$Previous = $null, [datetime]$NowUtc = [datetime]::UtcNow,
          [scriptblock]$FeatureOn = $null, [scriptblock]$Approved = $null, [switch]$PreviousUnreadable, [scriptblock]$Gated = $null)
    if (-not $FeatureOn) { $FeatureOn = { param($s) Test-PimDriftScopeFeatureOn -Scope $s } }
    if (-not $Approved) { $Approved = { param($s) $true } }
    if (-not $Gated) { $Gated = { param($s) Test-PimDriftScopeFeatureGated -Scope $s } }
    $prevBy = @{}
    $prevAt = "$(ConvertTo-PimDriftIsoStamp (Get-PimDriftSnapshotField $Previous 'refreshedUtc'))"
    foreach ($ps in @(@(Get-PimDriftSnapshotField $Previous 'scopes') | Where-Object { $null -ne $_ })) {
        if ([bool](Get-PimDriftSnapshotField $ps 'ok') -and [bool](Get-PimDriftSnapshotField $ps 'checked')) { $prevBy["$(Get-PimDriftSnapshotField $ps 'scope')"] = $ps }
    }
    $failed = [System.Collections.Generic.List[string]]::new(); $carried = [System.Collections.Generic.List[object]]::new()
    $unknown = [System.Collections.Generic.List[object]]::new(); $reasons = [System.Collections.Generic.List[object]]::new()
    $stale = [System.Collections.Generic.List[object]]::new(); $staleNew = [System.Collections.Generic.List[object]]::new()
    $out = [System.Collections.Generic.List[object]]::new()
    $maxDays = Get-PimTrustCarryMaxAgeDays
    foreach ($sd in @($Doc['scopes'])) {
        if ($null -eq $sd) { continue }
        $name = "$(Get-PimDriftSnapshotField $sd 'scope')"
        $ok = [bool](Get-PimDriftSnapshotField $sd 'ok'); $chk = [bool](Get-PimDriftSnapshotField $sd 'checked')
        $skipF = "$(Get-PimDriftSnapshotField $sd 'skippedFeature')".Trim()
        if (-not $ok -or (-not $chk -and -not $skipF)) {
            $why = "$(Get-PimDriftSnapshotField $sd 'error')".Trim(); if (-not $why) { $why = "$(Get-PimDriftSnapshotField $sd 'notCheckedReason')".Trim() }
            $readBefore = $prevBy.ContainsKey($name)
            $fOn = [bool](& $FeatureOn $name)
            # round 4 item 2 (Invardia): a scope NEVER compared before fails THIS time only on a real rights-gap signal -- an
            # approved right refused (HTTP 401 / 403: DRIFT-RIGHT-MISSING, also a RIGHTS-LIVE-1 missing-right case); anything else
            # (no licence, nothing discovered yet, a first-run error) is UNKNOWN and blocks nothing. A previous document that could
            # not be READ is never "never compared" (-PreviousUnreadable).
            # Round 5 H5: "never compared = unknown" holds ONLY for a scope behind a feature switch (-Gated); a CORE scope (no feature
            # key, or it cannot be told) with ANY error is FAILED this time.
            $rightsGap = ($why -match '(?i)\b40[13]\b|Forbidden|Unauthori[sz]ed|Authorization_RequestDenied|AuthorizationFailed|Insufficient privileges')
            $gatedS = [bool](& $Gated $name)
            $countsFailed = $fOn -and ($readBefore -or $PreviousUnreadable -or -not $gatedS -or ($rightsGap -and [bool](& $Approved $name)))
            if (-not $countsFailed) {
                $unknown.Add([ordered]@{ scope = $name; code = 'DRIFT-SCOPE-NOT-PRESENT'; reason = $(if (-not $fOn) { "the feature of this area is off for this install ($why)" } else { "never compared, no approved right refused ($why)" }) })
                # round 4 item 10: an area the install does not have is not "not checked" -- it says skippedFeature, so the uplink's
                # driftItems is not left out for good because of it
                if (-not $fOn -and $sd -is [System.Collections.IDictionary]) { $sd['skippedFeature'] = 'off-for-this-install'; $sd['ok'] = $true; $sd['checked'] = $false; $sd['notCheckedReason'] = "the feature of this area is off for this install ($why)" }
                elseif ($sd -is [System.Collections.IDictionary]) { $sd['skippedFeature'] = 'not-present'; $sd['ok'] = $true; $sd['checked'] = $false; $sd['notCheckedReason'] = "not part of this install's check yet ($why)" }
                $out.Add($sd); continue
            }
            $code = if ($rightsGap -and -not $readBefore) { 'DRIFT-RIGHT-MISSING' } else { '' }
            $failed.Add($name); $reasons.Add([ordered]@{ scope = $name; error = $why; code = $code })
            if ($readBefore) {
                $p = $prevBy[$name]; $c = [ordered]@{}
                foreach ($pp in $p.PSObject.Properties) { $c[$pp.Name] = $pp.Value }
                $from = "$(ConvertTo-PimDriftIsoStamp (Get-PimDriftSnapshotField $p 'carriedFromUtc'))"; if (-not $from) { $from = $prevAt }
                $c['carried'] = $true; $c['carriedFromUtc'] = $from; $c['carriedReason'] = $why
                $at = $null; try { $at = [datetime]::Parse($from, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $at = $null }
                if ($null -ne $at -and ($NowUtc.ToUniversalTime() - $at).TotalDays -gt $maxDays) {
                    $c['stale'] = $true
                    $sx = [ordered]@{ scope = $name; code = 'DRIFT-SOURCE-STALE'; sinceUtc = $from }
                    $stale.Add($sx); if (-not [bool](Get-PimDriftSnapshotField $p 'stale')) { $staleNew.Add($sx) }
                }
                $out.Add($c); $carried.Add([ordered]@{ scope = $name; fromUtc = $from; stale = [bool]$c['stale'] })
                continue
            }
        } elseif (-not $chk -and $skipF) {
            $unknown.Add([ordered]@{ scope = $name; code = 'DRIFT-SCOPE-NOT-PRESENT'; reason = "$(Get-PimDriftSnapshotField $sd 'notCheckedReason')" })
        }
        $out.Add($sd)
    }
    $m = 0; $ch = 0; $x = 0; $w = 0; $ex = 0; $compared = 0
    foreach ($sd in $out) {
        if (-not ([bool](Get-PimDriftSnapshotField $sd 'ok') -and [bool](Get-PimDriftSnapshotField $sd 'checked'))) { continue }
        if (-not [bool](Get-PimDriftSnapshotField $sd 'carried')) { $compared++ }
        $m += [int](Get-PimDriftSnapshotField $sd 'missing'); $ch += [int](Get-PimDriftSnapshotField $sd 'changed'); $x += [int](Get-PimDriftSnapshotField $sd 'extra')
        $w += [int](Get-PimDriftSnapshotField $sd 'warnings'); $ex += [int](Get-PimDriftSnapshotField $sd 'excluded')
    }
    $Doc['scopes'] = $out.ToArray()
    $Doc['total'] = ($m + $ch + $x + $w)
    $Doc['counts'] = [ordered]@{ missing = $m; changed = $ch; extra = $x; warnings = $w }
    $Doc['excluded'] = $ex
    $Doc['scopesChecked'] = $compared
    $Doc['scopesNotChecked'] = $out.Count - $compared
    $Doc['scopesFailed'] = $failed.Count
    $Doc['ok'] = ($failed.Count -eq 0 -and $out.Count -gt 0)
    $Doc['scopesCarried'] = $carried.ToArray()
    $Doc['scopesUnknown'] = $unknown.ToArray()
    $Doc['scopesStale'] = $stale.ToArray()
    $Doc['scopesFailedThisRun'] = $failed.ToArray()
    return @{ failed = $failed.ToArray(); carried = $carried.ToArray(); unknown = $unknown.ToArray(); stale = $stale.ToArray(); staleNew = $staleNew.ToArray(); reasons = $reasons.ToArray() }
}

# ===========================================================================
# THE SCHEDULER JOB -- 'drift-snapshot'
# ===========================================================================
function Invoke-PimDriftSnapshotJob {
    <#
      Compute the drift document and persist it as pim.TenantCache kind 'drift'. Returns the scheduler handler shape.
      🔒 -WhatIf reads NOTHING and writes NOTHING.
      🔒 No SQL store -> REFUSED (unimplemented), never a memory-only write the Manager could never read.
      🔴 Every scope failing is STORED (the page shows why) and then THROWS so the run is recorded failed.
         Some scopes failing (or not checked for a data reason) is stored and reported ran=$true, warning=$true with
         the scopes named (TRUST-1 gap 2).
      Drift found in a FULLY CHECKED run -> the 'drift' alert (debounced by the alerting layer) + the Invardia alert;
      a partial run sends neither (TRUST-1 gap 2).
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $type = $script:PimDriftSnapshotJobType
    $kind = $script:PimDriftSnapshotCacheKind
    if ($WhatIf) {
        return [pscustomobject]@{ ran = $false; whatIf = $true
            detail = "whatif:$type -- would plan every engine scope (Full, Prune, WhatIf) and write pim.TenantCache/$kind (nothing read, nothing written)" }
    }
    if (-not (Get-Command Set-PimTenantCacheEntry -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = $false
            detail = "unimplemented:$type (tools/pim-manager/_tenantSync.ps1 is not loaded on this worker -- no tenant-cache store to write to)" }
    }
    if (-not (Get-PimTenantCacheStoreCs)) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = $false
            detail = "unimplemented:$type -- no SQL store in this process, so the drift snapshot could only live in memory where the Manager can never read it" }
    }
    if (-not (Get-Command Invoke-PimEngine -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimDriftReport -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = $false
            detail = "unimplemented:$type (the engine core or PIM-Governance.ps1 is not loaded on this worker)" }
    }

    # TRUST-1 gap 4: the stored document BEFORE this run -- a scope that fails this time keeps its last good result from it.
    # Round 4 items 1 + 6: what was stored when this run STARTED (its refreshedUtc, for the compare-and-set), and a previous
    # document that could not be READ (a failed read, never "nothing stored": every unread scope then counts as failed, and
    # the stored document is NOT overwritten).
    $startDoc = $null; if (Get-Command Get-PimTenantCacheDocStamp -ErrorAction SilentlyContinue) { $startDoc = Get-PimTenantCacheDocStamp -Kind $kind -Path '$.refreshedUtc' }
    $prevDoc = $null; $prevUnreadable = $false
    try { $prevDoc = Get-PimTenantCacheEntry -Kind $kind } catch { $prevDoc = $null; $prevUnreadable = $true }
    if ($null -eq $prevDoc -and (Get-Command Get-PimTenantCacheReadError -ErrorAction SilentlyContinue) -and "$(Get-PimTenantCacheReadError -Kind $kind)".Trim()) { $prevUnreadable = $true }
    if ($null -ne $startDoc -and "$($startDoc.error)".Trim()) { $prevUnreadable = $true }
    $doc = Invoke-PimDriftSnapshot -NowUtc $NowUtc
    $doc['source'] = 'scheduler'
    $doc['correlationId'] = "$($global:PIM_JobCorrelationId)"
    $mg = Merge-PimDriftCarriedScopes -Doc $doc -Previous $prevDoc -NowUtc $NowUtc -PreviousUnreadable:$prevUnreadable
    # TRUST-1 point 8 + round 6 F6: EVERY stale area is handed to the register on every run -- the stall-report list decides
    # "already asked for" (one request per area and since-date, kept 60 days sent or not), so a registration that failed on the
    # day it became stale is made on the next run, and a kept document that is never rewritten still opens exactly one
    foreach ($sx in @($mg.stale)) {
        if (Get-Command Register-PimTrustStaleReport -ErrorAction SilentlyContinue) { try { [void](Register-PimTrustStaleReport -Job 'pim-drift-snapshot' -Part "$($sx.scope)" -Code 'DRIFT-SOURCE-STALE' -SinceUtc "$($sx.sinceUtc)" -NowUtc $NowUtc) } catch { } }
    }
    # round 4 items 6 + 12: NOT stored over the previous result while that one could not be read, or when EVERY scope failed this
    # run (the previous result stays, its "as of" unchanged, with 'lastRun' saying this run failed); else stored only over the
    # document this run STARTED with (round 4 item 1, second guard: a newer result stored meanwhile is kept).
    # Round 5 G10: "every scope failed" counts the scopes this install HAS -- an absent one (scopesUnknown) is not a scope that
    # could have been read.
    $liveScopeN = @($doc.scopes).Count - @($mg.unknown).Count
    $allFailedD = ($liveScopeN -gt 0 -and @($mg.failed).Count -ge $liveScopeN)
    $where = ''
    if ($prevUnreadable -or ($allFailedD -and $null -ne $prevDoc)) {
        # Round 5 G2: the kept document AGES -- the areas carried past Get-PimTrustCarryMaxAgeDays are named stale on its lastRun
        # (DRIFT-SOURCE-STALE: the Manager then refuses every action on them, Get-PimDriftCarriedSet; driftItems is left out while
        # lastRun.trusted = false)
        $lrD = [ordered]@{ utc = "$($doc.refreshedUtc)"; trusted = $false; failed = @($mg.failed); reason = $(if ($prevUnreadable) { 'the previous drift result could not be read' } else { 'every area failed this run' }) }
        if (@($mg.stale).Count) { $lrD['stale'] = @($mg.stale) }
        $mk = -1; if (-not $prevUnreadable -and (Get-Command Set-PimTenantCacheLastRun -ErrorAction SilentlyContinue)) { try { $mk = Set-PimTenantCacheLastRun -Kind $kind -Path '$.refreshedUtc' -Start $startDoc -LastRun $lrD } catch { $mk = -1 } }
        $where = "not stored ($($lrD.reason)) -- the previous result is kept" + $(if ($mk -gt 0) { ', lastRun recorded on it' } else { '' })
    } else {
        $wrD = Set-PimTenantCacheEntryIfUnchanged -Kind $kind -Value $doc -Path '$.refreshedUtc' -Start $startDoc
        if ($wrD.newer) {
            return [pscustomobject]@{ ran = $true; whatIf = $false; total = [int]$doc.total; newerKept = $true
                detail = "$type`: a newer drift result was stored meanwhile -- kept (this run's result is not stored, nothing mailed)" }
        }
        $where = "$($wrD.where)"
    }
    # Delegation overview (All privileged permissions) reads which live assignments are MANAGED from here (pim.TenantCache kind 'managed-live').
    if ($script:PimLastManagedLive) {
        $__mlStored = $false
        try { [void](Set-PimTenantCacheEntry -Kind 'managed-live' -Value $script:PimLastManagedLive); $__mlStored = $true }
        catch { Write-Warning "[drift-snapshot] the managed list for Delegation overview (All privileged permissions) was not stored: $($_.Exception.Message)" }
        # §33.0 MORE TELEMETRY round 2: the newest active-assignments generation is re-marked against the list just written, so
        # the heartbeat's roleAssignmentsOutsidePim stays current between snapshots (set-based in SQL; never fails this job).
        if ($__mlStored -and (Get-Command Update-PimActiveAssignmentsSnapshotMarks -ErrorAction SilentlyContinue)) {
            try { $__mk = Update-PimActiveAssignmentsSnapshotMarks; if (-not $__mk.ok) { Write-Warning "[drift-snapshot] the active-assignments marks were not brought up to date: $($__mk.reason)" } } catch { }
        }
    }
    $scopeDocs = @($doc.scopes)
    $failedNames = @($scopeDocs | Where-Object { -not $_.ok } | ForEach-Object { "$($_.scope)" })
    # TRUST-1 (points 2, 3, 7; round 3 item 1): held PER SCOPE. A scope that FAILED THIS TIME (an error, or not compared for a
    # data reason) keeps its last good result on the Drift page (carried, never actionable) and makes the run PARTIAL (a
    # WARNING); the drift mail + the Invardia alert still go out for the scopes compared THIS run, and the mail names the
    # held scopes and since when. driftItems on the uplink stays out until every scope is compared again (its SQL). A scope
    # this install does not have (its feature off) is named UNKNOWN and blocks nothing.
    $failedThisRun = @($mg.failed)
    $fullyChecked = ($failedThisRun.Count -eq 0 -and $scopeDocs.Count -gt 0)
    # REQ-U wave 2: live workload warnings (orphan group / unmanaged binding / wrong permissions) are drift too.
    $sum = "{0} drift item(s) (missing={1} changed={2} extra={3} warnings={7}) across {4} scope(s) in {5}s -> {6}" -f `
        $doc.total, $doc.counts.missing, $doc.counts.changed, $doc.counts.extra, $scopeDocs.Count, $doc.durationSeconds, $where, [int]$doc.counts.warnings

    # §79.4: ignored findings are not mailed (the STORED document stays complete; the Manager filters it at read time).
    $__ign = @(Get-PimDriftIgnores)
    if ($__ign.Count) { $doc = Invoke-PimDriftIgnoreFilter -Doc $doc -Ignores $__ign; $scopeDocs = @($doc.scopes) }
    # the scopes compared THIS run: only their items are mailed and counted for Invardia (a carried scope's items are old data)
    $mailScopes = @($scopeDocs | Where-Object { $null -ne $_ -and [bool](Get-PimDriftSnapshotField $_ 'ok') -and [bool](Get-PimDriftSnapshotField $_ 'checked') -and -not [bool](Get-PimDriftSnapshotField $_ 'carried') })
    $mc = [ordered]@{ missing = 0; changed = 0; extra = 0; warnings = 0 }
    foreach ($ms in $mailScopes) { foreach ($k in @('missing', 'changed', 'extra', 'warnings')) { $mc[$k] = [int]$mc[$k] + [int](Get-PimDriftSnapshotField $ms $k) } }
    $mailTotal = [int]$mc.missing + [int]$mc.changed + [int]$mc.extra + [int]$mc.warnings
    $heldTxt = ''
    if ($failedThisRun.Count) {
        $cfrom = @{}; foreach ($c in @($mg.carried)) { $cfrom["$($c.scope)"] = "$($c.fromUtc)" }
        $codeOf = @{}; foreach ($rr in @($mg.reasons)) { if ("$($rr.code)") { $codeOf["$($rr.scope)"] = "$($rr.code)" } }
        $heldTxt = 'Not checked this run (their drift is held, not mailed): ' + (@($failedThisRun | ForEach-Object { "$_" + $(if ($codeOf.ContainsKey("$_")) { " [$($codeOf["$_"])]" } else { '' }) + $(if ($cfrom.ContainsKey("$_")) { " (last complete check $($cfrom["$_"]))" } else { ' (never checked)' }) }) -join ', ')
        Write-Host "[$type] $heldTxt" -ForegroundColor DarkYellow
    }
    if ($mailTotal -gt 0) {
        $title = 'Configuration drift detected'
        # §79.3 (operator 2026-09-25: mails must carry "detailed information like configuration drift"): the counts, then
        # the items themselves -- area, type, what it is and, for a changed item, what differs (live -> desired). Capped;
        # the Drift page (the mail links to it) has the full list.
        $enc = { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
        $detail = "missing={0} changed={1} extra={2} warnings={3}" -f $mc.missing, $mc.changed, $mc.extra, [int]$mc.warnings
        if ($heldTxt) { $detail += '<br>' + (& $enc $heldTxt) }
        $all = @(foreach ($sd in $mailScopes) { foreach ($it in @($sd.items)) { if ($it -and "$($it.type)" -ne 'warning' -or ($it -and $it.counted)) { [pscustomobject]@{ scope = "$($sd.scope)"; type = "$($it.type)"; label = "$($it.label)"; detail = "$($it.detail)" } } } })
        if ($all.Count) {
            $lines = @($all | Select-Object -First 15 | ForEach-Object {
                '&bull; <b>' + (& $enc $_.scope) + '</b> [' + (& $enc $_.type) + '] ' + (& $enc $_.label) + $(if ($_.detail) { ' &mdash; <i>' + (& $enc $_.detail) + '</i>' } else { '' }) })
            $detail += '<br><br>' + ($lines -join '<br>') + $(if ($all.Count -gt 15) { "<br>... and $($all.Count - 15) more on the Drift page." } else { '' })
        }
        # 🔴 2026-09-26 (operator: "i also see alerts / errors from emails"): the SAME drift was mailed every 4 hours -- 7
        # identical mails in 30 h on a test tenant, to three people, two of them the customer's staff. The drift job runs every 4 h
        # and the debounce was the default 60 min, so it never held. Identical drift is now mailed once and then at most
        # once a day as a reminder; a CHANGE in the drift (the detail differs) is mailed at once.
        # SETTLING (operator 2026-09-26: "dont send ... alerts during a commit where things are not fully rolled out"): drift
        # found while a commit is still being applied is the rollout itself -- held; the next drift run mails it if it stays.
        $__settling = $false
        if ((Get-Command Test-PimAlertSettling -ErrorAction SilentlyContinue) -and (Get-Command Get-PimLastDesiredChangeUtc -ErrorAction SilentlyContinue)) {
            $__lc = Get-PimLastDesiredChangeUtc
            if (Test-PimAlertSettling -LastChangeUtc $__lc) { $__settling = $true; Write-Host ("[$type] drift found while the commit of {0:u} is still rolling out -- not mailed now" -f $__lc) -ForegroundColor DarkYellow }
        }
        # REQ-DRIFT-2 CADENCE (operator 2026-09-26: "monthly by default, but possible to define cadence as dropdown"): the
        # drift mail goes out once per cadence (pim.Settings 'DriftAlertCadence', default biweekly since 2026-10-07); a change in between
        # waits for the next mail. The last send is kept in pim.Settings 'DriftAlertState'.
        $__cad = 'biweekly'; $__last = $null
        if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
            try { $__cad = ConvertTo-PimDriftAlertCadence (Get-PimSetting -Name 'DriftAlertCadence') } catch { $__cad = 'biweekly' }
            try { $__st = Get-PimSetting -Name 'DriftAlertState'; if ($__st -is [string] -and "$__st".Trim()) { $__st = $__st | ConvertFrom-Json }; if ($__st) { $__last = $__st.lastMailUtc } } catch { $__last = $null }
        }
        $__due = Test-PimDriftAlertDue -Cadence $__cad -LastMailUtc $__last -NowUtc $NowUtc
        if (-not $__settling -and -not $__due) { Write-Host ("[$type] drift found; the $__cad drift mail was last sent {0} -- the next one waits for the cadence" -f $__last) -ForegroundColor DarkGray }
        if (-not $__settling -and $__due) { try {
            # PIM 100.105: the alert table's rows -- the tenant differs from what PIM Manager defines; one row per item
            # (kind = missing / changed / extra / warning, name = area and item). $title / $detail stay as they were.
            $__words = @{ Who = 'Customer'; Status = 'Warning'
                Problem = ("{0} item(s) in the tenant differ from what PIM Manager defines (configuration drift)" -f $mailTotal) + $(if ($heldTxt) { ". $heldTxt" } else { '' })
                Todo = 'Open the Drift page: tick what should follow the definitions and press Apply now, or press Ignore for what is intended'
                Findings = @($all | Select-Object -First 15 | ForEach-Object { @{ kind = $(switch ("$($_.type)") { 'missing' { 'Missing in the tenant'; break } 'changed' { 'Changed in the tenant'; break } 'extra' { 'Extra in the tenant'; break } default { 'Warning' } }); name = ("{0}: {1}" -f $_.scope, $_.label) + $(if ($_.detail) { " ($($_.detail))" } else { '' }) } }) }
            if (Get-Command Send-PimManagerAlert -ErrorAction SilentlyContinue) {
                $am = @{}; if (Get-Command Get-PimAlertMailArgs -ErrorAction SilentlyContinue) { $am = Get-PimAlertMailArgs -Command 'Send-PimManagerAlert' @__words }
                [void](Send-PimManagerAlert -Event 'drift' -Title $title -Detail $detail -LinkTab 'drift' -DebounceMinutes 0 @am)
            } elseif (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue) {
                $am = @{}; if (Get-Command Get-PimAlertMailArgs -ErrorAction SilentlyContinue) { $am = Get-PimAlertMailArgs -Command 'Send-PimJobAlertViaNotify' @__words }
                [void](Send-PimJobAlertViaNotify -Event 'drift' -Title $title -Detail $detail -LinkTab 'drift' -DebounceMinutes 0 @am)
            }
            if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { Set-PimSetting -Name 'DriftAlertState' -Value ([pscustomobject]@{ lastMailUtc = $NowUtc.ToUniversalTime().ToString('o'); cadence = $__cad; total = $mailTotal }) }
        } catch { Write-Warning "[$type] the drift alert could not be raised: $($_.Exception.Message)" }
            # OPEN-17 / framework 8.19: the same finding for Invardia (pim.drift.found, warning), at the same point and cadence as
            # the mail -- COUNTS only, never an item; recorded for the next uplink cycle, best effort (never throws).
            try {
                if (Get-Command Register-PimUplinkAlert -ErrorAction SilentlyContinue) {
                    [void](Register-PimUplinkAlert -Event 'drift' -NowUtc $NowUtc -Measured @{ total = [long]$mailTotal
                        missing = [long]$mc.missing; changed = [long]$mc.changed; extra = [long]$mc.extra })
                }
            } catch { }
        }
    }

    if ($allFailedD) {
        throw ("[$type] drift could not be computed for any scope; the failure was stored so the Drift page shows it. " +
            (@($mg.reasons | ForEach-Object { "[$($_.scope)] $($_.error)" }) -join '  |  '))
    }
    $partialTxt = if ($failedThisRun.Count) { " PARTIAL -- could not check: " + (@($mg.reasons | ForEach-Object { "$($_.scope)" + $(if ("$($_.code)") { " [$($_.code)]" } else { '' }) }) -join ', ') } else { '' }
    if (@($mg.carried).Count) { $partialTxt += " | last good result kept: " + (@($mg.carried | ForEach-Object { "$($_.scope) (of $($_.fromUtc))" }) -join ', ') }
    if (@($mg.unknown).Count) { $partialTxt += " | UNKNOWN (not part of this install's check): " + (@($mg.unknown | ForEach-Object { "$($_.scope) [$($_.code)]" }) -join ', ') }
    # REQ-U: a skipped (gated) area is named too -- it was NOT checked, whatever the totals say.
    $skippedDocs = @($scopeDocs | Where-Object { $_.ok -and -not $_.checked })
    if ($skippedDocs.Count) { $partialTxt += " NOT CHECKED: " + (@($skippedDocs | ForEach-Object { "$($_.scope) ($($_.notCheckedReason))" }) -join '; ') }
    $out = [pscustomobject]@{ ran = $true; whatIf = $false; total = [int]$doc.total; scopesFailed = $failedNames.Count
        detail = "$type`: $sum$partialTxt" }
    # TRUST-1: a partial run is a WARNING run (amber); the held scopes' drift was not mailed / sent (round 3 item 11: warningSummary)
    if (-not $fullyChecked -and $scopeDocs.Count -gt 0) {
        $out | Add-Member -NotePropertyName 'warning' -NotePropertyValue $true -Force
        $out | Add-Member -NotePropertyName 'trusted' -NotePropertyValue $false -Force
        $out | Add-Member -NotePropertyName 'warningSummary' -NotePropertyValue ("drift partial: $heldTxt") -Force
        $out.detail = "$($out.detail) | not every area was checked: $heldTxt"
    }
    return $out
}

function Register-PimDriftSnapshotHandler {
    # Called ONLY by tools/pim-scheduler/Start-PimScheduler.ps1, AFTER Initialize-PimDefaultJobHandlers.
    if (-not (Get-Command Register-PimJobHandler -ErrorAction SilentlyContinue)) {
        throw 'Register-PimDriftSnapshotHandler: PIM-Scheduler.ps1 is not loaded (Register-PimJobHandler missing).'
    }
    Register-PimJobHandler -Type $script:PimDriftSnapshotJobType -Handler {
        param($job, $now, $whatIf)
        Invoke-PimDriftSnapshotJob -Job $job -NowUtc $now -WhatIf:$whatIf
    }
}

# ===========================================================================
# THE MANAGER'S SIDE -- read the stored document, ask for a refresh. No engine run.
# ===========================================================================
function Request-PimDriftSnapshotRefresh {
    # Queue an on-demand 'drift-snapshot' run (deduped by type+scope inside Add-PimJobTrigger). Never throws.
    param([string]$Reason = 'manager')
    if (-not (Get-Command Add-PimJobTrigger -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ queued = $false; error = 'the scheduler trigger queue (PIM-Scheduler.ps1) is not loaded in this process' }
    }
    try {
        [void](Add-PimJobTrigger -Type $script:PimDriftSnapshotJobType -Scope 'All' -Reason $Reason)
        return [pscustomobject]@{ queued = $true; error = '' }
    } catch {
        return [pscustomobject]@{ queued = $false; error = "$($_.Exception.Message)" }
    }
}

function ConvertTo-PimDriftIsoStamp {
    # pwsh 7's ConvertFrom-Json turns an ISO string into a [datetime] (rendered in the current culture); 5.1 keeps
    # the string. Normalise both to 'yyyy-MM-ddTHH:mm:ssZ' so the GUI can parse it.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [datetime]) {
        $d = if ($Value.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) } else { $Value.ToUniversalTime() }
        return $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    return $s
}

function ConvertTo-PimDriftSnapshotView {
    <#
      PURE. Shape a stored drift document (or $null) into the GET /api/drift response:
        { ok; supported; snapshotMissing; refreshQueued; refreshError; refreshedUtc; ageSeconds; cadenceMinutes; stale;
          hint; durationSeconds; total; counts; scopesFailed; scopes; items (flat: scope/entity/type/key/label) }
    #>
    param(
        [AllowNull()][object]$Entry,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [int]$CadenceMinutes = 0,
        [bool]$RefreshQueued = $false,
        [string]$QueueError = ''
    )
    if ($CadenceMinutes -le 0) { $CadenceMinutes = $script:PimDriftSnapshotDefaultCadenceMinutes }
    $now = $NowUtc.ToUniversalTime()
    $refreshedIso = if ($null -ne $Entry) { ConvertTo-PimDriftIsoStamp -Value (Get-PimDriftSnapshotField $Entry 'refreshedUtc') } else { $null }
    if ($null -eq $Entry -or -not "$refreshedIso".Trim()) {
        $hint = if ($RefreshQueued) { 'No drift check has run yet -- one is queued. The scheduler runs it within a few minutes; this page does not wait for it.' }
                elseif ("$QueueError".Trim()) { "No drift check has run yet, and one could NOT be queued ($QueueError). The scheduler job 'drift-snapshot' runs it every $CadenceMinutes min." }
                else { "No drift check has run yet. The scheduler job 'drift-snapshot' runs it every $CadenceMinutes min; Check now queues one." }
        return [ordered]@{
            ok = $true; supported = $true; snapshot = $true; snapshotMissing = $true
            refreshQueued = [bool]$RefreshQueued; refreshError = "$QueueError"
            refreshedUtc = $null; generatedUtc = $null; ageSeconds = $null; cadenceMinutes = $CadenceMinutes; stale = $false
            hint = $hint; durationSeconds = $null; total = 0
            counts = [ordered]@{ missing = 0; changed = 0; extra = 0 }; scopesFailed = 0; scopes = @(); items = @()
            source = 'scheduler-snapshot'
        }
    }
    $refreshed = $null
    try { $refreshed = [datetime]::Parse($refreshedIso, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $refreshed = $null }
    $age = if ($refreshed) { [int64][math]::Max(0, [math]::Round(($now - $refreshed).TotalSeconds, 0)) } else { $null }
    $stale = ($null -ne $age) -and ($age -gt (2 * $CadenceMinutes * 60))
    $scopes = @(@(Get-PimDriftSnapshotField $Entry 'scopes') | Where-Object { $null -ne $_ })
    $flat = New-Object System.Collections.Generic.List[object]
    # Round 5 G2: a kept document whose lastRun (every area failed) names areas STALE -- their items are shown as not from today
    $lrSt = @{}; $lrStList = [System.Collections.Generic.List[object]]::new()
    $lrV = Get-PimDriftSnapshotField $Entry 'lastRun'
    $lrHeld = @{}
    if ($null -ne $lrV -and "$(Get-PimDriftSnapshotField $lrV 'trusted')" -match '^(?i)false$') {
        foreach ($x in @(@(Get-PimDriftSnapshotField $lrV 'stale') | Where-Object { $null -ne $_ })) { $lrSt["$(Get-PimDriftSnapshotField $x 'scope')"] = "$(ConvertTo-PimDriftIsoStamp (Get-PimDriftSnapshotField $x 'sinceUtc'))"; $lrStList.Add($x) }
        # round 6 F3: an area the newest run could not compare is shown as not from today at once (stale only once lastRun says so)
        foreach ($fn in @(@(Get-PimDriftSnapshotField $lrV 'failed') | Where-Object { "$_".Trim() })) { $lrHeld["$fn"] = "$refreshedIso" }
    }
    foreach ($s in $scopes) {
        $sName = "$(Get-PimDriftSnapshotField $s 'scope')"; $sHeld = $lrHeld.ContainsKey($sName) -or $lrSt.ContainsKey($sName); $sLr = $lrSt.ContainsKey($sName)
        foreach ($it in @(@(Get-PimDriftSnapshotField $s 'items') | Where-Object { $null -ne $_ })) {
            $flat.Add([ordered]@{ scope = $sName; entity = "$(Get-PimDriftSnapshotField $s 'entity')"
                type = "$(Get-PimDriftSnapshotField $it 'type')"; key = "$(Get-PimDriftSnapshotField $it 'key')"; label = "$(Get-PimDriftSnapshotField $it 'label')"
                kind = "$(Get-PimDriftSnapshotField $it 'kind')"   # REQ-U wave 2: a warning's kind (orphan-group / unmanaged-binding / wrong-permissions)
                # TRUST-1 point 2: an item of an area carried from its last complete read says so (shown, never actionable)
                carried = ([bool](Get-PimDriftSnapshotField $s 'carried') -or $sHeld); stale = ([bool](Get-PimDriftSnapshotField $s 'stale') -or $sLr)
                carriedFromUtc = $(if ($sHeld -and -not [bool](Get-PimDriftSnapshotField $s 'carried')) { $(if ($sLr) { $lrSt[$sName] } else { $lrHeld[$sName] }) } else { "$(ConvertTo-PimDriftIsoStamp (Get-PimDriftSnapshotField $s 'carriedFromUtc'))" }) })
        }
    }
    $asOf = if ($refreshed) { $refreshed.ToString('HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { "$refreshedIso" }
    $hint = "as of $asOf (checked every $CadenceMinutes min)"
    if ($RefreshQueued) { $hint += '; a new check is queued -- results in a few minutes' }
    elseif ("$QueueError".Trim()) { $hint += "; a new check could NOT be queued ($QueueError)" }
    if ($stale) { $hint += "; STALE -- older than two cadences, check the 'drift-snapshot' job on the Jobs page" }
    $counts = Get-PimDriftSnapshotField $Entry 'counts'
    if ($null -eq $counts) { $counts = [ordered]@{ missing = 0; changed = 0; extra = 0 } }
    $storedOk = Get-PimDriftSnapshotField $Entry 'ok'
    return [ordered]@{
        ok              = $(if ($null -ne $storedOk) { [bool]$storedOk } else { $true })
        supported       = $true
        snapshot        = $true
        snapshotMissing = $false
        refreshQueued   = [bool]$RefreshQueued
        refreshError    = "$QueueError"
        refreshedUtc    = $refreshedIso
        generatedUtc    = $refreshedIso
        ageSeconds      = $age
        cadenceMinutes  = $CadenceMinutes
        stale           = [bool]$stale
        hint            = $hint
        durationSeconds = Get-PimDriftSnapshotField $Entry 'durationSeconds'
        total           = [int](Get-PimDriftSnapshotField $Entry 'total')
        counts          = $counts
        # Platform-owned items (PIM's own SQL admin group) left out of the counts -- reported, never hidden.
        excluded        = [int](Get-PimDriftSnapshotField $Entry 'excluded')
        excludedNames   = @(@(Get-PimDriftSnapshotField $Entry 'excludedNames') | Where-Object { "$_".Trim() })
        # §79.4: findings an operator chose to IGNORE -- hidden from the counts, listed with who / why so they can be undone.
        ignored         = [int](Get-PimDriftSnapshotField $Entry 'ignored')
        ignoredItems    = @(@(Get-PimDriftSnapshotField $Entry 'ignoredItems') | Where-Object { $null -ne $_ })
        scopesFailed    = [int](Get-PimDriftSnapshotField $Entry 'scopesFailed')
        # REQ-U: an older document has no 'checked' -- a skipped (skippedFeature) or failed area is not checked.
        scopesNotChecked = @($scopes | Where-Object {
            $ck = Get-PimDriftSnapshotField $_ 'checked'; $okS = Get-PimDriftSnapshotField $_ 'ok'
            ($null -ne $ck -and -not [bool]$ck) -or ($null -ne $okS -and -not [bool]$okS) -or "$(Get-PimDriftSnapshotField $_ 'skippedFeature')".Trim() }).Count
        # TRUST-1: the areas carried from their last complete read (with since when), the areas not part of this install, and
        # the areas that failed THIS run -- so the page can say "not checked since <date>, shown from the last complete read"
        scopesCarried   = @(@(Get-PimDriftSnapshotField $Entry 'scopesCarried') | Where-Object { $null -ne $_ })
        scopesUnknown   = @(@(Get-PimDriftSnapshotField $Entry 'scopesUnknown') | Where-Object { $null -ne $_ })
        scopesFailedThisRun = @(@(Get-PimDriftSnapshotField $Entry 'scopesFailedThisRun') | Where-Object { "$_".Trim() })
        # round 4 item 11: the areas not compared for more than a week (DRIFT-SOURCE-STALE, still listed with their date)
        scopesStale     = @(@(@(Get-PimDriftSnapshotField $Entry 'scopesStale') | Where-Object { $null -ne $_ }) + @($lrStList.ToArray()))
        lastRun         = (Get-PimDriftSnapshotField $Entry 'lastRun')
        scopes          = $scopes
        items           = @($flat.ToArray())
        source          = 'scheduler-snapshot'
    }
}

# ---- REQ-DRIFT-2 (operator 2026-09-26: "similar logic for configuration drift but it must go to alert mail instead - and be
# possible to delete/keep/ignore"; "cadence for config drift must be monthly by default, but possible to define cadence as
# dropdown"). An EXTRA (in the tenant, not in PIM) can be DELETED -- queued as the matching revoke, with every gate the
# revoke path has (break-glass, count confirmation, approval, commit on the Queue) -- or KEPT: the desired row that defines it
# is staged, so PIM manages it and the drift is gone after Review & commit. Missing / changed items keep "Apply now".
function ConvertTo-PimDriftAuTag {
    # PURE. A tag for an adopted AU: its display name with anything but letters, digits, '.', '_', '-' made a '-'.
    param([string]$DisplayName)
    return (("$DisplayName".Trim() -replace '[^A-Za-z0-9._-]+', '-') -replace '-{2,}', '-').Trim('-')
}

function Get-PimDriftExtraActions {
    <#
      PURE. What Delete and Keep can do for ONE extra item, from the LIVE row the engine plan carried (-Payload) and its area
      (-Scope). Returns @{ revoke; revokeWhy; keep; keepWhy }:
        revoke -- the row POST /api/revoke takes ({ type = entra-role | pim-for-groups | azure-rbac; principalId; ... }), or
                  $null with revokeWhy saying why this item cannot be deleted from the Drift page;
        keep   -- @{ base; row } the desired row to stage, or $null with keepWhy.
      Nothing is guessed: a field the row lacks means "not from here", never a partial row.
    #>
    param([string]$Scope, [AllowNull()][object]$Payload)
    $f = { param($n) "$(Get-PimDriftSnapshotField $Payload $n)".Trim() }
    $out = [ordered]@{ revoke = $null; revokeWhy = ''; keep = $null; keepWhy = '' }
    if ($null -eq $Payload) { $out.revokeWhy = 'the stored check has no live details for this item'; $out.keepWhy = $out.revokeWhy; return $out }
    $prin = & $f 'principalId'; $type = & $f 'AssignmentType'; if (-not $type) { $type = 'Eligible' }
    $pname = & $f 'PrincipalName'
    if ((& $f 'groupId') -and $prin) {
        # a PIM-for-Groups membership / ownership (AdminMembers, GroupMembers)
        $out.revoke = [ordered]@{ type = 'pim-for-groups'; principalId = $prin; groupId = (& $f 'groupId'); accessId = $(if (& $f 'accessId') { & $f 'accessId' } else { 'member' }); assignmentType = $type; principal = $pname }
        $tag = & $f 'GroupTag'
        if ($Scope -eq 'AdminMembers' -and $tag -and $pname -and (& $f 'PrincipalKind') -eq 'user') {
            $out.keep = [ordered]@{ base = 'PIM-Assignments-Admins'; row = [ordered]@{ Username = $pname; GroupTag = $tag; AssignmentType = $type } }
        } elseif ($Scope -eq 'GroupMembers' -and $tag -and (& $f 'PrincipalTag')) {
            $out.keep = [ordered]@{ base = 'PIM-Assignments-Groups'; row = [ordered]@{ TargetGroupTag = (& $f 'PrincipalTag'); SourceGroupTag = $tag; AssignmentType = $type } }
        } else { $out.keepWhy = 'the member could not be named as a PIM row (not a known admin account or PIM group) -- add its row on its page if it should stay' }
        return $out
    }
    if ((& $f 'AzScope') -and $prin) {
        if ($type -ieq 'Eligible' -and (& $f 'roleDefinitionId')) {
            $out.revoke = [ordered]@{ type = 'azure-rbac'; principalId = $prin; roleDefinitionId = (& $f 'roleDefinitionId'); scope = (& $f 'AzScope'); assignmentType = 'Eligible'; principal = $pname }
        } else { $out.revokeWhy = 'an ACTIVE Azure assignment is removed by its assignment id -- revoke it from Reviews & controls > Delegation overview (All privileged permissions)' }
        $out.keepWhy = 'an Azure role is kept by adding its row on the Azure resources page (the role name is needed)'
        return $out
    }
    if ((& $f 'roleDefinitionId') -and $prin) {
        $ds = & $f 'directoryScopeId'; if (-not $ds) { $ds = '/' }
        $out.revoke = [ordered]@{ type = 'entra-role'; principalId = $prin; roleDefinitionId = (& $f 'roleDefinitionId'); directoryScopeId = $ds; assignmentType = $type; principal = $(if ($pname) { $pname } else { & $f 'GroupTag' }) }
        if ($Scope -eq 'EntraRoles' -and $ds -eq '/' -and (& $f 'GroupTag') -and (& $f 'RoleDefinitionName')) {
            $out.keep = [ordered]@{ base = 'PIM-Assignments-Roles-Groups'; row = [ordered]@{ GroupTag = (& $f 'GroupTag'); RoleDefinitionName = (& $f 'RoleDefinitionName'); AssignmentType = $type } }
        } elseif ($Scope -eq 'RolesAUs' -and (& $f 'PrincipalTag') -and (& $f 'AuTag') -and (& $f 'RoleDefinitionName')) {
            # REQ-AU-DRIFT-1 (2.4.455): an AU-scoped role on a PIM group, in an AU PIM defines -> its Roles-AUs row
            $out.keep = [ordered]@{ base = 'PIM-Assignments-Roles-AUs'; row = [ordered]@{ GroupTag = (& $f 'PrincipalTag'); AdministrativeUnitTag = (& $f 'AuTag'); RoleDefinitionName = (& $f 'RoleDefinitionName'); AssignmentType = $type } }
        } elseif ($Scope -eq 'RolesAUs') {
            $out.keepWhy = $(if (-not (& $f 'AuTag')) { 'the Administrative Unit is not defined in PIM -- Keep the AU first (its own drift item), then this assignment' } else { 'the group or role could not be named as a PIM row -- add it on the AU delegation page' })
        } else { $out.keepWhy = 'this role assignment is kept by adding its row on its page' }
        return $out
    }
    if ($Scope -eq 'AdministrativeUnits' -and ((& $f 'displayName') -or (& $f 'DisplayName'))) {
        # REQ-AU-DRIFT-1 (2.4.455): an AU in the tenant that PIM does not define. PIM matches AUs by display name, so Keep =
        # its PIM-Definitions-AU row under that name (description / visibility as they are). PIM never deletes an AU.
        $dn = if (& $f 'displayName') { & $f 'displayName' } else { & $f 'DisplayName' }
        $out.revokeWhy = 'PIM never deletes an Administrative Unit -- remove it in Entra if it should go, or Ignore it'
        $row = [ordered]@{ AUDisplayName = $dn; AUDescription = (& $f 'description'); AdministrativeUnitTag = (ConvertTo-PimDriftAuTag -DisplayName $dn) }
        if (& $f 'visibility') { $row['Visibility'] = (& $f 'visibility') }
        $out.keep = [ordered]@{ base = 'PIM-Definitions-AU'; row = $row }
        return $out
    }
    if ($Scope -eq 'Groups' -and ((& $f 'displayName') -or (& $f 'DisplayName'))) {
        # 🔴 DRIFT-EXTRAS (PIM 100.12, owner 2026-10-09): a GROUP that exists in Entra, carries the tenant's naming prefix (so the
        # lean context lists it) and that no PIM definition names -- typically created by the customer's own infrastructure
        # code. The engine NEVER deletes it: the Groups provider has no ApplyRemove, and the daily reconcile removes only what
        # PIM's ledger + journal say PIM made. Three explicit choices on the Drift page, never a default:
        #   Import into PIM -- stage the group DEFINITION row under its exact live name. The Groups provider keys on the name,
        #                      so the committed row MATCHES the existing group (adopted, nochange) -- never a second group.
        #   Delete          -- 🔒 PIM 100.22 (d) (owner 2026-10-09: "queue + own commit, then delete"): ONE red DELETE item in
        #                      the change queue (action 'group-delete', POST /api/drift/group-delete), committed ON ITS OWN; the
        #                      engine then deletes the group on its next run EVEN WITH group retirement switched off (a per-item
        #                      explicit intent, not the global switch) -- behind the prefix, unique-name, not-defined, break-glass
        #                      and removal-budget guards (Invoke-PimQueueGroupDelete). It replaced the staged Lifecycle=Retire row.
        #   Ignore          -- hide it (pim.Settings 'DriftIgnores'), reversible.
        $dn = if (& $f 'displayName') { & $f 'displayName' } else { & $f 'DisplayName' }
        $desc = & $f 'description'; if (-not $desc) { $desc = & $f 'Description' }
        $gid = & $f 'id'; if (-not $gid) { $gid = & $f 'Id' }
        $out.revokeWhy = 'a group is not a delegation the revoke queue removes -- Delete queues the deletion of the whole group instead (its own commit)'
        $row = [ordered]@{ GroupName = $dn; GroupDescription = $desc }
        # §100.12 (ii), 2.4.555: IsRoleAssignable is taken from the LIVE group (the lean read selects isAssignableToRole), so
        # the imported definition says what the group really is. Absent on the live row = left out (never guessed).
        $ra = Get-PimDriftSnapshotField $Payload 'isAssignableToRole'; if ($null -eq $ra -or "$ra" -eq '') { $ra = Get-PimDriftSnapshotField $Payload 'IsAssignableToRole' }
        if ($null -ne $ra -and "$ra".Trim() -ne '') { $row['IsRoleAssignable'] = $(if ("$ra".Trim() -ieq 'true') { 'TRUE' } else { 'FALSE' }) }
        $out.keep = [ordered]@{ base = 'PIM-Definitions-Roles'; kind = 'group'; groupId = $gid; row = $row }
        if ("$gid".Trim()) { $out['groupDelete'] = [ordered]@{ action = 'group-delete'; kind = 'group'; groupId = "$gid".Trim(); groupName = "$dn".Trim() } }
        return $out
    }
    $out.revokeWhy = 'nothing the revoke queue can address -- remove it at its source'
    $out.keepWhy = 'add its desired row on its page if it should stay'
    return $out
}

# The drift ALERT MAIL cadence (pim.Settings 'DriftAlertCadence'). The drift job keeps refreshing the page every run; this is
# only how often the mail goes out. A change in the drift between two mails waits for the next one.
# 2026-10-07 (operator: "Configuration drift detected should be a biweekly report by default, controllable in the settings"): biweekly, the default.
$script:PimDriftAlertCadences = [ordered]@{ daily = 1; weekly = 7; biweekly = 14; monthly = 30; quarterly = 91 }
function Get-PimDriftAlertCadenceNames { @($script:PimDriftAlertCadences.Keys) }
function ConvertTo-PimDriftAlertCadence {
    # PURE. A stored value -> daily | weekly | biweekly | monthly | quarterly; anything else (unset, unreadable) = biweekly (the default).
    param([AllowNull()][object]$Value)
    $v = "$Value".Trim().Trim('"').ToLowerInvariant()
    if ($script:PimDriftAlertCadences.Contains($v)) { return $v }
    return 'biweekly'
}
function Test-PimDriftAlertDue {
    <# PURE. Is a drift mail due now? Never mailed = yes; else when the cadence has passed since the last drift mail. #>
    param([AllowNull()][object]$Cadence, [AllowNull()][object]$LastMailUtc, [datetime]$NowUtc = [datetime]::UtcNow)
    $c = ConvertTo-PimDriftAlertCadence $Cadence
    $last = $null
    if ($LastMailUtc -is [datetime]) { $last = ([datetime]$LastMailUtc).ToUniversalTime() }   # pwsh 7 ConvertFrom-Json hands a date back as [datetime]
    elseif ("$LastMailUtc".Trim()) { try { $last = [datetime]::Parse("$LastMailUtc", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $last = $null } }
    if (-not $last) { return $true }
    # an hour of slack, so a job that runs on the same clock every time is not pushed a whole run later by seconds
    return (($NowUtc.ToUniversalTime() - $last).TotalHours -ge ([double]$script:PimDriftAlertCadences[$c] * 24 - 1))
}

# ---- §79.4 IGNORE A DRIFT FINDING (operator 2026-09-25: "configuration drift, it should be possible to have a ignore
# button so findings can be ignored and not shown (hidden)"). A STANDING EXCEPTION, not an ack: stored in
# pim.Settings['DriftIgnores'] as { scope; key; label; type; reason; by; atUtc }, listed on the Drift page with who and
# why, and reversible (un-ignore). An ignored finding is left out of the counts, the total and the drift mail; the
# engine is unaffected (ignoring is about what the operator is SHOWN, never about what PIM applies).
function Get-PimDriftIgnoreKey { param([string]$Scope, [string]$Key) return ("$Scope|$Key").Trim().ToLowerInvariant() }

function Get-PimDriftIgnores {
    # The stored list, normalised; @() when none / unreadable (an unreadable list hides NOTHING -- fail visible).
    $raw = $null
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { try { $raw = Get-PimSetting -Name 'DriftIgnores' } catch { $raw = $null } }
    if ($raw -is [string]) { try { $raw = $raw | ConvertFrom-Json } catch { $raw = $null } }
    # Stored as a CONTAINER { ignores = [...] } -- a bare array through ConvertTo-Json unrolls one element to an object (IMP-39).
    if ($raw -and $raw.PSObject.Properties['ignores']) { $raw = $raw.ignores }
    return @(@($raw) | Where-Object { $_ -and "$(Get-PimDriftSnapshotField $_ 'scope')".Trim() -and "$(Get-PimDriftSnapshotField $_ 'key')".Trim() })
}

function Invoke-PimDriftIgnoreFilter {
    <#
      PURE. A stored drift document + the ignore list -> the same document with every ignored item removed from its area's
      items, the area's counts and the document's counts/total lowered by what COUNTED (a warning shown but not counted
      stays out of the arithmetic), plus ignored (count) and ignoredItems (what was hidden, with who/why). Everything else
      is copied as it is.
    #>
    param([AllowNull()][object]$Doc, [AllowNull()][AllowEmptyCollection()][object[]]$Ignores = @())
    if ($null -eq $Doc) { return $null }
    $ign = @{}
    foreach ($i in @($Ignores)) { if ($i) { $ign[(Get-PimDriftIgnoreKey (Get-PimDriftSnapshotField $i 'scope') (Get-PimDriftSnapshotField $i 'key'))] = $i } }
    $out = [ordered]@{}
    $props = if ($Doc -is [System.Collections.IDictionary]) { @($Doc.Keys) } else { @($Doc.PSObject.Properties | ForEach-Object Name) }
    foreach ($p in $props) { $out[$p] = Get-PimDriftSnapshotField $Doc $p }
    $hidden = New-Object System.Collections.Generic.List[object]
    $dm = 0; $dc = 0; $dx = 0; $dw = 0
    $newScopes = New-Object System.Collections.Generic.List[object]
    foreach ($s in @(@(Get-PimDriftSnapshotField $Doc 'scopes') | Where-Object { $null -ne $_ })) {
        $sc = [ordered]@{}
        $sp = if ($s -is [System.Collections.IDictionary]) { @($s.Keys) } else { @($s.PSObject.Properties | ForEach-Object Name) }
        foreach ($p in $sp) { $sc[$p] = Get-PimDriftSnapshotField $s $p }
        $keep = New-Object System.Collections.Generic.List[object]
        foreach ($it in @(@($sc['items']) | Where-Object { $null -ne $_ })) {
            $k = Get-PimDriftIgnoreKey "$($sc['scope'])" "$(Get-PimDriftSnapshotField $it 'key')"
            if (-not $ign.ContainsKey($k)) { $keep.Add($it); continue }
            $t = "$(Get-PimDriftSnapshotField $it 'type')"
            $counted = if ($t -eq 'warning') { [bool](Get-PimDriftSnapshotField $it 'counted') } else { $true }
            if ($counted) {
                switch ($t) { 'missing' { $dm++; $sc['missing'] = [int]$sc['missing'] - 1 } 'changed' { $dc++; $sc['changed'] = [int]$sc['changed'] - 1 } 'extra' { $dx++; $sc['extra'] = [int]$sc['extra'] - 1 } 'warning' { $dw++; $sc['warnings'] = [int]$sc['warnings'] - 1 } }
            }
            $g = $ign[$k]
            $hidden.Add([ordered]@{ scope = "$($sc['scope'])"; key = "$(Get-PimDriftSnapshotField $it 'key')"; type = $t; label = "$(Get-PimDriftSnapshotField $it 'label')"
                reason = "$(Get-PimDriftSnapshotField $g 'reason')"; by = "$(Get-PimDriftSnapshotField $g 'by')"; atUtc = "$(Get-PimDriftSnapshotField $g 'atUtc')" })
        }
        $sc['items'] = @($keep.ToArray())
        $newScopes.Add($sc)
    }
    $out['scopes'] = @($newScopes.ToArray())
    $c = Get-PimDriftSnapshotField $Doc 'counts'
    if ($null -ne $c) {
        $out['counts'] = [ordered]@{ missing = [Math]::Max(0, [int](Get-PimDriftSnapshotField $c 'missing') - $dm); changed = [Math]::Max(0, [int](Get-PimDriftSnapshotField $c 'changed') - $dc)
                                     extra = [Math]::Max(0, [int](Get-PimDriftSnapshotField $c 'extra') - $dx); warnings = [Math]::Max(0, [int](Get-PimDriftSnapshotField $c 'warnings') - $dw) }
    }
    $out['total'] = [Math]::Max(0, [int](Get-PimDriftSnapshotField $Doc 'total') - ($dm + $dc + $dx + $dw))
    $out['ignored'] = $hidden.Count
    $out['ignoredItems'] = @($hidden.ToArray())
    return $out
}
