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
    return , @($g)
}
function Test-PimDriftItemExcluded {
    <# PURE. True when this drift item names a platform-owned object. Matches the item's key AND its
       label, because a provider may carry the group in either (an id-keyed item still labels it). #>
    param([AllowNull()][object]$Item, [string[]]$Names = @())
    if ($null -eq $Item) { return $false }
    $hay = "$(Get-PimDriftSnapshotField $Item 'key') $(Get-PimDriftSnapshotField $Item 'label') $(Get-PimDriftSnapshotField $Item 'group')"
    foreach ($n in @($Names)) {
        $nn = "$n".Trim()
        if (-not $nn) { continue }
        if ($hay.IndexOf($nn, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
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
                if ($labelFn) { try { $lbl = "$(Get-PimFailureItemLabel -Key "$($it.key)" -Row $payloads["$($sd.scope)|$($it.key)"])" } catch { $lbl = '' } }
                $probe = [pscustomobject]@{ key = "$($it.key)"; label = $lbl }
                if (Test-PimDriftItemExcluded -Item $probe -Names $exclNames) { $exclN++ } else { $keep.Add($it) }
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
            if ($labelFn) { try { $label = "$(Get-PimFailureItemLabel -Key "$($it.key)" -Row $payloads["$($sd.scope)|$($it.key)"])" } catch { $label = '' } }
            if (-not $label.Trim()) { $label = "$($it.key)" }
            # §79.3: a changed item says WHAT differs (live -> desired); missing / extra say where the item is.
            $det = switch ("$($it.type)") { 'changed' { "$($diffOf["$($sd.scope)|$($it.key)"])" } 'missing' { 'in PIM, not in the tenant' } 'extra' { 'in the tenant, not in PIM' } default { '' } }
            $items.Add([ordered]@{ type = "$($it.type)"; key = "$($it.key)"; label = $label; detail = $det })
        }
        # REQ-U wave 2 (design point 8): the area's live WARNINGS (orphan group, unmanaged binding, wrong permissions).
        # They count toward drift -- EXCEPT a warning that names an item the plan already lists (its key, or one of its
        # relatedKeys: a wrong-permissions warning IS the plan's 'changed' item), which is shown but counted once.
        $wf = @(if ($findByScope.ContainsKey("$($sd.scope)")) { @($findByScope["$($sd.scope)"]) } else { @() })   # see the 5.1 note above
        if (@($wf).Count) {
            $keepW = New-Object System.Collections.Generic.List[object]
            foreach ($f in $wf) { if (Test-PimDriftItemExcluded -Item $f -Names $exclNames) { $exclN++ } else { $keepW.Add($f) } }
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
    try { Add-PimDriftPayloadNames -ScopeResults @($results.ToArray()) } catch { Write-Warning "[drift-snapshot] names for drift items could not be resolved: $($_.Exception.Message)" }
    $sw.Stop()
    return (ConvertTo-PimDriftSnapshotDocument -ScopeResults @($results.ToArray()) -NowUtc $NowUtc -DurationSeconds $sw.Elapsed.TotalSeconds)
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
    $cache = @{}; $owned = $null; $ownedTried = $false
    foreach ($r in @($ScopeResults)) {
        foreach ($pc in @(@(Get-PimDriftSnapshotField $r 'plan') | Where-Object { $null -ne $_ })) {
            $pl = Get-PimDriftSnapshotField $pc 'payload'
            if ($null -eq $pl) { continue }
            $prin = "$(Get-PimDriftSnapshotField $pl 'principalId')".Trim()
            $gid  = "$(Get-PimDriftSnapshotField $pl 'groupId')".Trim()
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
            if ($pc -is [System.Collections.IDictionary]) { $pc['payload'] = $copy } else { $pc.payload = $copy }
        }
    }
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
         Some scopes failing is stored and reported ran=$true with the failed scopes named.
      Drift found -> the 'drift' alert (debounced by the alerting layer), through whichever sender this process has.
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

    $doc = Invoke-PimDriftSnapshot -NowUtc $NowUtc
    $doc['source'] = 'scheduler'
    $doc['correlationId'] = "$($global:PIM_JobCorrelationId)"
    $where = Set-PimTenantCacheEntry -Kind $kind -Value $doc
    $scopeDocs = @($doc.scopes)
    $failedNames = @($scopeDocs | Where-Object { -not $_.ok } | ForEach-Object { "$($_.scope)" })
    # REQ-U wave 2: live workload warnings (orphan group / unmanaged binding / wrong permissions) are drift too.
    $sum = "{0} drift item(s) (missing={1} changed={2} extra={3} warnings={7}) across {4} scope(s) in {5}s -> {6}" -f `
        $doc.total, $doc.counts.missing, $doc.counts.changed, $doc.counts.extra, $scopeDocs.Count, $doc.durationSeconds, $where, [int]$doc.counts.warnings

    # §79.4: ignored findings are not mailed (the STORED document stays complete; the Manager filters it at read time).
    $__ign = @(Get-PimDriftIgnores)
    if ($__ign.Count) { $doc = Invoke-PimDriftIgnoreFilter -Doc $doc -Ignores $__ign; $scopeDocs = @($doc.scopes) }
    if ([int]$doc.total -gt 0) {
        $title = 'Configuration drift detected'
        # §79.3 (operator 2026-09-25: mails must carry "detailed information like configuration drift"): the counts, then
        # the items themselves -- area, type, what it is and, for a changed item, what differs (live -> desired). Capped;
        # the Drift page (the mail links to it) has the full list.
        $enc = { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
        $detail = "missing={0} changed={1} extra={2} warnings={3}" -f $doc.counts.missing, $doc.counts.changed, $doc.counts.extra, [int]$doc.counts.warnings
        $all = @(foreach ($sd in $scopeDocs) { foreach ($it in @($sd.items)) { if ($it -and "$($it.type)" -ne 'warning' -or ($it -and $it.counted)) { [pscustomobject]@{ scope = "$($sd.scope)"; type = "$($it.type)"; label = "$($it.label)"; detail = "$($it.detail)" } } } })
        if ($all.Count) {
            $lines = @($all | Select-Object -First 15 | ForEach-Object {
                '&bull; <b>' + (& $enc $_.scope) + '</b> [' + (& $enc $_.type) + '] ' + (& $enc $_.label) + $(if ($_.detail) { ' &mdash; <i>' + (& $enc $_.detail) + '</i>' } else { '' }) })
            $detail += '<br><br>' + ($lines -join '<br>') + $(if ($all.Count -gt 15) { "<br>... and $($all.Count - 15) more on the Drift page." } else { '' })
        }
        try {
            if (Get-Command Send-PimManagerAlert -ErrorAction SilentlyContinue) {
                [void](Send-PimManagerAlert -Event 'drift' -Title $title -Detail $detail -LinkTab 'drift')
            } elseif (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue) {
                [void](Send-PimJobAlertViaNotify -Event 'drift' -Title $title -Detail $detail -LinkTab 'drift')
            }
        } catch { Write-Warning "[$type] the drift alert could not be raised: $($_.Exception.Message)" }
    }

    if ($scopeDocs.Count -gt 0 -and $failedNames.Count -eq $scopeDocs.Count) {
        throw ("[$type] drift could not be computed for any scope; the failure was stored so the Drift page shows it. " +
            (@($scopeDocs | ForEach-Object { "[$($_.scope)] $($_.error)" }) -join '  |  '))
    }
    $partialTxt = if ($failedNames.Count) { " PARTIAL -- could not check: " + ($failedNames -join ', ') } else { '' }
    # REQ-U: a skipped (gated) area is named too -- it was NOT checked, whatever the totals say.
    $skippedDocs = @($scopeDocs | Where-Object { $_.ok -and -not $_.checked })
    if ($skippedDocs.Count) { $partialTxt += " NOT CHECKED: " + (@($skippedDocs | ForEach-Object { "$($_.scope) ($($_.notCheckedReason))" }) -join '; ') }
    return [pscustomobject]@{ ran = $true; whatIf = $false; total = [int]$doc.total; scopesFailed = $failedNames.Count
        detail = "$type`: $sum$partialTxt" }
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
    foreach ($s in $scopes) {
        foreach ($it in @(@(Get-PimDriftSnapshotField $s 'items') | Where-Object { $null -ne $_ })) {
            $flat.Add([ordered]@{ scope = "$(Get-PimDriftSnapshotField $s 'scope')"; entity = "$(Get-PimDriftSnapshotField $s 'entity')"
                type = "$(Get-PimDriftSnapshotField $it 'type')"; key = "$(Get-PimDriftSnapshotField $it 'key')"; label = "$(Get-PimDriftSnapshotField $it 'label')"
                kind = "$(Get-PimDriftSnapshotField $it 'kind')" })   # REQ-U wave 2: a warning's kind (orphan-group / unmanaged-binding / wrong-permissions)
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
        scopes          = $scopes
        items           = @($flat.ToArray())
        source          = 'scheduler-snapshot'
    }
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
