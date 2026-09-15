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

  The stored document:
    { refreshedUtc; durationSeconds; total; counts{missing,changed,extra}; scopesFailed; ok; source; correlationId;
      scopes:[ { scope; entity; desired; live; nochange; missing; changed; extra; ok; error; skippedFeature;
                 truncated; items:[ { type; key; label } ] } ] }

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
                missing = $null; changed = $null; extra = $null; ok = $false; error = $err; skippedFeature = ''; truncated = 0; items = @() })
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
        }
        $diffs.Add([pscustomobject]@{ scope = $scope; entity = $entity; create = @($cre.ToArray()); update = @($upd.ToArray()); remove = @($rem.ToArray()) })
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
            missing = 0; changed = 0; extra = 0
            ok = $true; error = ''
            skippedFeature = "$(Get-PimDriftSnapshotField $r 'skippedFeature')"
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
    foreach ($sd in $scopeDocs) {
        if (-not $sd.ok) { continue }
        $list = if ($byScope.ContainsKey("$($sd.scope)")) { @($byScope["$($sd.scope)"].ToArray()) } else { @() }
        $sd.missing = @($list | Where-Object { $_.type -eq 'missing' }).Count
        $sd.changed = @($list | Where-Object { $_.type -eq 'changed' }).Count
        $sd.extra   = @($list | Where-Object { $_.type -eq 'extra' }).Count
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($it in $list) {
            if ($items.Count -ge $ItemCap) { break }
            $label = ''
            if ($labelFn) { try { $label = "$(Get-PimFailureItemLabel -Key "$($it.key)" -Row $payloads["$($sd.scope)|$($it.key)"])" } catch { $label = '' } }
            if (-not $label.Trim()) { $label = "$($it.key)" }
            $items.Add([ordered]@{ type = "$($it.type)"; key = "$($it.key)"; label = $label })
        }
        $sd.items = @($items.ToArray())
        $sd.truncated = [int]([math]::Max(0, $list.Count - $items.Count))
    }

    $okScopes = @($scopeDocs | Where-Object { $_.ok })
    $m = 0; $c = 0; $x = 0
    foreach ($sd in $okScopes) { $m += [int]$sd.missing; $c += [int]$sd.changed; $x += [int]$sd.extra }
    $failed = @($scopeDocs | Where-Object { -not $_.ok }).Count
    return [ordered]@{
        refreshedUtc    = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        durationSeconds = [math]::Round([double]$DurationSeconds, 1)
        total           = ($m + $c + $x)
        counts          = [ordered]@{ missing = $m; changed = $c; extra = $x }
        scopesFailed    = $failed
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
    $sum = "{0} drift item(s) (missing={1} changed={2} extra={3}) across {4} scope(s) in {5}s -> {6}" -f `
        $doc.total, $doc.counts.missing, $doc.counts.changed, $doc.counts.extra, $scopeDocs.Count, $doc.durationSeconds, $where

    if ([int]$doc.total -gt 0) {
        $title = 'Configuration drift detected'
        $detail = "missing={0} changed={1} extra={2}" -f $doc.counts.missing, $doc.counts.changed, $doc.counts.extra
        try {
            if (Get-Command Send-PimManagerAlert -ErrorAction SilentlyContinue) {
                [void](Send-PimManagerAlert -Event 'drift' -Title $title -Detail $detail -LinkTab 'drift')
            } elseif (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue) {
                [void](Send-PimJobAlertViaNotify -Event 'drift' -Title $title -Detail $detail)
            }
        } catch { Write-Warning "[$type] the drift alert could not be raised: $($_.Exception.Message)" }
    }

    if ($scopeDocs.Count -gt 0 -and $failedNames.Count -eq $scopeDocs.Count) {
        throw ("[$type] drift could not be computed for any scope; the failure was stored so the Drift page shows it. " +
            (@($scopeDocs | ForEach-Object { "[$($_.scope)] $($_.error)" }) -join '  |  '))
    }
    $partialTxt = if ($failedNames.Count) { " PARTIAL -- could not check: " + ($failedNames -join ', ') } else { '' }
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
                type = "$(Get-PimDriftSnapshotField $it 'type')"; key = "$(Get-PimDriftSnapshotField $it 'key')"; label = "$(Get-PimDriftSnapshotField $it 'label')" })
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
        scopesFailed    = [int](Get-PimDriftSnapshotField $Entry 'scopesFailed')
        scopes          = $scopes
        items           = @($flat.ToArray())
        source          = 'scheduler-snapshot'
    }
}
