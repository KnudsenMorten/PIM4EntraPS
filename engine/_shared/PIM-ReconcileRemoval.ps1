<#
  PIM 96.5 (operator 2026-10-06) -- THE DAILY RECONCILE: purpose 2 (removal of PIM-managed leftovers) and PAUSE / RESUME.

  PURPOSE 2. The daily 'full-reconcile' (engine-full, scope All) catches up what the configuration holds and the tenant
  lacks (purpose 1, unchanged). It now ALSO plans which live items it WOULD remove because PIM put them there and PIM's
  configuration no longer has them. A live item qualifies only when ALL hold:
    1. PIM DEFINED it   -- a journal row added / modified its store row through a PIM commit (Source is not 'system');
    2. it was ACTIVE BECAUSE OF PIM -- its managed-key ledger entry is CONFIRMED (PIM created it, or a live read after a
                           PIM commit saw it live; decision D2). A key PIM only MATCHED never qualifies;
    3. PIM REMOVED it   -- the LATEST journal row of that store row is a Remove (nothing re-added it);
    4. NOTHING SIMILAR is configured -- no desired row gives the same delegation (Eligible + Active are ONE delegation, the
                           engine's conflict rule), and never a shared Defender / Intune assignment;
    5. the GUARDS pass  -- the removal budget (G4) for the scope, and a desired set that is not empty.
  Items from before the journal fail rule 1 and are NEVER removed (report only). ADMINS ARE NEVER DELETED OR DISABLED by
  this: an admin-account scope is excluded before any rule is evaluated, whatever the journal says.

  MODES (pim.Settings 'ReconcileRemovalMode'): 'enforce' (DEFAULT since 2.4.517, operator 2026-10-06: "switch it on
  everywhere + default") hands the qualifying items to the normal remove path (ledger, budget, audit, applied outcome);
  'report' plans and reports, removes nothing. Only the exact word 'report' reports; empty / unset enforces, and any OTHER
  word (a typo) reports -- a mistyped setting never removes more than the operator asked for.

  THE REPORT is stored per run in pim.TenantCache kind 'reconcile-removal' (like the drift snapshot) for the Jobs page:
  would remove N, and per item which rule held it.

  PAUSE / RESUME (decision D4: a pause stops ONLY the daily reconcile -- commits, deltas and Run now still apply).
  pim.Settings 'ReconcilePause' = { paused; by; sinceUtc; reason; untilUtc; resumedBy; resumedUtc; resumeReason }. Set by a
  SuperAdmin with a reason (audited) in the Manager; the scheduler reads it right before it runs 'full-reconcile' and
  records the run as skipped while it holds. An 'until' in the past means the pause has lapsed (it resumes by itself).

  Windows PowerShell 5.1 and pwsh 7. Test seams: $global:PIM_ReconcilePauseState (the stored state), $global:
  PIM_ReconcileRemovalReportStore (a hashtable that receives the report instead of SQL).
#>

Set-StrictMode -Off

# The rules read the journal (PIM-CommitJournal.ps1) and the ledger (PIM-ManagedKeys.ps1); load them when this file is
# dot-sourced on its own (a test, a tool).
foreach ($__rrDep in @(@{ fn = 'Test-PimCommitJournalIsPimCommit'; file = 'PIM-CommitJournal.ps1' }, @{ fn = 'Get-PimManagedKeyRecords'; file = 'PIM-ManagedKeys.ps1' })) {
    if (-not (Get-Command $__rrDep.fn -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot $__rrDep.file))) { . (Join-Path $PSScriptRoot $__rrDep.file) }
}

$script:PimReconcileJobName = 'full-reconcile'
$script:PimReconcileRemovalCacheKind = 'reconcile-removal'
$script:PimReconcilePauseSettingName = 'ReconcilePause'
$script:PimReconcileReportItemCap = 200

function Get-PimReconcileJobName { $script:PimReconcileJobName }
function Get-PimReconcileRemovalCacheKind { $script:PimReconcileRemovalCacheKind }
function Get-PimReconcilePauseSettingName { $script:PimReconcilePauseSettingName }

# ---- the mode ---------------------------------------------------------------------------------------------------------
function ConvertTo-PimReconcileRemovalMode {
    <# PURE. Empty / unset = 'enforce' (the default); 'enforce' enforces; 'report' and any other word (a typo, 'true') = 'report'. #>
    param([AllowNull()][object]$Value)
    $s = "$Value".Trim().ToLowerInvariant()
    if (-not $s -or $s -eq 'enforce') { return 'enforce' }
    return 'report'
}

function Get-PimReconcileRemovalMode {
    <# The configured mode (pim.Settings / $global:PIM_ReconcileRemovalMode / env PIM_ReconcileRemovalMode), default 'enforce'. #>
    $v = $null
    if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) { try { $v = Get-PimPolicySetting -Name 'ReconcileRemovalMode' -Default $null } catch { $v = $null } }
    elseif ($global:PIM_NamingConventions -is [hashtable] -and $global:PIM_NamingConventions.ContainsKey('ReconcileRemovalMode')) { $v = $global:PIM_NamingConventions['ReconcileRemovalMode'] }
    elseif ($null -ne $global:PIM_ReconcileRemovalMode) { $v = $global:PIM_ReconcileRemovalMode }
    elseif ("$env:PIM_ReconcileRemovalMode".Trim()) { $v = $env:PIM_ReconcileRemovalMode }
    return (ConvertTo-PimReconcileRemovalMode -Value $v)
}

# ---- which scopes the rules never reach ------------------------------------------------------------------------------
function Get-PimReconcileAdminScopes {
    <# The scopes whose removal disables, deletes or offboards an ACCOUNT. The reconcile never removes there. #>
    @('Admins', 'AdminTap', 'AdminOffboarding', 'HybridAdProvisioning')
}
function Get-PimReconcileSharedWorkloadScopes {
    <# The workload role scopes whose live item is an assignment other principals may share (SEC-83). Never removed here. #>
    @('DefenderXdrRoles', 'IntuneRoles')
}

function Get-PimReconcileScopeClass {
    <# PURE. 'admin' | 'shared-workload' | 'normal'. -Provider: the registered provider (isAccountDisable = an admin scope). #>
    param([Parameter(Mandatory)][string]$Scope, [AllowNull()][object]$Provider)
    $s = "$Scope".Trim().ToLowerInvariant()
    $isDisable = $false
    if ($Provider -is [System.Collections.IDictionary]) { $isDisable = [bool]$Provider['isAccountDisable'] } elseif ($null -ne $Provider -and $Provider.PSObject.Properties['isAccountDisable']) { $isDisable = [bool]$Provider.isAccountDisable }
    if ($isDisable -or @(Get-PimReconcileAdminScopes | ForEach-Object { $_.ToLowerInvariant() }) -contains $s) { return 'admin' }
    if (@(Get-PimReconcileSharedWorkloadScopes | ForEach-Object { $_.ToLowerInvariant() }) -contains $s) { return 'shared-workload' }
    return 'normal'
}

function Get-PimReconcileNeutralKey {
    <# PURE. The delegation key without its assignment type (the engine's conflict rule: Eligible + Active are one). #>
    param([string]$Key)
    return ("$Key".Trim().ToLowerInvariant() -replace '\|[^|]*$', '')
}

# ---- the rules (pure) ------------------------------------------------------------------------------------------------
function Test-PimReconcileRemovalItem {
    <#
      PURE. Evaluates the 96.5 rules for ONE live item no desired row has.
        -Key           the live key;  -ScopeClass Get-PimReconcileScopeClass;
        -Record        its ledger record (Get-PimManagedKeyRecords) or $null when it is not in the ledger;
        -History       the journal rows of the record's store row (oldest first), or $null when they could not be read;
        -DesiredNeutral @{ neutral key -> $true } of the desired rows, when the scope has assignment types (else $null).
      Returns { key; eligible; rule; reason; failed[]; definedBy; confirmedBy; removedBy; removedUtc }. rule = '' when it
      qualifies, else the FIRST rule that holds it ('admin', '1', '2', '3', '4'); failed[] lists every rule that holds.
    #>
    param([Parameter(Mandatory)][string]$Key, [string]$ScopeClass = 'normal', [AllowNull()][object]$Record, [AllowNull()][object[]]$History,
          [AllowNull()][hashtable]$DesiredNeutral, [switch]$HistoryUnreadable)
    $out = [ordered]@{ key = $Key; eligible = $false; rule = ''; reason = ''; failed = @(); definedBy = ''; confirmedBy = ''; removedBy = ''; removedUtc = '' }
    if ($ScopeClass -eq 'admin') {
        # Never even evaluated further: an admin is never deleted or disabled by the reconcile or any prune (operator).
        $out.rule = 'admin'; $out.failed = @('admin')
        $out.reason = 'an admin account -- the reconcile never deletes or disables an admin (only an operator action does)'
        return [pscustomobject]$out
    }
    $failed = New-Object System.Collections.Generic.List[string]
    $why = @{}
    # rule 1 -- PIM defined it: a PIM commit added / modified its store row.
    $hasRef = ($null -ne $Record -and "$($Record.sourceEntity)".Trim() -and "$($Record.sourceKey)".Trim())
    $pimRows = @(@($History) | Where-Object { $_ -and (Test-PimCommitJournalIsPimCommit -Row $_) })
    $defs = @($pimRows | Where-Object { "$($_.Op)" -in @('Add', 'Modify') })
    if ($HistoryUnreadable) { $failed.Add('1'); $why['1'] = 'the change journal could not be read -- nothing is removed on an unreadable journal' }
    elseif (-not $hasRef) { $failed.Add('1'); $why['1'] = 'no PIM commit is known to have defined it (it was matched, or recorded before the journal)' }
    elseif (-not $defs.Count) { $failed.Add('1'); $why['1'] = 'existed before the change journal -- never removed by the reconcile (report only)' }
    else { $out.definedBy = "$($defs[-1].CommitId)" }
    # rule 2 -- active because of PIM: the ledger key is CONFIRMED (D2).
    if ($null -eq $Record) { $failed.Add('2'); $why['2'] = 'not in the managed-key ledger (not managed by PIM)' }
    elseif (-not $Record.confirmed) { $failed.Add('2'); $why['2'] = 'PIM only recognised it (matched) -- never confirmed live because of a PIM commit' }
    else { $out.confirmedBy = "$($Record.commitId)" }
    # rule 3 -- PIM removed it: the LATEST PIM journal row of the store row is a Remove.
    if (-not $HistoryUnreadable -and $pimRows.Count) {
        $last = $pimRows[-1]
        if ("$($last.Op)" -eq 'Remove') { $out.removedBy = "$($last.CommitId)"; $out.removedUtc = "$($last.CommittedUtc)" }
        else { $failed.Add('3'); $why['3'] = ("the definition is still there (last change: {0} in commit {1})" -f "$($last.Op)", "$($last.CommitId)") }
    } else { $failed.Add('3'); $why['3'] = 'no PIM commit is known to have removed it' }
    # rule 4 -- nothing similar configured.
    if ($ScopeClass -eq 'shared-workload') { $failed.Add('4'); $why['4'] = 'a workload role assignment other principals may share -- never removed by the reconcile' }
    elseif ($null -ne $DesiredNeutral -and $DesiredNeutral.ContainsKey((Get-PimReconcileNeutralKey -Key $Key))) { $failed.Add('4'); $why['4'] = 'the same delegation is configured with the other assignment type (Eligible + Active are one delegation)' }
    $out.failed = @($failed.ToArray())
    if ($failed.Count) { $out.rule = $failed[0]; $out.reason = "rule $($failed[0]): " + $why[$failed[0]] }
    else { $out.eligible = $true; $out.reason = 'qualifies: defined by PIM, confirmed live because of PIM, removed by PIM, nothing similar configured' }
    return [pscustomobject]$out
}

function Get-PimReconcileRemovalPlan {
    <#
      Plans purpose 2 for ONE scope pass. Reads the ledger records and the journal history of the candidates; the rules are
      Test-PimReconcileRemovalItem. Candidates = live items whose key no desired row has and that no targeted Remove row
      already removes (-ClaimedKeys).
        -Budget / -AlreadyRemoving: rule 5 -- when the qualifying items plus the removals this pass already plans exceed the
         removal budget, EVERY qualifying item is held (never a partial mass removal, like G4).
      Never throws: an unreadable ledger or journal holds everything (rule 2 / rule 1) and says so.
      Returns { scope; class; mode; candidates; wouldRemove; eligible[] (the live items); items[] (the per-item verdicts);
                heldBy @{ rule -> n }; error }.
    #>
    param([Parameter(Mandatory)][string]$Scope, [AllowNull()][object]$Provider, [object[]]$Desired = @(), [object[]]$Live = @(),
          [Parameter(Mandatory)][scriptblock]$KeyOf, [switch]$HasTypes, [string[]]$ClaimedKeys = @(), [string]$LedgerConnectionString = '',
          [string]$Mode = 'report', [int]$Budget = -1, [int]$AlreadyRemoving = 0, [scriptblock]$LabelOf = $null)
    $cls = Get-PimReconcileScopeClass -Scope $Scope -Provider $Provider
    $desKeys = @{}; $desNeutral = if ($HasTypes) { @{} } else { $null }
    foreach ($d in @($Desired)) { if ($null -eq $d) { continue }; $k = "$(& $KeyOf $d)".Trim().ToLowerInvariant(); if ($k) { $desKeys[$k] = $true; if ($HasTypes) { $desNeutral[(Get-PimReconcileNeutralKey -Key $k)] = $true } } }
    $claimed = @{}; foreach ($c in @($ClaimedKeys)) { if ("$c".Trim()) { $claimed["$c".Trim().ToLowerInvariant()] = $true } }
    $cands = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($l in @($Live)) {
        if ($null -eq $l) { continue }
        $k = "$(& $KeyOf $l)".Trim(); $lk = $k.ToLowerInvariant()
        if (-not $lk -or $desKeys.ContainsKey($lk) -or $claimed.ContainsKey($lk) -or $seen.ContainsKey($lk)) { continue }
        $seen[$lk] = $true
        $cands.Add([pscustomobject]@{ key = $k; live = $l })
    }
    $res = [ordered]@{ scope = $Scope; class = $cls; mode = (ConvertTo-PimReconcileRemovalMode -Value $Mode); candidates = $cands.Count; wouldRemove = 0
                       eligible = @(); items = @(); heldBy = @{}; error = '' }
    if (-not $cands.Count) { return [pscustomobject]$res }
    $records = $null; $hist = @{}; $histBad = $false
    if ($cls -ne 'admin') {
        try { $records = Get-PimManagedKeyRecords -ConnectionString $LedgerConnectionString -Scope $Scope }
        catch { $records = $null; $res.error = "the managed-key ledger could not be read: $($_.Exception.Message)" }
        if ($null -ne $records) {
            $refs = @(foreach ($c in $cands) { $r = $records[$c.key.ToLowerInvariant()]; if ($r -and $r.sourceEntity -and $r.sourceKey) { @{ entity = $r.sourceEntity; key = $r.sourceKey } } })
            if ($refs.Count) {
                try { $hist = Get-PimCommitJournalKeyHistory -ConnectionString $LedgerConnectionString -Refs $refs }
                catch { $histBad = $true; $res.error = (("$($res.error) " + "the change journal could not be read: $($_.Exception.Message)").Trim()) }
            }
        }
    }
    $verdicts = New-Object System.Collections.Generic.List[object]
    $elig = New-Object System.Collections.Generic.List[object]
    foreach ($c in $cands) {
        $rec = if ($null -ne $records) { $records[$c.key.ToLowerInvariant()] } else { $null }
        $h = $null
        if ($rec -and $rec.sourceEntity -and $rec.sourceKey) { $hk = ("{0}|{1}" -f $rec.sourceEntity, $rec.sourceKey).ToLowerInvariant(); if ($hist.ContainsKey($hk)) { $h = @($hist[$hk]) } }
        $v = Test-PimReconcileRemovalItem -Key $c.key -ScopeClass $cls -Record $rec -History $h -DesiredNeutral $desNeutral -HistoryUnreadable:$histBad
        if ($null -eq $records -and $cls -ne 'admin' -and -not ($v.failed -contains '2')) { $v.failed = @(@($v.failed) + '2'); if ($v.eligible) { $v.eligible = $false; $v.rule = '2'; $v.reason = 'rule 2: the managed-key ledger could not be read -- nothing is removed' } }
        $label = ''
        if ($LabelOf) { try { $label = "$(& $LabelOf $c)" } catch { $label = '' } }
        $v | Add-Member -NotePropertyName label -NotePropertyValue $(if ($label) { $label } else { $c.key }) -Force
        $verdicts.Add($v)
        if ($v.eligible) { $elig.Add($c) }
    }
    # rule 5 -- the guards: an empty desired set is never authoritative; the removal budget covers the whole pass.
    $hold5 = ''
    if (@($Desired | Where-Object { $null -ne $_ }).Count -eq 0 -and $elig.Count) { $hold5 = 'rule 5: the desired set of this scope is EMPTY -- never authoritative, nothing is removed' }
    elseif ($elig.Count -and $Budget -ge 0 -and ($elig.Count + [int]$AlreadyRemoving) -gt $Budget) {
        $hold5 = ("rule 5: {0} removal(s) in this scope (plus {1} already planned) are over the removal budget of {2} -- none is removed (never a partial mass removal)" -f $elig.Count, [int]$AlreadyRemoving, $Budget)
    }
    if ($hold5) {
        foreach ($v in $verdicts) { if ($v.eligible) { $v.eligible = $false; $v.rule = '5'; $v.failed = @('5'); $v.reason = $hold5 } }
        $elig.Clear()
    }
    $held = @{}
    foreach ($v in $verdicts) { if (-not $v.eligible) { $held["$($v.rule)"] = 1 + [int]$held["$($v.rule)"] } }
    $res.eligible = @($elig.ToArray()); $res.wouldRemove = $elig.Count; $res.items = @($verdicts.ToArray()); $res.heldBy = $held
    return [pscustomobject]$res
}

# ---- the report --------------------------------------------------------------------------------------------------------
function ConvertTo-PimReconcileRemovalReport {
    <#
      PURE. The per-run document from the scope plans (-Plans: the scope results' reconcileRemoval). Counts + items + the rule
      that held each, items capped per scope. -Removed: how many an ENFORCE run actually removed.
    #>
    param([object[]]$Plans = @(), [string]$Mode = 'report', [datetime]$NowUtc = [datetime]::UtcNow, [string]$CorrelationId = '', [int]$Removed = 0)
    $cap = [int]$script:PimReconcileReportItemCap; if ($cap -lt 1) { $cap = 200 }
    # Plain hashtables while counting: an [ordered] dictionary indexed with "1" can bind to its INTEGER indexer.
    $acc = @{ 'admin' = 0; '1' = 0; '2' = 0; '3' = 0; '4' = 0; '5' = 0 }
    $scopes = New-Object System.Collections.Generic.List[object]
    $would = 0; $cands = 0; $errs = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($Plans)) {
        if ($null -eq $p) { continue }
        $would += [int]$p.wouldRemove; $cands += [int]$p.candidates
        if ($p.heldBy -is [System.Collections.IDictionary]) { foreach ($k in @($p.heldBy.Keys)) { if ($acc.ContainsKey("$k")) { $acc["$k"] = [int]$acc["$k"] + [int]$p.heldBy[$k] } } }
        if ("$($p.error)".Trim()) { $errs.Add(("{0}: {1}" -f $p.scope, $p.error)) }
        if ([int]$p.candidates -eq 0) { continue }
        $its = @(@($p.items) | Sort-Object @{ Expression = { -not $_.eligible } }, @{ Expression = { "$($_.rule)" } } | Select-Object -First $cap | ForEach-Object {
            [ordered]@{ key = "$($_.key)"; label = "$($_.label)"; eligible = [bool]$_.eligible; rule = "$($_.rule)"; reason = "$($_.reason)"
                        definedBy = "$($_.definedBy)"; removedBy = "$($_.removedBy)"; removedUtc = "$($_.removedUtc)" } })
        $hb = New-Object System.Collections.Specialized.OrderedDictionary
        if ($p.heldBy -is [System.Collections.IDictionary]) { foreach ($k in @($p.heldBy.Keys | Sort-Object)) { $hb.Add("$k", [int]$p.heldBy[$k]) } }
        $scopes.Add([ordered]@{ scope = "$($p.scope)"; class = "$($p.class)"; candidates = [int]$p.candidates; wouldRemove = [int]$p.wouldRemove
                                heldBy = $hb; error = "$($p.error)"; items = $its; truncated = (@($p.items).Count -gt $cap) })
    }
    $held = New-Object System.Collections.Specialized.OrderedDictionary
    foreach ($k in @('admin', '1', '2', '3', '4', '5')) { $held.Add($k, [int]$acc[$k]) }
    $m = ConvertTo-PimReconcileRemovalMode -Value $Mode
    $sum = if ($m -eq 'enforce') { "enforce: {0} qualified, {1} removed; {2} live item(s) not in the configuration were left alone" -f $would, $Removed, ($cands - $would) }
           else { "report only: would remove {0}; {1} live item(s) not in the configuration are held by a rule (nothing was removed)" -f $would, ($cands - $would) }
    return [ordered]@{ generatedUtc = $NowUtc.ToUniversalTime().ToString('o'); mode = $m; correlationId = "$CorrelationId"; candidates = $cands
                       wouldRemove = $would; removed = $(if ($m -eq 'enforce') { $Removed } else { 0 }); heldBy = $held; summary = $sum
                       errors = @($errs.ToArray()); scopes = @($scopes.ToArray()) }
}

function Save-PimReconcileRemovalReport {
    <# Stores the document as pim.TenantCache kind 'reconcile-removal'. Returns where it went. Throws on a store error. #>
    param([Parameter(Mandatory)][object]$Doc, [string]$ConnectionString = '')
    if ($global:PIM_ReconcileRemovalReportStore -is [hashtable]) { $global:PIM_ReconcileRemovalReportStore[$script:PimReconcileRemovalCacheKind] = $Doc; return 'memory' }
    if (-not "$ConnectionString".Trim() -and (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue)) { try { $ConnectionString = "$(Get-PimSqlSettingsConnectionString)" } catch { $ConnectionString = '' } }
    if (-not "$ConnectionString".Trim()) { return 'none (no SQL store)' }
    Set-PimSqlTenantCache -ConnectionString $ConnectionString -Kind $script:PimReconcileRemovalCacheKind -Value $Doc
    return "sql:pim.TenantCache/$($script:PimReconcileRemovalCacheKind)"
}

function Get-PimReconcileRemovalReport {
    <# The last stored report, or $null. #>
    param([string]$ConnectionString = '')
    if ($global:PIM_ReconcileRemovalReportStore -is [hashtable]) { return $global:PIM_ReconcileRemovalReportStore[$script:PimReconcileRemovalCacheKind] }
    if (-not "$ConnectionString".Trim()) { return $null }
    return (Get-PimSqlTenantCache -ConnectionString $ConnectionString -Kind $script:PimReconcileRemovalCacheKind)
}

# ---- pause / resume ----------------------------------------------------------------------------------------------------
function ConvertTo-PimReconcileUtc {
    <# PURE. A time (string or DateTime) -> UTC DateTime, or $null. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    return $null
}

function New-PimReconcilePauseState {
    <#
      PURE. A pause by -By for -Reason (REQUIRED), until -UntilUtc (optional; must be in the future). Throws a readable
      message on a missing reason or an until-time that is not in the future.
    #>
    param([Parameter(Mandatory)][string]$By, [string]$Reason = '', [AllowNull()][object]$UntilUtc = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $r = "$Reason".Trim()
    if (-not $r) { throw 'a reason is required to pause the daily reconcile' }
    if ($r.Length -gt 500) { $r = $r.Substring(0, 500) }
    $u = $null
    if ($null -ne $UntilUtc -and "$UntilUtc".Trim()) {
        $u = ConvertTo-PimReconcileUtc -Value $UntilUtc
        if ($null -eq $u) { throw "the until-time '$UntilUtc' is not a date and time" }
        if ($u -le $NowUtc.ToUniversalTime()) { throw 'the until-time must be in the future' }
    }
    return [ordered]@{ paused = $true; by = "$By".Trim(); sinceUtc = $NowUtc.ToUniversalTime().ToString('o'); reason = $r
                       untilUtc = $(if ($u) { $u.ToString('o') } else { '' }); resumedBy = ''; resumedUtc = ''; resumeReason = '' }
}

function New-PimReconcileResumeState {
    <# PURE. The resumed state; keeps the pause it ended (who / since / why) for the record. #>
    param([AllowNull()][object]$Current, [Parameter(Mandatory)][string]$By, [string]$Reason = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $f = { param($n) $v = if ($Current -is [System.Collections.IDictionary]) { $Current[$n] } elseif ($null -ne $Current -and $Current.PSObject.Properties[$n]) { $Current.$n } else { '' }
                     if ($v -is [datetime]) { $v.ToUniversalTime().ToString('o') } else { "$v" } }
    return [ordered]@{ paused = $false; by = (& $f 'by'); sinceUtc = (& $f 'sinceUtc'); reason = (& $f 'reason'); untilUtc = (& $f 'untilUtc')
                       resumedBy = "$By".Trim(); resumedUtc = $NowUtc.ToUniversalTime().ToString('o'); resumeReason = "$Reason".Trim() }
}

function Test-PimReconcilePauseActive {
    <#
      PURE. Does -State hold the daily reconcile at -NowUtc? Returns { paused; lapsed; by; sinceUtc; reason; untilUtc; banner }.
      lapsed = it was paused with an until-time that has passed (the reconcile runs again by itself).
    #>
    param([AllowNull()][object]$State, [datetime]$NowUtc = [datetime]::UtcNow)
    $f = { param($n) if ($State -is [System.Collections.IDictionary]) { $State[$n] } elseif ($null -ne $State -and $State.PSObject.Properties[$n]) { $State.$n } else { $null } }
    $isP = $false; $pv = & $f 'paused'
    if ($pv -is [bool]) { $isP = $pv } elseif ($null -ne $pv) { $isP = ("$pv".Trim() -match '^(?i)(true|1|yes)$') }
    $until = ConvertTo-PimReconcileUtc -Value (& $f 'untilUtc')
    $lapsed = ($isP -and $null -ne $until -and $until -le $NowUtc.ToUniversalTime())
    $active = ($isP -and -not $lapsed)
    # pwsh 7's ConvertFrom-Json turns an ISO string into a DateTime; give every time back as UTC ISO text.
    $iso = { param($v) if ($v -is [datetime]) { $v.ToUniversalTime().ToString('o') } else { "$v" } }
    $o = [ordered]@{ paused = $active; lapsed = $lapsed; by = "$(& $f 'by')"; sinceUtc = (& $iso (& $f 'sinceUtc')); reason = "$(& $f 'reason')"
                     untilUtc = $(if ($until) { $until.ToString('o') } else { '' }); resumedBy = "$(& $f 'resumedBy')"; resumedUtc = (& $iso (& $f 'resumedUtc')); banner = '' }
    if ($active) { $o.banner = Format-PimReconcilePauseBanner -State $o }
    return [pscustomobject]$o
}

function Format-PimReconcilePauseBanner {
    <# PURE. "Daily reconcile PAUSED by <who> since <time>: <reason>" (+ " -- until <time>"). Times as stored (UTC ISO); the GUI shows local time. #>
    param([Parameter(Mandatory)][object]$State)
    $u = "$($State.untilUtc)".Trim()
    return ("Daily reconcile PAUSED by {0} since {1}: {2}{3}" -f "$($State.by)", "$($State.sinceUtc)", "$($State.reason)", $(if ($u) { " -- until $u" } else { '' }))
}

function Get-PimReconcilePauseState {
    <# The stored pause state (pim.Settings 'ReconcilePause'), or $null. THROWS when the store cannot be read. #>
    param([string]$ConnectionString = '')
    if ($null -ne $global:PIM_ReconcilePauseState) { return $global:PIM_ReconcilePauseState }
    if (-not "$ConnectionString".Trim() -and (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue)) { $ConnectionString = "$(Get-PimSqlSettingsConnectionString)" }
    if (-not "$ConnectionString".Trim()) { return $null }
    $v = Get-PimSqlSetting -ConnectionString $ConnectionString -Name $script:PimReconcilePauseSettingName
    if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { $v = $null } }
    return $v
}

function Get-PimReconcilePauseGate {
    <#
      The scheduler asks this right before it runs a job. $null = run it. For the daily reconcile while a pause holds: the
      SKIP result (status 'skipped', the banner as its detail). Only 'full-reconcile' is ever held (D4). A pause state that
      cannot be READ does not hold the reconcile (the reconcile is the safe catch-up; it is reported in the detail instead).
    #>
    param([Parameter(Mandatory)][object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    if ("$($Job.name)" -ne $script:PimReconcileJobName) { return $null }
    $st = $null
    try { $st = Get-PimReconcilePauseState } catch { Write-Warning "[reconcile] the pause state could not be read -- the daily reconcile runs: $($_.Exception.Message)"; return $null }
    $a = Test-PimReconcilePauseActive -State $st -NowUtc $NowUtc
    if (-not $a.paused) { return $null }
    Write-Host ("[reconcile] {0} -- the daily reconcile is SKIPPED (commits, deltas and Run now still apply)" -f $a.banner) -ForegroundColor Yellow
    return [pscustomobject]@{ ran = $false; outOfScope = $true; paused = $true; whatIf = [bool]$WhatIf; pause = $a
                              detail = ("{0}. Skipped: a pause stops only the daily reconcile; commits, deltas and Run now still apply." -f $a.banner) }
}
