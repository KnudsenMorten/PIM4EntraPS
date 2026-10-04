#Requires -Version 5.1
<#
  §88 COMMIT WATCHER (operator 2026-10-02: "it could be fantastic to have a watcher feature which detect when commit
  actually is active in platform which could be seen in queue" / "build the watcher too").

  A commit only writes SQL; the engine applies it later. The watcher closes the gap between "saved" and "live":
    1. every commit records WHICH keys it changed      -> pim.Settings 'CommitWatch'      (the Manager, on commit)
    2. every engine run records, for WATCHED keys only, what it did with each one, and which entities a CLEAN pass
       covered                                          -> pim.Settings 'CommitOutcomes'   (the engine, at run end)
    3. a pure function turns the two into a state per key:
         saved     the engine has not run over this change yet
         applied   the engine wrote it to the platform (create / update / remove) -- the read-back is next
         live      the engine read the platform back and found it as committed (plan nochange), or a clean pass over
                   the entity after the commit found nothing to do for this key
         waiting   the engine is waiting on the platform (replication lag, an approval hold) -- with the reason
         failed    the engine could not apply it -- with the reason
         stored    the entity has no platform object (companies, settings-like rows): saved is final
  Free (Community) -- it is how every commit is seen, not a Pro feature.
#>

$script:PimCommitWatchMax      = 100     # commit records kept
$script:PimCommitWatchKeepDays = 14
$script:PimCommitWatchMaxKeys  = 500     # keys tracked per commit (a bulk import beyond that is summarised)

# The entities the engine applies to the platform, and the engine PROVIDER scope(s) that APPLY each (PIM-Cutover.ps1's
# entity -> scope map names more scopes per entity: those READ the rows -- AdminTap reads admin rows -- but do not apply
# the row itself, so their passes must not confirm it). An entity not listed has no platform object of its own: its
# commit is final when saved.
$script:PimCommitWatchEntityScopes = @{
    'Account-Definitions-Admins'      = @('Admins')
    'PIM-Assignments-Admins'          = @('AdminMembers')
    'PIM-Assignments-Groups'          = @('GroupMembers')
    'PIM-Assignments-Roles-Groups'    = @('EntraRoles', 'EntraRolesDirect')
    'PIM-Assignments-Roles-AUs'       = @('RolesAUs')
    'PIM-Assignments-Azure-Resources' = @('AzRes')
    'PIM-Assignments-Workloads'       = @('WorkloadConnectors', 'DefenderXdrRoles', 'IntuneRoles', 'EntraAppRole')
    'PIM-Definitions-AU'              = @('AdministrativeUnits')
    'PIM-Definitions-Roles'           = @('Groups')
    'PIM-Definitions-Tasks'           = @('Groups')
    'PIM-Definitions-Services'        = @('Groups')
    'PIM-Definitions-Processes'       = @('Groups')
    'PIM-Definitions-Resources'       = @('Groups')
    'PIM-Definitions-Departments'     = @('Groups')
    'PIM-Definitions-Organization'    = @('Groups')
    'PIM-Definitions-Projects'        = @('Groups')
    'PIM-Definitions-CrossOrg'        = @('Groups')
}

function Get-PimCommitWatchEntityScopes {
    param([Parameter(Mandatory)][string]$Entity)
    if ($script:PimCommitWatchEntityScopes.ContainsKey($Entity)) { return @($script:PimCommitWatchEntityScopes[$Entity]) }
    return @()
}

function Get-PimCommitWatchPlatformEntities { return @($script:PimCommitWatchEntityScopes.Keys | Sort-Object) }

function Test-PimCommitWatchScopeApplies {
    # PURE. Does this engine scope APPLY rows of this entity (case-insensitive)?
    param([Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Scope)
    return [bool](@(Get-PimCommitWatchEntityScopes -Entity $Entity | Where-Object { $_ -ieq $Scope }).Count)
}

function Get-PimCommitChangedKeys {
    <#
      PURE. The keys a commit changed: add / modify / remove, by the store's own row key (-KeyOf = Get-PimStoreRowKey
      by default) and the row's JSON. Returns @( @{ key; op } ).
    #>
    param([Parameter(Mandatory)][string]$Base, [object[]]$OldRows = @(), [object[]]$NewRows = @(), [scriptblock]$KeyOf)
    if (-not $KeyOf) { $KeyOf = { param($b, $r) Get-PimStoreRowKey -Base $b -Row $r } }
    $old = @{}; $oldRow = @{}
    foreach ($r in @($OldRows)) { if ($null -eq $r) { continue }; $k = & $KeyOf $Base $r; if ("$k".Trim()) { $old["$k"] = ($r | ConvertTo-Json -Depth 12 -Compress); $oldRow["$k"] = $r } }
    $out = New-Object System.Collections.Generic.List[object]; $seen = @{}
    foreach ($r in @($NewRows)) {
        if ($null -eq $r) { continue }
        $k = "$(& $KeyOf $Base $r)"; if (-not $k.Trim() -or $seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $j = $r | ConvertTo-Json -Depth 12 -Compress
        if (-not $old.ContainsKey($k)) { $out.Add([pscustomobject]@{ key = $k; op = 'add' }) }
        elseif ($old[$k] -ne $j) { $out.Add([pscustomobject]@{ key = $k; op = 'modify'; fields = @(Get-PimCommitFieldChanges -Old $oldRow[$k] -New $r) }) }
    }
    foreach ($k in @($old.Keys | Sort-Object)) { if (-not $seen.ContainsKey($k)) { $out.Add([pscustomobject]@{ key = $k; op = 'remove' }) } }
    return $out.ToArray()   # .ToArray(): pwsh 7 throws "Argument types do not match" on @() over a List[object]
}

function Get-PimCommitFieldChanges {
    <#
      PURE. What a MODIFY changed, in words: @( 'Column: old -> new' ) for every column that differs (values shortened
      to 60 characters, at most 8 columns). Operator 2026-10-02: "it would be nice to show the actual changes".
    #>
    param([AllowNull()][object]$Old, [AllowNull()][object]$New)
    $props = { param($o) if ($null -eq $o) { @{} } elseif ($o -is [System.Collections.IDictionary]) { $h = @{}; foreach ($k in $o.Keys) { $h["$k"] = $o[$k] }; $h } else { $h = @{}; foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value }; $h } }
    $a = & $props $Old; $b = & $props $New
    $short = { param($v) $s = "$v".Trim(); if (-not $s) { '(blank)' } elseif ($s.Length -gt 60) { $s.Substring(0, 57) + '...' } else { $s } }
    $out = @()
    foreach ($k in @(@($a.Keys) + @($b.Keys) | Select-Object -Unique | Sort-Object)) {
        if ($k -in @('__pimRowNo', 'RfaRequestId', 'UpdatedUtc')) { continue }
        $x = "$($a[$k])".Trim(); $y = "$($b[$k])".Trim()
        if ($x -ceq $y) { continue }
        $out += ('{0}: {1} -> {2}' -f $k, (& $short $x), (& $short $y))
    }
    if ($out.Count -gt 8) { $out = @($out[0..7]) + @("... and $($out.Count - 8) more") }
    return @($out)
}

function New-PimCommitWatchRecord {
    # PURE. The record one commit leaves. $null when the commit changed nothing.
    param([Parameter(Mandatory)][string]$Entity, [object[]]$Changes = @(), [string]$By = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $ch = @($Changes)
    if (-not $ch.Count) { return $null }
    $more = [Math]::Max(0, $ch.Count - $script:PimCommitWatchMaxKeys)
    return [pscustomobject]@{
        id = [guid]::NewGuid().ToString('n'); entity = $Entity; committedUtc = $NowUtc.ToUniversalTime().ToString('o'); by = "$By"
        platform = [bool](@(Get-PimCommitWatchEntityScopes -Entity $Entity).Count)
        keys = @($ch | Select-Object -First $script:PimCommitWatchMaxKeys | ForEach-Object { [pscustomobject]@{ key = "$($_.key)"; op = "$($_.op)"; fields = @(if ($_.PSObject.Properties["fields"]) { $_.fields }) } })
        moreKeys = $more
    }
}

function ConvertFrom-PimCommitWatchUtc {
    param([AllowNull()][object]$Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $t = "$Value".Trim(); if (-not $t) { return $null }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$d)) { return $d }
    return $null
}

function Select-PimCommitWatchRecords {
    # PURE. Keep the newest -Max records younger than -KeepDays.
    param([object[]]$Records = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    return @(@($Records | Where-Object { $_ -and ($t = ConvertFrom-PimCommitWatchUtc $_.committedUtc) -and ($now - $t).TotalDays -lt $script:PimCommitWatchKeepDays }) |
        Sort-Object { ConvertFrom-PimCommitWatchUtc $_.committedUtc } -Descending | Select-Object -First $script:PimCommitWatchMax)
}

function ConvertTo-PimCommitOutcome {
    <#
      PURE. One engine item -> what the watcher stores. -Action create|update|remove|nochange; -Result the item's result
      (ok / failed / skipped / held / waiting / whatif). Returns @{ state; action; reason }.
    #>
    param([string]$Action, [string]$Result, [string]$Reason = '')
    $a = "$Action".ToLowerInvariant(); $r = "$Result".ToLowerInvariant()
    if ($r -match 'whatif|plan') { return $null }
    if ($r -match 'fail|error') { return @{ state = 'failed'; action = $a; reason = "$Reason" } }
    if ($r -match 'held|hold|approval|wait|pending|replicat|skip') { return @{ state = 'waiting'; action = $a; reason = "$Reason" } }
    if ($a -match 'nochange|unchanged|none') { return @{ state = 'live'; action = $a; reason = '' } }
    return @{ state = 'applied'; action = $a; reason = "$Reason" }
}

function Get-PimCommitWatchKeyState {
    <#
      PURE. The state of one committed key.
        -Outcome   the engine's latest outcome for 'entity|key' { state; action; reason; atUtc } or $null
        -CoveredUtc the end of the latest CLEAN engine pass over the entity, or $null
      Only engine results AFTER the commit count.
    #>
    param([Parameter(Mandatory)][object]$Record, [Parameter(Mandatory)][object]$Key, [AllowNull()][object]$Outcome, [AllowNull()][object]$CoveredUtc, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not $Record.platform) { return [pscustomobject]@{ state = 'stored'; reason = 'saved -- this list has no object in Entra or Azure of its own'; atUtc = $Record.committedUtc } }
    $at = ConvertFrom-PimCommitWatchUtc $Record.committedUtc
    $oAt = if ($Outcome) { ConvertFrom-PimCommitWatchUtc $Outcome.atUtc } else { $null }
    $cov = ConvertFrom-PimCommitWatchUtc $CoveredUtc
    if ($Outcome -and $oAt -and $oAt -ge $at) {
        $st = "$($Outcome.state)"
        # an applied write that a LATER clean pass covered (and did not report again) is confirmed live
        if ($st -eq 'applied' -and $cov -and $cov -gt $oAt) { return [pscustomobject]@{ state = 'live'; reason = "applied ($($Outcome.action)) and confirmed by the next pass"; atUtc = $cov.ToString('o') } }
        $why = switch ($st) {
            'applied' { "applied ($($Outcome.action)) -- waiting for the next pass to read it back" }
            'live'    { 'live -- the platform matches' }
            default   { "$($Outcome.reason)" }
        }
        return [pscustomobject]@{ state = $st; reason = $why; atUtc = $oAt.ToString('o') }
    }
    # no item for this key after the commit, but a clean pass covered the entity: nothing was left to do -> live
    if ($cov -and $at -and $cov -gt $at) { return [pscustomobject]@{ state = 'live'; reason = 'a clean pass after the commit found nothing to change'; atUtc = $cov.ToString('o') } }
    $age = if ($at) { [int]($NowUtc.ToUniversalTime() - $at).TotalMinutes } else { 0 }
    return [pscustomobject]@{ state = 'saved'; reason = $(if ($age -ge 30) { "saved $age min ago -- the engine has not applied it yet (check the Jobs page)" } else { 'saved -- the engine applies it on its next run' }); atUtc = $Record.committedUtc }
}

function Get-PimCommitWatchStatus {
    <#
      PURE. A commit record + the outcome store -> { id; entity; committedUtc; by; total; counts{state:n}; done; keys[] }.
      done = every key is live / stored / failed (nothing left to wait for).
      -Outcomes = @{ items = @{ 'entity|key' = {state;action;reason;atUtc} }; covered = @{ entity = utc } }
    #>
    param([Parameter(Mandatory)][object]$Record, [AllowNull()][object]$Outcomes, [datetime]$NowUtc = [datetime]::UtcNow)
    $items = $null; $covered = $null; $coveredFull = $null
    $get = { param($bag, $name) if ($null -eq $bag) { return $null }; if ($bag -is [System.Collections.IDictionary]) { if ($bag.Contains($name)) { return $bag[$name] }; return $null }; $p = $bag.PSObject.Properties[$name]; if ($p) { return $p.Value }; return $null }
    if ($Outcomes) { $items = & $get $Outcomes 'items'; $covered = & $get $Outcomes 'covered'; $coveredFull = & $get $Outcomes 'coveredFull' }
    $cov = & $get $covered "$($Record.entity)"; $covFull = & $get $coveredFull "$($Record.entity)"
    $keys = @(foreach ($k in @($Record.keys)) {
        $o = & $get $items ("$($Record.entity)|$($k.key)")
        # a REMOVED row has no item in a Delta pass: only a Full clean pass proves it is gone
        $c = if ("$($k.op)" -eq 'remove') { $covFull } else { $cov }
        $s = Get-PimCommitWatchKeyState -Record $Record -Key $k -Outcome $o -CoveredUtc $c -NowUtc $NowUtc
        [pscustomobject]@{ key = "$($k.key)"; op = "$($k.op)"; fields = @(if ($k.PSObject.Properties["fields"]) { $k.fields }); state = $s.state; reason = $s.reason; atUtc = $s.atUtc }
    })
    $counts = [ordered]@{}; foreach ($k in $keys) { $counts[$k.state] = 1 + [int]$counts[$k.state] }
    $done = -not @($keys | Where-Object { $_.state -in @('saved', 'applied', 'waiting') }).Count
    return [pscustomobject]@{ id = "$($Record.id)"; entity = "$($Record.entity)"; committedUtc = "$($Record.committedUtc)"; by = "$($Record.by)"
                              total = $keys.Count + [int]$Record.moreKeys; counts = $counts; done = $done; keys = $keys; moreKeys = [int]$Record.moreKeys }
}

function Get-PimCommitWatchItemRef {
    <#
      PURE (given Get-PimStoreRowKey). An engine plan item -> the pim.Rows entity + row key a commit recorded, or $null.
      The engine keys items by what it reads live (a principal id, a lower-cased tag|role ...); the commit keys rows by
      the store key. The item's SOURCE ROW joins the two: desired for create / update / nochange, the Remove row for a
      targeted removal. A prune (only the live object) has no row. The group-definition scopes say 'PIM-Definitions';
      their rows carry SourceEntity. Central admin copies (AdminSource=central) are not the local row.
    #>
    param([Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][object]$Item, [string]$Op = '')
    $row = $null
    if ($Op -eq 'Remove') { if ($Item.PSObject.Properties['row'] -and $null -ne $Item.row) { $row = $Item.row } }
    elseif ($Item.PSObject.Properties['desired']) { $row = $Item.desired }
    if ($null -eq $row) { return $null }
    $ent = $Entity
    if ($ent -eq 'PIM-Definitions') { $se = "$(if ($row.PSObject.Properties['SourceEntity']) { $row.SourceEntity })".Trim(); if (-not $se) { return $null }; $ent = $se }
    if ($row.PSObject.Properties['AdminSource'] -and "$($row.AdminSource)" -eq 'central') { return $null }
    if (-not (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue)) { return $null }
    $k = "$(Get-PimStoreRowKey -Base $ent -Row $row)".Trim()
    if (-not $k) { return $null }
    return [pscustomobject]@{ entity = $ent; key = $k }
}

# ---- SQL (pim.Settings) ----------------------------------------------------------------------------------------------
function Read-PimCommitWatchDoc {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Name)
    $raw = Get-PimSqlSettingRaw -ConnectionString $ConnectionString -Name $Name
    $doc = $null; if ("$raw".Trim()) { try { $doc = $raw | ConvertFrom-Json } catch { $doc = $null } }
    return [pscustomobject]@{ raw = $raw; doc = $doc }
}

function Add-PimCommitWatchRecord {
    # Append one record (CAS, 5 tries). Never throws into a commit: returns $false and warns.
    param([Parameter(Mandatory)][string]$ConnectionString, [AllowNull()][object]$Record, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Record) { return $true }
    for ($i = 0; $i -lt 5; $i++) {
        try {
            $cur = Read-PimCommitWatchDoc -ConnectionString $ConnectionString -Name 'CommitWatch'
            $recs = @(if ($cur.doc -and $cur.doc.PSObject.Properties['commits']) { $cur.doc.commits }) + $Record
            $new = [pscustomobject]@{ commits = @(Select-PimCommitWatchRecords -Records $recs -NowUtc $NowUtc) } | ConvertTo-Json -Depth 8 -Compress
            if ([int](Set-PimSqlSettingIfUnchanged -ConnectionString $ConnectionString -Name 'CommitWatch' -NewValueJson $new -ExpectedValueJson $cur.raw) -eq 1) { return $true }
        } catch { Write-Warning "  [commit-watch] the commit could not be recorded for the watcher: $($_.Exception.Message)"; return $false }
    }
    Write-Warning '  [commit-watch] the commit could not be recorded for the watcher (5 concurrent writers in a row)'
    return $false
}

function Get-PimCommitWatchKeysWanted {
    # PURE. 'entity|key' for every key of a record that is still in flight -- the engine records outcomes for these only.
    param([object[]]$Records = @(), [AllowNull()][object]$Outcomes, [datetime]$NowUtc = [datetime]::UtcNow)
    $want = @{}
    foreach ($r in @($Records)) {
        if (-not $r.platform) { continue }
        $st = Get-PimCommitWatchStatus -Record $r -Outcomes $Outcomes -NowUtc $NowUtc
        foreach ($k in @($st.keys | Where-Object { $_.state -in @('saved', 'applied', 'waiting') })) { $want["$($r.entity)|$($k.key)"] = $true }
    }
    return $want
}

function Update-PimCommitOutcomes {
    <#
      The engine's half, at the end of a run (NOT WhatIf). -Items = @( @{ entity; key; action; result; reason } ) from the
      run; -CleanEntities = entities a clean pass covered. Records ONLY keys some in-flight commit waits for, so the
      document stays small. CAS, 5 tries; never throws into the engine run.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Items = @(), [string[]]$CleanEntities = @(),
          [string]$Scope = '', [string]$Mode = 'Delta', [datetime]$NowUtc = [datetime]::UtcNow)
    # only the scope that APPLIES an entity speaks for it (AdminTap reads admin rows but does not apply them)
    # BUG-284 hardening: an item or entity with NO name is dropped here -- a blank -Entity is a binding error, and this
    # filter used to sit OUTSIDE the try below, so one blank item threw into (and failed) the whole engine run.
    $Items = @($Items | Where-Object { $null -ne $_ -and "$($_.entity)".Trim() -and "$($_.key)".Trim() })
    $CleanEntities = @($CleanEntities | Where-Object { "$_".Trim() })
    if ("$Scope".Trim()) {
        $Items = @($Items | Where-Object { Test-PimCommitWatchScopeApplies -Entity "$($_.entity)" -Scope $Scope })
        $CleanEntities = @($CleanEntities | Where-Object { Test-PimCommitWatchScopeApplies -Entity "$_" -Scope $Scope })
    }
    if (-not @($Items).Count -and -not @($CleanEntities).Count) { return }
    try {
        $w = Read-PimCommitWatchDoc -ConnectionString $ConnectionString -Name 'CommitWatch'
        $recs = @(if ($w.doc -and $w.doc.PSObject.Properties['commits']) { $w.doc.commits })
        if (-not $recs.Count) { return }
        for ($i = 0; $i -lt 5; $i++) {
            $cur = Read-PimCommitWatchDoc -ConnectionString $ConnectionString -Name 'CommitOutcomes'
            $wanted = Get-PimCommitWatchKeysWanted -Records $recs -Outcomes $cur.doc -NowUtc $NowUtc
            $kept = @{}; $covered = @{}; $coveredFull = @{}   # NOT $items: PowerShell names are case-insensitive, that IS the -Items parameter
            if ($cur.doc) {
                if ($cur.doc.items) { foreach ($p in $cur.doc.items.PSObject.Properties) { if ($wanted.ContainsKey($p.Name)) { $kept[$p.Name] = $p.Value } } }
                if ($cur.doc.covered) { foreach ($p in $cur.doc.covered.PSObject.Properties) { $covered[$p.Name] = $p.Value } }
                if ($cur.doc.PSObject.Properties['coveredFull'] -and $cur.doc.coveredFull) { foreach ($p in $cur.doc.coveredFull.PSObject.Properties) { $coveredFull[$p.Name] = $p.Value } }
            }
            $now = $NowUtc.ToUniversalTime().ToString('o')
            foreach ($it in @($Items)) {
                $id = "$($it.entity)|$($it.key)"
                if (-not $wanted.ContainsKey($id)) { continue }
                $o = ConvertTo-PimCommitOutcome -Action "$($it.action)" -Result "$($it.result)" -Reason "$($it.reason)"
                if ($o) { $kept[$id] = [pscustomobject]@{ state = $o.state; action = $o.action; reason = $o.reason; atUtc = $now } }
            }
            # a Delta pass never removes: only a FULL clean pass confirms a removed row (coveredFull)
            foreach ($e in @($CleanEntities | Where-Object { "$_".Trim() } | Select-Object -Unique)) { $covered[$e] = $now; if ($Mode -eq 'Full') { $coveredFull[$e] = $now } }
            $new = [pscustomobject]@{ items = [pscustomobject]$kept; covered = [pscustomobject]$covered; coveredFull = [pscustomobject]$coveredFull } | ConvertTo-Json -Depth 6 -Compress
            if ($new -eq "$($cur.raw)") { return }
            if ([int](Set-PimSqlSettingIfUnchanged -ConnectionString $ConnectionString -Name 'CommitOutcomes' -NewValueJson $new -ExpectedValueJson $cur.raw) -eq 1) { return }
        }
        Write-Warning '  [commit-watch] the engine outcomes could not be recorded (5 concurrent writers in a row)'
    } catch { Write-Warning "  [commit-watch] the engine outcomes could not be recorded: $($_.Exception.Message)" }
}
