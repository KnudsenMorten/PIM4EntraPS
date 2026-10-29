<#
  PIM4EntraPS -- ACTIVE-ASSIGNMENTS SNAPSHOT (REQUIREMENTS §70.1b option 2).

  🔴 WHY THIS FILE EXISTS. The Manager serves every HTTP request on ONE loop. GET
  /api/active-assignments used to read every Entra-role / Azure-RBAC / PIM-for-Groups active
  assignment LIVE (Graph throttles PIM-for-Groups; measured 140-170 s on internal), and every other
  user of the Manager waited behind it ("Jobs / Engine runs pages take forever", ~2.5 min freezes).

  🔑 THE READ MOVED TO THE SCHEDULER. The compute below (Invoke-PimActiveAssignmentsSnapshot) is the
  former Get-PimActiveAssignmentsCached body, moved here verbatim in behaviour -- same row shape,
  counts, surfaceErrors and hints -- so the scheduler tick (ca-pim-tick / VisualCron) can run it as
  job 'active-assignments-snapshot' and write the result to SQL pim.TenantCache kind
  'active-assignments'. The Manager only READS that row (ConvertTo-PimActiveAssignmentsSnapshotView)
  and asks for a refresh by queueing a trigger (Request-PimActiveAssignmentsSnapshotRefresh).

  🔒 THE MANAGER NEVER COMPUTES THE SNAPSHOT (operator, 2026-09-13: near-real-time with a delay of a
  few hours is acceptable; no Manager-side "capture when idle" path, because a capture that is running
  when a user arrives freezes them). The Manager dot-sources this file only for the principal/role
  lookup helpers other endpoints share; the job handler is registered ONLY by
  tools/pim-scheduler/Start-PimScheduler.ps1 (Register-PimActiveAssignmentsSnapshotHandler).

  Dependencies: engine/_shared/PIM-Rest.ps1 (Invoke-PimGraph / Invoke-PimArm / Invoke-PimGraphBatchGet /
  Get-PimArmActiveRoleAssignmentsViaArg / ConvertTo-PimSdkShape), tools/pim-manager/_tenantSync.ps1
  (Assert-PimTenantConnectionContext, Get-/Set-PimTenantCacheEntry) and,
  for the trigger, engine/_shared/PIM-Scheduler.ps1 (Add-PimJobTrigger). Runs on pwsh 7 and 5.1.
#>

Set-StrictMode -Off

# The job type + the pim.TenantCache kind, named once.
$script:PimActiveAssignmentsSnapshotJobType   = 'active-assignments-snapshot'
$script:PimActiveAssignmentsSnapshotCacheKind = 'active-assignments'
$script:PimActiveAssignmentsSnapshotDefaultCadenceMinutes = 120

# ---------------------------------------------------------------------------
# v2.4.2 Revoke tab -- bulk-revoke of active PIM assignments.
#
# §70.1b option 2: the read is a SCHEDULER job now (see the header). The Manager serves the stored
# snapshot; Refresh queues a trigger. Three sources are combined into a single row set:
#
#   * Entra-role active assignments:  GET /roleManagement/directory/roleAssignmentSchedules (REST, paged)
#   * Azure-RBAC active assignments:  one Azure Resource Graph query (Get-PimArmActiveRoleAssignmentsViaArg)
#   * PIM-for-Groups active assignments: one filtered assignmentSchedules read per group, 20 per $batch
# All REST through PIM-Rest.ps1 (§100.42: no Graph / Az PowerShell module, no SDK fallback).
#
# The Revoke tab in the Manager only acts on ACTIVE (Assigned) rows -- not
# Eligible -- because eligibility removal is a different operator workflow.
# ---------------------------------------------------------------------------

function Initialize-PimManagerTenantConnection {
    # Lazy-connect Graph + Az on first Revoke tab use. Reuses the
    # _tenantSync.ps1 helpers so we share the engine-SPN connection logic
    # (no interactive Connect-MgGraph / Connect-AzAccount ever).
    if ($script:PimManagerTenantConnected) { return }
    if (-not (Get-Command Assert-PimTenantConnectionContext -ErrorAction SilentlyContinue)) {
        throw "_tenantSync.ps1 helpers not loaded -- file missing next to Open-PimManager.ps1"
    }
    [void](Assert-PimTenantConnectionContext)
    # §100.42 (owner 2026-10-09: "modern single connect only"): there is no SDK sign-in any more. PIM-Rest.ps1 mints a
    # token per call (managed identity / certificate / Support-app session / browser) -- nothing to connect up front.
    if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) {
        throw 'PIM-Rest.ps1 is not loaded (Invoke-PimGraph missing) -- the REST client is the only tenant connection'
    }
    $script:PimManagerTenantConnected = $true
}

function Get-PimActiveGroupAccessLabel {
    <#
      PURE. 95.2l: the access word shown after a PIM-for-Groups row's group name on Review current delegations. A member
      stays 'member'. An owner says which kind: 'eligible owner, activated' (an eligible owner who activated ownership),
      'permanent owner' (an owner assignment with no end date), else 'owner' (a time-bound owner assignment), as before.
    #>
    param([string]$AccessId, [string]$AssignmentType = '', [string]$ExpirationType = '', [AllowNull()][object]$End = $null)
    $a = "$AccessId".Trim(); if (-not $a) { $a = 'member' }
    if ($a -ine 'owner') { return $a }
    if ("$AssignmentType".Trim() -ieq 'activated') { return 'eligible owner, activated' }
    if ("$ExpirationType".Trim() -ieq 'noExpiration' -or ("$AssignmentType".Trim() -ieq 'assigned' -and -not "$End".Trim() -and -not "$ExpirationType".Trim())) { return 'permanent owner' }
    return $a
}

function Test-PimActiveAssignmentsRestOnly {
    # §100.42: REST is the only path. Kept as a function (callers ask it) -- true whenever the REST client is loaded.
    return [bool](Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)
}

function Get-PimActiveAssignmentsGroupPrefix {
    # The PIM-group naming prefix (e.g. 'PIM-') from the naming convention in pim.Settings. Same rule as
    # Get-PimNamePrefix (PIM-Functions.psm1: the literal text before the first {Token}), inlined so a host
    # that does not import that 13k-line module -- the scheduler tick -- resolves the SAME prefix instead of
    # silently falling back to 'PIM-'. A prefix shorter than 3 characters is ignored, as before.
    $pfx = 'PIM-'
    try {
        $pat = $null
        if ($global:PIM_NamingConventions -and $global:PIM_NamingConventions.PimGroupPattern) { $pat = "$($global:PIM_NamingConventions.PimGroupPattern)" }
        if ($pat) {
            $p = if (Get-Command Get-PimNamePrefix -ErrorAction SilentlyContinue) { Get-PimNamePrefix -Pattern $pat }
                 else { $i = $pat.IndexOf('{'); if ($i -lt 0) { $pat } else { $pat.Substring(0, $i) } }
            if ($p -and $p.Length -ge 3) { $pfx = $p }
        }
    } catch { }
    return $pfx
}

function Get-PimActiveAssignmentsGraphItems {
    # 100.31 SNAPSHOT-OOM (2026-10-09). Emit a Graph collection's items to the PIPELINE one page at a time, following
    # @odata.nextLink. `Invoke-PimGraph -All` aggregates every page first; a consumer that projects as it goes
    # (`Get-PimActiveAssignmentsGraphItems -Path ... | ForEach-Object { <project> }`) then holds one raw page, not the
    # whole collection plus its projection. A response with no `value` (an invoker that already returns the items)
    # is emitted as is. Errors throw, exactly like Invoke-PimGraph.
    param([Parameter(Mandatory)][string]$Path)
    $next = $Path
    while ($next) {
        $resp = Invoke-PimGraph -Path $next
        $next = $null
        if ($null -eq $resp) { break }
        if (($resp -isnot [array]) -and $resp.PSObject -and $resp.PSObject.Properties['value']) {
            foreach ($v in @($resp.value)) { if ($null -ne $v) { $v } }
            $nl = $resp.PSObject.Properties['@odata.nextLink']
            if ($nl -and "$($nl.Value)".Trim()) { $next = "$($nl.Value)" }
        } else {
            foreach ($v in @($resp)) { if ($null -ne $v) { $v } }
        }
        $resp = $null
    }
}

function ConvertTo-PimActiveAssignmentsJsonString {
    # 100.31. PURE. One JSON string literal (quotes included) for a value of a snapshot row: $null -> null, a bool ->
    # true/false, a number -> invariant digits, anything else -> its string, escaped per RFC 8259.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) { return ([System.Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture)) }
    $s = [string]$Value
    if ($s -notmatch '[\x00-\x1f"\\]') { return '"' + $s + '"' }
    $sb = New-Object System.Text.StringBuilder ($s.Length + 8)
    [void]$sb.Append('"')
    foreach ($ch in $s.ToCharArray()) {
        switch ($ch) {
            '"'  { [void]$sb.Append('\"'); continue }
            '\'  { [void]$sb.Append('\\'); continue }
            "`n" { [void]$sb.Append('\n'); continue }
            "`r" { [void]$sb.Append('\r'); continue }
            "`t" { [void]$sb.Append('\t'); continue }
            default { if ([int]$ch -lt 0x20) { [void]$sb.Append(('\u{0:x4}' -f [int]$ch)) } else { [void]$sb.Append($ch) } }
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-PimActiveAssignmentsSnapshotJson {
    <#
      100.31 SNAPSHOT-OOM (2026-10-09). The stored 'active-assignments' document as ONE compact JSON string, written row by
      row into a StringBuilder. Same document as `$Entry | ConvertTo-Json -Depth 12 -Compress` (same keys, same order,
      same values -- Test-PimSnapshotMemory compares the two parsed), without ConvertTo-Json's intermediate copy of
      every row: on a ~20k-row tenant that copy plus the rows was what ran a 1 GiB tick out of memory.
      Rows are flat (string / bool / number / null values); every other field is small and goes through ConvertTo-Json.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Entry)
    $sb = New-Object System.Text.StringBuilder 65536
    $keyQuoted = @{}
    [void]$sb.Append('{')
    $first = $true
    foreach ($k in @($Entry.Keys)) {
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        [void]$sb.Append((ConvertTo-PimActiveAssignmentsJsonString -Value ([string]$k))).Append(':')
        $v = $Entry[$k]
        if ("$k" -eq 'rows') {
            [void]$sb.Append('[')
            $firstRow = $true
            foreach ($row in @($v)) {
                if ($null -eq $row) { continue }
                if (-not $firstRow) { [void]$sb.Append(',') }
                $firstRow = $false
                [void]$sb.Append('{')
                $firstField = $true
                foreach ($fk in @($row.Keys)) {
                    if (-not $firstField) { [void]$sb.Append(',') }
                    $firstField = $false
                    $kq = $keyQuoted[$fk]
                    if ($null -eq $kq) { $kq = (ConvertTo-PimActiveAssignmentsJsonString -Value ([string]$fk)) + ':'; $keyQuoted[$fk] = $kq }
                    [void]$sb.Append($kq)
                    $fv = $row[$fk]
                    # fast path inline (the common case: a plain string); everything else through the escaper
                    if ($null -eq $fv) { [void]$sb.Append('null') }
                    elseif (($fv -is [string]) -and ($fv -notmatch '[\x00-\x1f"\\]')) { [void]$sb.Append('"').Append($fv).Append('"') }
                    else { [void]$sb.Append((ConvertTo-PimActiveAssignmentsJsonString -Value $fv)) }
                }
                [void]$sb.Append('}')
            }
            [void]$sb.Append(']')
        } elseif ($null -eq $v -or $v -is [string] -or $v -is [bool] -or $v -is [int] -or $v -is [long]) {
            [void]$sb.Append((ConvertTo-PimActiveAssignmentsJsonString -Value $v))
        } elseif ($v -is [array]) {
            [void]$sb.Append((ConvertTo-Json -InputObject @($v) -Depth 8 -Compress))
        } else {
            [void]$sb.Append((ConvertTo-Json -InputObject $v -Depth 8 -Compress))
        }
    }
    [void]$sb.Append('}')
    return $sb.ToString()
}

# ===========================================================================
# REQ 100.114 (2) / 100.110 -- THE ROWS IN A TABLE (pim.ActiveAssignmentRows, engine/_shared/PIM-SqlStore.ps1)
# ===========================================================================
function ConvertTo-PimActiveAssignmentsRowJson {
    # PURE. ONE snapshot row (an ordered dictionary, or an object) as compact JSON -- the same text the one-document
    # serialiser writes for that row (same keys, order and values).
    # -KeyCache: the quoted field names, kept by the caller across the rows of one snapshot (every row has the same few).
    param([Parameter(Mandatory)][AllowNull()][object]$Row, [hashtable]$KeyCache = $null)
    if ($null -eq $Row) { return 'null' }
    if ($null -eq $KeyCache) { $KeyCache = @{} }
    $sb = New-Object System.Text.StringBuilder 512
    [void]$sb.Append('{')
    $first = $true
    $isDict = ($Row -is [System.Collections.IDictionary])
    $names = if ($isDict) { @($Row.Keys) } else { @(foreach ($pp in $Row.PSObject.Properties) { $pp.Name }) }
    foreach ($fk in $names) {
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        $kq = $KeyCache[$fk]
        if ($null -eq $kq) { $kq = (ConvertTo-PimActiveAssignmentsJsonString -Value ([string]$fk)) + ':'; $KeyCache[$fk] = $kq }
        [void]$sb.Append($kq)
        $fv = if ($isDict) { $Row[$fk] } else { $Row.$fk }
        if ($null -eq $fv) { [void]$sb.Append('null') }
        elseif (($fv -is [string]) -and ($fv -notmatch '[\x00-\x1f"\\]')) { [void]$sb.Append('"').Append($fv).Append('"') }
        else { [void]$sb.Append((ConvertTo-PimActiveAssignmentsJsonString -Value $fv)) }
    }
    [void]$sb.Append('}')
    return $sb.ToString()
}

function ConvertTo-PimActiveAssignmentsStoreValues {
    <#
      PURE. One snapshot row -> the values of its table row (pim.ActiveAssignmentRows), each cut to its column's length:
      the columns the page filters and sorts on, the row's MANAGED identity (Get-PimActiveRowIdentity), the lower-cased
      text the page's search looks in (principal id, principal, role, scope, justification) and the whole row as JSON.
      Dates that cannot be read are stored as no date (the row's own text stays in RowJson).
    #>
    param([Parameter(Mandatory)][object]$Row, [hashtable]$KeyCache = $null)
    # (written without helper script blocks: this runs once per row of a snapshot of tens of thousands)
    $names = @('id', 'type', 'principal', 'principalId', 'principalKind', 'principalUpn', 'role', 'scope', 'groupId', 'start', 'end', 'justification', 'accessId', 'roleDefinitionId', 'directoryScopeId')
    $val = @{}
    if ($Row -is [System.Collections.IDictionary]) { foreach ($n in $names) { if ($Row.Contains($n)) { $val[$n] = $Row[$n] } } }
    else { foreach ($n in $names) { $p = $Row.PSObject.Properties[$n]; if ($p) { $val[$n] = $p.Value } } }
    $limit = @{ id = 900; type = 40; principal = 400; principalId = 100; principalKind = 40; principalUpn = 400; role = 400; scope = 400; groupId = 100; justification = 400 }
    $cut = @{}
    foreach ($n in @($limit.Keys)) {
        $v = $val[$n]
        if ($null -eq $v) { $cut[$n] = $null; continue }
        $s = [string]$v
        if ($s.Length -gt $limit[$n]) { $s = $s.Substring(0, $limit[$n]) }
        $cut[$n] = $s
    }
    $dates = @{}
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    foreach ($n in 'start', 'end') {
        $v = $val[$n]; $dates[$n] = $null
        if ($null -eq $v) { continue }
        if ($v -is [datetime]) { $dates[$n] = $v.ToUniversalTime(); continue }
        $s = ([string]$v).Trim(); if (-not $s) { continue }
        $d = [datetime]::MinValue
        if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d) -and $d.Year -ge 1753) { $dates[$n] = $d }
    }
    $search = ([string]$val['principalId'] + "`n" + [string]$val['principal'] + "`n" + [string]$val['role'] + "`n" + [string]$val['scope'] + "`n" + [string]$val['justification']).ToLowerInvariant()
    if ($search.Length -gt 4000) { $search = $search.Substring(0, 4000) }
    $kind = ([string]$val['type']).Trim(); if (-not $kind) { $kind = '(none)' }; if ($kind.Length -gt 40) { $kind = $kind.Substring(0, 40) }
    # the MANAGED identity (the rule of Get-PimActiveRowIdentity, from the values already read)
    $idKey = ''
    switch ($kind) {
        'pim-for-groups' { $idKey = ConvertTo-PimManagedIdentity -Kind 'g' -PrincipalId ([string]$val['principalId']) -GroupId ([string]$val['groupId']) -AccessId ([string]$val['accessId']) }
        'entra-role'     { $idKey = ConvertTo-PimManagedIdentity -Kind 'r' -PrincipalId ([string]$val['principalId']) -RoleDefinitionId ([string]$val['roleDefinitionId']) -Scope ([string]$val['directoryScopeId']) }
        'azure-rbac'     { $idKey = ConvertTo-PimManagedIdentity -Kind 'a' -PrincipalId ([string]$val['principalId']) -RoleDefinitionId ([string]$val['roleDefinitionId']) -Scope ([string]$val['scope']) }
    }
    if ($idKey.Length -gt 450) { $idKey = $idKey.Substring(0, 450) }
    return [ordered]@{
        RowId         = $cut['id']
        Kind          = $kind
        Principal     = $cut['principal']
        PrincipalId   = $cut['principalId']
        PrincipalKind = $cut['principalKind']
        PrincipalUpn  = $cut['principalUpn']
        Role          = $cut['role']
        Scope         = $cut['scope']
        GroupId       = $cut['groupId']
        StartUtc      = $dates['start']
        EndUtc        = $dates['end']
        Justification = $cut['justification']
        IdentityKey   = $idKey
        SearchText    = $search
        RowJson       = (ConvertTo-PimActiveAssignmentsRowJson -Row $Row -KeyCache $KeyCache)
    }
}

function ConvertTo-PimActiveAssignmentsHeaderJson {
    <#
      PURE. The pim.TenantCache 'active-assignments' document of a TABLE-form snapshot: the entry WITHOUT its rows, with
      rowStore / snapshotId / rowCount FIRST (the store reads the form and the generation from the first characters).
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Entry, [Parameter(Mandatory)][long]$SnapshotId, [Parameter(Mandatory)][int]$RowCount)
    $head = [ordered]@{}
    foreach ($k in @($Entry.Keys)) { if ("$k" -ne 'rows' -and "$k" -ne 'rowStore' -and "$k" -ne 'snapshotId' -and "$k" -ne 'rowCount') { $head[$k] = $Entry[$k] } }
    $inner = ConvertTo-PimActiveAssignmentsSnapshotJson -Entry $head
    $lead = '{"rowStore":"table","snapshotId":' + $SnapshotId.ToString([System.Globalization.CultureInfo]::InvariantCulture) + ',"rowCount":' + $RowCount.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    if ($inner.Length -le 2) { return $lead + '}' }
    return $lead + ',' + $inner.Substring(1)
}

function Save-PimActiveAssignmentsSnapshotRows {
    <#
      Store one snapshot in the TABLE form: a new generation of rows in pim.ActiveAssignmentRows, written in batches of
      Get-PimActiveAssignmentRowsBatchSize (each its own transaction, with a command timeout and a retry on a transient
      error -- engine/_shared/PIM-SqlStore.ps1), then ONE transaction that checks the row count and switches the
      pim.TenantCache header to the new generation.
        .stored = $true   the snapshot is stored ({ where; rows; batches; retries; seconds; snapshotId })
        .stored = $false  NOTHING was written and the caller keeps the one-document form: the row store is not loaded in
                          this process, there is no SQL store, or the table is not there and could not be created
                          (.reason; .said = worth a line in the job's detail)
      THROWS when the table is there and a write fails: the header still names the previous generation, whose rows are
      untouched -- the previous complete snapshot stays in place and readable.
      -Writer / -Sleep: test seams, passed to Invoke-PimSqlActiveAssignmentBatchWrite.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Entry, [string]$ConnectionString = '', [scriptblock]$Writer = $null, [scriptblock]$Sleep = $null)
    $no = { param($why, $said) [pscustomobject]@{ stored = $false; reason = "$why"; said = [bool]$said; where = ''; rows = 0; batches = 0; retries = 0; seconds = 0; snapshotId = [long]0 } }
    foreach ($fn in 'Confirm-PimSqlActiveAssignmentRowsReady', 'Start-PimSqlActiveAssignmentSnapshot', 'Invoke-PimSqlActiveAssignmentBatchWrite', 'Complete-PimSqlActiveAssignmentSnapshot', 'New-PimSqlActiveAssignmentRowTable') {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { return (& $no 'the row store is not loaded in this process' $false) }
    }
    if (-not "$ConnectionString".Trim() -and (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) { $ConnectionString = "$(Get-PimTenantCacheStoreCs)" }
    if (-not "$ConnectionString".Trim()) { return (& $no 'no SQL store in this process' $false) }
    # §12.23 run 2 (PIM 100.156): a read-only check -- the schema step creates the tables; the create is only a fallback
    $ddl = Confirm-PimSqlActiveAssignmentRowsReady -ConnectionString $ConnectionString
    if (-not $ddl.ok) { return (& $no "the table pim.ActiveAssignmentRows is not there and could not be created: $($ddl.error)" $true) }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rows = @(); if ($null -ne $Entry['rows']) { $rows = @($Entry['rows']) }   # a reference per row, never a copy of the rows
    $total = $rows.Count
    $gen = Start-PimSqlActiveAssignmentSnapshot -ConnectionString $ConnectionString -ExpectedRows $total
    $sid = [long]$gen.snapshotId
    $size = Get-PimActiveAssignmentRowsBatchSize
    $batches = 0; $retries = 0; $seq = 0; $written = 0
    $table = New-PimSqlActiveAssignmentRowTable
    $keyCache = @{}
    # 2.4.645 (E3 regression, measured): the MANAGED mark goes in with the row when the engine's managed list is stored, so
    # the set-based marks pass after this write (the job's Update-PimActiveAssignmentsSnapshotMarks, the Manager's page)
    # rewrites only the rows it disagrees with -- normally none -- instead of every managed row and its five indexes.
    # Optimisation only: that SQL pass stays the authority (the marks key is NOT set here), and no list / a failed read = $false.
    $mlSet = $null
    if ($total -gt 0 -and (Get-Command Get-PimSqlManagedLiveIdentitySet -ErrorAction SilentlyContinue)) {
        try { $mlSet = Get-PimSqlManagedLiveIdentitySet -ConnectionString $ConnectionString } catch { $mlSet = $null }
    }
    $hasManagedCol = $table.Columns.Contains('Managed')
    if ($total -gt 0) {
        $e = ([System.Collections.IEnumerable]$rows).GetEnumerator()
        $more = $e.MoveNext()
        while ($more -or $table.Rows.Count -gt 0) {
            if ($more) {
                $row = $e.Current
                $more = $e.MoveNext()
                if ($null -ne $row) {
                    $v = ConvertTo-PimActiveAssignmentsStoreValues -Row $row -KeyCache $keyCache
                    $dr = $table.NewRow()
                    $dr['SnapshotId'] = $sid; $dr['Seq'] = $seq
                    foreach ($k in @($v.Keys)) { if ($null -eq $v[$k]) { $dr[$k] = [System.DBNull]::Value } else { $dr[$k] = $v[$k] } }
                    if ($hasManagedCol) { $ik = "$($v['IdentityKey'])"; $dr['Managed'] = [bool]($null -ne $mlSet -and $ik -ne '' -and $mlSet.Contains($ik.ToLowerInvariant())) }
                    $table.Rows.Add($dr)
                    $seq++
                }
            }
            # a full batch, or the last (partial) one once the rows have run out
            if ($table.Rows.Count -ge $size -or (-not $more -and $table.Rows.Count -gt 0)) {
                $r = Invoke-PimSqlActiveAssignmentBatchWrite -ConnectionString $ConnectionString -SnapshotId $sid -Table $table -Writer $Writer -Sleep $Sleep
                $batches++; $retries += ([int]$r.attempts - 1); $written += [int]$r.rows
                $table.Clear()
            }
        }
    }
    $table.Dispose()
    $header = ConvertTo-PimActiveAssignmentsHeaderJson -Entry $Entry -SnapshotId $sid -RowCount $seq
    Complete-PimSqlActiveAssignmentSnapshot -ConnectionString $ConnectionString -SnapshotId $sid -ExpectedRows $seq -HeaderJson $header
    $sw.Stop()
    return [pscustomobject]@{ stored = $true; reason = ''; said = $false; where = "sql:pim.ActiveAssignmentRows/$sid + pim.TenantCache/active-assignments"
        rows = $written; batches = $batches; retries = $retries; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2); snapshotId = $sid }
}

function Select-PimActiveAssignmentsPimGroupCandidates {
    # BUG-217 (§33.28). PURE. The groups whose PIM-for-Groups assignments the Revoke snapshot reads: EVERY group that
    # can carry one -- security-enabled or Microsoft 365 -- whatever it is called. A mail-only distribution list is
    # skipped (it cannot be onboarded to PIM); a group whose securityEnabled is UNKNOWN (an older cache shape) is kept,
    # so nothing is dropped on a guess. Dynamic groups are skipped by the caller, which counts them.
    param([object[]]$Groups = @())
    @(@($Groups) | Where-Object {
        if (-not $_ -or -not $_.Id) { return $false }
        $types = @($_.GroupTypes)
        $sec = $null
        if ($_.PSObject.Properties['SecurityEnabled']) { $sec = $_.SecurityEnabled }
        if ($null -eq $sec -or "$sec" -eq '') { return $true }
        return ([bool]$sec -or ($types -contains 'Unified'))
    })
}

function Test-PimGroupNotPimOnboardedError {
    # BUG-217. PURE. A per-group assignmentSchedules error that only means "this group is not a PIM group" -- not a
    # failed read. Anything else (401/403/5xx, throttling) is still counted as a failure.
    param([string]$Message)
    return ("$Message" -match '(?i)ResourceNotOnboarded|NotOnboarded|not onboarded|ResourceTypeNotSupported|RoleAssignmentDoesNotExist|GroupNotFound|Request_ResourceNotFound')
}

function Get-PimManagerLookupCaches {
    # Populate $script:PimManager_Users / Groups / Roles for principal +
    # role-display-name resolution in the active-assignments row builder.
    # Pulled once per server start; refreshed only when -Force passed.
    param([switch]$Force)
    if (-not $Force -and $script:PimManager_LookupCachesLoaded) { return }

    Initialize-PimManagerTenantConnection

    Write-Host "  [revoke] loading principal + role lookup caches (one-shot per session) ..." -ForegroundColor DarkGray
    # REST only (§100.42): pull via PIM-Rest's Invoke-PimGraph and re-shape to SDK casing (.Id/.DisplayName/.UPN) so
    # the row-builder + id indexes below are unchanged.

    # Users.
    try {
            # 🔒 DELIBERATELY UNFILTERED (operator, 2026-09-12: "for the revoke solution, we dont
            # filter as it contains legacy assignements").
            # This list resolves PRINCIPAL NAMES for the revoke screen, and that screen must show
            # LEGACY assignments -- grants to accounts that predate, or sit outside, the admin
            # naming convention. Filtering by AdminAccountPatterns here (briefly shipped in
            # 2.4.330 and reverted) would blank the name of exactly the assignments an operator
            # most needs to see and revoke.
            # 🪤 So the 250k-tenant fix here is NOT a prefix filter -- a filter trades a slow screen
            # for a WRONG one. It is to resolve only the ids the rows actually reference.
            # ✅ §67.2 (2026-09-13): nothing is pre-loaded. Every row builder already ends with ONE
            # /directoryObjects/getByIds call for the ids it references (Resolve-PimManagerPrincipalIdBatch),
            # and that call now also fills $script:PimManager_UserById for the users it returns -- so every
            # consumer of the user index sees the same UPN + display name the directory pull gave, for
            # exactly the principals on screen, whether the tenant has 300 users or 250,000.
            $script:PimManager_Users = @()
    } catch {
        Write-Warning "  [revoke] user cache load failed: $($_.Exception.Message). Principal names may be blank."
        $script:PimManager_Users = @()
    }
    # Groups (PIM-prefix filter if naming-conventions present, else full set).
    try {
            # 🔴 BUG-217 (§33.28, operator decision 2026-09-18): the Revoke snapshot covers EVERY PIM-for-Groups group,
            # not only the ones named by our convention -- a legacy or hand-made PIM group's active grants are exactly
            # what the revoke screen must show. So the cache is no longer prefix-filtered: ALL groups, paged 999 at a
            # time (a 30k-group tenant is ~30 list calls), with the two fields the snapshot needs to skip groups that
            # can never carry a PIM-for-Groups assignment (dynamic membership, mail-only distribution lists).
            # 🔴 100.31 SNAPSHOT-OOM (2026-10-09): page by page, each group projected at once to the five fields (SDK casing;
            # PowerShell property names are case-insensitive, so .id / .displayName still answer). The old
            # `-All | ConvertTo-PimSdkShape` held every raw page AND a doubled-property copy of the whole group list.
            # SNAP-INC (owner 2026-10-20): + isAssignableToRole -- a role-assignable group is re-read on every incremental run.
            $script:PimManager_Groups = @(Get-PimActiveAssignmentsGraphItems -Path "/groups?`$select=id,displayName,description,groupTypes,securityEnabled,isAssignableToRole&`$top=999" | ForEach-Object {
                $sec = $null; if ($_.PSObject.Properties['securityEnabled']) { $sec = $_.securityEnabled }
                $gt = @(); if ($null -ne $_.groupTypes) { $gt = @($_.groupTypes) }
                $rag = $false; if ($_.PSObject.Properties['isAssignableToRole']) { $rag = [bool]$_.isAssignableToRole }
                [pscustomobject]@{ Id = "$($_.id)"; DisplayName = [string]$_.displayName; Description = [string]$_.description; GroupTypes = $gt; SecurityEnabled = $sec; IsAssignableToRole = $rag }
            })
    } catch {
        Write-Warning "  [revoke] group cache load failed: $($_.Exception.Message). Group names may be blank."
        $script:PimManager_Groups = @()
    }
    # Entra role definitions (small, single call, no filtering).
    try {
        $script:PimManager_EntraRoles = @(Invoke-PimGraph -Path "/roleManagement/directory/roleDefinitions?`$select=id,displayName,isBuiltIn,templateId" -All | ConvertTo-PimSdkShape)
    } catch {
        Write-Warning "  [revoke] entra role-definition cache load failed: $($_.Exception.Message). Entra role names may be blank."
        $script:PimManager_EntraRoles = @()
    }
    # AU directory cache (for /administrativeUnits/<id> scope display).
    try {
        $script:PimManager_AUs = @(Invoke-PimGraph -Path "/directory/administrativeUnits?`$select=id,displayName" -All | ConvertTo-PimSdkShape)
    } catch {
        $script:PimManager_AUs = @()
    }

    # Engine helpers (Resolve-PimGroupCached etc.) read $Global:Users_All_ID /
    # $Global:Groups_All_ID. Mirror our caches there so the v2.4.0 helpers
    # stay first-class.
    $Global:Users_All_ID  = $script:PimManager_Users
    $Global:Groups_All_ID = $script:PimManager_Groups

    # Id-keyed indexes: the row builder resolves principal/role/AU labels per
    # assignment row, and a linear scan per row is O(rows x principals) --
    # measurably seconds on a 944-row tenant. Hashtables make it O(rows).
    $script:PimManager_UserById  = @{}
    foreach ($u in $script:PimManager_Users)  { if ($u -and $u.Id)  { $script:PimManager_UserById["$($u.Id)"]  = $u } }
    # §67.2: users already resolved by id this session stay indexed across a -Force refresh.
    foreach ($rk in @(if ($script:PimManager_ResolvedById -is [hashtable]) { $script:PimManager_ResolvedById.Keys })) {
        $rv = $script:PimManager_ResolvedById[$rk]
        if ($rv -and "$($rv.kind)" -eq 'user') { Add-PimManagerUserIndexEntry -Id "$rk" -DisplayName "$($rv.displayName)" -UserPrincipalName "$($rv.userPrincipalName)" }
    }
    $script:PimManager_GroupById = @{}
    foreach ($g in $script:PimManager_Groups) { if ($g -and $g.Id)  { $script:PimManager_GroupById["$($g.Id)"] = $g } }
    $script:PimManager_RoleById  = @{}
    foreach ($r in $script:PimManager_EntraRoles) { if ($r -and $r.Id) { $script:PimManager_RoleById["$($r.Id)"] = $r } }
    $script:PimManager_AuById    = @{}
    foreach ($a in $script:PimManager_AUs) { if ($a -and $a.Id) { $script:PimManager_AuById["$($a.Id)"] = $a } }

    $script:PimManager_LookupCachesLoaded = $true
}

# BUG-98 -- RESOLVE PRINCIPALS BY ID, NOT BY NAMING CONVENTION.
#
# The two caches above are built by FILTERED queries: users via /users, groups via
# startswith(displayName,'<PimGroupPattern prefix>'), and SERVICE PRINCIPALS NOT AT ALL. So the
# revoke table showed a bare objectId for
#   * every service principal            (never cached), and
#   * every group outside the PIM- prefix (filtered out).
# The operator saw both shapes in one list and asked "i see both, why". Resolved live
# 2026-08-30: the unresolved ids were groups and servicePrincipals, exactly as above.
#
# 🔑 A display-name resolver must NEVER depend on a naming convention being obeyed. This one
# asks Graph for the ids it actually has, in one batched call, and caches the answers.
if (-not ($script:PimManager_ResolvedById -is [hashtable])) { $script:PimManager_ResolvedById = @{} }

function Add-PimManagerUserIndexEntry {
    param([Parameter(Mandatory)][string]$Id, [string]$DisplayName, [string]$UserPrincipalName)
    if (-not ($script:PimManager_UserById -is [hashtable])) { $script:PimManager_UserById = @{} }
    if ($script:PimManager_UserById.ContainsKey($Id)) { return }
    # Property names are case-insensitive, so the SDK casing below also answers .id / .displayName.
    $script:PimManager_UserById[$Id] = [pscustomobject]@{ Id = $Id; DisplayName = $DisplayName; UserPrincipalName = $UserPrincipalName }
}

function Resolve-PimManagerPrincipalIdBatch {
    # Fill $script:PimManager_ResolvedById for every id not already known. /directoryObjects
    # /getByIds takes up to 1000 ids per call and returns users, groups AND servicePrincipals,
    # so ~700 assignment rows collapse to a single request. Best-effort: a failure here leaves
    # the ids unresolved (the caller still renders the GUID) and never breaks the table.
    param([string[]]$Ids)
    # 100.31: de-duplicated through a set, in first-seen order -- `Select-Object -Unique` compares every id with every
    # earlier one (O(n^2)), which on a ~17k-principal snapshot is minutes of CPU for nothing.
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $needList = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($Ids)) { $sx = "$x"; if ($sx -and -not $script:PimManager_ResolvedById.ContainsKey($sx) -and $seen.Add($sx)) { $needList.Add($sx) } }
    $need = $needList.ToArray()
    if (-not $need -or $need.Count -eq 0) { return }
    if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) { return }
    for ($i = 0; $i -lt $need.Count; $i += 1000) {
        $chunk = @($need[$i..([Math]::Min($i + 999, $need.Count - 1))])
        $answered = $false
        try {
            $body = @{ ids = $chunk; types = @('user', 'group', 'servicePrincipal') } | ConvertTo-Json -Depth 4
            $r = Invoke-PimGraph -Path '/directoryObjects/getByIds' -Method POST -Body $body
            $answered = $true
            foreach ($o in @($r.value)) {
                if (-not $o -or -not $o.id) { continue }
                $kind = ("$($o.'@odata.type')" -replace '#microsoft\.graph\.', '')
                $label = if ($o.userPrincipalName) { [string]$o.userPrincipalName } else { [string]$o.displayName }
                if (-not $label) { $label = [string]$o.id }
                $script:PimManager_ResolvedById["$($o.id)"] = [pscustomobject]@{ label = $label; kind = $kind; displayName = [string]$o.displayName; userPrincipalName = [string]$o.userPrincipalName }
                # §67.2: the user index is no longer a directory pull -- it is filled HERE, for the users a
                # screen actually references, in the same SDK shape the pull produced.
                if ($kind -eq 'user') { Add-PimManagerUserIndexEntry -Id "$($o.id)" -DisplayName ([string]$o.displayName) -UserPrincipalName ([string]$o.userPrincipalName) }
            }
        } catch {
            Write-Warning "  [revoke] principal batch resolve failed: $($_.Exception.Message). Some rows will show a raw object id."
        }
        # An id Graph did not return is DELETED (or not visible to us). Record that explicitly:
        # a role still held by a principal that no longer exists is a FINDING, not a blank.
        # 🔒 Only when Graph ANSWERED: a failed call proves nothing about the ids, and now that users are
        # resolved here too (§67.2) it would otherwise brand every admin "(deleted principal)" for the session.
        if (-not $answered) { continue }
        foreach ($id in $chunk) {
            if (-not $script:PimManager_ResolvedById.ContainsKey("$id")) {
                $script:PimManager_ResolvedById["$id"] = [pscustomobject]@{ label = '(deleted principal)'; kind = 'deleted' }
            }
        }
    }
}

function Resolve-PimManagerPrincipalLabel {
    # Try user UPN first, then group DisplayName, then the by-id resolver (BUG-98), then the
    # bare id. Hashtable lookups -- called once per assignment row (944 rows on a real tenant).
    param([Parameter(Mandatory)][AllowEmptyString()][string]$PrincipalId)
    if ([string]::IsNullOrWhiteSpace($PrincipalId)) { return '' }
    if ($script:PimManager_UserById -and $script:PimManager_UserById.ContainsKey($PrincipalId)) {
        $u = $script:PimManager_UserById[$PrincipalId]
        if ($u.UserPrincipalName) { return [string]$u.UserPrincipalName }
        if ($u.DisplayName)       { return [string]$u.DisplayName }
        return $PrincipalId
    }
    if ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($PrincipalId)) {
        $g = $script:PimManager_GroupById[$PrincipalId]
        if ($g.DisplayName) { return [string]$g.DisplayName }
        return $PrincipalId
    }
    if ($script:PimManager_ResolvedById -and $script:PimManager_ResolvedById.ContainsKey($PrincipalId)) {
        $r = $script:PimManager_ResolvedById[$PrincipalId]
        if ($r -and $r.label) { return [string]$r.label }
    }
    return $PrincipalId
}

function Get-PimManagerPrincipalKind {
    # BUG-98: the GUI shows this as a small chip, so a group or an app is not mistaken for a
    # person on a screen whose whole job is deciding whose access to revoke.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$PrincipalId)
    if ([string]::IsNullOrWhiteSpace($PrincipalId)) { return '' }
    if ($script:PimManager_UserById  -and $script:PimManager_UserById.ContainsKey($PrincipalId))  { return 'user' }
    if ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($PrincipalId)) { return 'group' }
    if ($script:PimManager_ResolvedById -and $script:PimManager_ResolvedById.ContainsKey($PrincipalId)) {
        return [string]$script:PimManager_ResolvedById[$PrincipalId].kind
    }
    return ''
}

function Resolve-PimManagerEntraRoleName {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RoleDefinitionId)
    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) { return '' }
    # Trim a possible /providers/.../roleDefinitions/<guid> prefix.
    $guid = $RoleDefinitionId
    $slash = $RoleDefinitionId.LastIndexOf('/')
    if ($slash -ge 0 -and $slash -lt ($RoleDefinitionId.Length - 1)) {
        $guid = $RoleDefinitionId.Substring($slash + 1)
    }
    if ($script:PimManager_RoleById -and $script:PimManager_RoleById.ContainsKey($guid)) {
        $r = $script:PimManager_RoleById[$guid]
        if ($r.DisplayName) { return [string]$r.DisplayName }
    }
    return $guid
}

function Resolve-PimManagerDirectoryScope {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$DirectoryScopeId)
    if ([string]::IsNullOrWhiteSpace($DirectoryScopeId)) { return '/ (tenant-wide)' }
    if ($DirectoryScopeId -eq '/')                       { return '/ (tenant-wide)' }
    if ($DirectoryScopeId -like '/administrativeUnits/*') {
        $auId = ($DirectoryScopeId -split '/')[-1]
        if ($script:PimManager_AuById -and $script:PimManager_AuById.ContainsKey($auId)) {
            return '/AdministrativeUnits/' + [string]$script:PimManager_AuById[$auId].DisplayName
        }
        return $DirectoryScopeId
    }
    return $DirectoryScopeId
}

function Get-PimActiveAssignmentSurfaceHint {
    # Map a failed active-assignments surface + its error text to an ACTIONABLE
    # remediation: which Graph app-role / Azure RBAC role is needed and the exact
    # tools/setup/Grant-PimGraphAppRoles.ps1 invocation. Returns '' when the failure is
    # not a recognised auth/permission failure (transport/transient -> retry).
    param(
        [Parameter(Mandatory)][ValidateSet('entra-role','azure-rbac','pim-for-groups')][string]$Surface,
        [string]$ErrorMessage = ''
    )
    $em = "$ErrorMessage"
    # Recognise the permission-failure signatures (Graph 403 / ARM AuthorizationFailed).
    $isAuth = ($em -match '(?i)\b(401|403)\b' -or
               $em -match '(?i)Authorization_RequestDenied|InsufficientPrivileges|insufficient privileges|Forbidden|AuthorizationFailed|does not have authorization|Authentication_MissingOrMalformed')
    switch ($Surface) {
        'entra-role' {
            if (-not $isAuth) { return '' }
            return ("Engine SPN is missing the Graph app-role to read Entra-role active assignments " +
                    "(roleManagement/directory). Grant RoleManagement.Read.Directory (or RoleManagement.ReadWrite.Directory) " +
                    "with the published Grant-PimEnginePermissions.ps1 (browser sign-in, no modules) -- Overview > Verify permissions shows the exact command.")
        }
        'pim-for-groups' {
            if (-not $isAuth) { return '' }
            return ("Engine SPN is missing the Graph app-role to read PIM-for-Groups active assignments " +
                    "(identityGovernance/privilegedAccess/group). Grant PrivilegedAccess.Read.AzureADGroup " +
                    "(or PrivilegedAccess.ReadWrite.AzureADGroup) with the published Grant-PimEnginePermissions.ps1 (browser sign-in) -- Overview > Verify permissions shows the exact command.")
        }
        'azure-rbac' {
            return ("Engine SPN cannot read Azure-RBAC active assignments. Grant it at least Reader on the " +
                    "target subscription(s) (Azure RBAC, not a Graph app-role) so " +
                    "Microsoft.Authorization/roleAssignmentScheduleInstances can be enumerated.")
        }
    }
    return ''
}

function Invoke-PimActiveAssignmentsSnapshot {
    # THE LIVE READ -- scheduler only (§70.1b option 2). Returns an ordered hashtable:
    #   @{ ok; rows = [...]; counts = @{...}; surfaceErrors; partial; loadedUtc; refreshedUtc; cacheHit=$false;
    #      elapsedSec; durationMs; error? }
    # This was the compute half of the Manager's Get-PimActiveAssignmentsCached, moved here unchanged in
    # behaviour (row shape, counts, surfaceErrors, hints). What is GONE is the in-process 5-minute cache and
    # the lazy PIM-Functions.psm1 import: the result is persisted to SQL by the job, and every reader in the
    # REST path lives in PIM-Rest.ps1 (the psm1 only fed the SDK branches, and Get-PimNamePrefix is inlined as
    # Get-PimActiveAssignmentsGroupPrefix).
    # 🔒 Never call this from the Manager: one run is 140-170 s of Graph reads, and the Manager's single request
    # loop would freeze every user for that long. Test-PimActiveAssignmentsSnapshot asserts it.
    # -Fresh: reload the group/role/AU lookups AND forget principal names resolved earlier in this process, so a
    # long-running scheduler loop does not keep a renamed or deleted principal's old label for ever.
    # -GroupDelta: SNAP-INC (owner 2026-10-20) -- the incremental PIM-for-Groups read's context (New-PimSnapshotGroupDeltaContext);
    # $null = every group is read, exactly as before. The result then carries 'groupDelta' (the state the job stores).
    [CmdletBinding()]
    param([switch]$Fresh, [AllowNull()][hashtable]$GroupDelta = $null)

    if ($Fresh) { $script:PimManager_ResolvedById = @{} }
    # Initial connect + lookup caches (idempotent).
    Initialize-PimManagerTenantConnection
    Get-PimManagerLookupCaches -Force:$Fresh

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rows = New-Object System.Collections.ArrayList

    # Per-surface failure ledger. Each entry: @{ surface; error; hint }.
    # When a surface FETCH fails (auth/permission/transport) we record it here
    # instead of silently swallowing to @(). This is what lets the endpoint and
    # GUI tell "genuinely no active assignments" apart from "we could not read
    # them" -- the old code returned ok=$true,total=0 for BOTH, which surfaced as
    # the misleading "Cache may be empty -- click Refresh." (root cause).
    $surfaceErrors = New-Object System.Collections.ArrayList

    # REST only (§100.42): mint tokens + read Graph/ARM via PIM-Rest.ps1 -- no Graph/Az PowerShell SDK anywhere.
    $restArm   = [bool](Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)

    # ---- Entra-role active assignments -------------------------------------
    # 🔴 100.31 SNAPSHOT-OOM (2026-10-09, a ~10.8k-object tenant at 0.5 CPU / 1 GiB: System.OutOfMemoryException). Every
    # surface is now PROJECTED AS IT IS READ: a raw Graph / Resource Graph page becomes rows and is released before the
    # next page is fetched (Get-PimActiveAssignmentsGraphItems / Get-PimArmActiveRoleAssignmentsViaArg -Stream piped into
    # the row builder), the PIM-for-Groups items are released as they are built, and the stored document is written as
    # ONE compact string (ConvertTo-PimActiveAssignmentsSnapshotJson) instead of ConvertTo-Json over every row. A surface
    # that fails part-way drops the rows it had added, so the stored result is what it always was: all of a surface or none.
    $addEntraRow = {
        param($e)
        if (-not $e) { return }
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$e.PrincipalId)
        $roleLabel      = Resolve-PimManagerEntraRoleName -RoleDefinitionId ([string]$e.RoleDefinitionId)
        $scopeLabel     = Resolve-PimManagerDirectoryScope -DirectoryScopeId ([string]$e.DirectoryScopeId)
        # SDK objects expose PascalCase; REST returns camelCase nested objects
        # (ConvertTo-PimSdkShape only aliases the top level). Tolerate both.
        $si = if ($e.ScheduleInfo) { $e.ScheduleInfo } else { $e.scheduleInfo }
        $start = $null; $end = $null
        if ($si) {
            $sdt = if ($si.StartDateTime) { $si.StartDateTime } else { $si.startDateTime }
            if ($sdt) { try { $start = ([DateTime]$sdt).ToUniversalTime().ToString('o') } catch {} }
            $exp = if ($si.Expiration) { $si.Expiration } else { $si.expiration }
            if ($exp) {
                $edt = if ($exp.EndDateTime) { $exp.EndDateTime } else { $exp.endDateTime }
                if ($edt) { try { $end = ([DateTime]$edt).ToUniversalTime().ToString('o') } catch {} }
            }
        }
        [void]$rows.Add([ordered]@{
            id               = "entra-role:$($e.Id)"
            type             = 'entra-role'
            principal        = $principalLabel
            principalId      = [string]$e.PrincipalId
            role             = $roleLabel
            roleDefinitionId = [string]$e.RoleDefinitionId
            scope            = $scopeLabel
            directoryScopeId = [string]$e.DirectoryScopeId
            start            = $start
            end              = $end
            justification    = ''  # Entra role assignment schedules don't carry the original activation justification on the assignment object.
        })
    }
    $entraStart = $rows.Count
    try {
        # REST, page by page: each schedule becomes a row as its page arrives (property names are case-insensitive,
        # so the PascalCase reads in the builder resolve on the camelCase REST objects; nested ones are tolerated).
        Get-PimActiveAssignmentsGraphItems -Path '/roleManagement/directory/roleAssignmentSchedules' | ForEach-Object { & $addEntraRow $_ }
    } catch {
        $em = "$($_.Exception.Message)"
        Write-Warning "  [revoke] entra-role assignment-schedules load failed: $em"
        [void]$surfaceErrors.Add([ordered]@{
            surface = 'entra-role'
            error   = $em
            hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'entra-role' -ErrorMessage $em)
        })
        if ($rows.Count -gt $entraStart) { $rows.RemoveRange($entraStart, $rows.Count - $entraStart) }   # all of a surface or none
    }

    # ---- Azure-RBAC active assignments -------------------------------------
    # REQUIREMENTS 67.3: ONE Azure Resource Graph query over REST (Get-PimArmActiveRoleAssignmentsViaArg,
    # PIM-Rest.ps1) returns every role assignment the engine identity can see -- management groups,
    # subscriptions, resource groups, resources -- with the role name joined in. It replaces a
    # subscriptions list plus one instances read per subscription, which also never saw a management group
    # without a subscription under it. Each row carries its roleAssignmentId, which an ACTIVE revoke needs
    # (the per-subscription rows had none, so queueing one threw). If the query fails the old walk still runs.
    $addAzRow = {
        param($a)
        if (-not $a) { return }
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$a.PrincipalId)
        $roleName       = if ($a.RoleDefinitionName) { [string]$a.RoleDefinitionName } else { [string]$a.RoleDefinitionId }
        $azRow = [ordered]@{
            id               = "azure-rbac:$($a.Id)"
            type             = 'azure-rbac'
            principal        = $principalLabel
            principalId      = [string]$a.PrincipalId
            role             = $roleName
            roleDefinitionId = [string]$a.RoleDefinitionId
            scope            = [string]$a.Scope
            directoryScopeId = ''
            start            = ''  # ARG row doesn't carry start/end for the assignment record.
            end              = ''
            justification    = ''
        }
        if ($a.PSObject.Properties['RoleAssignmentId'] -and "$($a.RoleAssignmentId)".Trim()) {
            $azRow['roleAssignmentId']   = [string]$a.RoleAssignmentId
            $azRow['roleAssignmentName'] = [string]$a.RoleAssignmentName
        }
        [void]$rows.Add($azRow)
    }
    $azRows = @()
    $argDone = $false
    if ((Get-Command Get-PimArmActiveRoleAssignmentsViaArg -ErrorAction SilentlyContinue) -and (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)) {
        $azStart = $rows.Count
        try {
            # 100.31: streamed -- each Resource Graph row becomes a snapshot row as its page arrives.
            Get-PimArmActiveRoleAssignmentsViaArg -Stream | ForEach-Object {
                & $addAzRow ([pscustomobject]@{ Id = $_.Id; PrincipalId = $_.PrincipalId; RoleDefinitionId = $_.RoleDefinitionId; RoleDefinitionName = $_.RoleDefinitionName
                                                Scope = $_.Scope; RoleAssignmentId = $_.Id; RoleAssignmentName = $_.Name; PrincipalType = $_.PrincipalType })
            }
            $argDone = $true
            Write-Host ("  [revoke] azure-rbac: {0} role assignment(s) from one Resource Graph query" -f ($rows.Count - $azStart)) -ForegroundColor DarkGray
        } catch {
            Write-Warning ("  [revoke] Resource Graph role-assignment query failed ({0}) -- falling back to the per-subscription read." -f $_.Exception.Message)
            if ($rows.Count -gt $azStart) { $rows.RemoveRange($azStart, $rows.Count - $azStart) }
            $azRows = @()
            $restArm = [bool](Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)
        }
    }
    if ($argDone) { }
    elseif ($restArm) {
        # REST: enumerate active role-assignment-schedule-instances at each
        # subscription scope (ARM has no tenant-wide list). PrincipalNotFound /
        # auth errors per-sub are tolerated so one bad sub doesn't blank the tab.
        try {
            $subs = @(Invoke-PimArm -Path '/subscriptions' -ApiVersion '2020-01-01' -All)
            if ($subs.Count -eq 0) {
                Write-Warning "  [revoke] ARM returned 0 subscriptions for this identity -- Azure RBAC rows will be empty (engine SPN has no subscription scope / no Reader)."
                [void]$surfaceErrors.Add([ordered]@{
                    surface = 'azure-rbac'
                    error   = 'ARM returned 0 subscriptions visible to the engine identity.'
                    hint    = 'Grant the engine SPN at least Reader on the target subscription(s) so Azure-RBAC active assignments can be enumerated.'
                })
            }
            foreach ($s in $subs) {
                $scope = "/subscriptions/$($s.subscriptionId)"
                try {
                    foreach ($ri in @(Invoke-PimArm -Path "$scope/providers/Microsoft.Authorization/roleAssignmentScheduleInstances" -ApiVersion '2020-10-01-preview' -All)) {
                        $p = $ri.properties
                        $rdId = "$($p.roleDefinitionId)"
                        $azRows += [pscustomobject]@{
                            Id                 = "$($ri.id)"
                            PrincipalId        = "$($p.principalId)"
                            RoleDefinitionId   = $rdId
                            RoleDefinitionName = ($rdId -split '/' | Select-Object -Last 1)
                            Scope              = "$($p.scope)"
                        }
                    }
                } catch { Write-Warning ("  [revoke] ARM role-assignment instances for {0} failed: {1}" -f $scope, $_.Exception.Message) }
            }
        } catch {
            $em = "$($_.Exception.Message)"
            Write-Warning "  [revoke] ARM subscriptions enumeration failed: $em. Azure RBAC rows will be empty."
            [void]$surfaceErrors.Add([ordered]@{
                surface = 'azure-rbac'
                error   = $em
                hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'azure-rbac' -ErrorMessage $em)
            })
            $azRows = @()
        }
    } else {
        $em = 'Azure-RBAC reader not available (the ARM REST helper Invoke-PimArm is not loaded).'
        Write-Warning "  [revoke] $em Azure RBAC rows will be empty."
        [void]$surfaceErrors.Add([ordered]@{
            surface = 'azure-rbac'
            error   = $em
            hint    = 'Ensure engine/_shared/PIM-Rest.ps1 is dot-sourced (hosted) so Invoke-PimArm is available.'
        })
    }
    foreach ($a in $azRows) { & $addAzRow $a }
    $azRows = $null

    # ---- PIM-for-Groups active assignments ---------------------------------
    # Graph REFUSES an unfiltered list on assignmentSchedules ('MissingParameters:
    # The required parameters GroupId or PrincipalId is missing') -- both the
    # engine's bulk preload and a naive -All call get BadRequest. The supported
    # shape is one filtered query per group. Two scale guards:
    #   1. Only PIM-convention groups qualify (the lookup cache can contain the
    #      whole tenant when the naming filter is broad; dynamic groups fail
    #      with ResourceTypeNotSupported anyway).
    #   2. Queries go through /v1.0/$batch, 20 per round-trip -- a per-group
    #      sequential loop took >4 minutes on a real tenant.
    $pimGroupRows = New-Object System.Collections.Generic.List[object]   # 100.31: .Add, never += (each += copied the whole array)
    # 🔴 BUG-217 (§33.28): EVERY group that can be a PIM-for-Groups group -- not only the '<prefix>' ones. A group
    # qualifies unless it is a mail-only distribution list (not security-enabled and not a Microsoft 365 group);
    # dynamic groups are dropped just below. Cost stays bounded: one filtered read per group, 20 per $batch
    # round-trip, run by the tick's snapshot job (never on the Manager's request loop). A group that is simply not
    # onboarded to PIM answers with no schedules and is not a failure (Test-PimGroupNotPimOnboardedError).
    $pimGroupsToQuery = @(Select-PimActiveAssignmentsPimGroupCandidates -Groups @($script:PimManager_Groups))
    # A DYNAMIC-membership group cannot carry a PIM-for-Groups assignment (Graph answers
    # ResourceTypeNotSupported), so its request can only fail. The lookup cache now selects groupTypes,
    # which lets the read skip them instead of spending a batch slot to collect a known error.
    $pimDynamicSkipped = @($pimGroupsToQuery | Where-Object { @($_.GroupTypes) -contains 'DynamicMembership' }).Count
    if ($pimDynamicSkipped) { $pimGroupsToQuery = @($pimGroupsToQuery | Where-Object { -not (@($_.GroupTypes) -contains 'DynamicMembership') }) }
    # SNAP-INC (owner 2026-10-20): EVERY group above stays covered (BUG-217) -- an incremental run re-reads the changed and the
    # always-re-read groups and carries the rows of the others forward from the previous complete generation. No context, or a
    # plan that cannot be made = every group is read, as before (and no delta state is stored, so the next run is full too).
    $pimGroupsToRead = $pimGroupsToQuery
    $gdRun = $null; $gdPlan = $null; $gdCarried = $null; $gdText = ''
    $gFailedIds = New-Object System.Collections.Generic.List[string]
    if ($null -ne $GroupDelta -and $pimGroupsToQuery.Count -gt 0) {
        try { $gdRun = Invoke-PimSnapshotGroupIncrementalPlan -Context $GroupDelta -Candidates $pimGroupsToQuery -NowUtc ([datetime]::UtcNow) }
        catch { $gdRun = $null; Write-Warning ("  [revoke] pim-for-groups: the incremental plan failed ({0}) -- every group is read" -f $_.Exception.Message) }
        if ($null -ne $gdRun) {
            $gdPlan = $gdRun.plan
            if ("$($gdPlan.mode)" -eq 'incremental') {
                $gdCarried = $gdRun.carried
                $pimGroupsToRead = @($pimGroupsToQuery | Where-Object { $gdPlan.reread.Contains("$($_.Id)".Trim().ToLowerInvariant()) })
                $gdText = "incremental -- {0} changed + {1} always re-read of {2} groups, {3} carried forward ({4} rows){5}" -f $gdPlan.changed, $gdPlan.always, $pimGroupsToQuery.Count, $gdPlan.carry.Count, $gdPlan.carryRows, $(if ($gdPlan.removed -or $gdPlan.dropped) { "; $($gdPlan.removed) removed in the delta, $($gdPlan.dropped) group(s) dropped" } else { '' })
            } else {
                $gdText = "full read (reason: $($gdPlan.reason))"
            }
            if ($gdRun.deltaError) { $gdText += "; no delta link for the next run ($($gdRun.deltaError))" }
            Write-Host ("  [revoke] pim-for-groups: {0}" -f $gdText) -ForegroundColor DarkGray
        }
    }
    if ($pimGroupsToRead.Count -gt 0 -and (Get-Command Invoke-PimGraphBatchGet -ErrorAction SilentlyContinue)) {
        # REQUIREMENTS 67.1: the SAME one-filtered-query-per-group reads, through the engine's shared batch
        # reader -- which also follows @odata.nextLink (the inline loop below kept only the first page) and
        # re-runs a throttled (429) or 5xx request on its own instead of counting it as a failed group.
        $gFail = 0
        $gFirstErr = $null
        $gRes = Invoke-PimGraphBatchGet -Paths @($pimGroupsToRead | ForEach-Object { "/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($_.Id)'" })
        if ($null -ne $gRes -and $gRes -isnot [System.Collections.IList]) { $gRes = @($gRes) }   # 100.31: one answer can arrive unrolled; the release below assigns by index
        for ($i = 0; $i -lt $pimGroupsToRead.Count; $i++) {
            $gr = $gRes[$i]; $gRes[$i] = $null   # 100.31: released as it is consumed
            if ($gr -and $gr.ok) { foreach ($v in @($gr.items)) { if ($null -ne $v) { $pimGroupRows.Add($v) } }; continue }
            if ($gr -and (Test-PimGroupNotPimOnboardedError -Message "$($gr.error)")) { continue }   # BUG-217: not a PIM group -- nothing to list, not a failure
            $gFail++
            $gFailedIds.Add("$($pimGroupsToRead[$i].Id)")   # SNAP-INC: re-read on the next run
            $errText = if ($gr) { "$($gr.error)" } else { 'no response' }
            if (-not $gFirstErr -and $gr -and ($gr.status -eq 401 -or $gr.status -eq 403 -or $errText -match 'HTTP (401|403)\b')) { $gFirstErr = $errText }
            if ($gFail -le 3) { Write-Warning ("  [revoke] assignmentSchedules for group '{0}' failed: {1}" -f $pimGroupsToRead[$i].DisplayName, $errText) }
        }
        $gRes = $null
        if ($gFail -gt 3) { Write-Warning ("  [revoke] assignmentSchedules failed for {0} group(s) total (first 3 shown)." -f $gFail) }
        if ($pimGroupRows.Count -eq 0 -and $gFail -ge $pimGroupsToRead.Count -and $gFirstErr) {
            [void]$surfaceErrors.Add([ordered]@{
                surface = 'pim-for-groups'
                error   = $gFirstErr
                hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'pim-for-groups' -ErrorMessage $gFirstErr)
            })
        }
        Write-Host ("  [revoke] pim-for-groups: {0} active assignment(s) across {1} PIM group(s) ({2} batch round-trips; {3} dynamic group(s) skipped)" -f $pimGroupRows.Count, $pimGroupsToRead.Count, [Math]::Ceiling($pimGroupsToRead.Count / 20), $pimDynamicSkipped) -ForegroundColor DarkGray
    } elseif ($pimGroupsToRead.Count -gt 0) {
        $gFail = 0
        $gFirstErr = $null
        for ($ofs = 0; $ofs -lt $pimGroupsToRead.Count; $ofs += 20) {
            $slice = @($pimGroupsToRead[$ofs..([Math]::Min($ofs + 19, $pimGroupsToRead.Count - 1))])
            $requests = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt $slice.Count; $i++) {
                [void]$requests.Add(@{
                    id     = "$i"
                    method = 'GET'
                    url    = "/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($slice[$i].Id)'"
                })
            }
            try {
                # REST: Invoke-PimGraph posts the JSON batch with its own app-only token.
                $resp = Invoke-PimGraph -Method POST -Path 'https://graph.microsoft.com/v1.0/$batch' -Body @{ requests = $requests.ToArray() }
                foreach ($br in @($resp.responses)) {
                    if ($br.status -ge 200 -and $br.status -lt 300 -and $br.body -and $br.body.value) {
                        foreach ($v in @($br.body.value)) { $pimGroupRows.Add($v) }
                    } elseif ($br.status -ge 400 -and -not (Test-PimGroupNotPimOnboardedError -Message "$(if ($br.body -and $br.body.error) { "$($br.body.error.code) $($br.body.error.message)" })")) {
                        $gFail++
                        if ("$($br.id)" -match '^\d+$' -and [int]$br.id -lt $slice.Count) { $gFailedIds.Add("$($slice[[int]$br.id].Id)") }   # SNAP-INC: re-read next run
                        $errCode = if ($br.body -and $br.body.error) { $br.body.error.code } else { $br.status }
                        $errMsg  = if ($br.body -and $br.body.error -and $br.body.error.message) { $br.body.error.message } else { "$errCode" }
                        if (-not $gFirstErr -and ($br.status -eq 401 -or $br.status -eq 403)) { $gFirstErr = "HTTP $($br.status) $errCode : $errMsg" }
                        if ($gFail -le 3) { Write-Warning ("  [revoke] assignmentSchedules for group '{0}' failed: {1}" -f $slice[[int]$br.id].DisplayName, $errCode) }
                    }
                }
            } catch {
                $gFail += $slice.Count
                foreach ($sg in $slice) { $gFailedIds.Add("$($sg.Id)") }   # SNAP-INC: re-read next run
                if (-not $gFirstErr) { $gFirstErr = "$($_.Exception.Message)" }
                if ($gFail -le 25) { Write-Warning "  [revoke] `$batch round-trip failed: $($_.Exception.Message)" }
            }
        }
        if ($gFail -gt 3) { Write-Warning ("  [revoke] assignmentSchedules failed for {0} group(s) total (first 3 shown)." -f $gFail) }
        # Only a surface-level error when EVERY queried group failed AND we got
        # nothing back -- a few per-group failures (e.g. dynamic groups) are
        # tolerated and must not mask a partially-successful read.
        if ($pimGroupRows.Count -eq 0 -and $gFail -ge $pimGroupsToRead.Count -and $gFirstErr) {
            [void]$surfaceErrors.Add([ordered]@{
                surface = 'pim-for-groups'
                error   = $gFirstErr
                hint    = (Get-PimActiveAssignmentSurfaceHint -Surface 'pim-for-groups' -ErrorMessage $gFirstErr)
            })
        }
        Write-Host ("  [revoke] pim-for-groups: {0} active assignment(s) across {1} PIM group(s) ({2} batch round-trips)" -f $pimGroupRows.Count, $pimGroupsToRead.Count, [Math]::Ceiling($pimGroupsToRead.Count / 20)) -ForegroundColor DarkGray
    } elseif ($pimGroupsToQuery.Count -eq 0) {
        Write-Warning "  [revoke] no groups in the lookup cache that can carry a PIM-for-Groups assignment. PIM-for-Groups rows will be empty."
    }   # (else: an incremental run with nothing to re-read -- every group's rows are carried forward)
    # Casing-tolerant property read: SDK objects are PascalCase, REST/$batch
    # bodies are camelCase. Returns the first present alias (or '').
    $pf = {
        param($Obj, [string[]]$Names)
        foreach ($n in $Names) { $pr = $Obj.PSObject.Properties[$n]; if ($pr -and $null -ne $pr.Value) { return $pr.Value } }
        return $null
    }
    for ($pgi = 0; $pgi -lt $pimGroupRows.Count; $pgi++) {
        $p = $pimGroupRows[$pgi]; $pimGroupRows[$pgi] = $null   # 100.31: the raw schedule goes once its row exists
        if (-not $p) { continue }
        $principalId = "$(& $pf $p @('PrincipalId','principalId'))"
        $groupId     = "$(& $pf $p @('GroupId','groupId'))"
        $itemId      = "$(& $pf $p @('Id','id'))"
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId $principalId
        # Group display name from cache, fall back to embedded Group.DisplayName.
        $groupLabel = ''
        # Id-keyed lookup (built with the caches) -- the old linear scan was O(rows x groups).
        if ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($groupId)) {
            $groupLabel = [string]$script:PimManager_GroupById[$groupId].DisplayName
        } elseif ($script:PimManager_Groups -and -not $script:PimManager_GroupById) {
            foreach ($g in $script:PimManager_Groups) {
                if ($g -and "$($g.Id)" -eq $groupId) { $groupLabel = [string]$g.DisplayName; break }
            }
        }
        $grp = & $pf $p @('Group','group')
        if (-not $groupLabel -and $grp) { $gdn = & $pf $grp @('DisplayName','displayName'); if ($gdn) { $groupLabel = [string]$gdn } }
        if (-not $groupLabel) { $groupLabel = $groupId }
        $si = & $pf $p @('ScheduleInfo','scheduleInfo')
        $start = $null; $end = $null
        if ($si) {
            $sdt = & $pf $si @('StartDateTime','startDateTime')
            if ($sdt) { try { $start = ([DateTime]$sdt).ToUniversalTime().ToString('o') } catch {} }
            $exp = & $pf $si @('Expiration','expiration')
            if ($exp) { $edt = & $pf $exp @('EndDateTime','endDateTime'); if ($edt) { try { $end = ([DateTime]$edt).ToUniversalTime().ToString('o') } catch {} } }
        }
        $access = "$(& $pf $p @('AccessId','accessId'))"; if (-not $access) { $access = 'member' }
        $just   = "$(& $pf $p @('Justification','justification'))"
        # 95.2l: an owner says WHICH kind -- an eligible owner who activated, or a permanent (no end date) owner assignment.
        $__expT = ''; if ($si) { $__ex = & $pf $si @('Expiration','expiration'); if ($__ex) { $__expT = "$(& $pf $__ex @('Type','type'))" } }
        $__accLbl = Get-PimActiveGroupAccessLabel -AccessId $access -AssignmentType "$(& $pf $p @('AssignmentType','assignmentType'))" -ExpirationType $__expT -End $end
        [void]$rows.Add([ordered]@{
            id               = "pim-for-groups:$itemId"
            type             = 'pim-for-groups'
            principal        = $principalLabel
            principalId      = $principalId
            role             = "$groupLabel ($__accLbl)"
            roleDefinitionId = ''
            scope            = $groupLabel
            directoryScopeId = ''
            groupId          = $groupId
            accessId         = $access
            start            = $start
            end              = $end
            justification    = $just
        })
    }
    $pimGroupRows.Clear()
    # SNAP-INC: the rows of the groups that did not change, carried forward from the previous complete generation -- with the
    # group's CURRENT name (the lookup cache was just read). NOT when the group read itself failed as a surface: that run is
    # stored as the failed read it is (and no delta state is written, so the next run reads every group).
    $pfgFailed = $false
    foreach ($se in $surfaceErrors) { if ("$($se.surface)" -eq 'pim-for-groups') { $pfgFailed = $true } }
    if ($null -ne $gdCarried) {
        if (-not $pfgFailed) {
            foreach ($cr in $gdCarried) {
                if ($null -eq $cr) { continue }
                $cgid = "$($cr['groupId'])"
                if ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($cgid) -and "$($script:PimManager_GroupById[$cgid].DisplayName)") {
                    $cgl = [string]$script:PimManager_GroupById[$cgid].DisplayName
                    $cacc = "$($cr['accessId'])"; if (-not $cacc) { $cacc = 'member' }
                    # 95.2l: a carried row keeps the owner kind it was stored with (the raw schedule is not carried)
                    if ("$($cr['role'])" -match '\((eligible owner, activated|permanent owner)\)$') { $cacc = $Matches[1] }
                    $cr['role'] = "$cgl ($cacc)"; $cr['scope'] = $cgl
                }
                [void]$rows.Add($cr)
            }
        }
        $gdCarried.Clear(); $gdCarried = $null
    }

    # ---- BUG-98: second pass -- resolve every principal that the filtered caches missed ----
    # Done ONCE here rather than per surface: all three row builders have run, so the distinct
    # id set is complete and ~700 rows collapse into a single /directoryObjects/getByIds call.
    # Every row also gains principalKind so the GUI can tell a person from a group or an app on
    # a screen whose whole job is deciding whose access to revoke.
    try {
        # 100.31: one pass over the rows into a set (the pipeline + Select-Object -Unique was O(n^2) on ~20k rows).
        $unresolvedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        $unresolvedList = New-Object System.Collections.Generic.List[string]
        foreach ($row in $rows) {
            $rpid = [string]$row.principalId
            if ($rpid -and ("$($row.principal)" -eq $rpid -or -not $row.principal) -and $unresolvedSet.Add($rpid)) { $unresolvedList.Add($rpid) }
        }
        $unresolved = $unresolvedList.ToArray()
        $unresolvedSet = $null; $unresolvedList = $null
        if ($unresolved.Count -gt 0) {
            Write-Host ("  [revoke] resolving {0} principal id(s) the name caches did not cover ..." -f $unresolved.Count) -ForegroundColor DarkGray
            Resolve-PimManagerPrincipalIdBatch -Ids $unresolved
        }
        foreach ($row in $rows) {
            if (-not $row.principalId) { continue }
            if (-not $row.principal -or "$($row.principal)" -eq "$($row.principalId)") {
                $row.principal = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$row.principalId)
            }
            # SNAP-INC: a carried row keeps the kind it was stored with when this run has no answer for it (users are resolved
            # only for the rows that need a name, so an unchanged user row would otherwise lose its 'user' chip)
            $pk = Get-PimManagerPrincipalKind -PrincipalId ([string]$row.principalId)
            if ($pk -or -not $row.Contains('principalKind')) { $row['principalKind'] = $pk }
        }
    } catch {
        Write-Warning "  [revoke] principal second-pass resolve failed: $($_.Exception.Message)"
    }

    $sw.Stop()
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    $byType = @{ 'entra-role' = 0; 'azure-rbac' = 0; 'pim-for-groups' = 0 }
    foreach ($row in $rows) { $t = "$($row.type)"; if ($byType.ContainsKey($t)) { $byType[$t]++ } }   # 100.31: one pass, no pipeline copies
    $counts = [ordered]@{
        total           = $rows.Count
        'entra-role'    = $byType['entra-role']
        'azure-rbac'    = $byType['azure-rbac']
        'pim-for-groups' = $byType['pim-for-groups']
    }
    Write-Host ("  [revoke] active-assignments loaded: {0} total ({1}e + {2}a + {3}g) in {4}s" -f $counts.total, $counts['entra-role'], $counts['azure-rbac'], $counts['pim-for-groups'], $elapsed) -ForegroundColor DarkGray

    $errArr = $surfaceErrors.ToArray()
    if ($errArr.Count -gt 0) {
        Write-Warning ("  [revoke] {0} surface(s) could NOT be read: {1}" -f $errArr.Count, (($errArr | ForEach-Object { $_.surface }) -join ', '))
    }
    # A read is FULLY-FAILED (not "empty") when nothing came back AND at least one
    # surface raised an auth/permission/transport error. The endpoint flags that
    # so the GUI shows an actionable error instead of "Cache may be empty".
    $allFailedEmpty = ($rows.Count -eq 0 -and $errArr.Count -gt 0)

    $loadedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $payload = [ordered]@{
        ok            = (-not $allFailedEmpty)
        rows          = $rows.ToArray()
        counts        = $counts
        surfaceErrors = $errArr
        partial       = ($rows.Count -gt 0 -and $errArr.Count -gt 0)
        loadedUtc     = $loadedUtc
        refreshedUtc  = $loadedUtc
        cacheHit      = $false
        elapsedSec    = $elapsed
        durationMs    = [int64][math]::Round($sw.Elapsed.TotalMilliseconds, 0)
    }
    # SNAP-INC: how the group part was read, and the delta state the JOB stores once the rows are saved (never stored here).
    # No state when the group read failed as a surface: the next run then reads every group.
    if ($null -ne $gdPlan) {
        $gdState = $null
        if (-not $pfgFailed) {
            $gdState = New-PimSnapshotGroupDeltaState -Plan $gdPlan -PreviousState $gdRun.state -NowUtc $gdRun.nowUtc -DeltaLink "$($gdRun.deltaLink)" -PimGroupRows ([long]$counts['pim-for-groups']) -FailedGroupIds $gFailedIds.ToArray()
        }
        $payload['groupDelta'] = [ordered]@{ mode = "$($gdPlan.mode)"; reason = "$($gdPlan.reason)"; text = $gdText; state = $gdState }
    }
    if ($allFailedEmpty) {
        $payload.error = "Active PIM assignments could not be read from any surface. " + (($errArr | ForEach-Object {
            $h = if ($_.hint) { " ($($_.hint))" } else { '' }
            "[$($_.surface)] $($_.error)$h"
        }) -join '  |  ')
    }
    return $payload
}

# ===========================================================================
# SNAP-INC (owner 2026-10-20) -- THE PIM-FOR-GROUPS READ IS INCREMENTAL
# ===========================================================================
# Measured live: one assignmentSchedules read per group for EVERY group (BUG-217) is 125,004 groups / 514,472 rows / 15.3 h /
# 132,504 Graph 429s per run at a school tenant, back to back every 2 h. Owner decision: keep every group, but re-read only
# the groups that CHANGED since the last run (Graph groups delta, members@delta), carry the rows of the others forward from
# the previous complete generation (pim.ActiveAssignmentRows), and read every group in full once a week.
#   * always re-read, every run: groups whose rows a membership delta cannot announce -- any row with an end date, a start
#     still ahead, an owner row (Get-PimSqlActiveAssignmentGroupSummary) -- role-assignable groups, the groups in the
#     engine's managed list (defined in PIM), and the groups whose read failed last time
#   * FULL read when: no stored state / no delta link / the previous snapshot was not complete or is not the stored one /
#     the last full read is Get-PimSnapshotGroupFullReadDays old / the delta read fails (410 = resync) / the previous rows
#     cannot be read or do not add up. A full read takes its delta link BEFORE the group reads (the stored link advanced to
#     now, or a fresh round when there is none / it is refused), so a change made during the long read is caught next time.
#   * state in pim.Settings 'ActiveAssignmentsGroupDelta', written by the job ONLY after the rows were stored (a failed run
#     never advances the delta link).
function Get-PimSnapshotGroupDeltaSettingName { return 'ActiveAssignmentsGroupDelta' }
function Get-PimSnapshotGroupFullReadDays     { return 7 }        # a full read of every group at least this often
function Get-PimSnapshotGroupRetryMax         { return 2000 }     # failed group reads kept for the next run; more = not complete
function Get-PimSnapshotGroupDeltaMaxPages    { return 200000 }   # a delta round that does not end is a failed read
function Get-PimSnapshotGroupDeltaPath        { return '/groups/delta?$select=id,members' }

function ConvertFrom-PimGroupDeltaPage {
    # SNAP-INC. PURE. One page of GET /groups/delta -> { changed; removed; nextLink; deltaLink } (group ids lower-case). A group
    # carrying '@removed' is deleted; any other group in the page changed (members@delta, created, or a selected property).
    param([AllowNull()][object]$Page)
    $changed = New-Object System.Collections.Generic.List[string]
    $removed = New-Object System.Collections.Generic.List[string]
    $next = ''; $delta = ''
    if ($null -ne $Page -and $Page.PSObject) {
        $vp = $Page.PSObject.Properties['value']
        if ($vp -and $null -ne $vp.Value) {
            foreach ($g in @($vp.Value)) {
                if ($null -eq $g) { continue }
                $id = "$($g.id)".Trim().ToLowerInvariant(); if (-not $id) { continue }
                if ($g.PSObject.Properties['@removed']) { $removed.Add($id) } else { $changed.Add($id) }
            }
        }
        $nl = $Page.PSObject.Properties['@odata.nextLink'];  if ($nl -and "$($nl.Value)".Trim()) { $next = "$($nl.Value)".Trim() }
        $dl = $Page.PSObject.Properties['@odata.deltaLink']; if ($dl -and "$($dl.Value)".Trim()) { $delta = "$($dl.Value)".Trim() }
    }
    return [pscustomobject]@{ changed = $changed.ToArray(); removed = $removed.ToArray(); nextLink = $next; deltaLink = $delta }
}

function Read-PimGroupDeltaRound {
    <#
      SNAP-INC. Follow one delta round from -Link (the initial '/groups/delta?...' or a stored deltaLink) through every
      @odata.nextLink to its @odata.deltaLink, one page at a time. -CollectIds keeps the changed / removed group ids (an
      initial round only needs the link). NEVER throws: { ok; error; resync; changed; removed; deltaLink; pages }.
      resync = Graph refused the link (HTTP 410 / resync required) -- the caller reads every group.
      -Graph: param($path) -> one page (default Invoke-PimGraph -Path).
    #>
    param([Parameter(Mandatory)][string]$Link, [scriptblock]$Graph = $null, [switch]$CollectIds)
    if (-not $Graph) { $Graph = { param($p) Invoke-PimGraph -Path $p } }
    $changed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $removed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $next = $Link; $pages = 0; $max = Get-PimSnapshotGroupDeltaMaxPages
    try {
        while ($next) {
            if ($pages -ge $max) { throw "the delta round did not end within $max pages" }
            $resp = & $Graph $next
            $pages++
            $pg = ConvertFrom-PimGroupDeltaPage -Page $resp
            $resp = $null
            if ($CollectIds) { foreach ($i in $pg.changed) { [void]$changed.Add($i) }; foreach ($i in $pg.removed) { [void]$removed.Add($i) } }
            if ($pg.deltaLink) {
                return [pscustomobject]@{ ok = $true; error = ''; resync = $false; changed = $changed; removed = $removed; deltaLink = $pg.deltaLink; pages = $pages }
            }
            if (-not $pg.nextLink) { throw 'the delta round ended without a deltaLink' }
            $next = $pg.nextLink
        }
        throw 'the delta round had no link to start from'
    } catch {
        $em = "$($_.Exception.Message)"
        return [pscustomobject]@{ ok = $false; error = $em; resync = [bool]($em -match '(?i)HTTP 410\b|resyncRequired|syncStateNotFound|SyncStateInvalid|resync')
            changed = $changed; removed = $removed; deltaLink = ''; pages = $pages }
    }
}

function ConvertTo-PimSnapshotGroupUtc {
    # SNAP-INC. PURE. A stored stamp (ISO text, or the [datetime] pwsh 7's ConvertFrom-Json makes of it) -> UTC [datetime], or $null.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function ConvertFrom-PimSnapshotGroupDeltaState {
    <#
      SNAP-INC. PURE. The stored pim.Settings 'ActiveAssignmentsGroupDelta' (raw JSON text, or an already parsed object) -> the
      normalised state { deltaLink; lastFullUtc; lastRunUtc; mode; snapshotId; pimGroupRows; complete; retryGroupIds }, $null
      when nothing is stored, or { unreadable = $true } for a value that is not the state's shape.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $o = $Value
    if ($Value -is [string]) {
        if (-not $Value.Trim()) { return $null }
        try { $o = $Value | ConvertFrom-Json } catch { return [pscustomobject]@{ unreadable = $true } }
    }
    if ($null -eq $o -or -not $o.PSObject -or -not $o.PSObject.Properties['deltaLink']) { return [pscustomobject]@{ unreadable = $true } }
    $sid = [long]0; [void][long]::TryParse("$($o.snapshotId)", [ref]$sid)
    $pgr = [long]-1; if (-not [long]::TryParse("$($o.pimGroupRows)", [ref]$pgr)) { $pgr = -1 }
    $retry = @(); if ($o.PSObject.Properties['retryGroupIds'] -and $null -ne $o.retryGroupIds) { $retry = @(@($o.retryGroupIds) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ }) }
    return [pscustomobject]@{
        unreadable    = $false
        deltaLink     = "$($o.deltaLink)".Trim()
        lastFullUtc   = (ConvertTo-PimSnapshotGroupUtc -Value $o.lastFullUtc)
        lastRunUtc    = (ConvertTo-PimSnapshotGroupUtc -Value $o.lastRunUtc)
        mode          = "$($o.mode)"
        snapshotId    = $sid
        pimGroupRows  = $pgr
        complete      = ($o.PSObject.Properties['complete'] -and [bool]$o.complete)
        retryGroupIds = $retry
    }
}

function Get-PimSnapshotGroupFullReason {
    # SNAP-INC. PURE. Why THIS run must read every group ('' = an incremental run may be tried). -State: normalised
    # (ConvertFrom-PimSnapshotGroupDeltaState). -CurrentSnapshotId: the generation the stored header names (0 = none).
    param([AllowNull()][object]$State, [long]$CurrentSnapshotId = 0, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $State) { return 'first run (no stored delta state)' }
    if ([bool]$State.unreadable) { return 'the stored delta state could not be read' }
    if (-not "$($State.deltaLink)".Trim()) { return 'no stored delta link' }
    if (-not [bool]$State.complete) { return 'the previous snapshot was not complete' }
    if ($CurrentSnapshotId -le 0 -or [long]$State.snapshotId -ne $CurrentSnapshotId) { return 'the stored snapshot is not the one the delta state belongs to' }
    if ($null -eq $State.lastFullUtc) { return 'no full read recorded' }
    $now = $NowUtc.ToUniversalTime()
    if (($now - $State.lastFullUtc).TotalDays -ge (Get-PimSnapshotGroupFullReadDays)) {
        return ("weekly full read (last full read {0})" -f $State.lastFullUtc.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
    }
    return ''
}

function Get-PimSnapshotGroupReadPlan {
    <#
      SNAP-INC. PURE. THE DECISION. Which groups this run reads and which carry their rows forward:
        { mode = 'full' | 'incremental'; reason; reread (HashSet of group ids, $null = every group); carry (HashSet); carryRows;
          changed; always; removed; dropped; candidates }
      -State / -CurrentSnapshotId / -NowUtc   see Get-PimSnapshotGroupFullReason
      -Delta        Read-PimGroupDeltaRound -CollectIds from the stored deltaLink ($null = not read)
      -Summary      Get-PimSqlActiveAssignmentGroupSummary of the current generation ($null = not read; -SummaryError says why)
      -CandidateIds the groups a full read would read (BUG-217 candidates, dynamic groups already out)
      -AlwaysIds    groups re-read every run on top of the summary's (role-assignable, managed in PIM)
      Fail-safe: anything that does not add up is a FULL read with its reason, never a partial snapshot.
    #>
    param([AllowNull()][object]$State, [long]$CurrentSnapshotId = 0, [datetime]$NowUtc = [datetime]::UtcNow,
          [AllowNull()][object]$Delta = $null, [AllowNull()][object]$Summary = $null, [string]$SummaryError = '',
          [string[]]$CandidateIds = @(), [string[]]$AlwaysIds = @())
    $cand = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($c in @($CandidateIds)) { $s = "$c".Trim().ToLowerInvariant(); if ($s) { [void]$cand.Add($s) } }
    $full = { param($why) [pscustomobject]@{ mode = 'full'; reason = "$why"; reread = $null; carry = $null; carryRows = [long]0; changed = 0; always = 0; removed = 0; dropped = 0; candidates = $cand.Count } }
    $why = Get-PimSnapshotGroupFullReason -State $State -CurrentSnapshotId $CurrentSnapshotId -NowUtc $NowUtc
    if ($why) { return (& $full $why) }
    if ($null -eq $Delta) { return (& $full 'the group delta was not read') }
    if (-not [bool]$Delta.ok) {
        if ([bool]$Delta.resync) { return (& $full "the delta link was refused (resync): $($Delta.error)") }
        return (& $full "the group delta read failed: $($Delta.error)")
    }
    if ($null -eq $Summary) { return (& $full "the previous rows could not be read: $SummaryError") }
    if ([long]$Summary.noGroup -gt 0) { return (& $full "$($Summary.noGroup) previous row(s) have no group id") }
    if ([long]$Summary.total -ne [long]$State.pimGroupRows) { return (& $full ("the previous rows do not add up ({0} stored, {1} expected)" -f [long]$Summary.total, [long]$State.pimGroupRows)) }
    $removed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($r in @($Delta.removed)) { $s = "$r".Trim().ToLowerInvariant(); if ($s) { [void]$removed.Add($s) } }
    $reread = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $nChanged = 0; $nAlways = 0
    foreach ($id in @($Delta.changed)) { $s = "$id".Trim().ToLowerInvariant(); if ($s -and $cand.Contains($s) -and -not $removed.Contains($s) -and $reread.Add($s)) { $nChanged++ } }
    foreach ($g in @($Summary.groups)) { if ($null -eq $g -or -not [bool]$g.alwaysRead) { continue }; $s = "$($g.groupId)".Trim().ToLowerInvariant(); if ($s -and $cand.Contains($s) -and -not $removed.Contains($s) -and $reread.Add($s)) { $nAlways++ } }
    foreach ($id in (@($AlwaysIds) + @($State.retryGroupIds))) { $s = "$id".Trim().ToLowerInvariant(); if ($s -and $cand.Contains($s) -and -not $removed.Contains($s) -and $reread.Add($s)) { $nAlways++ } }
    $carry = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $carryRows = [long]0; $dropped = 0
    foreach ($g in @($Summary.groups)) {
        if ($null -eq $g) { continue }
        $s = "$($g.groupId)".Trim().ToLowerInvariant()
        if (-not $cand.Contains($s) -or $removed.Contains($s)) { $dropped++; continue }   # deleted, or no longer a group a full read would read
        if ($reread.Contains($s)) { continue }
        if ($carry.Add($s)) { $carryRows += [long]$g.rows }
    }
    return [pscustomobject]@{ mode = 'incremental'; reason = ''; reread = $reread; carry = $carry; carryRows = $carryRows
        changed = $nChanged; always = $nAlways; removed = $removed.Count; dropped = $dropped; candidates = $cand.Count }
}

function ConvertFrom-PimActiveAssignmentsStoredRow {
    # SNAP-INC. PURE. One stored row (parsed RowJson) -> the ordered row the snapshot builds, field for field. pwsh 7's
    # ConvertFrom-Json turns the ISO start / end into [datetime]; they go back to the round-trip text the builder wrote.
    param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return $null }
    $o = [ordered]@{}
    foreach ($p in $Row.PSObject.Properties) {
        $v = $p.Value
        if ($v -is [datetime]) {
            $d = if ($v.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($v, [DateTimeKind]::Utc) } else { $v.ToUniversalTime() }
            $v = $d.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
        }
        $o[$p.Name] = $v
    }
    return $o
}

function New-PimSnapshotGroupDeltaContext {
    <#
      SNAP-INC. What the incremental read needs from the store, as a context the snapshot takes (-GroupDelta), or $null when
      this process cannot run it (no SQL store, the row table is not there, a helper is not loaded) -- the read is then the
      full read it always was. Nothing is read here: every read happens in Invoke-PimSnapshotGroupIncrementalPlan.
      The scriptblocks are the test seams.
    #>
    param([string]$ConnectionString = '')
    foreach ($fn in 'Get-PimSqlSettingRaw', 'Set-PimSqlSetting', 'Get-PimSqlActiveAssignmentsCurrentSnapshotId', 'Get-PimSqlActiveAssignmentGroupSummary', 'Read-PimSqlActiveAssignmentGroupRows', 'Confirm-PimSqlActiveAssignmentRowsReady', 'Invoke-PimGraph') {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { return $null }
    }
    if (-not "$ConnectionString".Trim() -and (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) { $ConnectionString = "$(Get-PimTenantCacheStoreCs)" }
    if (-not "$ConnectionString".Trim()) { return $null }
    $ddl = $null; try { $ddl = Confirm-PimSqlActiveAssignmentRowsReady -ConnectionString $ConnectionString } catch { $ddl = $null }
    if ($null -eq $ddl -or -not [bool]$ddl.ok) { return $null }   # carried rows come from the table form only
    return @{
        cs                = $ConnectionString
        settingName       = (Get-PimSnapshotGroupDeltaSettingName)
        ReadState         = { param($ctx) Get-PimSqlSettingRaw -ConnectionString $ctx.cs -Name $ctx.settingName }
        WriteState        = { param($ctx, $json) Set-PimSqlSetting -ConnectionString $ctx.cs -Name $ctx.settingName -ValueJson $json }
        CurrentSnapshotId = { param($ctx) Get-PimSqlActiveAssignmentsCurrentSnapshotId -ConnectionString $ctx.cs }
        ReadSummary       = { param($ctx, $sid, $now) Get-PimSqlActiveAssignmentGroupSummary -ConnectionString $ctx.cs -SnapshotId $sid -NowUtc $now }
        ReadRows          = { param($ctx, $sid, $groupIds, $onChunk) Read-PimSqlActiveAssignmentGroupRows -ConnectionString $ctx.cs -SnapshotId $sid -GroupIds $groupIds -OnChunk $onChunk }
        # the groups defined in PIM: the group part of the engine's managed list ('g|<principal>|<group>|<access>'); none stored = none
        ManagedGroupIds   = { param($ctx)
            if (-not (Get-Command Get-PimSqlManagedLiveIdentitySet -ErrorAction SilentlyContinue)) { return @() }
            $set = Get-PimSqlManagedLiveIdentitySet -ConnectionString $ctx.cs
            if ($null -eq $set) { return @() }
            @(foreach ($k in $set) { $p = "$k".Split('|'); if ($p.Count -ge 4 -and $p[0] -eq 'g' -and $p[2]) { $p[2] } }) }
        Graph             = { param($p) Invoke-PimGraph -Path $p }
    }
}

function Invoke-PimSnapshotGroupIncrementalPlan {
    <#
      SNAP-INC. Run the decision for one snapshot: read the stored state + the generation it belongs to, then (when an
      incremental run is allowed) the delta since the stored deltaLink, the previous generation's per-group summary and the
      always-re-read groups, and decide (Get-PimSnapshotGroupReadPlan). An incremental plan reads its carried rows here, and a
      carry that fails or does not add up turns the plan into a FULL read. A full read takes its delta link HERE, before any
      group is read: the stored link advanced to now, else a fresh round from Get-PimSnapshotGroupDeltaPath. Returns { plan; state (the stored one, normalised); deltaLink; deltaError; carried (rows); nowUtc }.
      -Context: New-PimSnapshotGroupDeltaContext (or a test's). -Candidates: the group objects a full read would read.
    #>
    param([Parameter(Mandatory)][hashtable]$Context, [object[]]$Candidates = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $candIds = @(foreach ($g in @($Candidates)) { if ($g -and "$($g.Id)".Trim()) { "$($g.Id)".Trim().ToLowerInvariant() } })
    $state = $null
    try { $state = ConvertFrom-PimSnapshotGroupDeltaState -Value (& $Context.ReadState $Context) } catch { $state = [pscustomobject]@{ unreadable = $true } }
    $curId = [long]0
    try { $v = & $Context.CurrentSnapshotId $Context; if ($null -ne $v) { $curId = [long]$v } } catch { $curId = 0 }
    $delta = $null; $summary = $null; $sumErr = ''; $always = @()
    if (-not (Get-PimSnapshotGroupFullReason -State $state -CurrentSnapshotId $curId -NowUtc $now)) {
        $delta = Read-PimGroupDeltaRound -Link "$($state.deltaLink)" -Graph $Context.Graph -CollectIds
        if ($delta.ok) {
            try {
                $summary = & $Context.ReadSummary $Context $curId $now
                $always = @(@($Candidates | Where-Object { $_ -and $_.PSObject.Properties['IsAssignableToRole'] -and $_.IsAssignableToRole -eq $true } | ForEach-Object { "$($_.Id)" }) + @(& $Context.ManagedGroupIds $Context))
            } catch { $summary = $null; $sumErr = "$($_.Exception.Message)" }
        }
    } elseif ($null -ne $state -and -not [bool]$state.unreadable -and "$($state.deltaLink)".Trim()) {
        # a full read (weekly, or the previous snapshot not usable) with a stored link: advancing THAT link to now is far
        # cheaper than a fresh round over every group and its members, and positions the next run just the same
        $delta = Read-PimGroupDeltaRound -Link "$($state.deltaLink)" -Graph $Context.Graph
    }
    $plan = Get-PimSnapshotGroupReadPlan -State $state -CurrentSnapshotId $curId -NowUtc $now -Delta $delta -Summary $summary -SummaryError $sumErr -CandidateIds $candIds -AlwaysIds @($always)
    $carried = New-Object System.Collections.Generic.List[object]
    if ($plan.mode -eq 'incremental' -and $plan.carry.Count -gt 0) {
        $onChunk = {
            param([string[]]$chunk)
            $parsed = ConvertFrom-Json -InputObject ('[' + ($chunk -join ',') + ']')   # assigned first: PS 5.1 emits the array as ONE object
            foreach ($x in @($parsed)) { if ($null -ne $x) { $carried.Add((ConvertFrom-PimActiveAssignmentsStoredRow -Row $x)) } }
        }   # (no GetNewClosure: a closure's module scope would not see the script-scope helpers; $carried resolves up the call stack)
        try {
            [void](& $Context.ReadRows $Context $curId $plan.carry $onChunk)
            if ([long]$carried.Count -ne [long]$plan.carryRows) { throw ("{0} of {1} rows came back" -f $carried.Count, $plan.carryRows) }
        } catch {
            $carried.Clear()
            $plan = [pscustomobject]@{ mode = 'full'; reason = "the previous rows could not be carried forward: $($_.Exception.Message)"; reread = $null; carry = $null; carryRows = [long]0
                changed = 0; always = 0; removed = 0; dropped = 0; candidates = $plan.candidates }
        }
    }
    $deltaLink = ''; $deltaError = ''
    if ($null -ne $delta -and [bool]$delta.ok) { $deltaLink = "$($delta.deltaLink)" }   # the round already runs up to now -- before any group read
    else {
        # a FULL read starts a fresh round to its deltaLink BEFORE reading the groups: what changes during the read is caught next time
        $round = Read-PimGroupDeltaRound -Link (Get-PimSnapshotGroupDeltaPath) -Graph $Context.Graph
        if ($round.ok) { $deltaLink = "$($round.deltaLink)" } else { $deltaError = "$($round.error)" }
    }
    return [pscustomobject]@{ plan = $plan; state = $state; deltaLink = $deltaLink; deltaError = $deltaError; carried = $carried; nowUtc = $now }
}

function New-PimSnapshotGroupDeltaState {
    <#
      SNAP-INC. PURE. The pim.Settings 'ActiveAssignmentsGroupDelta' value after a run (the job stamps snapshotId once the rows are
      stored). complete = the next run may be incremental: a delta link is held and the failed group reads fit in the retry list.
    #>
    param([Parameter(Mandatory)][object]$Plan, [AllowNull()][object]$PreviousState = $null, [datetime]$NowUtc = [datetime]::UtcNow,
          [string]$DeltaLink = '', [long]$PimGroupRows = 0, [string[]]$FailedGroupIds = @())
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $now = $NowUtc.ToUniversalTime()
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $failed = @(foreach ($f in @($FailedGroupIds)) { $s = "$f".Trim().ToLowerInvariant(); if ($s -and $seen.Add($s)) { $s } })
    $complete = ("$DeltaLink".Trim() -ne '' -and $failed.Count -le (Get-PimSnapshotGroupRetryMax))
    $lastFull = $null
    if ("$($Plan.mode)" -eq 'full') { $lastFull = $now }
    elseif ($null -ne $PreviousState -and $null -ne $PreviousState.lastFullUtc) { $lastFull = $PreviousState.lastFullUtc }
    $retry = [string[]]@(); if ($complete -and $failed.Count -gt 0) { $retry = [string[]]$failed }   # a variable, not $(...): that would unroll a 0/1-item list
    return [ordered]@{
        version       = 1
        mode          = "$($Plan.mode)"
        reason        = "$($Plan.reason)"
        deltaLink     = "$DeltaLink".Trim()
        lastFullUtc   = $(if ($null -ne $lastFull) { $lastFull.ToString('yyyy-MM-ddTHH:mm:ssZ', $inv) } else { '' })
        lastRunUtc    = $now.ToString('yyyy-MM-ddTHH:mm:ssZ', $inv)
        snapshotId    = [long]0
        pimGroupRows  = [long]$PimGroupRows
        complete      = [bool]$complete
        retryGroupIds = $retry
    }
}

function Save-PimSnapshotGroupDeltaState {
    # SNAP-INC. Write the state for the generation that was just stored (-SnapshotId). Called by the job ONLY after the rows
    # were saved. Never throws: { ok; error }.
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][System.Collections.IDictionary]$State, [Parameter(Mandatory)][long]$SnapshotId)
    try {
        $State['snapshotId'] = $SnapshotId
        $json = ConvertTo-Json -InputObject $State -Depth 6 -Compress
        [void](& $Context.WriteState $Context $json)
        return [pscustomobject]@{ ok = $true; error = '' }
    } catch { return [pscustomobject]@{ ok = $false; error = "$($_.Exception.Message)" } }
}

# ===========================================================================
# THE SCHEDULER JOB -- 'active-assignments-snapshot'
# ===========================================================================
function Invoke-PimActiveAssignmentsSnapshotJob {
    <#
      Run the live read once and persist it as pim.TenantCache kind 'active-assignments':
        { refreshedUtc; rows; counts; surfaceErrors; partial; ok; error; durationMs; source; correlationId }
      Returns the scheduler's handler result shape ({ ran; whatIf; detail; ... }).

      🔒 -WhatIf reads NOTHING and writes NOTHING -- not even a token mint: the whole value of a dry run on this
         job is that it costs nothing.
      🔒 No SQL store -> REFUSED (unimplemented), never a memory-only write. A snapshot kept in the scheduler's
         own process is one the Manager -- another process, usually another container -- can never read, so
         reporting it as written would be the BUG-134 conflation ("a step that cannot work reports success").
      🔴 A read where EVERY surface failed is STILL WRITTEN (the Revoke tab must show the actionable permission
         hint rather than a stale "all good"), and the job then THROWS so the run is recorded failed and the
         engine-failure alert can fire. A PARTIAL read is written and reported ran=$true with the failed surfaces
         named in the detail.
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $type = $script:PimActiveAssignmentsSnapshotJobType
    $kind = $script:PimActiveAssignmentsSnapshotCacheKind
    if ($WhatIf) {
        return [pscustomobject]@{ ran = $false; whatIf = $true
            detail = "whatif:$type -- would read Entra-role / Azure-RBAC / PIM-for-Groups active assignments and write pim.TenantCache/$kind (nothing read, nothing written)" }
    }
    if (-not (Get-Command Set-PimTenantCacheEntry -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = $false
            detail = "unimplemented:$type (tools/pim-manager/_tenantSync.ps1 is not loaded on this worker -- no tenant-cache store to write to)" }
    }
    if (-not (Get-PimTenantCacheStoreCs)) {
        return [pscustomobject]@{ ran = $false; unimplemented = $true; whatIf = $false
            detail = "unimplemented:$type -- no SQL store in this process, so the snapshot could only live in memory where the Manager can never read it (this is 'cannot answer', not 'nothing to do')" }
    }

    # SNAP-INC (owner 2026-10-20): the PIM-for-Groups part is read INCREMENTALLY when this store can carry rows forward (the
    # context reads nothing itself). Passed only to a snapshot that takes it -- a stand-in without -GroupDelta still runs.
    $gdCtx = $null
    try { $gdCtx = New-PimSnapshotGroupDeltaContext } catch { $gdCtx = $null }
    # Named switches, never a hashtable splat: @{ Fresh = $true } reaches a wrapper as '-Fresh:', $true and the bare $true then
    # binds BY POSITION to -GroupDelta (VM gate 2026-10-20, Test-PimActiveAssignmentsSnapshot B6).
    $useGd = $false
    if ($null -ne $gdCtx) { $sc = Get-Command Invoke-PimActiveAssignmentsSnapshot -ErrorAction SilentlyContinue; $useGd = [bool]($sc -and $sc.Parameters.ContainsKey('GroupDelta')) }
    $snap = if ($useGd) { Invoke-PimActiveAssignmentsSnapshot -Fresh -GroupDelta $gdCtx } else { Invoke-PimActiveAssignmentsSnapshot -Fresh }
    $errs = @($snap.surfaceErrors)
    $entry = [ordered]@{
        refreshedUtc  = "$($snap.refreshedUtc)"
        rows          = $snap.rows   # 100.31: the same array, not an @() copy of it
        counts        = $snap.counts
        surfaceErrors = $errs
        partial       = [bool]$snap.partial
        ok            = [bool]$snap.ok
        error         = $(if ($snap.Contains('error')) { "$($snap.error)" } else { '' })
        durationMs    = [int64]$snap.durationMs
        source        = 'scheduler'
        correlationId = "$($global:PIM_JobCorrelationId)"
    }
    # 100.68: the Dashboard's "Activations handled" ledger -- every time-bound active assignment seen, recorded once
    # (insert-only, engine/_shared/PIM-ImpactCounters.ps1). Never fails the snapshot: a ledger error is said in the detail.
    $ledTxt = ''
    if (Get-Command Update-PimImpactActivationLedger -ErrorAction SilentlyContinue) {
        $led = Update-PimImpactActivationLedger -ConnectionString (Get-PimTenantCacheStoreCs) -Rows $snap.rows
        $ledTxt = if ($led.ok) { "; activation ledger +$($led.added)" } else { "; activation ledger NOT updated ($($led.error))" }
    }
    # REQ 100.114 (2) / 100.110: THE ROWS GO INTO A TABLE, IN BATCHES (pim.ActiveAssignmentRows); pim.TenantCache keeps the
    # small header that names the generation. The one-row write of the whole snapshot (22 MB at 38,000 assignments) is
    # what timed out. A failed batch write THROWS from here: the run is recorded failed and the previous complete
    # snapshot stays in place and readable. Only a store that cannot hold the table at all (.stored = $false) still gets
    # the one-document form below.
    $where = ''; $formTxt = ''
    $tbl = Save-PimActiveAssignmentsSnapshotRows -Entry $entry
    if ($tbl.stored) {
        $entry['rows'] = $null; $snap['rows'] = $null
        $where = "$($tbl.where)"
        $formTxt = "; {0} row(s) in {1} batch(es), {2}s{3}" -f $tbl.rows, $tbl.batches, $tbl.seconds, $(if ($tbl.retries) { ", $($tbl.retries) batch retr$(if ($tbl.retries -eq 1) { 'y' } else { 'ies' })" } else { '' })
        # §33.0 round 2: the MANAGED marks of the new generation, here (not only when the Manager's page reads it)
        $mkR = Update-PimActiveAssignmentsSnapshotMarks -SnapshotId ([long]$tbl.snapshotId)
        if ($mkR.ok -and $mkR.updated) { $formTxt += "; managed marks computed ($($mkR.changed) row(s) marked)" }
        elseif (-not $mkR.ok) { $formTxt += "; managed marks NOT computed ($($mkR.reason))" }
    } else {
        # 100.31 SNAPSHOT-OOM: ONE compact string written row by row, not a `-Depth 12` serialisation of the whole document
        # (which built a second, dictionary-shaped copy of every row before it wrote a character). The rows are released
        # before the SQL write, so the write holds the string and nothing else.
        $json = ConvertTo-PimActiveAssignmentsSnapshotJson -Entry $entry
        $entry['rows'] = $null; $snap['rows'] = $null
        $where = Set-PimTenantCacheEntry -Kind $kind -ValueJson $json
        $json = $null
        if ("$($tbl.reason)".Trim() -and [bool]$tbl.said) { $formTxt = "; stored as one document ($($tbl.reason))" }
    }
    # SNAP-INC: the delta state moves ONLY now -- the rows of this run are stored in the table form (a failed write threw
    # above and left the previous state, which still names the previous generation). Not for a read that failed everywhere.
    if ($snap.Contains('groupDelta') -and $null -ne $snap['groupDelta']) {
        $gdr = $snap['groupDelta']
        $formTxt += "; pim-for-groups $($gdr.text)"
        if ($null -eq $gdr.state) { $formTxt += '; group delta state not advanced (the group read failed)' }
        elseif (-not $tbl.stored) { $formTxt += '; group delta state not advanced (the rows are not in the table form)' }
        elseif (-not [bool]$snap.ok) { $formTxt += '; group delta state not advanced (the read failed)' }
        elseif ($null -ne $gdCtx) {
            $gdw = Save-PimSnapshotGroupDeltaState -Context $gdCtx -State $gdr.state -SnapshotId ([long]$tbl.snapshotId)
            if (-not $gdw.ok) { $formTxt += "; group delta state NOT saved ($($gdw.error)) -- the next run reads every group" }
        }
    }
    $c = $snap.counts
    $sum = "{0} total ({1} entra-role, {2} azure-rbac, {3} pim-for-groups) in {4}s -> {5}{6}" -f $c.total, $c['entra-role'], $c['azure-rbac'], $c['pim-for-groups'], $snap.elapsedSec, $where, $formTxt
    if (-not $snap.ok) {
        throw ("[$type] active assignments could not be read from any surface; the failure was stored so the Revoke tab shows it. " + "$($entry.error)")
    }
    $partialTxt = if ($errs.Count) { " PARTIAL -- could not read: " + (@($errs | ForEach-Object { "$($_.surface)" }) -join ', ') } else { '' }
    return [pscustomobject]@{ ran = $true; whatIf = $false; total = [int]$c.total; partial = [bool]$snap.partial
        detail = "$type`: $sum$partialTxt$ledTxt" }
}

function Update-PimActiveAssignmentsSnapshotMarks {
    <#
      §33.0 MORE TELEMETRY round 2 (owner "add relevant. i want data"). The MANAGED marks of a stored generation, computed
      where the JOB runs -- the Manager's own code (Get-PimActiveAssignmentMarksKey + Sync-PimSqlActiveAssignmentMarks, set-based
      in SQL against the engine's 'managed-live' list) -- so the heartbeat's roleAssignmentsOutsidePim no longer waits for
      someone to open the Active assignments page. The break-glass list is marked too (the store); PIM Manager's own
      identities / the Support app need a directory read and are left to the Manager (its key then differs, and its page
      re-marks before it serves a row -- nothing it shows changes).
      -SnapshotId 0 = the newest COMPLETE generation. Nothing is done while the managed list is not there (no marks are
      better than marks that call every row unmanaged). Never throws: returns { ok; updated; changed; reason }.
      -Stamps / -BreakGlass / -Sync: test seams.
    #>
    param([string]$ConnectionString = '', [long]$SnapshotId = 0, [scriptblock]$Stamps = $null, [scriptblock]$BreakGlass = $null, [scriptblock]$Sync = $null, [scriptblock]$Latest = $null)
    $res = { param($ok, $upd, $chg, $why) [pscustomobject]@{ ok = [bool]$ok; updated = [bool]$upd; changed = [int]$chg; reason = "$why" } }
    try {
        if (-not "$ConnectionString".Trim() -and (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) { $ConnectionString = "$(Get-PimTenantCacheStoreCs)" }
        if (-not "$ConnectionString".Trim()) { return (& $res $false $false 0 'no SQL store') }
        if (-not $Sync) {
            foreach ($fn in 'Get-PimActiveAssignmentMarksKey', 'Sync-PimSqlActiveAssignmentMarks') { if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { return (& $res $false $false 0 'the marks writer is not loaded') } }
            $Sync = { param($cs, $sid, $mk, $known, $bg) Sync-PimSqlActiveAssignmentMarks -ConnectionString $cs -SnapshotId $sid -MarksKey $mk -ManagedKnown $known -BreakGlass @($bg) }
        }
        if ($SnapshotId -le 0) {
            if (-not $Latest) { $Latest = { param($cs) Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT MAX(SnapshotId) FROM pim.ActiveAssignmentSnapshots WHERE State = N'complete'" } }
            $v = & $Latest $ConnectionString
            $n = [long]0; if ($null -eq $v -or $v -is [System.DBNull] -or -not [long]::TryParse("$v", [ref]$n) -or $n -le 0) { return (& $res $true $false 0 'no complete generation') }
            $SnapshotId = $n
        }
        if (-not $Stamps) { $Stamps = { if (Get-Command Get-PimTenantCacheStamps -ErrorAction SilentlyContinue) { Get-PimTenantCacheStamps -Kinds @('managed-live') } else { $null } } }
        $st = & $Stamps
        if ($null -eq $st -or -not [bool]$st.ok -or -not $st.stamps -or -not $st.stamps.ContainsKey('managed-live')) { return (& $res $true $false 0 'the managed list is not stored yet') }
        $mlStamp = "$($st.stamps['managed-live'])"
        $bg = @()
        if (-not $BreakGlass) { $BreakGlass = { if (Get-Command Get-PimBreakGlassAccountStatus -ErrorAction SilentlyContinue) { Get-PimBreakGlassAccountStatus } else { $null } } }
        $bgS = $null; try { $bgS = & $BreakGlass } catch { $bgS = $null }
        if ($null -ne $bgS -and -not ([bool]$bgS.storeConfigured -and -not [bool]$bgS.storeOk)) { $bg = @(@($bgS.accounts) | Where-Object { $_ }) }
        $mk = Get-PimActiveAssignmentMarksKey -ManagedStamp $mlStamp -ManagedKnown $true -BreakGlass @($bg)
        $r = & $Sync $ConnectionString $SnapshotId $mk $true @($bg)
        return (& $res $true ([bool]$r.updated) ([int]$r.changed) '')
    } catch { return (& $res $false $false 0 "$($_.Exception.Message)") }
}

function Register-PimActiveAssignmentsSnapshotHandler {
    # Called ONLY by tools/pim-scheduler/Start-PimScheduler.ps1. The default handler registered by
    # Initialize-PimDefaultJobHandlers declares the job unimplemented, so a process that never calls this --
    # the Manager above all -- cannot run the live read through "Run now" or any other dispatch.
    if (-not (Get-Command Register-PimJobHandler -ErrorAction SilentlyContinue)) {
        throw 'Register-PimActiveAssignmentsSnapshotHandler: PIM-Scheduler.ps1 is not loaded (Register-PimJobHandler missing).'
    }
    Register-PimJobHandler -Type $script:PimActiveAssignmentsSnapshotJobType -Handler {
        param($job, $now, $whatIf)
        Invoke-PimActiveAssignmentsSnapshotJob -Job $job -NowUtc $now -WhatIf:$whatIf
    }
}

# ===========================================================================
# THE MANAGER'S SIDE -- read the stored snapshot, ask for a refresh. No Graph, no ARM.
# ===========================================================================
function Request-PimActiveAssignmentsSnapshotRefresh {
    # Queue an on-demand 'active-assignments-snapshot' run for the scheduler (pim.Settings SchedulerTriggers).
    # Deduped by type+scope inside Add-PimJobTrigger, so a page that asks repeatedly does not pile up runs.
    # Returns @{ queued; error }. Never throws: failing to queue is reported, and the caller still serves.
    param([string]$Reason = 'manager')
    if (-not (Get-Command Add-PimJobTrigger -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ queued = $false; error = 'the scheduler trigger queue (PIM-Scheduler.ps1) is not loaded in this process' }
    }
    try {
        [void](Add-PimJobTrigger -Type $script:PimActiveAssignmentsSnapshotJobType -Scope 'All' -Reason $Reason)
        return [pscustomobject]@{ queued = $true; error = '' }
    } catch {
        return [pscustomobject]@{ queued = $false; error = "$($_.Exception.Message)" }
    }
}

function Get-PimActiveAssignmentsRefreshState {
    <#
      PURE. §100.47 (a) (owner 2026-10-10): is a read of the active-assignments snapshot ALREADY queued or running?
      The Delegation overview page used to say "Click Refresh to load" while the scheduler was reading in the background,
      so people pressed Refresh and asked for a second read. This answers from the scheduler's own records, never a guess:
        * running -- a live lock of a run of this job type (every run holds the area 'job:<name>' while it runs; the name
          is the job's own or 'trigger:<type>:<scope>' for a queued Run now / Refresh)
        * queued  -- a pending trigger of this job type in pim.Settings SchedulerTriggers (it stays there until it has run)
      Returns @{ pending; state = '' | 'queued' | 'running'; sinceUtc = ISO or '' }. Running wins over queued.
    #>
    param([object[]]$Triggers = @(), [AllowNull()][System.Collections.IDictionary]$LockMap, [datetime]$NowUtc = [datetime]::UtcNow,
          [string]$JobType = $script:PimActiveAssignmentsSnapshotJobType)
    $now = $NowUtc.ToUniversalTime()
    $iso = { param($v) if ($null -eq $v) { '' } else { "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value $v)" } }
    $rx = '(^|[:])' + [regex]::Escape($JobType) + '($|[:])'
    if ($null -ne $LockMap) {
        foreach ($k in @($LockMap.Keys)) {
            $l = $LockMap[$k]
            if ($null -eq $l) { continue }
            $jn = "$($l.job)"; $area = "$k"
            if (-not (($area -match '^job:' -and ($area -replace '^job:', '') -match $rx) -or ($jn -replace '^job:', '') -match $rx)) { continue }
            # a lock past its expiry belongs to a run that is gone (Test-PimAreaLockLive's rule, inlined: this file is pure)
            $live = $true
            $exp = [datetime]::MinValue
            $raw = if ($l.expiresUtc -is [datetime]) { $l.expiresUtc.ToUniversalTime().ToString('o') } else { "$($l.expiresUtc)" }
            $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
            if ("$raw".Trim() -and [datetime]::TryParse($raw, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$exp)) { $live = ($now -lt $exp.ToUniversalTime()) }
            if (-not $live) { continue }
            return [pscustomobject]@{ pending = $true; state = 'running'; sinceUtc = (& $iso $l.acquiredUtc) }
        }
    }
    $q = @(@($Triggers) | Where-Object { $_ -and "$($_.type)" -eq $JobType }) | Sort-Object { "$($_.requestedUtc)" } | Select-Object -First 1
    if ($q) { return [pscustomobject]@{ pending = $true; state = 'queued'; sinceUtc = (& $iso $q.requestedUtc) } }
    return [pscustomobject]@{ pending = $false; state = ''; sinceUtc = '' }
}

function Read-PimActiveAssignmentsRefreshState {
    # The store half of Get-PimActiveAssignmentsRefreshState: the trigger queue + the lock map, each read guarded (a read that
    # fails counts as "nothing pending", so the page still serves and Refresh still works).
    param([datetime]$NowUtc = [datetime]::UtcNow)
    $trig = @(); $locks = $null
    if (Get-Command Get-PimPendingTriggers -ErrorAction SilentlyContinue) { try { $trig = @(Get-PimPendingTriggers) } catch { $trig = @() } }
    if (Get-Command Get-PimSchedulerLocksRaw -ErrorAction SilentlyContinue) { try { $locks = (Get-PimSchedulerLocksRaw).Map } catch { $locks = $null } }
    return (Get-PimActiveAssignmentsRefreshState -Triggers $trig -LockMap $locks -NowUtc $NowUtc)
}

function ConvertTo-PimActiveAssignmentsIsoStamp {
    # 🪤 pwsh 7's ConvertFrom-Json turns an ISO string into a [datetime], and "$([datetime])" then renders in the
    # CURRENT CULTURE ("09/13/2026 10:00:00") -- which the GUI's "as of HH:MM" parser cannot read. 5.1 keeps the
    # string. Normalise both to 'yyyy-MM-ddTHH:mm:ssZ'.
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

function ConvertTo-PimActiveAssignmentsSnapshotView {
    <#
      PURE. Shape a stored snapshot (or $null) into the GET /api/active-assignments response. Keeps every field
      the GUI already reads -- ok, rows, loadedUtc, counts, surfaceErrors, cacheHit -- and adds the "as of"
      facts: refreshedUtc, ageSeconds, cadenceMinutes, stale, snapshotMissing, refreshQueued, hint.
    #>
    param(
        [AllowNull()][object]$Entry,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [int]$CadenceMinutes = 0,
        [bool]$RefreshQueued = $false,
        [string]$QueueError = '',
        # §100.47 (a): a read already queued / running (Get-PimActiveAssignmentsRefreshState) -- the page shows "Loading..."
        # and keeps Refresh disabled; -RefreshAlreadyQueued = this request asked for one and was NOT queued again.
        [AllowNull()][object]$RefreshState = $null,
        [bool]$RefreshAlreadyQueued = $false,
        # REQ 100.112: -ReadError = a snapshot IS stored but could not be read (plain reason). That is never "no snapshot
        # yet": snapshotMissing stays $false and snapshotReadError says why. -SnapshotStamp = when the stored row was
        # written (the store's own stamp, read without the document); the page compares it with ?state=1.
        [string]$ReadError = '',
        [string]$SnapshotStamp = ''
    )
    if ($CadenceMinutes -le 0) { $CadenceMinutes = $script:PimActiveAssignmentsSnapshotDefaultCadenceMinutes }
    if ($CadenceMinutes -le 0) { $CadenceMinutes = 120 }
    $now = $NowUtc.ToUniversalTime()
    $rsPending = [bool]$RefreshQueued; $rsState = if ($RefreshQueued) { 'queued' } else { '' }; $rsSince = ''
    if ($null -ne $RefreshState -and [bool]$RefreshState.pending) { $rsPending = $true; $rsState = "$($RefreshState.state)"; $rsSince = "$($RefreshState.sinceUtc)" }
    if ($rsPending -and -not $rsSince -and $RefreshQueued) { $rsSince = $now.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) }
    $rsWord = if ($rsState -eq 'running') { 'is running' } else { 'is queued' }
    $refreshedIso = if ($null -ne $Entry) { ConvertTo-PimActiveAssignmentsIsoStamp -Value $Entry.refreshedUtc } else { $null }
    $hasEntry = ($null -ne $Entry) -and ("$refreshedIso".Trim() -ne '')
    if (-not $hasEntry -and "$ReadError".Trim()) {
        $msg = "The stored read could not be loaded ($("$ReadError".Trim()))."
        return [ordered]@{
            ok              = $false
            error           = $msg
            rows            = @()
            counts          = [ordered]@{ total = 0; 'entra-role' = 0; 'azure-rbac' = 0; 'pim-for-groups' = 0 }
            surfaceErrors   = @()
            partial         = $false
            loadedUtc       = $null
            refreshedUtc    = $null
            ageSeconds      = $null
            cacheHit        = $false
            snapshot        = $true
            snapshotMissing = $false
            snapshotReadError = "$ReadError".Trim()
            snapshotStamp   = "$SnapshotStamp"
            refreshQueued   = [bool]$RefreshQueued
            refreshPending  = [bool]$rsPending
            refreshState    = $rsState
            refreshSinceUtc = $rsSince
            refreshAlreadyQueued = [bool]$RefreshAlreadyQueued
            cadenceMinutes  = $CadenceMinutes
            stale           = $false
            hint            = "$msg A snapshot is stored; no new read of the tenant was asked for because of this."
            source          = 'scheduler-snapshot'
        }
    }
    if (-not $hasEntry) {
        $hint = if ($rsPending -and -not $RefreshQueued) { "No snapshot yet -- a read $rsWord (since $rsSince); not queued again. This page does not wait for it." }
                elseif ($RefreshQueued) { 'No snapshot yet -- queued. The scheduler builds it within ~5 min; this page does not wait for it.' }
                else { "No snapshot yet, and a refresh could NOT be queued ($QueueError). The scheduler job 'active-assignments-snapshot' builds it on its cadence." }
        return [ordered]@{
            ok              = $true
            rows            = @()
            counts          = [ordered]@{ total = 0; 'entra-role' = 0; 'azure-rbac' = 0; 'pim-for-groups' = 0 }
            surfaceErrors   = @()
            partial         = $false
            loadedUtc       = $null
            refreshedUtc    = $null
            ageSeconds      = $null
            cacheHit        = $false
            snapshot        = $true
            snapshotMissing = $true
            snapshotReadError = ''
            snapshotStamp   = "$SnapshotStamp"
            refreshQueued   = [bool]$RefreshQueued
            refreshPending  = [bool]$rsPending
            refreshState    = $rsState
            refreshSinceUtc = $rsSince
            refreshAlreadyQueued = [bool]$RefreshAlreadyQueued
            cadenceMinutes  = $CadenceMinutes
            stale           = $false
            hint            = $hint
            source          = 'scheduler-snapshot'
        }
    }
    $refreshed = $null
    if (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue) { $refreshed = Get-PimUtcStamp $refreshedIso }
    else { try { $refreshed = [datetime]::Parse($refreshedIso, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $refreshed = $null } }
    $age = if ($refreshed) { [int64][math]::Max(0, [math]::Round(($now - $refreshed).TotalSeconds, 0)) } else { $null }
    # Stale = older than two cadences: one missed run is normal (a long tick), two is a scheduler that is not running it.
    $stale = ($null -ne $age) -and ($age -gt (2 * $CadenceMinutes * 60))
    $errs = @(@($Entry.surfaceErrors) | Where-Object { $null -ne $_ })
    $rows = @(@($Entry.rows) | Where-Object { $null -ne $_ })
    $counts = $Entry.counts
    if ($null -eq $counts) {
        $counts = [ordered]@{ total = $rows.Count
            'entra-role' = @($rows | Where-Object { "$($_.type)" -eq 'entra-role' }).Count
            'azure-rbac' = @($rows | Where-Object { "$($_.type)" -eq 'azure-rbac' }).Count
            'pim-for-groups' = @($rows | Where-Object { "$($_.type)" -eq 'pim-for-groups' }).Count }
    }
    $asOf = if ($refreshed) { $refreshed.ToString('HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { "$refreshedIso" }
    $hint = "as of $asOf (the scheduler refreshes it every $CadenceMinutes min)"
    if ($rsPending -and -not $RefreshQueued) { $hint += "; a read $rsWord (since $rsSince) -- not queued again" }
    elseif ($RefreshQueued) { $hint += '; a refresh is queued -- the scheduler picks it up within ~5 min' }
    elseif ("$QueueError".Trim()) { $hint += "; a refresh could NOT be queued ($QueueError)" }
    if ($stale) { $hint += "; STALE -- older than two cadences, check the 'active-assignments-snapshot' job on the Jobs page" }
    # A stored all-surfaces-failed read stays ok=$false so the Revoke tab shows the actionable error.
    $storedOk = $null
    if ($Entry -is [System.Collections.IDictionary]) { if ($Entry.Contains('ok')) { $storedOk = [bool]$Entry['ok'] } }
    elseif ($Entry.PSObject.Properties['ok']) { $storedOk = [bool]$Entry.ok }
    if ($null -eq $storedOk) { $storedOk = -not ($rows.Count -eq 0 -and $errs.Count -gt 0) }
    $view = [ordered]@{
        ok              = [bool]$storedOk
        rows           = $rows
        counts          = $counts
        surfaceErrors   = $errs
        partial         = [bool]$Entry.partial
        loadedUtc       = $refreshedIso
        refreshedUtc    = $refreshedIso
        ageSeconds      = $age
        cacheHit        = $true
        snapshot        = $true
        snapshotMissing = $false
        snapshotReadError = ''
        snapshotStamp   = "$SnapshotStamp"
        refreshQueued   = [bool]$RefreshQueued
        refreshPending  = [bool]$rsPending
        refreshState    = $rsState
        refreshSinceUtc = $rsSince
        refreshAlreadyQueued = [bool]$RefreshAlreadyQueued
        cadenceMinutes  = $CadenceMinutes
        stale           = [bool]$stale
        durationMs      = $Entry.durationMs
        hint            = $hint
        source          = 'scheduler-snapshot'
    }
    if ("$($Entry.error)".Trim()) { $view['error'] = "$($Entry.error)" }
    # REQ 100.114 (2): a table-form snapshot says so, with the generation its rows are in (the paged answer asks that table).
    $rs = ''
    if ($Entry -is [System.Collections.IDictionary]) { if ($Entry.Contains('rowStore')) { $rs = "$($Entry['rowStore'])" } }
    elseif ($Entry.PSObject.Properties['rowStore']) { $rs = "$($Entry.rowStore)" }
    if ($rs -eq 'table') { $view['rowStore'] = 'table'; $view['snapshotId'] = "$($Entry.snapshotId)"; $view['rowCount'] = $Entry.rowCount }
    return $view
}

function ConvertTo-PimActiveAssignmentsReadErrorText {
    # PURE. REQ 100.112: the plain reason a stored snapshot could not be read, for the page ("The stored read could not be
    # loaded (<reason>)"). The raw exception text stays in the Manager's log (the tenant-cache warning).
    param([AllowNull()][string]$Message)
    $m = ("$Message" -replace '\s+', ' ').Trim()
    if (-not $m) { return '' }
    if ($m -match '(?i)OutOfMemory|insufficient memory') { return 'PIM Manager did not have enough memory to load it' }
    if ($m -match '(?i)timeout|timed out') { return 'the database did not answer in time' }
    if ($m.Length -gt 200) { $m = $m.Substring(0, 200) + '...' }
    return $m
}

# 2026-10-07: the MANAGED identity shared by the engine's drift read and Review current delegations (both load this file).
function ConvertTo-PimManagedIdentity {
    <#
      PURE. One normalised identity for a live assignment, shared by the engine's drift read (what it MATCHED to a definition)
      and the Review current delegations rows (what is live), so the two meet exactly:
        g|<principalId>|<groupId>|<member|owner>                       PIM for Groups
        r|<principalId>|<roleDefinitionGuid>|<directoryScopeId or />   Entra role
        a|<principalId>|<roleDefinitionGuid>|<azure scope>             Azure role
      '' when a part is missing (never a partial identity).
    #>
    param([string]$Kind, [string]$PrincipalId, [string]$GroupId = '', [string]$AccessId = '', [string]$RoleDefinitionId = '', [string]$Scope = '')
    $p = "$PrincipalId".Trim().ToLowerInvariant(); if (-not $p) { return '' }
    $guid = { param($v) $s = "$v".Trim().TrimEnd('/'); if ($s -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$') { $Matches[1].ToLowerInvariant() } else { $s.ToLowerInvariant() } }
    switch ($Kind) {
        'g' { $g = "$GroupId".Trim().ToLowerInvariant(); if (-not $g) { return '' }; $a = "$AccessId".Trim().ToLowerInvariant(); if (-not $a) { $a = 'member' }; return "g|$p|$g|$a" }
        'r' { $r = & $guid $RoleDefinitionId; if (-not $r) { return '' }; $s = "$Scope".Trim().ToLowerInvariant(); if (-not $s) { $s = '/' }; return "r|$p|$r|$s" }
        'a' { $r = & $guid $RoleDefinitionId; $s = "$Scope".Trim().TrimEnd('/').ToLowerInvariant(); if (-not $r -or -not $s) { return '' }; return "a|$p|$r|$s" }
    }
    return ''
}

function Get-PimManagedLiveIdentity {
    <# PURE. The identity of one LIVE engine item (a provider's live row), or ''. Field names as the providers carry them. #>
    param([AllowNull()][object]$Live)
    if ($null -eq $Live) { return '' }
    $f = { param($n) $v = $null; if ($Live -is [System.Collections.IDictionary]) { if ($Live.Contains($n)) { $v = $Live[$n] } } elseif ($Live.PSObject.Properties[$n]) { $v = $Live.$n }; "$v".Trim() }
    $prin = & $f 'principalId'; if (-not $prin) { return '' }
    if (& $f 'groupId') { return (ConvertTo-PimManagedIdentity -Kind 'g' -PrincipalId $prin -GroupId (& $f 'groupId') -AccessId (& $f 'accessId')) }
    if (& $f 'AzScope') { return (ConvertTo-PimManagedIdentity -Kind 'a' -PrincipalId $prin -RoleDefinitionId (& $f 'roleDefinitionId') -Scope (& $f 'AzScope')) }
    if (& $f 'roleDefinitionId') { return (ConvertTo-PimManagedIdentity -Kind 'r' -PrincipalId $prin -RoleDefinitionId (& $f 'roleDefinitionId') -Scope (& $f 'directoryScopeId')) }
    return ''
}

function Get-PimActiveRowIdentity {
    <# PURE. The identity of one Review current delegations row (PIM-ActiveAssignments shape), or ''. #>
    param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return '' }
    $f = { param($n) $v = $null; if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $v = $Row[$n] } } elseif ($Row.PSObject.Properties[$n]) { $v = $Row.$n }; "$v".Trim() }
    switch (& $f 'type') {
        'pim-for-groups' { return (ConvertTo-PimManagedIdentity -Kind 'g' -PrincipalId (& $f 'principalId') -GroupId (& $f 'groupId') -AccessId (& $f 'accessId')) }
        'entra-role'     { return (ConvertTo-PimManagedIdentity -Kind 'r' -PrincipalId (& $f 'principalId') -RoleDefinitionId (& $f 'roleDefinitionId') -Scope (& $f 'directoryScopeId')) }
        'azure-rbac'     { return (ConvertTo-PimManagedIdentity -Kind 'a' -PrincipalId (& $f 'principalId') -RoleDefinitionId (& $f 'roleDefinitionId') -Scope (& $f 'scope')) }
    }
    return ''
}
