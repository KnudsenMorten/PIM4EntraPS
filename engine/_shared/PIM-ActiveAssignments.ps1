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
#   * Entra roles, active + eligible: roleAssignmentSchedules + roleEligibilitySchedules (REST, paged)
#   * Azure roles, active + eligible: one Azure Resource Graph query + roleEligibilitySchedules per subscription
#     (owner split cadence 2026-11-11: read nightly / after PIM changed Azure, carried forward between)
#   * PIM-for-Groups, active + eligible: assignmentSchedules + eligibilitySchedules, 20 per $batch, ONLY for the groups of
#     DELEGATION-SCOPE-1 (PIM's own, role-assignable, role-holding -- never every group)
#   * app-permission: apps holding a high-privilege API permission (the privilege tier catalog)
# All REST through PIM-Rest.ps1 (§100.42: no Graph / Az PowerShell module, no SDK fallback).
#
# Every row carries state = 'active' | 'eligible'. The Revoke tab acts on ACTIVE rows only -- eligibility removal is a
# different operator workflow.
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
    $names = @('id', 'type', 'principal', 'principalId', 'principalKind', 'principalUpn', 'role', 'scope', 'groupId', 'start', 'end', 'justification', 'accessId', 'roleDefinitionId', 'directoryScopeId', 'state')
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
    # DELEGATION-SCOPE-1: 'active' | 'eligible'; a row without one (built before the change, or by an app-permission read) is active
    $state = ([string]$val['state']).Trim().ToLowerInvariant(); if ($state -ne 'eligible') { $state = 'active' }
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
        State         = $state
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
    # DELEGATION-SCOPE-1: a table that has no State column yet (the schema step has not run, and this identity may not ALTER)
    # is written without it -- every row then reads as 'active' there; RowJson still carries "state".
    if ($ddl.PSObject.Properties['stateColumn'] -and -not [bool]$ddl.stateColumn -and $table.Columns.Contains('State')) { $table.Columns.Remove('State') }
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
                    foreach ($k in @($v.Keys)) { if (-not $table.Columns.Contains($k)) { continue }; if ($null -eq $v[$k]) { $dr[$k] = [System.DBNull]::Value } else { $dr[$k] = $v[$k] } }
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
    # Framework 12.27 SQL-STATS: a whole generation of rows was just written (and the previous ones deleted) -> refresh the
    # stale pim.* statistics, AFTER the switch committed. Best effort: never throws, one warning line; the snapshot stands.
    if (Get-Command Invoke-PimSqlStatisticsRefresh -ErrorAction SilentlyContinue) { [void](Invoke-PimSqlStatisticsRefresh -ConnectionString $ConnectionString -Reason 'active-assignments snapshot') }
    $sw.Stop()
    return [pscustomobject]@{ stored = $true; reason = ''; said = $false; where = "sql:pim.ActiveAssignmentRows/$sid + pim.TenantCache/active-assignments"
        rows = $written; batches = $batches; retries = $retries; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2); snapshotId = $sid }
}

function Save-PimActiveAssignmentsSnapshotFailure {
    <#
      TRUST-1 gap 1 (framework TRUST-1 points 1 + 2; PIM REQUIREMENTS TRUST-1-CHECK). A run where EVERY surface that should
      be read failed (no row read) never becomes the snapshot: NO generation is written, so the newest COMPLETE generation
      (what the uplink Counts + Security, Get-PimSnapshotAzurePlan and every reader use) stays the previous read. The
      failure stays visible:
        kept = $true   a stored snapshot worth keeping exists: its header gets 'lastRun' { utc; trusted = $false; ok; partial;
                       error; surfaceErrors } (Set-PimSqlActiveAssignmentsLastRun) and nothing else changes; the Manager's view
                       (ConvertTo-PimActiveAssignmentsSnapshotView) says the latest read failed.
        kept = $false  nothing worth keeping is stored (a first run, or only an earlier failure): the failure itself is stored
                       as a one-document entry with NO rows, zero counts and ok = $false, so the Revoke tab shows the hint.
        newer = $true  a newer header was stored while this run read the tenant (-Start, review finding 5): left untouched.
      -Start: the header's identity when the run STARTED (Get-PimSqlActiveAssignmentsHeaderStamp { exists; snapshotId;
      refreshedUtc }); $null = read it now. Returns { kept; newer; where; keptRefreshedUtc }. A store error THROWS.
      -Mark { param($cs, $lastRunJson, $start) -> rows marked } / -Store { param($json, $start) -> rows written or a 'where'
      text } / -ReadKept { param($cs) -> header }: test seams; the defaults are the SQL store.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Entry, [string]$ConnectionString = '', [scriptblock]$Mark = $null, [scriptblock]$Store = $null,
          [scriptblock]$ReadKept = $null, [AllowNull()][object]$Start = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $kind = $script:PimActiveAssignmentsSnapshotCacheKind
    if (-not "$ConnectionString".Trim() -and (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) { $ConnectionString = "$(Get-PimTenantCacheStoreCs)" }
    if ($null -eq $Start -and "$ConnectionString".Trim() -and (Get-Command Get-PimSqlActiveAssignmentsHeaderStamp -ErrorAction SilentlyContinue)) { $Start = Get-PimSqlActiveAssignmentsHeaderStamp -ConnectionString $ConnectionString }
    $lastRun = [ordered]@{ utc = "$($Entry['refreshedUtc'])"; trusted = $false; ok = [bool]$Entry['ok']; partial = [bool]$Entry['partial']
                           error = "$($Entry['error'])"; surfaceErrors = @($Entry['surfaceErrors']); correlationId = "$($Entry['correlationId'])" }
    # Round 5 G2: the KEPT snapshot AGES. Each part that failed this run is named STALE (AA-SOURCE-STALE) on lastRun once its last
    # good read (the start header's per-part time; the header's refreshedUtc for one written before the per-part times) is older
    # than Get-PimTrustCarryMaxAgeDays -- the uplink then holds its keys (lastRun.trusted = false holds them already) and the
    # revoke API refuses its rows (Get-PimActiveAssignmentsCarriedRows).
    $staleL = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $Start -and [bool](Get-PimActiveAssignmentsHeaderField $Start 'exists')) {
        $partsA = Get-PimActiveAssignmentsSurfaceParts
        $perPart = $false; foreach ($pk in 'entraReadUtc', 'azureReadUtc', 'groupsReadUtc', 'appPermissionsReadUtc') { if ("$(Get-PimActiveAssignmentsHeaderField $Start $pk)".Trim()) { $perPart = $true } }
        $failedS = @(@($Entry['surfaceErrors']) | Where-Object { $null -ne $_ } | ForEach-Object { "$(Get-PimActiveAssignmentsHeaderField $_ 'surface')" } | Where-Object { $partsA.ContainsKey($_) } | Select-Object -Unique)
        foreach ($sf in $failedS) {
            $from = "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value (Get-PimActiveAssignmentsHeaderField $Start $partsA[$sf].stamp))"
            if (-not $from -and -not $perPart) { $from = "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value (Get-PimActiveAssignmentsHeaderField $Start 'refreshedUtc'))" }
            if (-not $from) { continue }
            $at = $null; try { $at = [datetime]::Parse($from, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $at = $null }
            if ($null -ne $at -and ($NowUtc.ToUniversalTime() - $at).TotalDays -gt (Get-PimTrustCarryMaxAgeDays)) { $staleL.Add([ordered]@{ surface = $sf; code = 'AA-SOURCE-STALE'; sinceUtc = $from }) }
        }
        # round 6 F1: a PIM-for-Groups SUBSET carried before this run -- each such group ages from ITS OWN last real read
        # (the header's carried[].groupsFrom), not from the part's read time; one stale entry per group
        if ($failedS -contains 'pim-for-groups' -and @($staleL | Where-Object { "$($_.surface)" -eq 'pim-for-groups' }).Count -eq 0) {
            $cjS = "$(Get-PimActiveAssignmentsHeaderField $Start 'carriedJson')"
            if ($cjS.Trim()) {
                try {
                    foreach ($ce in @($cjS | ConvertFrom-Json)) { foreach ($c1 in @($ce)) {
                        if ($null -eq $c1 -or "$($c1.surface)" -ne 'pim-for-groups' -or $null -eq $c1.groupsFrom) { continue }
                        foreach ($gp in @($c1.groupsFrom.PSObject.Properties)) {
                            $gf = "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value $gp.Value)"
                            $ga = $null; try { $ga = [datetime]::Parse($gf, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $ga = $null }
                            if ($null -ne $ga -and ($NowUtc.ToUniversalTime() - $ga).TotalDays -gt (Get-PimTrustCarryMaxAgeDays)) {
                                $staleL.Add([ordered]@{ surface = 'pim-for-groups'; groupId = "$($gp.Name)"; code = 'AA-SOURCE-STALE'; sinceUtc = $ga.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) })
                            }
                        } } }
                } catch { }
            }
        }
    }
    if ($staleL.Count) { $lastRun['stale'] = $staleL.ToArray() }
    $lrJson = ConvertTo-PimActiveAssignmentsSnapshotJson -Entry $lastRun
    if (-not $Mark -and (Get-Command Set-PimSqlActiveAssignmentsLastRun -ErrorAction SilentlyContinue) -and "$ConnectionString".Trim()) {
        $Mark = { param($cs, $j, $st) Set-PimSqlActiveAssignmentsLastRun -ConnectionString $cs -LastRunJson $j -StartSnapshotId "$($st.snapshotId)" -StartRefreshedUtc "$($st.refreshedUtc)" }
    }
    $marked = 0
    if ($Mark) { $marked = [int](& $Mark $ConnectionString $lrJson $Start) }
    if ($marked -gt 0) {
        $keptAt = ''
        if (-not $ReadKept -and (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue)) { $ReadKept = { param($cs) Get-PimTenantCacheEntry -Kind 'active-assignments' -HeaderOnly } }
        if ($ReadKept) { try { $h = & $ReadKept $ConnectionString; if ($null -ne $h) { $keptAt = "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value $h.refreshedUtc)" } } catch { $keptAt = '' } }
        return [pscustomobject]@{ kept = $true; newer = $false; where = "sql:pim.TenantCache/$kind (lastRun on the kept snapshot)"; keptRefreshedUtc = $keptAt; stale = $staleL.ToArray() }
    }
    $fail = [ordered]@{}
    foreach ($k in @($Entry.Keys)) { $fail[$k] = $Entry[$k] }
    $fail['rows'] = @()
    $fail['counts'] = [ordered]@{ total = 0; 'entra-role' = 0; 'azure-rbac' = 0; 'pim-for-groups' = 0; 'app-permission' = 0; eligible = 0 }
    $fail['ok'] = $false
    if (-not "$($fail['error'])".Trim()) {
        $fail['error'] = "Active PIM assignments could not be read (could not read: " + (@(@($Entry['surfaceErrors']) | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.surface)" }) -join ', ') + ")."
    }
    # no part was stored, so no part has an "as of"; and nothing to carry Azure forward from
    foreach ($pk in 'entraReadUtc', 'azureReadUtc', 'azureMode', 'azureReason', 'azureRows', 'groupsReadUtc', 'groupsRead', 'appPermissionsReadUtc') { if ($fail.Contains($pk)) { $fail.Remove($pk) } }
    $fail['lastRun'] = $lastRun
    if (-not $Store) {
        if ((Get-Command Set-PimSqlActiveAssignmentsFailureDocument -ErrorAction SilentlyContinue) -and "$ConnectionString".Trim() -and $null -ne $Start) {
            $Store = { param($j, $st) Set-PimSqlActiveAssignmentsFailureDocument -ConnectionString $ConnectionString -ValueJson $j -StartExists ([bool]$st.exists) -StartRefreshedUtc "$($st.refreshedUtc)" }
        } else { $Store = { param($j, $st) Set-PimTenantCacheEntry -Kind 'active-assignments' -ValueJson $j } }
    }
    $w = & $Store (ConvertTo-PimActiveAssignmentsSnapshotJson -Entry $fail) $Start
    if ($w -is [int] -or $w -is [long]) {
        if ([long]$w -le 0) { return [pscustomobject]@{ kept = $false; newer = $true; where = ''; keptRefreshedUtc = ''; stale = @() } }
        $w = "sql:pim.TenantCache/$kind"
    }
    return [pscustomobject]@{ kept = $false; newer = $false; where = "$w"; keptRefreshedUtc = ''; stale = @() }
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
            # The group LIST is not prefix-filtered: ALL groups, paged 999 at a time (a 125k-group tenant is ~126 list calls),
            # because it names principals and finds the groups the snapshot reads (Select-PimActiveAssignmentsPimGroupCandidates:
            # PIM's own, role-assignable, role-holding). 🔴 DELEGATION-SCOPE-1 (owner 2026-11-11) replaced BUG-217's "read the
            # schedules of EVERY group": listing a group here never means its members are read.
            # 🔴 100.31 SNAPSHOT-OOM (2026-10-09): page by page, each group projected at once to the five fields (SDK casing;
            # PowerShell property names are case-insensitive, so .id / .displayName still answer). The old
            # `-All | ConvertTo-PimSdkShape` held every raw page AND a doubled-property copy of the whole group list.
            # + isAssignableToRole: a role-assignable group is always read (DELEGATION-SCOPE-1 (b)).
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
        [Parameter(Mandatory)][ValidateSet('entra-role','azure-rbac','pim-for-groups','app-permission')][string]$Surface,
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
        'app-permission' {
            if (-not $isAuth) { return '' }
            return ("Engine SPN is missing the Graph app-role to read which apps hold API permissions " +
                    "(servicePrincipals/appRoleAssignedTo). Grant Application.Read.All with the published Grant-PimEnginePermissions.ps1 (browser sign-in) -- Overview > Verify permissions shows the exact command.")
        }
        'azure-rbac' {
            return ("Engine SPN cannot read Azure-RBAC active assignments. Grant it at least Reader on the " +
                    "target subscription(s) (Azure RBAC, not a Graph app-role) so " +
                    "Microsoft.Authorization/roleAssignmentScheduleInstances can be enumerated.")
        }
    }
    return ''
}

# ===========================================================================
# DELEGATION-SCOPE-1 (owner 2026-11-11) -- WHAT THE SNAPSHOT READS
# ===========================================================================
# The owner REPLACED BUG-217's "every group" rule (2026-09-18) with DELEGATION-SCOPE-1 on 2026-11-11: PIM-for-Groups
# schedules are read ONLY for the groups that matter to delegation -- never for every group. Microsoft answers
# assignmentSchedules with the PLAIN MEMBERS of any group, so "every group" turned ordinary groups and their members into
# 'pim-for-groups' rows (one school tenant: 125,004 groups, 529,050 rows, 5-15 h per run, Graph throttled).
# Read, in this order:
#   1. Entra roles, ACTIVE + ELIGIBLE (roleAssignmentSchedules + roleEligibilitySchedules, tenant-wide, paged)
#   2. Azure roles, ACTIVE + ELIGIBLE (one Resource Graph query + roleEligibilitySchedules per subscription) -- at most
#      once a night plus after PIM changed an Azure assignment; carried forward from the last complete read otherwise
#      (owner, split cadence 2026-11-11: Test-PimSnapshotAzureReadDue)
#   3. PIM-for-Groups assignmentSchedules AND eligibilitySchedules (members AND owners) for the groups of
#      Select-PimActiveAssignmentsPimGroupCandidates, chosen AFTER 1 + 2 (a group that holds a role is one of them)
#   4. apps / service principals holding a HIGH-PRIVILEGE API permission (the privilege tier catalog, Tier 0 + Tier 1
#      application permissions): appRoleAssignedTo of each catalogued RESOURCE service principal, never per app
# Every row carries 'state' = 'active' | 'eligible' (app-permission rows: 'active').

function Get-PimSnapshotAzureNightStartHourUtc { return 0 }   # the nightly Azure read: the first run at or after this hour (UTC) ...
function Get-PimSnapshotAzureNightEndHourUtc   { return 5 }   # ... and before this one
function Get-PimSnapshotAzureMarkWindowHours   { return 3 }   # after PIM changed an Azure assignment, Azure is re-read on every run this long (the engine applies the change after the commit)
function Get-PimSnapshotAzureMaxAgeHours       { return 26 }  # a carried Azure read older than this is read again, whatever the clock (a missed night)
function Get-PimSnapshotAzureRefreshSettingName { return 'ActiveAssignmentsAzureRefresh' }
function Get-PimPrivilegeTierApiPermissionsPath { return (Join-Path $PSScriptRoot 'PIM-PrivilegeTierApiPermissions.json') }

function Get-PimPrivilegeTierApiPermissions {
    <#
      The HIGH-PRIVILEGE application permissions (Tier 0 + Tier 1) of the privilege tier catalog, as shipped in
      engine/_shared/PIM-PrivilegeTierApiPermissions.json (generated from SecurityInsight's privilege tier catalog raised to
      the TIER-CATALOG-1 tier floors -- never hand-tiered). Returns [{ api; appId; value; tier }]. Throws when the file
      cannot be read: the app-permission section is then a failed surface, never an empty "nothing found".
    #>
    param([string]$Path = '')
    if (-not "$Path".Trim()) { $Path = Get-PimPrivilegeTierApiPermissionsPath }
    $doc = [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json
    $out = @(foreach ($e in @($doc.entries)) {
        if ($null -eq $e -or -not "$($e.appId)".Trim() -or -not "$($e.value)".Trim() -or "$($e.tier)" -notmatch '^Tier[01]$') { continue }
        [pscustomobject]@{ api = "$($e.api)"; appId = "$($e.appId)".Trim().ToLowerInvariant(); value = "$($e.value)".Trim(); tier = "$($e.tier)" }
    })
    if ($out.Count -eq 0) { throw "the privilege tier list '$Path' has no Tier 0 / Tier 1 entry" }
    return $out
}

function Select-PimActiveAssignmentsRoleHolderGroupIds {
    <#
      PURE. DELEGATION-SCOPE-1 (c). The ids (lower-case) of the GROUPS that are the principal of an Entra-role or Azure-role row,
      active or eligible. A principal is a group when the group lookup has it (-GroupIds), the by-id resolver called it a group
      (-ResolvedKinds: id -> kind), or the row says so (Azure: principalType 'Group').
    #>
    param([object[]]$Rows = @(), [string[]]$GroupIds = @(), [hashtable]$ResolvedKinds = @{})
    $known = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($g in @($GroupIds)) { $s = "$g".Trim().ToLowerInvariant(); if ($s) { [void]$known.Add($s) } }
    if ($ResolvedKinds) { foreach ($k in @($ResolvedKinds.Keys)) { if ("$($ResolvedKinds[$k])" -ieq 'group') { $s = "$k".Trim().ToLowerInvariant(); if ($s) { [void]$known.Add($s) } } } }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $f = { param($n) if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $r[$n] } } elseif ($r.PSObject.Properties[$n]) { $r.$n } }
        $t = "$(& $f 'type')"
        if ($t -ne 'entra-role' -and $t -ne 'azure-rbac') { continue }
        $p = "$(& $f 'principalId')".Trim().ToLowerInvariant(); if (-not $p) { continue }
        $isGroup = $known.Contains($p) -or ("$(& $f 'principalType')" -ieq 'Group') -or ("$(& $f 'principalKind')" -ieq 'group')
        if ($isGroup -and $seen.Add($p)) { $out.Add($p) }
    }
    return @($out.ToArray())
}

function Select-PimActiveAssignmentsPimGroupCandidates {
    <#
      PURE. DELEGATION-SCOPE-1 (owner 2026-11-11, REPLACES BUG-217's "every group" rule of 2026-09-18). The groups whose
      PIM-for-Groups schedules (assignment AND eligibility) the snapshot reads -- ONLY:
        (a) PIM's own groups: defined in PIM (-ManagedGroupIds, the engine's managed list) or named by PIM's group naming
            convention (-Prefix, the literal before the first {Token}; at least 3 characters) -- so a leftover named like
            ours is still read and coverage can call it an 'Orphan group';
        (b) role-assignable groups (IsAssignableToRole);
        (c) groups that hold an Entra role or an Azure role, active or eligible (-RoleHolderIds,
            Select-PimActiveAssignmentsRoleHolderGroupIds) -- a role holder the group lookup does not know is added by id.
      NEVER every group: an ordinary group that is none of these is not read, whatever members it has. A mail-only
      distribution list is never read. Dynamic groups are skipped by the caller, which counts them.
    #>
    param([object[]]$Groups = @(), [string[]]$ManagedGroupIds = @(), [string[]]$RoleHolderIds = @(), [string]$Prefix = '')
    $managed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($m in @($ManagedGroupIds)) { $s = "$m".Trim().ToLowerInvariant(); if ($s) { [void]$managed.Add($s) } }
    $holders = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    foreach ($h in @($RoleHolderIds)) { $s = "$h".Trim().ToLowerInvariant(); if ($s) { [void]$holders.Add($s) } }
    $pfx = "$Prefix".Trim(); if ($pfx.Length -lt 3) { $pfx = '' }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Groups)) {
        if (-not $g -or -not "$($g.Id)".Trim()) { continue }
        $id = "$($g.Id)".Trim().ToLowerInvariant()
        $types = @($g.GroupTypes)
        $sec = $null; if ($g.PSObject.Properties['SecurityEnabled']) { $sec = $g.SecurityEnabled }
        $mailOnly = ($null -ne $sec -and "$sec" -ne '' -and -not [bool]$sec -and -not ($types -contains 'Unified'))
        $rag = ($g.PSObject.Properties['IsAssignableToRole'] -and $g.IsAssignableToRole -eq $true)
        $named = ($pfx -and "$($g.DisplayName)".StartsWith($pfx, [System.StringComparison]::OrdinalIgnoreCase))
        $take = $managed.Contains($id) -or $holders.Contains($id) -or $rag -or $named
        if ($take -and $mailOnly -and -not $holders.Contains($id) -and -not $rag) { $take = $false }
        if ($take -and $seen.Add($id)) { $out.Add($g) }
    }
    # a role-holding group the lookup does not know (a failed or partial group list): read it by id all the same
    foreach ($h in $holders) { if ($seen.Add($h)) { $out.Add([pscustomobject]@{ Id = $h; DisplayName = ''; Description = ''; GroupTypes = @(); SecurityEnabled = $null; IsAssignableToRole = $false }) } }
    return @($out.ToArray())
}

function Test-PimSnapshotAzureReadDue {
    <#
      PURE. Owner split cadence (2026-11-11): the Azure part (active + eligible role schedules) is read at most ONCE A NIGHT,
      off-peak, plus right after PIM changed an Azure assignment; between those its rows are CARRIED FORWARD. Returns
      { read; reason }. -LastReadUtc: when the stored generation's Azure rows were read ($null / '' = none usable).
      -MarkUtc: the 'refresh Azure' mark (pim.Settings ActiveAssignmentsAzureRefresh), $null = none.
    #>
    param([AllowNull()][object]$LastReadUtc, [AllowNull()][object]$MarkUtc = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $now = $NowUtc.ToUniversalTime()
    $last = ConvertTo-PimSnapshotStampUtc -Value $LastReadUtc
    $mark = ConvertTo-PimSnapshotStampUtc -Value $MarkUtc
    $r = { param($read, $why) [pscustomobject]@{ read = [bool]$read; reason = "$why" } }
    if ($null -eq $last) { return (& $r $true 'no usable earlier Azure read') }
    if ($null -ne $mark -and ($mark -gt $last -or ($now - $mark).TotalHours -lt (Get-PimSnapshotAzureMarkWindowHours))) {
        return (& $r $true ("PIM changed an Azure assignment ({0})" -f $mark.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)))
    }
    $nightStart = [datetime]::SpecifyKind($now.Date.AddHours((Get-PimSnapshotAzureNightStartHourUtc)), [DateTimeKind]::Utc)
    $nightEnd   = [datetime]::SpecifyKind($now.Date.AddHours((Get-PimSnapshotAzureNightEndHourUtc)), [DateTimeKind]::Utc)
    if ($now -ge $nightStart -and $now -lt $nightEnd -and $last -lt $nightStart) { return (& $r $true 'nightly Azure read') }
    if (($now - $last).TotalHours -ge (Get-PimSnapshotAzureMaxAgeHours)) { return (& $r $true ("the last Azure read is older than {0} h" -f (Get-PimSnapshotAzureMaxAgeHours))) }
    return (& $r $false ("carried forward from the Azure read of {0}" -f $last.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)))
}

function ConvertTo-PimSnapshotStampUtc {
    # PURE. A stored stamp (ISO text, or the [datetime] pwsh 7's ConvertFrom-Json makes of it) -> UTC [datetime], or $null.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function ConvertFrom-PimActiveAssignmentsStoredRow {
    # PURE. One stored row (parsed RowJson) -> the ordered row the snapshot builds, field for field. pwsh 7's
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
    if (-not $o.Contains('state')) { $o['state'] = 'active' }   # a row stored before DELEGATION-SCOPE-1 is an active one
    return $o
}

function New-PimSnapshotAzureContext {
    <#
      What the split cadence needs from the store, or $null when this process cannot carry Azure rows forward (no SQL
      store, no table form, a helper not loaded) -- Azure is then read on every run, as before. The scriptblocks are the
      test seams; nothing is read here.
    #>
    param([string]$ConnectionString = '')
    foreach ($fn in 'Invoke-PimSqlScalar', 'Get-PimSqlActiveAssignmentRowsJson', 'Confirm-PimSqlActiveAssignmentRowsReady') {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { return $null }
    }
    if (-not "$ConnectionString".Trim() -and (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) { $ConnectionString = "$(Get-PimTenantCacheStoreCs)" }
    if (-not "$ConnectionString".Trim()) { return $null }
    $ddl = $null; try { $ddl = Confirm-PimSqlActiveAssignmentRowsReady -ConnectionString $ConnectionString } catch { $ddl = $null }
    if ($null -eq $ddl -or -not [bool]$ddl.ok) { return $null }
    return @{
        cs          = $ConnectionString
        # the stored header -- only the table form (a few hundred characters); the one-document form is never parsed here
        ReadHeader  = { param($ctx)
            $v = Invoke-PimSqlScalar -ConnectionString $ctx.cs -Sql 'SELECT ValueJson FROM pim.TenantCache WHERE Kind = @k' -Parameters @{ k = 'active-assignments' }
            if ($null -eq $v -or $v -is [System.DBNull]) { return $null }
            $t = "$v"; if ($t -notmatch '^\s*\{\s*"rowStore"\s*:\s*"table"') { return $null }
            return ($t | ConvertFrom-Json) }
        ReadMark    = { param($ctx)
            $v = Invoke-PimSqlScalar -ConnectionString $ctx.cs -Sql 'SELECT ValueJson FROM pim.Settings WHERE Name = @n' -Parameters @{ n = (Get-PimSnapshotAzureRefreshSettingName) }
            if ($null -eq $v -or $v -is [System.DBNull] -or -not "$v".Trim()) { return $null }
            try { return ("$v" | ConvertFrom-Json).requestedUtc } catch { return $null } }
        ReadAzure   = { param($ctx, $sid) Get-PimSqlActiveAssignmentRowsJson -ConnectionString $ctx.cs -SnapshotId $sid -Kind 'azure-rbac' }
        # TRUST-1 gap 4: any part's rows of a stored generation (a surface that failed this run is carried from here)
        ReadKind    = { param($ctx, $sid, $k) Get-PimSqlActiveAssignmentRowsJson -ConnectionString $ctx.cs -SnapshotId $sid -Kind $k }
    }
}

function Get-PimSnapshotAzurePlan {
    <#
      The Azure part of one run: read it, or carry the previous generation's Azure rows forward. Never throws:
        { read; reason; carried (rows, only when read = $false); previousReadUtc }
      Fail-safe: no context, no stored header, no Azure read stamp in it, rows that cannot be read or do not add up to the
      header's count = READ (never a partial snapshot presented as complete).
    #>
    param([AllowNull()][hashtable]$Context, [datetime]$NowUtc = [datetime]::UtcNow)
    $readIt = { param($why, $prev) [pscustomobject]@{ read = $true; reason = "$why"; carried = $null; previousReadUtc = "$prev" } }
    if ($null -eq $Context) { return (& $readIt 'no table store to carry Azure rows from' '') }
    $head = $null
    try { $head = & $Context.ReadHeader $Context } catch { return (& $readIt "the stored header could not be read: $($_.Exception.Message)" '') }
    if ($null -eq $head) { return (& $readIt 'no stored table-form snapshot' '') }
    # TRUST-1 round 4 item 8: Azure CARRIED because the last read failed keeps its OLD read time -- never "not due" from it;
    # it is read again on every run until a read succeeds (never carried silently)
    if ($head.PSObject.Properties['carried'] -and @(@($head.carried) | Where-Object { $null -ne $_ -and "$($_.surface)" -eq 'azure-rbac' }).Count) {
        return (& $readIt 'the last run could not read Azure (its rows are carried) -- read again' "$(if ($head.PSObject.Properties['azureReadUtc']) { ConvertTo-PimActiveAssignmentsIsoStamp -Value $head.azureReadUtc })")
    }
    $prev = ''; if ($head.PSObject.Properties['azureReadUtc']) { $prev = "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value $head.azureReadUtc)" }
    $mark = $null; try { $mark = & $Context.ReadMark $Context } catch { $mark = $null }
    $due = Test-PimSnapshotAzureReadDue -LastReadUtc $prev -MarkUtc $mark -NowUtc $NowUtc
    if ($due.read) { return (& $readIt $due.reason $prev) }
    $sid = [long]0; [void][long]::TryParse("$($head.snapshotId)", [ref]$sid)
    $want = [long]-1; if ($head.PSObject.Properties['azureRows']) { [void][long]::TryParse("$($head.azureRows)", [ref]$want) }
    if ($sid -le 0 -or $want -lt 0) { return (& $readIt 'the stored header does not say how many Azure rows it holds' $prev) }
    try {
        $json = & $Context.ReadAzure $Context $sid
        $carried = New-Object System.Collections.Generic.List[object]
        if ("$json".Length -gt 2) {
            $parsed = ConvertFrom-Json -InputObject "$json"   # assigned first: PS 5.1 emits the array as ONE object
            foreach ($x in @($parsed)) { foreach ($y in @($x)) { if ($null -ne $y) { $carried.Add((ConvertFrom-PimActiveAssignmentsStoredRow -Row $y)) } } }
        }
        if ([long]$carried.Count -ne $want) { throw ("{0} of {1} Azure rows came back" -f $carried.Count, $want) }
        return [pscustomobject]@{ read = $false; reason = $due.reason; carried = $carried; previousReadUtc = $prev }
    } catch {
        return (& $readIt "the previous Azure rows could not be carried forward: $($_.Exception.Message)" $prev)
    }
}

function Request-PimActiveAssignmentsAzureRefresh {
    <#
      The 'refresh Azure next run' mark: PIM changed an Azure assignment (a committed PIM-Assignments-Azure-Resources row, an
      applied Azure revoke). Written by the scheduler's queue-apply; the snapshot reads Azure on every run for
      Get-PimSnapshotAzureMarkWindowHours after it. Never throws: { ok; error }. -Writer: test seam.
    #>
    param([string]$ConnectionString = '', [string]$Reason = '', [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Writer = $null)
    try {
        $json = ConvertTo-Json -Compress -InputObject ([ordered]@{ requestedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture); reason = "$Reason" })
        if (-not $Writer) {
            if (-not "$ConnectionString".Trim() -and (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) { $ConnectionString = "$(Get-PimTenantCacheStoreCs)" }
            if (-not "$ConnectionString".Trim()) { return [pscustomobject]@{ ok = $false; error = 'no SQL store' } }
            $Writer = { param($cs, $j) Set-PimSqlSetting -ConnectionString $cs -Name (Get-PimSnapshotAzureRefreshSettingName) -ValueJson $j }
        }
        [void](& $Writer $ConnectionString $json)
        return [pscustomobject]@{ ok = $true; error = '' }
    } catch { return [pscustomobject]@{ ok = $false; error = "$($_.Exception.Message)" } }
}

function Get-PimActiveAssignmentsManagedGroupIds {
    # The groups defined in PIM: the group part of the engine's managed list ('g|<principal>|<group>|<access>'). Best effort:
    # none stored / no store / a failed read = none (the naming-convention rule still finds PIM's own groups).
    param([string]$ConnectionString = '')
    try {
        if (-not (Get-Command Get-PimSqlManagedLiveIdentitySet -ErrorAction SilentlyContinue)) { return @() }
        if (-not "$ConnectionString".Trim() -and (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) { $ConnectionString = "$(Get-PimTenantCacheStoreCs)" }
        if (-not "$ConnectionString".Trim()) { return @() }
        $set = Get-PimSqlManagedLiveIdentitySet -ConnectionString $ConnectionString
        if ($null -eq $set) { return @() }
        return @(foreach ($k in $set) { $p = "$k".Split('|'); if ($p.Count -ge 4 -and $p[0] -eq 'g' -and $p[2]) { $p[2] } })
    } catch { return @() }
}

function Get-PimActiveAssignmentsAppPermissionRows {
    <#
      DELEGATION-SCOPE-1 (2). Apps / service principals holding a HIGH-PRIVILEGE API permission: for each RESOURCE in the
      privilege tier list (Microsoft Graph, Exchange Online, ...) ONE lookup of its service principal (appRoles) and ONE paged
      read of /servicePrincipals/{id}/appRoleAssignedTo -- never a read per app in the tenant. Only assignments of a catalogued
      Tier 0 / Tier 1 app role to a service principal become rows. Returns { rows; reads; error } -- error = '' or the first
      failure (the caller records the surface; rows read before a failure are dropped: all of the surface or none).
      -Catalog: Get-PimPrivilegeTierApiPermissions (a test passes its own).
    #>
    param([AllowNull()][object[]]$Catalog = $null)
    $rows = New-Object System.Collections.Generic.List[object]
    $reads = 0
    try {
        if ($null -eq $Catalog) { $Catalog = @(Get-PimPrivilegeTierApiPermissions) }
        $byApp = [ordered]@{}
        foreach ($c in @($Catalog)) { if ($null -eq $c) { continue }; $a = "$($c.appId)".Trim().ToLowerInvariant(); if (-not $a) { continue }; if (-not $byApp.Contains($a)) { $byApp[$a] = @{} }; $byApp[$a]["$($c.value)".Trim().ToLowerInvariant()] = $c }
        foreach ($appId in @($byApp.Keys)) {
            $spResp = Invoke-PimGraph -Path ("/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,displayName,appRoles" -f $appId)
            $reads++
            $sps = if ($null -ne $spResp -and ($spResp -isnot [array]) -and $spResp.PSObject.Properties['value']) { @($spResp.value) } else { @($spResp) }
            $sp = @($sps | Where-Object { $_ -and "$($_.id)" })[0]
            if (-not $sp) { continue }   # the API is not in this tenant: nothing can hold its permissions
            $roleById = @{}
            foreach ($ar in @($sp.appRoles)) { if ($ar -and "$($ar.id)" -and $byApp[$appId].ContainsKey("$($ar.value)".Trim().ToLowerInvariant())) { $roleById["$($ar.id)".ToLowerInvariant()] = $byApp[$appId]["$($ar.value)".Trim().ToLowerInvariant()] } }
            if ($roleById.Count -eq 0) { continue }
            $resName = "$($sp.displayName)"; if (-not $resName) { $resName = "$(@($byApp[$appId].Values)[0].api)" }
            $reads++
            Get-PimActiveAssignmentsGraphItems -Path ("/servicePrincipals/{0}/appRoleAssignedTo?`$top=999" -f $sp.id) | ForEach-Object {
                $a = $_
                if (-not $a -or "$($a.principalType)" -ine 'ServicePrincipal') { return }
                $hit = $roleById["$($a.appRoleId)".ToLowerInvariant()]
                if (-not $hit) { return }   # not a high-privilege permission (User.Read, ...): not listed
                $rows.Add([ordered]@{
                    id               = "app-permission:$($a.id)"
                    type             = 'app-permission'
                    principal        = "$($a.principalDisplayName)"
                    principalId      = "$($a.principalId)"
                    principalKind    = 'servicePrincipal'
                    role             = "$($hit.value)"
                    roleDefinitionId = "$($a.appRoleId)"
                    scope            = $resName
                    directoryScopeId = ''
                    start            = ''
                    end              = ''
                    justification    = ''
                    state            = 'active'
                    tier             = "$($hit.tier)"
                    resourceId       = "$($sp.id)"
                })
            }
        }
        return [pscustomobject]@{ rows = $rows; reads = $reads; error = '' }
    } catch {
        $rows.Clear()
        return [pscustomobject]@{ rows = $rows; reads = $reads; error = "$($_.Exception.Message)" }
    }
}

function Get-PimAzureEligibilityParallelMinimum { 40 }   # fewer subscriptions than this: read one by one (no runspaces)

function Get-PimAzureEligibilitySchedules {
    <#
      ENGINE-LONG-RUN-1 (2026-11-12): the ELIGIBLE Azure role schedules of every subscription in -SubscriptionIds. ARM has no
      tenant-wide list for them (measured 2026-11-12: the tenant root management group answers only what sits AT or ABOVE it,
      and Resource Graph carries no eligibility type), so it is one read per subscription -- at ~1.2-1.6 s each, 2,024
      subscriptions took 39 minutes one by one. With -Parallel > 1 on PowerShell 7 and at least
      Get-PimAzureEligibilityParallelMinimum subscriptions, the reads run in runspaces (ForEach-Object -Parallel, one ARM
      token, nextLink paging, 429 / 5xx retried with Retry-After). A subscription a runspace could not read is read again
      one by one through Invoke-PimArm (its own retries) afterwards; only one that fails THERE counts as failed.
      Returns { items (List, in subscription order); failed; failedIds (the subscription ids that failed); error (the first
      failure); parallel (bool) }. Never throws.
      -ChunkReader: test seam ( { param([string[]]$subIds) } returning @{ sub; ok; items; error } per subscription ).
    #>
    param([string[]]$SubscriptionIds = @(), [ValidateRange(1, 64)][int]$Parallel = 16, [scriptblock]$ChunkReader = $null)
    $subsIn = @($SubscriptionIds | Where-Object { "$_".Trim() })
    $items = New-Object System.Collections.Generic.List[object]
    $failed = 0; $firstErr = ''
    $failedIds = New-Object System.Collections.Generic.List[string]   # TRUST-1-NEXT (b): WHICH subscriptions failed
    $readOne ={ param($sid) @(Invoke-PimArm -Path "/subscriptions/$sid/providers/Microsoft.Authorization/roleEligibilitySchedules" -ApiVersion '2020-10-01' -All) }
    $usePar = ($Parallel -gt 1 -and $subsIn.Count -ge (Get-PimAzureEligibilityParallelMinimum) -and ($ChunkReader -or $PSVersionTable.PSVersion.Major -ge 7))
    $answers = @{}
    if ($usePar) {
        try {
            if (-not $ChunkReader) {
                $tok = "$(Get-PimRestToken -Resource 'arm')"
                $to = 100; if (Get-Command Get-PimRestTimeoutSec -ErrorAction SilentlyContinue) { $to = [int](Get-PimRestTimeoutSec) }
                $par = $Parallel
                $ChunkReader = {
                    param([string[]]$ids)
                    $ids | ForEach-Object -ThrottleLimit $par -Parallel {
                        $sid = "$_"; $tk = $using:tok; $tmo = $using:to
                        $got = New-Object System.Collections.Generic.List[object]; $err = ''
                        $next = "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01"
                        while ($next -and -not $err) {
                            $resp = $null
                            for ($try = 1; $try -le 4; $try++) {
                                try { $resp = Invoke-RestMethod -Method GET -Uri $next -Headers @{ Authorization = "Bearer $tk" } -TimeoutSec $tmo; break }
                                catch {
                                    $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
                                    if (($code -eq 429 -or $code -ge 500) -and $try -lt 4) {
                                        $wait = 5 * $try; try { $ra = "$($_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds)"; if ($ra) { $wait = [Math]::Min(60, [Math]::Max(1, [int][double]$ra)) } } catch {}
                                        Start-Sleep -Seconds $wait; continue
                                    }
                                    $err = "$($_.Exception.Message)"; break
                                }
                            }
                            if ($err) { break }
                            foreach ($v in @($resp.value)) { if ($null -ne $v) { $got.Add($v) } }
                            $next = "$($resp.nextLink)"
                        }
                        @{ sub = $sid; ok = (-not $err); items = $got; error = $err }
                    }
                }
            }
            foreach ($a in @(& $ChunkReader $subsIn)) { if ($a -is [hashtable] -and "$($a.sub)") { $answers["$($a.sub)"] = $a } }
        } catch {
            Write-Warning ("  [revoke] parallel Azure eligibility read failed ({0}) -- reading the subscriptions one by one." -f $_.Exception.Message)
            $answers = @{}
        }
    }
    foreach ($sid in $subsIn) {
        $a = $answers[$sid]
        if ($a -and $a.ok) { if ($null -ne $a.items) { foreach ($v in $a.items) { if ($null -ne $v) { $items.Add($v) } } }; continue }   # 🪤 no @() around a List[object] (pwsh 7.6)
        try { foreach ($v in @(& $readOne $sid)) { if ($null -ne $v) { $items.Add($v) } } }
        catch {
            $failed++
            $failedIds.Add("$sid")
            if (-not $firstErr) { $firstErr = "$($_.Exception.Message)" }
            Write-Warning ("  [revoke] ARM role-eligibility schedules for /subscriptions/{0} failed: {1}" -f $sid, $_.Exception.Message)
        }
    }
    return [pscustomobject]@{ items = $items; failed = $failed; failedIds = $failedIds.ToArray(); error = $firstErr; parallel = $usePar }
}

function Invoke-PimActiveAssignmentsSnapshot {
    # THE LIVE READ -- scheduler only (§70.1b option 2). Returns an ordered hashtable:
    #   @{ ok; rows = [...]; counts = @{...}; surfaceErrors; partial; loadedUtc; refreshedUtc; cacheHit=$false;
    #      elapsedSec; durationMs; parts; error? }
    # 🔒 Never call this from the Manager: one run is minutes of Graph reads, and the Manager's single request loop would
    # freeze every user for that long. Test-PimActiveAssignmentsSnapshot asserts it.
    # -Fresh: reload the group/role/AU lookups AND forget principal names resolved earlier in this process.
    # -AzurePlan: the owner's split cadence (Get-PimSnapshotAzurePlan) -- read = $false carries the previous generation's Azure
    #   rows forward instead of reading Azure. $null = Azure is read (a caller without a store).
    # -ManagedGroupIds: the groups defined in PIM; $null = read from the store's managed list (best effort).
    # DELEGATION-SCOPE-1: SNAP-INC's incremental group read (owner 2026-10-20) is GONE -- it existed only because EVERY group was
    # read; the candidate set is now small, an eligible schedule is not announced by a membership delta, and its delta round
    # itself walked every group and its members. Every candidate group is read in full on every run.
    [CmdletBinding()]
    param([switch]$Fresh, [AllowNull()][object]$AzurePlan = $null, [AllowNull()][string[]]$ManagedGroupIds = $null)

    if ($Fresh) { $script:PimManager_ResolvedById = @{} }
    Initialize-PimManagerTenantConnection
    Get-PimManagerLookupCaches -Force:$Fresh

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $runUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $rows = New-Object System.Collections.ArrayList
    # Per-surface failure ledger. Each entry: @{ surface; error; hint; state? }. A failed fetch is recorded, never an empty list:
    # it lets the page tell "genuinely none" from "we could not read them". state = 'eligible' when only the eligible half failed.
    $surfaceErrors = New-Object System.Collections.ArrayList
    $addErr = { param($surface, $em, $state)
        $e = [ordered]@{ surface = $surface; error = "$em"; hint = (Get-PimActiveAssignmentSurfaceHint -Surface $surface -ErrorMessage "$em") }
        if ($state) { $e['state'] = $state }
        [void]$surfaceErrors.Add($e) }
    $restArm = [bool](Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)

    # ---- 1. Entra roles, ACTIVE + ELIGIBLE ----------------------------------
    # 🔴 100.31 SNAPSHOT-OOM: every surface is PROJECTED AS IT IS READ (a raw page becomes rows and is released before the next
    # page). A surface that fails part-way drops the rows it had added: all of a surface (half) or none.
    $addEntraRow = {
        param($e, $state)
        if (-not $e) { return }
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$e.PrincipalId)
        $roleLabel      = Resolve-PimManagerEntraRoleName -RoleDefinitionId ([string]$e.RoleDefinitionId)
        $scopeLabel     = Resolve-PimManagerDirectoryScope -DirectoryScopeId ([string]$e.DirectoryScopeId)
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
            id               = $(if ($state -eq 'eligible') { "entra-role-eligible:$($e.Id)" } else { "entra-role:$($e.Id)" })
            type             = 'entra-role'
            principal        = $principalLabel
            principalId      = [string]$e.PrincipalId
            role             = $roleLabel
            roleDefinitionId = [string]$e.RoleDefinitionId
            scope            = $scopeLabel
            directoryScopeId = [string]$e.DirectoryScopeId
            start            = $start
            end              = $end
            justification    = ''  # Entra role schedules don't carry the original activation justification on the assignment object.
            state            = $state
        })
    }
    $entraStart = $rows.Count
    $entraOk = $true
    try {
        Get-PimActiveAssignmentsGraphItems -Path '/roleManagement/directory/roleAssignmentSchedules' | ForEach-Object { & $addEntraRow $_ 'active' }
    } catch {
        $em = "$($_.Exception.Message)"
        Write-Warning "  [revoke] entra-role assignment-schedules load failed: $em"
        [void]$surfaceErrors.Add([ordered]@{ surface = 'entra-role'; error = $em; hint = (Get-PimActiveAssignmentSurfaceHint -Surface 'entra-role' -ErrorMessage $em) })
        $entraOk = $false
        if ($rows.Count -gt $entraStart) { $rows.RemoveRange($entraStart, $rows.Count - $entraStart) }
    }
    $entraEligStart = $rows.Count
    try {
        Get-PimActiveAssignmentsGraphItems -Path '/roleManagement/directory/roleEligibilitySchedules' | ForEach-Object { & $addEntraRow $_ 'eligible' }
    } catch {
        $em = "$($_.Exception.Message)"
        Write-Warning "  [revoke] entra-role eligibility-schedules load failed: $em"
        if ($entraOk) { & $addErr 'entra-role' $em 'eligible' }   # one ledger entry per surface
        $entraOk = $false
        if ($rows.Count -gt $entraEligStart) { $rows.RemoveRange($entraEligStart, $rows.Count - $entraEligStart) }
    }
    # ENTRA-DIRECT-1 (2026-11-11): roleAssignmentSchedules lists only what PIM's schedule API knows -- a role assigned OUTSIDE
    # PIM (a partner's GDAP group, a Microsoft first-party service principal, a direct roleAssignments POST, AU-scoped ones
    # among them) is missing from it, measured live. /roleManagement/directory/roleAssignments is the ground truth of who
    # holds an Entra role NOW: every one of its rows the schedules did not already give becomes an ACTIVE row (key: principal
    # + role + directory scope, Get-PimActiveRowIdentity). The schedule row wins when both have it (start / end, activation).
    # Eligible rows never enter the key set: roleAssignments holds no eligibility, so nothing eligible becomes active here.
    $entraActiveKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
    for ($ki = $entraStart; $ki -lt $entraEligStart; $ki++) { $k = Get-PimActiveRowIdentity -Row $rows[$ki]; if ($k) { [void]$entraActiveKeys.Add($k) } }
    $entraDirectStart = $rows.Count
    try {
        Get-PimActiveAssignmentsGraphItems -Path '/roleManagement/directory/roleAssignments?$expand=principal' | ForEach-Object {
            $ra = $_
            if (-not $ra) { return }
            $k = ConvertTo-PimManagedIdentity -Kind 'r' -PrincipalId "$($ra.principalId)" -RoleDefinitionId "$($ra.roleDefinitionId)" -Scope "$($ra.directoryScopeId)"
            if (-not $k -or -not $entraActiveKeys.Add($k)) { return }   # already a schedule row (or a repeat): once only
            # the expanded principal names the holder and its kind -- a partner's GDAP group is not always resolvable by id
            $pr = $ra.principal; $prId = "$($ra.principalId)"
            if ($pr -and $prId -and $script:PimManager_ResolvedById -is [hashtable] -and -not $script:PimManager_ResolvedById.ContainsKey($prId) -and
                -not ($script:PimManager_UserById -and $script:PimManager_UserById.ContainsKey($prId)) -and -not ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($prId))) {
                $pk = ("$($pr.'@odata.type')" -replace '#microsoft\.graph\.', '')
                if ($pk) {
                    $pupn = "$($pr.userPrincipalName)"; $pdn = "$($pr.displayName)"
                    $pl = if ($pupn) { $pupn } elseif ($pdn) { $pdn } else { $prId }
                    $script:PimManager_ResolvedById[$prId] = [pscustomobject]@{ label = $pl; kind = $pk; displayName = $pdn; userPrincipalName = $pupn }
                    if ($pk -eq 'user') { Add-PimManagerUserIndexEntry -Id $prId -DisplayName $pdn -UserPrincipalName $pupn }
                }
            }
            & $addEntraRow ([pscustomobject]@{ Id = "$($ra.id)"; PrincipalId = $prId; RoleDefinitionId = "$($ra.roleDefinitionId)"; DirectoryScopeId = "$($ra.directoryScopeId)" }) 'active'
            $kind = Get-PimManagerPrincipalKind -PrincipalId $prId
            if ($kind) { $rows[$rows.Count - 1]['principalKind'] = $kind }   # a role-holding group counts for DELEGATION-SCOPE-1 (c)
        }
        Write-Host ("  [revoke] entra-role: {0} active role assignment(s) outside PIM's schedules (roleAssignments)" -f ($rows.Count - $entraDirectStart)) -ForegroundColor DarkGray
    } catch {
        $em = "$($_.Exception.Message)"
        Write-Warning "  [revoke] entra-role roleAssignments load failed: $em"
        if ($entraOk) { & $addErr 'entra-role' $em '' }
        $entraOk = $false
        if ($rows.Count -gt $entraDirectStart) { $rows.RemoveRange($entraDirectStart, $rows.Count - $entraDirectStart) }
    }
    $entraActiveKeys = $null

    # ---- 2. Azure roles, ACTIVE + ELIGIBLE (or carried forward) -------------
    # REQUIREMENTS 67.3: ONE Azure Resource Graph query over REST returns every active role assignment the engine identity can
    # see (management groups, subscriptions, resource groups, resources) with the role name joined in; the per-subscription
    # walk is only its fallback. Eligible: roleEligibilitySchedules per subscription (ARM has no tenant-wide list for them).
    $addAzRow = {
        param($a, $state)
        if (-not $a) { return }
        $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId ([string]$a.PrincipalId)
        $roleName       = if ($a.RoleDefinitionName) { [string]$a.RoleDefinitionName } else { [string]$a.RoleDefinitionId }
        $azRow = [ordered]@{
            id               = $(if ($state -eq 'eligible') { "azure-rbac-eligible:$($a.Id)" } else { "azure-rbac:$($a.Id)" })
            type             = 'azure-rbac'
            principal        = $principalLabel
            principalId      = [string]$a.PrincipalId
            role             = $roleName
            roleDefinitionId = [string]$a.RoleDefinitionId
            scope            = [string]$a.Scope
            directoryScopeId = ''
            start            = $(if ($a.PSObject.Properties['Start']) { [string]$a.Start } else { '' })
            end              = $(if ($a.PSObject.Properties['End']) { [string]$a.End } else { '' })
            justification    = ''
            state            = $state
        }
        if ($a.PSObject.Properties['RoleAssignmentId'] -and "$($a.RoleAssignmentId)".Trim()) {
            $azRow['roleAssignmentId']   = [string]$a.RoleAssignmentId
            $azRow['roleAssignmentName'] = [string]$a.RoleAssignmentName
        }
        [void]$rows.Add($azRow)
    }
    $azRead = $true; $azReason = ''; $azPrevUtc = ''
    if ($null -ne $AzurePlan) { $azRead = [bool]$AzurePlan.read; $azReason = "$($AzurePlan.reason)"; $azPrevUtc = "$($AzurePlan.previousReadUtc)" }
    $azOk = $true
    if (-not $azRead) {
        # 🪤 never @() around the carried List[object] of ordered rows: pwsh 7.6 throws "Argument types do not match" (measured on
        # the runner, Test-PimDelegationScope C12) -- enumerate it directly
        $carriedN = 0
        if ($null -ne $AzurePlan.carried) { foreach ($cr in $AzurePlan.carried) { if ($null -ne $cr) { [void]$rows.Add($cr); $carriedN++ } } }
        Write-Host ("  [revoke] azure-rbac: {0} row(s) carried forward ({1})" -f $carriedN, $azReason) -ForegroundColor DarkGray
    } else {
        $azRows = @()
        $argDone = $false
        if ((Get-Command Get-PimArmActiveRoleAssignmentsViaArg -ErrorAction SilentlyContinue) -and (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)) {
            $azStart = $rows.Count
            try {
                # 100.31: streamed -- each Resource Graph row becomes a snapshot row as its page arrives.
                Get-PimArmActiveRoleAssignmentsViaArg -Stream | ForEach-Object {
                    & $addAzRow ([pscustomobject]@{ Id = $_.Id; PrincipalId = $_.PrincipalId; RoleDefinitionId = $_.RoleDefinitionId; RoleDefinitionName = $_.RoleDefinitionName
                                                    Scope = $_.Scope; RoleAssignmentId = $_.Id; RoleAssignmentName = $_.Name; PrincipalType = $_.PrincipalType }) 'active'
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
            # REST: active role-assignment-schedule-instances at each subscription scope (ARM has no tenant-wide list).
            try {
                $subs = @(Invoke-PimArm -Path '/subscriptions' -ApiVersion '2020-01-01' -All)
                if ($subs.Count -eq 0) {
                    Write-Warning "  [revoke] ARM returned 0 subscriptions for this identity -- Azure RBAC rows will be empty (engine SPN has no subscription scope / no Reader)."
                    [void]$surfaceErrors.Add([ordered]@{ surface = 'azure-rbac'; error = 'ARM returned 0 subscriptions visible to the engine identity.'
                        hint = 'Grant the engine SPN at least Reader on the target subscription(s) so Azure-RBAC active assignments can be enumerated.' })
                    $azOk = $false
                }
                # TRUST-1-NEXT (b): a subscription that cannot be read is named (its id), never a silent gap -- only ITS rows are
                # then carried from the last good read (AA-AZURE-SUBSCRIPTION-NOT-READ); every other subscription is read as normal
                $actFailIds = New-Object System.Collections.Generic.List[string]; $actFailErr = ''
                foreach ($s in $subs) {
                    $scope = "/subscriptions/$($s.subscriptionId)"
                    try {
                        $subRows = @()
                        foreach ($ri in @(Invoke-PimArm -Path "$scope/providers/Microsoft.Authorization/roleAssignmentScheduleInstances" -ApiVersion '2020-10-01-preview' -All)) {
                            $p = $ri.properties
                            $rdId = "$($p.roleDefinitionId)"
                            $subRows += [pscustomobject]@{ Id = "$($ri.id)"; PrincipalId = "$($p.principalId)"; RoleDefinitionId = $rdId
                                RoleDefinitionName = ($rdId -split '/' | Select-Object -Last 1); Scope = "$($p.scope)"; PrincipalType = "$($p.principalType)" }
                        }
                        $azRows += $subRows   # all of a subscription or none of it
                    } catch {
                        $actFailIds.Add("$($s.subscriptionId)"); if (-not $actFailErr) { $actFailErr = "$($_.Exception.Message)" }
                        Write-Warning ("  [revoke] ARM role-assignment instances for {0} failed: {1}" -f $scope, $_.Exception.Message)
                    }
                }
                if ($actFailIds.Count -gt 0 -and $actFailIds.Count -ge $subs.Count) {
                    # not one subscription could be read: the whole Azure part failed (carried as a whole by the job)
                    & $addErr 'azure-rbac' ("all {0} subscription(s) could not be read: {1}" -f $subs.Count, $actFailErr) ''
                    $azOk = $false; $azRows = @()
                } elseif ($actFailIds.Count -gt 0) {
                    $sem = "{0} of {1} subscription(s) could not be read: {2}" -f $actFailIds.Count, $subs.Count, $actFailErr
                    [void]$surfaceErrors.Add([ordered]@{ surface = 'azure-rbac'; code = 'AA-AZURE-SUBSCRIPTION-NOT-READ'; error = $sem
                        hint = (Get-PimActiveAssignmentSurfaceHint -Surface 'azure-rbac' -ErrorMessage $actFailErr); subscriptionIds = [string[]]@($actFailIds | Sort-Object -Unique) })
                }
            } catch {
                $em = "$($_.Exception.Message)"
                Write-Warning "  [revoke] ARM subscriptions enumeration failed: $em. Azure RBAC rows will be empty."
                & $addErr 'azure-rbac' $em ''
                $azOk = $false
                $azRows = @()
            }
        } else {
            $em = 'Azure-RBAC reader not available (the ARM REST helper Invoke-PimArm is not loaded).'
            Write-Warning "  [revoke] $em Azure RBAC rows will be empty."
            [void]$surfaceErrors.Add([ordered]@{ surface = 'azure-rbac'; error = $em; hint = 'Ensure engine/_shared/PIM-Rest.ps1 is dot-sourced (hosted) so Invoke-PimArm is available.' })
            $azOk = $false
        }
        foreach ($a in $azRows) { & $addAzRow $a 'active' }
        $azRows = $null

        # ELIGIBLE Azure roles: roleEligibilitySchedules at every subscription the identity sees (the list at a subscription
        # also returns what sits below it and what it inherits from above; de-duplicated by schedule id).
        if ($restArm) {
            $azEligStart = $rows.Count
            $eligErr = ''; $eligFailedSubs = 0
            try {
                $eSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
                $eSubs = @(Invoke-PimArm -Path '/subscriptions' -ApiVersion '2020-01-01' -All)
                # ENGINE-LONG-RUN-1: read in parallel (Get-PimAzureEligibilitySchedules); failures are re-read one by one there
                $eSw = [System.Diagnostics.Stopwatch]::StartNew()
                $eRead = Get-PimAzureEligibilitySchedules -SubscriptionIds @($eSubs | ForEach-Object { "$($_.subscriptionId)" })
                $eligFailedSubs = [int]$eRead.failed; $eligErr = "$($eRead.error)"
                Write-Host ("  [revoke] azure-rbac eligibility: {0} subscription(s) read {1} in {2:n1}s" -f $eSubs.Count, $(if ($eRead.parallel) { 'in parallel' } else { 'one by one' }), $eSw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
                foreach ($es in $eRead.items) {   # 🪤 never @() around the List[object]: pwsh 7.6 "Argument types do not match"
                    if (-not $es -or -not "$($es.id)") { continue }
                    $p = $es.properties
                    if ("$($p.memberType)" -ieq 'Group') { continue }   # reached through a group: the group's own schedule is the row
                    if (-not $eSeen.Add("$($es.id)".ToLowerInvariant())) { continue }
                    $rdId = "$($p.roleDefinitionId)"
                    $rdName = $null
                    if ($p.expandedProperties -and $p.expandedProperties.roleDefinition -and "$($p.expandedProperties.roleDefinition.displayName)") { $rdName = "$($p.expandedProperties.roleDefinition.displayName)" }
                    if (-not $rdName) { $rdName = ($rdId -split '/' | Select-Object -Last 1) }
                    $st = ''; $en = ''
                    if ("$($p.startDateTime)") { try { $st = ([DateTime]$p.startDateTime).ToUniversalTime().ToString('o') } catch {} }
                    if ("$($p.endDateTime)")   { try { $en = ([DateTime]$p.endDateTime).ToUniversalTime().ToString('o') } catch {} }
                    & $addAzRow ([pscustomobject]@{ Id = "$($es.id)"; PrincipalId = "$($p.principalId)"; RoleDefinitionId = $rdId; RoleDefinitionName = $rdName
                                                    Scope = "$($p.scope)"; PrincipalType = "$($p.principalType)"; Start = $st; End = $en }) 'eligible'
                }
                # TRUST-1-NEXT (b): SOME subscriptions failed -> only THOSE are unknown (a surface error naming them, code
                # AA-AZURE-SUBSCRIPTION-NOT-READ; the job carries their last good eligible rows), every other subscription's rows
                # stay. Every subscription failed (or a reader that does not name them) -> the whole eligible half, as before.
                $eFailIds = @(); if ($eRead.PSObject.Properties['failedIds']) { $eFailIds = @($eRead.failedIds | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Sort-Object -Unique) }
                if ($eligFailedSubs -gt 0 -and ($eligFailedSubs -ge $eSubs.Count -or $eFailIds.Count -ne $eligFailedSubs)) { throw ("{0} of {1} subscription(s) could not be read: {2}" -f $eligFailedSubs, $eSubs.Count, $eligErr) }
                if ($eligFailedSubs -gt 0) {
                    $sem = "{0} of {1} subscription(s) could not be read: {2}" -f $eligFailedSubs, $eSubs.Count, $eligErr
                    [void]$surfaceErrors.Add([ordered]@{ surface = 'azure-rbac'; code = 'AA-AZURE-SUBSCRIPTION-NOT-READ'; error = $sem
                        hint = (Get-PimActiveAssignmentSurfaceHint -Surface 'azure-rbac' -ErrorMessage $eligErr); state = 'eligible'; subscriptionIds = [string[]]$eFailIds })
                }
                Write-Host ("  [revoke] azure-rbac: {0} eligible role schedule(s) across {1} subscription(s)" -f ($rows.Count - $azEligStart), $eSubs.Count) -ForegroundColor DarkGray
            } catch {
                $em = "$($_.Exception.Message)"
                Write-Warning "  [revoke] azure-rbac eligibility read failed: $em"
                if ($azOk) { & $addErr 'azure-rbac' $em 'eligible' }
                $azOk = $false
                if ($rows.Count -gt $azEligStart) { $rows.RemoveRange($azEligStart, $rows.Count - $azEligStart) }
            }
        }
    }
    # the Azure read stamp of THIS generation: now when Azure was read completely, the carried read's stamp when carried, none
    # when the read failed (the next run then reads Azure again)
    # TRUST-1-NEXT (b): some subscriptions not read = not read completely ('' here; the job stamps the part when it carried their
    # rows, and the header's 'carried' entry makes the next run read Azure again)
    $azSubUnread = @($surfaceErrors | Where-Object { "$($_.surface)" -eq 'azure-rbac' -and $_.Contains('subscriptionIds') }).Count -gt 0
    $azureReadUtc = if (-not $azRead) { $azPrevUtc } elseif ($azOk -and -not $azSubUnread) { $runUtc } else { '' }

    # ---- 3. the groups to read: chosen AFTER the role rows ------------------
    # The group list holds EVERY group of the tenant, so a group that holds a role is known by it. Only when that list could not
    # be read are the role rows' principals resolved FIRST (one getByIds call per 1000) to recognise the groups among them --
    # not otherwise: resolving every user here would hold them through the group reads (Test-PimSnapshotMemory M1, 384 MB cap).
    $groupListKnown = ($script:PimManager_GroupById -is [hashtable] -and $script:PimManager_GroupById.Count -gt 0)
    if (-not $groupListKnown) { try {
        $preSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
        $preList = New-Object System.Collections.Generic.List[string]
        foreach ($row in $rows) {
            $rpid = [string]$row.principalId
            if (-not $rpid) { continue }
            if (($script:PimManager_UserById -and $script:PimManager_UserById.ContainsKey($rpid)) -or ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($rpid))) { continue }
            if ($preSet.Add($rpid)) { $preList.Add($rpid) }
        }
        if ($preList.Count -gt 0) { Resolve-PimManagerPrincipalIdBatch -Ids $preList.ToArray() }
    } catch { Write-Warning "  [revoke] role principal resolve failed: $($_.Exception.Message)" } }
    $resolvedKinds = @{}
    if (-not $groupListKnown -and $script:PimManager_ResolvedById -is [hashtable]) { foreach ($k in @($script:PimManager_ResolvedById.Keys)) { $resolvedKinds["$k"] = "$($script:PimManager_ResolvedById[$k].kind)" } }
    $roleHolders = @(Select-PimActiveAssignmentsRoleHolderGroupIds -Rows @($rows.ToArray()) -GroupIds @(if ($script:PimManager_GroupById) { $script:PimManager_GroupById.Keys }) -ResolvedKinds $resolvedKinds)
    if ($null -eq $ManagedGroupIds) { $ManagedGroupIds = @(Get-PimActiveAssignmentsManagedGroupIds) }
    $pimGroupsToQuery = @(Select-PimActiveAssignmentsPimGroupCandidates -Groups @($script:PimManager_Groups) -ManagedGroupIds @($ManagedGroupIds) -RoleHolderIds $roleHolders -Prefix (Get-PimActiveAssignmentsGroupPrefix))
    # A DYNAMIC-membership group cannot carry a PIM-for-Groups schedule (Graph answers ResourceTypeNotSupported), so its
    # request can only fail: skipped and counted.
    $pimDynamicSkipped = @($pimGroupsToQuery | Where-Object { @($_.GroupTypes) -contains 'DynamicMembership' }).Count
    if ($pimDynamicSkipped) { $pimGroupsToQuery = @($pimGroupsToQuery | Where-Object { -not (@($_.GroupTypes) -contains 'DynamicMembership') }) }
    $pimGroupsToRead = $pimGroupsToQuery
    Write-Host ("  [revoke] pim-for-groups: {0} group(s) to read ({1} hold a role; {2} dynamic skipped) -- DELEGATION-SCOPE-1, never every group" -f $pimGroupsToRead.Count, $roleHolders.Count, $pimDynamicSkipped) -ForegroundColor DarkGray

    # ---- 4. PIM-for-Groups schedules of those groups: ACTIVE + ELIGIBLE ------
    # Graph refuses an unfiltered list ('MissingParameters: GroupId or PrincipalId'): one filtered read per group and kind,
    # 20 per $batch round-trip. Paths: [2i] = assignmentSchedules, [2i+1] = eligibilitySchedules of group i.
    $pimGroupRows = New-Object System.Collections.Generic.List[object]       # active (100.31: .Add, never +=)
    $pimGroupEligRows = New-Object System.Collections.Generic.List[object]   # eligible
    $gPaths = New-Object System.Collections.Generic.List[string]
    foreach ($g in $pimGroupsToRead) {
        $gPaths.Add("/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($g.Id)'")
        $gPaths.Add("/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($g.Id)'")
    }
    $gFail = 0; $gFirstErr = $null
    $takeAnswer = {
        param([int]$pi, [bool]$ok, [object[]]$items, [int]$status, [string]$errText)
        if ($ok) { foreach ($v in @($items)) { if ($null -ne $v) { if ($pi % 2 -eq 0) { $pimGroupRows.Add($v) } else { $pimGroupEligRows.Add($v) } } }; return }
        if (Test-PimGroupNotPimOnboardedError -Message $errText) { return }   # not a PIM group -- nothing to list, not a failure
        # TRUST-1 round 6 F5: the group is GONE (deleted while this run read the tenant: HTTP 404 / ResourceNotFound) -- it has no
        # assignments left, so it is no failure (no warning, nothing carried, no key held). Every other error stays a failure.
        if ($status -eq 404 -or $errText -match '(?i)\bHTTP 404\b|Request_ResourceNotFound|\bResourceNotFound\b') { return }
        $script:__gFail++
        # TRUST-1 round 4 item 14: WHICH groups failed, so only their rows are carried (the others' fresh rows stay)
        $gfId = "$($pimGroupsToRead[[int][Math]::Floor($pi / 2)].Id)".Trim(); if ($gfId -and $null -ne $script:__gFailIds) { [void]$script:__gFailIds.Add($gfId) }
        if (-not $script:__gFirstErr -and ($status -eq 401 -or $status -eq 403 -or $errText -match 'HTTP (401|403)\b')) { $script:__gFirstErr = $errText }
        if ($script:__gFail -le 3) { Write-Warning ("  [revoke] {0} for group '{1}' failed: {2}" -f $(if ($pi % 2 -eq 0) { 'assignmentSchedules' } else { 'eligibilitySchedules' }), $pimGroupsToRead[[int][Math]::Floor($pi / 2)].DisplayName, $errText) }
    }
    $script:__gFail = 0; $script:__gFirstErr = $null; $script:__gFailIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($gPaths.Count -gt 0 -and (Get-Command Invoke-PimGraphBatchGet -ErrorAction SilentlyContinue)) {
        # REQUIREMENTS 67.1: through the engine's shared batch reader (follows @odata.nextLink, re-runs a 429 / 5xx itself).
        $gRes = Invoke-PimGraphBatchGet -Paths @($gPaths.ToArray()) -ProgressLabel '[revoke] pim-for-groups'   # SCHEMA-QUIESCE-LONG-SNAPSHOT: alive every 5 min
        if ($null -ne $gRes -and $gRes -isnot [System.Collections.IList]) { $gRes = @($gRes) }   # 100.31: one answer can arrive unrolled
        for ($i = 0; $i -lt $gPaths.Count; $i++) {
            $gr = $gRes[$i]; $gRes[$i] = $null   # 100.31: released as it is consumed
            if ($gr -and $gr.ok) { & $takeAnswer $i $true @($gr.items) 200 ''; continue }
            & $takeAnswer $i $false @() $(if ($gr) { [int]$gr.status } else { 0 }) $(if ($gr) { "$($gr.error)" } else { 'no response' })
        }
        $gRes = $null
    } elseif ($gPaths.Count -gt 0) {
        for ($ofs = 0; $ofs -lt $gPaths.Count; $ofs += 20) {
            $last = [Math]::Min($ofs + 19, $gPaths.Count - 1)
            $requests = New-Object System.Collections.ArrayList
            for ($i = $ofs; $i -le $last; $i++) { [void]$requests.Add(@{ id = "$i"; method = 'GET'; url = $gPaths[$i] }) }
            try {
                $resp = Invoke-PimGraph -Method POST -Path 'https://graph.microsoft.com/v1.0/$batch' -Body @{ requests = $requests.ToArray() }
                foreach ($br in @($resp.responses)) {
                    if ("$($br.id)" -notmatch '^\d+$') { continue }
                    $pi = [int]$br.id
                    if ($br.status -ge 200 -and $br.status -lt 300) { & $takeAnswer $pi $true @(if ($br.body) { @($br.body.value) }) ([int]$br.status) ''; continue }
                    $errText = if ($br.body -and $br.body.error) { "HTTP $($br.status) $($br.body.error.code) : $($br.body.error.message)" } else { "HTTP $($br.status)" }
                    & $takeAnswer $pi $false @() ([int]$br.status) $errText
                }
            } catch {
                for ($i = $ofs; $i -le $last; $i++) { & $takeAnswer $i $false @() 0 "$($_.Exception.Message)" }
            }
        }
    }
    $gFail = $script:__gFail; $gFirstErr = $script:__gFirstErr
    if ($gFail -gt 3) { Write-Warning ("  [revoke] PIM-for-Groups schedules failed for {0} read(s) total (first 3 shown)." -f $gFail) }
    # A surface-level error only when EVERY read failed AND nothing came back -- a few per-group failures are tolerated.
    if (($pimGroupRows.Count + $pimGroupEligRows.Count) -eq 0 -and $gPaths.Count -gt 0 -and $gFail -ge $gPaths.Count -and $gFirstErr) {
        [void]$surfaceErrors.Add([ordered]@{ surface = 'pim-for-groups'; error = $gFirstErr; hint = (Get-PimActiveAssignmentSurfaceHint -Surface 'pim-for-groups' -ErrorMessage $gFirstErr) })
    } elseif ($null -ne $script:__gFailIds -and $script:__gFailIds.Count -gt 0) {
        # TRUST-1 round 4 item 14: SOME groups could not be read -- a surface error that names them (groupIds), so the job carries
        # only those groups' last good rows and keeps the fresh rows of every group that was read (it used to drop them silently)
        $gIds = [string[]]@($script:__gFailIds | Sort-Object)
        $gEm = "the schedules of $($gIds.Count) group(s) could not be read" + $(if ($gFirstErr) { ": $gFirstErr" } else { '' })
        [void]$surfaceErrors.Add([ordered]@{ surface = 'pim-for-groups'; error = $gEm; hint = (Get-PimActiveAssignmentSurfaceHint -Surface 'pim-for-groups' -ErrorMessage "$gFirstErr"); groupIds = $gIds })
    }
    Write-Host ("  [revoke] pim-for-groups: {0} active + {1} eligible schedule(s) across {2} group(s) ({3} batch round-trips)" -f $pimGroupRows.Count, $pimGroupEligRows.Count, $pimGroupsToRead.Count, [Math]::Ceiling($gPaths.Count / 20)) -ForegroundColor DarkGray
    # Casing-tolerant property read: SDK objects are PascalCase, REST/$batch bodies are camelCase.
    $pf = {
        param($Obj, [string[]]$Names)
        foreach ($n in $Names) { $pr = $Obj.PSObject.Properties[$n]; if ($pr -and $null -ne $pr.Value) { return $pr.Value } }
        return $null
    }
    foreach ($set in @(@{ list = $pimGroupRows; state = 'active' }, @{ list = $pimGroupEligRows; state = 'eligible' })) {
        $lst = $set.list; $gState = $set.state
        for ($pgi = 0; $pgi -lt $lst.Count; $pgi++) {
            $p = $lst[$pgi]; $lst[$pgi] = $null   # 100.31: the raw schedule goes once its row exists
            if (-not $p) { continue }
            $principalId = "$(& $pf $p @('PrincipalId','principalId'))"
            $groupId     = "$(& $pf $p @('GroupId','groupId'))"
            $itemId      = "$(& $pf $p @('Id','id'))"
            $principalLabel = Resolve-PimManagerPrincipalLabel -PrincipalId $principalId
            $groupLabel = ''
            # Id-keyed lookup (built with the caches) -- the old linear scan was O(rows x groups).
            if ($script:PimManager_GroupById -and $script:PimManager_GroupById.ContainsKey($groupId)) {
                $groupLabel = [string]$script:PimManager_GroupById[$groupId].DisplayName
            } elseif ($script:PimManager_ResolvedById -and $script:PimManager_ResolvedById.ContainsKey($groupId)) {
                $groupLabel = [string]$script:PimManager_ResolvedById[$groupId].displayName
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
            # 95.2l: an ACTIVE owner says WHICH kind -- an eligible owner who activated, or a permanent (no end date) owner assignment.
            $__accLbl = $access
            if ($gState -eq 'active') {
                $__expT = ''; if ($si) { $__ex = & $pf $si @('Expiration','expiration'); if ($__ex) { $__expT = "$(& $pf $__ex @('Type','type'))" } }
                $__accLbl = Get-PimActiveGroupAccessLabel -AccessId $access -AssignmentType "$(& $pf $p @('AssignmentType','assignmentType'))" -ExpirationType $__expT -End $end
            }
            [void]$rows.Add([ordered]@{
                id               = $(if ($gState -eq 'eligible') { "pim-for-groups-eligible:$itemId" } else { "pim-for-groups:$itemId" })
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
                state            = $gState
            })
        }
        $lst.Clear()
    }

    # ---- 5. apps holding a HIGH-PRIVILEGE API permission -----------------------
    $appRes = Get-PimActiveAssignmentsAppPermissionRows
    if ("$($appRes.error)".Trim()) {
        Write-Warning "  [revoke] app-permission read failed: $($appRes.error)"
        & $addErr 'app-permission' "$($appRes.error)" ''
    } else {
        foreach ($ar in $appRes.rows) { [void]$rows.Add($ar) }
        Write-Host ("  [revoke] app-permission: {0} high-privilege API permission(s) held by apps ({1} read(s))" -f $appRes.rows.Count, $appRes.reads) -ForegroundColor DarkGray
    }
    $appOk = -not "$($appRes.error)".Trim()
    $appRes = $null

    # ---- BUG-98: second pass -- resolve every principal that the filtered caches missed ----
    # Done ONCE here: the distinct id set is complete, ~700 rows collapse into a single /directoryObjects/getByIds call.
    # Every row also gains principalKind so the GUI can tell a person from a group or an app (or a DELETED principal).
    try {
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
            # a carried / app row keeps the kind it was built with when this run has no answer for it
            $pk = Get-PimManagerPrincipalKind -PrincipalId ([string]$row.principalId)
            if ($pk -or -not $row.Contains('principalKind')) { $row['principalKind'] = $pk }
        }
    } catch {
        Write-Warning "  [revoke] principal second-pass resolve failed: $($_.Exception.Message)"
    }

    $sw.Stop()
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    $byType = @{ 'entra-role' = 0; 'azure-rbac' = 0; 'pim-for-groups' = 0; 'app-permission' = 0 }
    $eligibleN = 0
    foreach ($row in $rows) { $t = "$($row.type)"; if ($byType.ContainsKey($t)) { $byType[$t]++ }; if ("$($row.state)" -eq 'eligible') { $eligibleN++ } }
    $counts = [ordered]@{
        total            = $rows.Count
        'entra-role'     = $byType['entra-role']
        'azure-rbac'     = $byType['azure-rbac']
        'pim-for-groups' = $byType['pim-for-groups']
        'app-permission' = $byType['app-permission']
        eligible         = $eligibleN
    }
    Write-Host ("  [revoke] delegations loaded: {0} total ({1}e + {2}a + {3}g + {4}p; {5} eligible) in {6}s" -f $counts.total, $counts['entra-role'], $counts['azure-rbac'], $counts['pim-for-groups'], $counts['app-permission'], $eligibleN, $elapsed) -ForegroundColor DarkGray

    $errArr = $surfaceErrors.ToArray()
    if ($errArr.Count -gt 0) {
        Write-Warning ("  [revoke] {0} surface(s) could NOT be read: {1}" -f $errArr.Count, (($errArr | ForEach-Object { $_.surface }) -join ', '))
    }
    $allFailedEmpty = ($rows.Count -eq 0 -and $errArr.Count -gt 0)
    $pfgFailed = $false; foreach ($se in $errArr) { if ("$($se.surface)" -eq 'pim-for-groups') { $pfgFailed = $true } }
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
        # when each part was read (owner, split cadence): '' = not read completely in this generation
        parts         = [ordered]@{
            entraReadUtc          = $(if ($entraOk) { $runUtc } else { '' })
            azureReadUtc          = $azureReadUtc
            azureMode             = $(if ($azRead) { 'read' } else { 'carried' })
            azureReason           = $azReason
            azureRows             = [long]$counts['azure-rbac']
            groupsReadUtc         = $(if (-not $pfgFailed) { $runUtc } else { '' })
            groupsRead            = [long]$pimGroupsToRead.Count
            appPermissionsReadUtc = $(if ($appOk) { $runUtc } else { '' })
        }
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
# TRUST-1 (framework points 1, 2, 3, 7): which surfaces failed THIS run, which the install does not have, and carrying a
# failed surface's last good rows forward
# ===========================================================================
function Get-PimActiveAssignmentsSurfaceParts {
    <# PURE. surface -> { type (the row type it feeds); stamp (the header's per-part read time) } -- a literal. #>
    return @{
        'entra-role'     = @{ type = 'entra-role';     stamp = 'entraReadUtc' }
        'azure-rbac'     = @{ type = 'azure-rbac';     stamp = 'azureReadUtc' }
        'pim-for-groups' = @{ type = 'pim-for-groups'; stamp = 'groupsReadUtc' }
        'app-permission' = @{ type = 'app-permission'; stamp = 'appPermissionsReadUtc' }
    }
}

function Get-PimActiveAssignmentsHeaderField {
    # PURE. A field of a stored header (parsed JSON or a dictionary), $null when absent.
    param([AllowNull()][object]$Header, [string]$Name)
    if ($null -eq $Header) { return $null }
    if ($Header -is [System.Collections.IDictionary]) { if ($Header.Contains($Name)) { return $Header[$Name] }; return $null }
    if ($Header.PSObject.Properties[$Name]) { return $Header.$Name }
    return $null
}

if (-not (Get-Command Get-PimTrustCarryMaxAgeDays -ErrorAction SilentlyContinue)) {
    function Get-PimTrustCarryMaxAgeDays { <# PURE. LITERAL. Framework TRUST-1 point 8 (the same value as PIM-JobLanes.ps1). #> return 7 }
}

function Split-PimActiveAssignmentsSurfaceErrors {
    <#
      PURE. Framework TRUST-1 point 7: a source the install does NOT HAVE is not part of the check. Every engine Graph read
      (RoleManagement.Read.All, Directory.Read.All, Application.Read.All, the PIM-for-Groups schedules) and the Azure Reader
      (reader@subscription / reader@tenant-root, 'always') are in PIM's approved rights list (engine\_shared\PIM-RightsList.ps1),
      so a failure of any of them FAILED THIS TIME. No surface of this read is behind a feature switch. The one source an
      install may simply not have is Azure itself: ARM lists NO subscription for the engine (an Entra-only tenant) and Azure was
      NEVER read before -- ABSENT BY DESIGN. "Read before" (round 3 item 5) = the previous header (either store form) has Azure
      rows: azureRows > 0 or counts.'azure-rbac' > 0 (an upgraded header without azureReadUtc counts too). -PreviousUnreadable
      (the previous header could not be read) = nothing is absent: every failure counts as failed this time.
      Returns @{ failed = [object[]]; absent = [object[]] { surface; code; reason } }.
    #>
    param([AllowNull()][object[]]$SurfaceErrors, [AllowNull()][object]$PreviousHeader = $null, [switch]$PreviousUnreadable)
    $failed = [System.Collections.Generic.List[object]]::new(); $absent = [System.Collections.Generic.List[object]]::new()
    $num = { param($v) $n = [long]0; [void][long]::TryParse("$v", [ref]$n); $n }
    $prevAzRows = & $num (Get-PimActiveAssignmentsHeaderField $PreviousHeader 'azureRows')
    $prevAzCount = & $num (Get-PimActiveAssignmentsHeaderField (Get-PimActiveAssignmentsHeaderField $PreviousHeader 'counts') 'azure-rbac')
    $azReadBefore = ($prevAzRows -gt 0 -or $prevAzCount -gt 0)
    foreach ($e in @($SurfaceErrors)) {
        if ($null -eq $e) { continue }
        $surf = "$(Get-PimActiveAssignmentsHeaderField $e 'surface')"
        $msg = "$(Get-PimActiveAssignmentsHeaderField $e 'error')"
        if (-not $PreviousUnreadable -and $surf -eq 'azure-rbac' -and $msg -match '(?i)\b0 subscriptions\b' -and -not $azReadBefore) {
            $absent.Add([ordered]@{ surface = $surf; code = 'AA-AZURE-NOT-PRESENT'; reason = 'no Azure subscription is visible to the engine (an Entra-only tenant): Azure is not part of this install''s check' })
        } else { $failed.Add($e) }
    }
    return @{ failed = $failed.ToArray(); absent = $absent.ToArray() }
}

function Get-PimActiveAssignmentsRowSubscriptionId {
    <# PURE. TRUST-1-NEXT (b): the subscription id an Azure row sits at or below (its scope, else its id), '' when above every
       subscription (a management group, the root) or not an Azure row. #>
    param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return '' }
    foreach ($n in 'scope', 'id') {
        $v = "$(Get-PimActiveAssignmentsHeaderField $Row $n)"
        if ($n -eq 'id') { $v = $v -replace '^azure-rbac(-eligible)?:', '' }
        if ($v -match '^(?i)/subscriptions/([^/]+)') { return "$($Matches[1])".ToLowerInvariant() }
        if ($n -eq 'scope' -and $v.Trim()) { return '' }   # a scope above every subscription
    }
    return ''
}

function Merge-PimActiveAssignmentsCarriedRows {
    <#
      TRUST-1 gap 4 (framework points 2 + 8). The rows of a surface that FAILED this run are replaced by that surface's rows of the
      previous complete generation (-PreviousHeader + -Context.ReadKind, as Azure is carried already), each part keeping its
      last good read time. Round 3 item 10: a surface whose failures are ALL of its eligible half (state = 'eligible') carries
      only its ELIGIBLE rows -- this run's fresh active rows stay. A part carried longer than Get-PimTrustCarryMaxAgeDays is
      STALE (point 8): its rows are still carried and listed with their date, and it is named in 'stale' with the stable code
      AA-SOURCE-STALE. A surface with no previous rows to carry (a NEW install, a part never read, a one-document previous
      store, rows that do not add up to the header's count) keeps what this run read of it and is named 'missing'.
      Returns @{ rows = [object[]]; carried = [object[]] { surface; type; rows; fromSnapshotId; readUtc; eligibleOnly };
      missing = [object[]]; stale = [object[]] { surface; code; sinceUtc } }.
    #>
    param([AllowNull()][object[]]$Rows, [AllowNull()][object[]]$Failed, [AllowNull()][object]$PreviousHeader = $null, [AllowNull()][hashtable]$Context = $null,
          [datetime]$NowUtc = [datetime]::UtcNow)
    $parts = Get-PimActiveAssignmentsSurfaceParts
    $carried = [System.Collections.Generic.List[object]]::new(); $missing = [System.Collections.Generic.List[object]]::new(); $stale = [System.Collections.Generic.List[object]]::new()
    $replace = @{}   # type -> @{ rows; eligibleOnly }
    $sid = [long]0; [void][long]::TryParse("$(Get-PimActiveAssignmentsHeaderField $PreviousHeader 'snapshotId')", [ref]$sid)
    $prevCounts = Get-PimActiveAssignmentsHeaderField $PreviousHeader 'counts'
    $bySurface = [ordered]@{}
    foreach ($e in @($Failed)) { $s = "$(Get-PimActiveAssignmentsHeaderField $e 'surface')"; if (-not $bySurface.Contains($s)) { $bySurface[$s] = [System.Collections.Generic.List[object]]::new() }; $bySurface[$s].Add($e) }
    foreach ($surf in @($bySurface.Keys)) {
        if (-not $parts.ContainsKey($surf)) { continue }
        $t = $parts[$surf].type
        $eligOnly = (@($bySurface[$surf] | Where-Object { "$(Get-PimActiveAssignmentsHeaderField $_ 'state')" -ne 'eligible' }).Count -eq 0)
        # round 4 item 14: a failure of SOME groups (every entry names its groupIds) carries only those groups' rows
        $grpSet = $null
        # (never `@(Get-...Field ...)`: a field that is absent returns $null and @() of a function that returns $null is EMPTY)
        if (@($bySurface[$surf] | Where-Object { $gv = Get-PimActiveAssignmentsHeaderField $_ 'groupIds'; $null -eq $gv -or -not @($gv | Where-Object { "$_".Trim() }).Count }).Count -eq 0) {
            $grpSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($ge in $bySurface[$surf]) { foreach ($gid in @(Get-PimActiveAssignmentsHeaderField $ge 'groupIds')) { if ("$gid".Trim()) { [void]$grpSet.Add("$gid".Trim()) } } }
            if ($grpSet.Count -eq 0) { $grpSet = $null }
        }
        # TRUST-1-NEXT (b): a failure of SOME Azure subscriptions (every entry names its subscriptionIds) carries only the rows of
        # those subscriptions (scope at or below /subscriptions/<id>), plus a previous row ABOVE every subscription (a management
        # group / the root, listed through a subscription) that this run did not see again -- never reported absent
        $subSet = $null
        if ($t -eq 'azure-rbac' -and @($bySurface[$surf] | Where-Object { $sv = Get-PimActiveAssignmentsHeaderField $_ 'subscriptionIds'; $null -eq $sv -or -not @($sv | Where-Object { "$_".Trim() }).Count }).Count -eq 0) {
            $subSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($se in $bySurface[$surf]) { foreach ($sbid in @(Get-PimActiveAssignmentsHeaderField $se 'subscriptionIds')) { if ("$sbid".Trim()) { [void]$subSet.Add("$sbid".Trim()) } } }
            if ($subSet.Count -eq 0) { $subSet = $null }
        }
        $prevRead ="$(ConvertTo-PimActiveAssignmentsIsoStamp -Value (Get-PimActiveAssignmentsHeaderField $PreviousHeader $parts[$surf].stamp))"
        $want = [long]-1; [void][long]::TryParse("$(Get-PimActiveAssignmentsHeaderField $prevCounts $t)", [ref]$want)
        $reader = $null
        if ($null -ne $Context) { if ($Context.ContainsKey('ReadKind')) { $reader = { param($c, $s, $k) & $c.ReadKind $c $s $k } } elseif ($t -eq 'azure-rbac' -and $Context.ContainsKey('ReadAzure')) { $reader = { param($c, $s, $k) & $c.ReadAzure $c $s } } }
        $got = $null
        if ($sid -gt 0 -and $prevRead -and $want -ge 0 -and $reader) {
            try {
                $json = & $reader $Context $sid $t
                $list = [System.Collections.Generic.List[object]]::new()
                if ("$json".Length -gt 2) {
                    $parsed = ConvertFrom-Json -InputObject "$json"   # assigned first: PS 5.1 emits the array as ONE object
                    foreach ($x in @($parsed)) { foreach ($y in @($x)) { if ($null -ne $y) { $list.Add((ConvertFrom-PimActiveAssignmentsStoredRow -Row $y)) } } }
                }
                if ([long]$list.Count -eq $want) { $got = $list }
            } catch { $got = $null }
        }
        if ($null -ne $got) {
            # never ` = if (...) { list }`: an if-statement's output unrolls the list (a one-row list became the row itself)
            $keep = $got
            if ($eligOnly -or $null -ne $grpSet -or $null -ne $subSet) {
                $nowIds = $null
                if ($null -ne $subSet) { $nowIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase); foreach ($r0 in @($Rows)) { if ($null -ne $r0 -and "$($r0.type)" -eq $t) { [void]$nowIds.Add("$($r0.id)") } } }
                $keep = [System.Collections.Generic.List[object]]::new()
                foreach ($r in $got) {
                    if ($eligOnly -and "$($r.state)" -ne 'eligible') { continue }
                    if ($null -ne $grpSet -and -not $grpSet.Contains("$($r.groupId)")) { continue }
                    if ($null -ne $subSet) {
                        $rSub = Get-PimActiveAssignmentsRowSubscriptionId -Row $r
                        if ($rSub) { if (-not $subSet.Contains($rSub)) { continue } }
                        elseif ($nowIds.Contains("$($r.id)")) { continue }   # above every subscription and read again this run
                    }
                    $keep.Add($r)
                }
            }
            $maxD = Get-PimTrustCarryMaxAgeDays
            $ageOf = { param($iso) $a = $null; try { $a = [datetime]::Parse("$iso", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } catch { $a = $null }; if ($null -eq $a) { -1 } else { ($NowUtc.ToUniversalTime() - $a).TotalDays } }
            $isStale = ((& $ageOf $prevRead) -gt $maxD)
            # round 4 item 4: EACH carried row says so (its JSON goes to the Revoke tab): never offered for a revoke there.
            # Round 5 G6: a row that was ALREADY carried keeps ITS carriedFromUtc (when it was last really read) -- for a subset of
            # PIM-for-Groups the part's read time moves on with this run, so the part's time is not the row's; stale is per row,
            # and for a group subset per GROUP (one stale entry per group, with that group's own date).
            $grpStale = [ordered]@{}; $grpFrom = [ordered]@{}
            foreach ($r in $keep) {
                if ($r -isnot [System.Collections.IDictionary]) { continue }
                $from = $prevRead
                if ($r.Contains('carried') -and [bool]$r['carried'] -and "$($r['carriedFromUtc'])".Trim()) {
                    # the stored row went through ConvertFrom-PimActiveAssignmentsStoredRow (round-trip 'o' text on pwsh 7) -- back to the header's form
                    $from = "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value $r['carriedFromUtc'])"
                    try { $from = [datetime]::Parse($from, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal').ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) } catch { }
                }
                $rs = ((& $ageOf $from) -gt $maxD)
                $r['carried'] = $true; $r['carriedFromUtc'] = $from; $r['stale'] = [bool]$rs
                if ($null -ne $grpSet) { $g0 = "$($r['groupId'])"; if (-not $grpFrom.Contains($g0) -or "$from" -lt "$($grpFrom[$g0])") { $grpFrom[$g0] = $from } }
                if ($null -ne $grpSet -and $rs) { $g0 = "$($r['groupId'])"; if (-not $grpStale.Contains($g0) -or "$from" -lt "$($grpStale[$g0])") { $grpStale[$g0] = $from } }
                if ($null -ne $subSet -and $rs) { $s0 = Get-PimActiveAssignmentsRowSubscriptionId -Row $r; if (-not $s0) { $s0 = '/' }; if (-not $grpStale.Contains($s0) -or "$from" -lt "$($grpStale[$s0])") { $grpStale[$s0] = $from } }
            }
            $replace[$t] = @{ rows = $keep; eligibleOnly = $eligOnly; groups = $grpSet; subscriptions = $subSet }
            $carried.Add([ordered]@{ surface = $surf; type = $t; rows = [long]$keep.Count; fromSnapshotId = $sid; readUtc = $prevRead; eligibleOnly = $eligOnly; groupIds = $(if ($null -ne $grpSet) { [string[]]@($grpSet | Sort-Object) } else { $null }); subset = ($null -ne $grpSet -or $null -ne $subSet)
                # round 6 F1: per carried group its oldest real read -- an all-failed run after this one ages each group from here
                groupsFrom = $(if ($null -ne $grpSet) { $grpFrom } else { $null })
                # TRUST-1-NEXT (b): the subscriptions not read this run (UNKNOWN, their rows carried) + the stable code
                subscriptionIds = $(if ($null -ne $subSet) { [string[]]@($subSet | Sort-Object) } else { $null }); code = $(if ($null -ne $subSet) { 'AA-AZURE-SUBSCRIPTION-NOT-READ' } else { $null }) })
            if ($null -ne $grpSet) { foreach ($g0 in @($grpStale.Keys)) { $stale.Add([ordered]@{ surface = $surf; groupId = "$g0"; code = 'AA-SOURCE-STALE'; sinceUtc = "$($grpStale[$g0])" }) } }
            elseif ($null -ne $subSet) { foreach ($s0 in @($grpStale.Keys)) { $stale.Add([ordered]@{ surface = $surf; subscriptionId = "$s0"; code = 'AA-SOURCE-STALE'; sinceUtc = "$($grpStale[$s0])" }) } }
            elseif ($isStale) { $stale.Add([ordered]@{ surface = $surf; code = 'AA-SOURCE-STALE'; sinceUtc = $prevRead }) }
        } else { $missing.Add([ordered]@{ surface = $surf; type = $t; reason = $(if ($sid -le 0) { 'no previous complete read to carry from' } else { 'the previous rows of this part could not be carried' }) }) }
    }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $rt = "$($r.type)"
        # a fresh row of a failed subscription is dropped (its last good rows replace it); a fresh row above every subscription stays
        if ($replace.ContainsKey($rt) -and (-not $replace[$rt].eligibleOnly -or "$($r.state)" -eq 'eligible') -and ($null -eq $replace[$rt].groups -or $replace[$rt].groups.Contains("$($r.groupId)")) -and
            ($null -eq $replace[$rt].subscriptions -or $replace[$rt].subscriptions.Contains("$(Get-PimActiveAssignmentsRowSubscriptionId -Row $r)"))) { continue }
        $out.Add($r)
    }
    foreach ($t in @($replace.Keys)) { foreach ($r in $replace[$t].rows) { $out.Add($r) } }
    return @{ rows = $out.ToArray(); carried = $carried.ToArray(); missing = $missing.ToArray(); stale = $stale.ToArray() }
}

function Find-PimActiveAssignmentsRowIdsForPayload {
    <#
      TRUST-1 round 6 F8: the stored snapshot rows a STAGED revoke names, found from its payload (a revoke queued before the
      payload carried sourceRowId). Read-only. Matches the current generation's rows of the payload's kind by principal and the
      assignment's own id (roleAssignmentId; else roleDefinitionId; groupId for PIM-for-Groups). Returns the row ids found PLUS
      '<kind>:' (no row id, only the kind) -- so a part the newest run did not read is refused by its kind even when no row matches.
      A store error THROWS (the caller refuses: "cannot tell"). -Read { param($kind, $p) -> ids }: test seam.
    #>
    param([Parameter(Mandatory)][object]$Payload, [string]$ConnectionString = '', [scriptblock]$Read = $null)
    $pv = { param($n) if ($Payload -is [System.Collections.IDictionary]) { "$($Payload[$n])".Trim() } elseif ($Payload.PSObject.Properties[$n]) { "$($Payload.$n)".Trim() } else { '' } }
    $map = @{ 'entra-role-revoke' = 'entra-role'; 'azure-rbac-revoke' = 'azure-rbac'; 'group-assignment-revoke' = 'pim-for-groups' }
    $kind = "$($map["$(& $pv 'type')".ToLowerInvariant()])"
    if (-not $kind) { return @() }
    $ids = [System.Collections.Generic.List[string]]::new()
    if (-not $Read) {
        if (-not "$ConnectionString".Trim() -and (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) { $ConnectionString = "$(Get-PimTenantCacheStoreCs)" }
        if ("$ConnectionString".Trim() -and (Get-Command Invoke-PimSqlQuery -ErrorAction SilentlyContinue) -and (Get-Command Get-PimSqlActiveAssignmentsCurrentSnapshotId -ErrorAction SilentlyContinue)) {
            $cs1 = $ConnectionString
            $Read = { param($k, $prm)
                $sid = [long](Get-PimSqlActiveAssignmentsCurrentSnapshotId -ConnectionString $cs1)
                $w = "(@ra <> N'' AND JSON_VALUE(j, '$.roleAssignmentId') = @ra) OR (@ra = N'' AND @rd <> N'' AND JSON_VALUE(j, '$.roleDefinitionId') = @rd) OR (@g <> N'' AND JSON_VALUE(j, '$.groupId') = @g)"
                if ($sid -gt 0) { $sql = "SELECT RowId AS id FROM (SELECT RowId, CASE WHEN ISJSON(RowJson) = 1 THEN RowJson END AS j FROM pim.ActiveAssignmentRows WHERE SnapshotId = @s AND Kind = @k AND PrincipalId = @p) x WHERE $w" }
                else { $sql = "SELECT j0.id AS id FROM pim.TenantCache t CROSS APPLY OPENJSON(CASE WHEN ISJSON(t.ValueJson) = 1 THEN t.ValueJson END, '$.rows') WITH (id nvarchar(450) '$.id', type nvarchar(40) '$.type', principalId nvarchar(200) '$.principalId', j nvarchar(max) '$' AS JSON) j0 WHERE t.Kind = N'active-assignments' AND j0.type = @k AND j0.principalId = @p AND ($w)" }
                @(Invoke-PimSqlQuery -ConnectionString $cs1 -Sql $sql -Parameters @{ s = $sid; k = $k; p = $prm.p; ra = $prm.ra; rd = $prm.rd; g = $prm.g } | ForEach-Object { "$($_.id)" }) }
        }
    }
    if ($Read) { foreach ($x in @(& $Read $kind @{ p = (& $pv 'principalId'); ra = (& $pv 'roleAssignmentId'); rd = (& $pv 'roleDefinitionId'); g = (& $pv 'groupId') })) { if ("$x".Trim()) { $ids.Add("$x".Trim()) } } }
    $ids.Add("$kind`:")
    return $ids.ToArray()
}

function Register-PimActiveAssignmentsStaleParts {
    <#
      TRUST-1 point 8 + round 6 F6 / F1: hand EVERY stale part of this run to Register-PimTrustStaleReport, on every run. The
      stall-report list is what says "already asked for" (id = job | part | source-stale | since; kept 60 days, sent or not), so
      the same stale part opens exactly ONE fix request, and a registration that failed (a throw, a store that was down) is
      simply made on the next run. A stale GROUP of PIM-for-Groups is its own part: pim-for-groups.<group id>. Never throws.
    #>
    param([AllowNull()][object[]]$Stale, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Get-Command Register-PimTrustStaleReport -ErrorAction SilentlyContinue)) { return }
    foreach ($sx in @($Stale)) {
        if ($null -eq $sx) { continue }
        $g = "$(Get-PimActiveAssignmentsHeaderField $sx 'groupId')".Trim()
        if (-not $g) { $g = "$(Get-PimActiveAssignmentsHeaderField $sx 'subscriptionId')".Trim() }   # TRUST-1-NEXT (b): azure-rbac.<subscription>
        $part = "$(Get-PimActiveAssignmentsHeaderField $sx 'surface')" + $(if ($g) { ".$g" } else { '' })
        try { [void](Register-PimTrustStaleReport -Job 'pim-active-assignments-snapshot' -Part $part -Code 'AA-SOURCE-STALE' -SinceUtc "$(Get-PimActiveAssignmentsHeaderField $sx 'sinceUtc')" -NowUtc $NowUtc) } catch { }
    }
}
function Get-PimActiveAssignmentsCarriedRows {
    <#
      TRUST-1 round 4 item 4: which of -Ids are CARRIED rows of the stored snapshot (not read this run, shown from the last
      complete read) -- the revoke API refuses them whatever the page sent. Table form: one read-only SQL over the current
      generation's rows (RowJson carried = true); the one-document form: the stored document's rows. Returns
      { known; rows = @{ id -> { carriedFromUtc; stale } }; error }. known = $false = could not tell (the caller refuses then).
      -Read { param($ids) -> rows { id; carriedFromUtc; stale } }: test seam.
    #>
    param([AllowNull()][string[]]$Ids, [string]$ConnectionString = '', [scriptblock]$Read = $null, [scriptblock]$Header = $null)
    $out = @{}
    $want = @(@($Ids) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Select-Object -Unique)
    if (-not $want.Count) { return [pscustomobject]@{ known = $true; rows = $out; error = '' } }
    try {
        if (-not $Read) {
            if (-not "$ConnectionString".Trim() -and (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue)) { $ConnectionString = "$(Get-PimTenantCacheStoreCs)" }
            $sid = [long]0
            if ("$ConnectionString".Trim() -and (Get-Command Get-PimSqlActiveAssignmentsCurrentSnapshotId -ErrorAction SilentlyContinue)) { $sid = [long](Get-PimSqlActiveAssignmentsCurrentSnapshotId -ConnectionString $ConnectionString) }
            if ($sid -gt 0) {
                $cs0 = $ConnectionString
                $Read = { param($ids) @(Invoke-PimSqlQuery -ConnectionString $cs0 -Sql "SELECT RowId AS id, CASE WHEN ISJSON(RowJson) = 1 THEN JSON_VALUE(RowJson, '$.carriedFromUtc') END AS carriedFromUtc, CASE WHEN ISJSON(RowJson) = 1 THEN JSON_VALUE(RowJson, '$.stale') END AS stale FROM pim.ActiveAssignmentRows WHERE SnapshotId = @s AND RowId IN (SELECT [value] FROM OPENJSON(@ids)) AND ISNULL(CASE WHEN ISJSON(RowJson) = 1 THEN JSON_VALUE(RowJson, '$.carried') END, N'') = N'true'" -Parameters @{ s = $sid; ids = (ConvertTo-Json -InputObject @($ids) -Compress) }) }
            } elseif ("$ConnectionString".Trim() -and (Get-Command Invoke-PimSqlQuery -ErrorAction SilentlyContinue)) {
                # round 5 H8: the ONE-DOCUMENT form is filtered IN SQL (OPENJSON over its rows, only the asked ids, only carried ones)
                # -- never the whole 22 MB document read and parsed into this process for a revoke
                $cs0 = $ConnectionString
                $Read = { param($ids) @(Invoke-PimSqlQuery -ConnectionString $cs0 -Sql "SELECT j.id AS id, j.carriedFromUtc AS carriedFromUtc, j.stale AS stale FROM pim.TenantCache t CROSS APPLY OPENJSON(CASE WHEN ISJSON(t.ValueJson) = 1 THEN t.ValueJson END, '$.rows') WITH (id nvarchar(450) '$.id', carried nvarchar(10) '$.carried', carriedFromUtc nvarchar(64) '$.carriedFromUtc', stale nvarchar(10) '$.stale') j WHERE t.Kind = N'active-assignments' AND j.carried = N'true' AND j.id IN (SELECT [value] FROM OPENJSON(@ids))" -Parameters @{ ids = (ConvertTo-Json -InputObject @($ids) -Compress) }) }
            } elseif (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue) {
                $Read = { param($ids) $e = Get-PimTenantCacheEntry -Kind 'active-assignments'; if ($null -eq $e) { return @() }; $set = @{}; foreach ($i in $ids) { $set["$i"] = $true }
                    @(@($e.rows) | Where-Object { $null -ne $_ -and [bool]$_.carried -and $set.ContainsKey("$($_.id)") } | ForEach-Object { [pscustomobject]@{ id = "$($_.id)"; carriedFromUtc = "$($_.carriedFromUtc)"; stale = [bool]$_.stale } }) }
            } else { return [pscustomobject]@{ known = $false; rows = $out; error = 'the stored snapshot cannot be read in this process' } }
        }
        foreach ($r in @(& $Read $want)) { if ($null -ne $r -and "$($r.id)".Trim()) { $out["$($r.id)"] = [pscustomobject]@{ carriedFromUtc = "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value $r.carriedFromUtc)"; stale = ("$($r.stale)" -match '^(?i)(true|1)$') } } }
        # Round 5 G2: the KEPT snapshot whose newest run failed on every surface ages -- a part its lastRun names STALE
        # (AA-SOURCE-STALE) is not from today, so every asked row of that part ('<type>:<id>') is refused too. A header that
        # cannot be read THROWS here (known = $false = refused). -Header { -> Get-PimSqlActiveAssignmentsHeaderStamp }: test seam.
        if (-not $Header -and "$ConnectionString".Trim() -and (Get-Command Get-PimSqlActiveAssignmentsHeaderStamp -ErrorAction SilentlyContinue)) { $csH = $ConnectionString; $Header = { Get-PimSqlActiveAssignmentsHeaderStamp -ConnectionString $csH } }
        if ($Header) {
            $hs = & $Header
            # round 6 F3 (decided: every action on data not read this run is refused): a part the newest run could NOT read
            # (lastRun.surfaceErrors) is refused AT ONCE -- its rows are the kept generation's, as a partial run's carried rows are;
            # stale = $true once lastRun names it stale (past Get-PimTrustCarryMaxAgeDays)
            if ($null -ne $hs -and "$(Get-PimActiveAssignmentsHeaderField $hs 'lastRunTrusted')" -eq 'false') {
                $partsC = Get-PimActiveAssignmentsSurfaceParts; $stT = @{}; $heldT = @{}
                $sjL = "$(Get-PimActiveAssignmentsHeaderField $hs 'lastRunStaleJson')"
                if ($sjL.Trim()) { foreach ($x in @($sjL | ConvertFrom-Json)) { foreach ($y in @($x)) { if ($null -ne $y -and $partsC.ContainsKey("$($y.surface)")) { $stT[$partsC["$($y.surface)"].type] = "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value $y.sinceUtc)" } } } }
                $fjL = "$(Get-PimActiveAssignmentsHeaderField $hs 'lastRunFailedJson')"
                if ($fjL.Trim()) { foreach ($x in @($fjL | ConvertFrom-Json)) { foreach ($y in @($x)) { if ($null -ne $y -and $partsC.ContainsKey("$($y.surface)")) { $p0 = $partsC["$($y.surface)"]; $heldT[$p0.type] = "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value (Get-PimActiveAssignmentsHeaderField $hs $p0.stamp))" } } } }
                foreach ($k in @($stT.Keys)) { $heldT[$k] = $stT[$k] }
                foreach ($id in $want) { $tp = ("$id" -split ':', 2)[0]; if ($heldT.ContainsKey($tp) -and -not $out.ContainsKey("$id")) { $out["$id"] = [pscustomobject]@{ carriedFromUtc = $heldT[$tp]; stale = [bool]$stT.ContainsKey($tp) } } }
            }
        }
        return [pscustomobject]@{ known = $true; rows = $out; error = '' }
    } catch { return [pscustomobject]@{ known = $false; rows = $out; error = "$($_.Exception.Message)" } }
}

function Get-PimRevokeCarriedRefusal {
    <#
      PURE. TRUST-1 round 4 item 4: the 409 answer for a revoke request that names a row NOT read this run (carried / stale --
      the page's own flag, or the stored snapshot's, -Stored = Get-PimActiveAssignmentsCarriedRows), or $null when none does.
      Data that is not current is never revoked from (the page's disabled box is not the guard). -Stored.known = $false =
      refused too ("cannot tell" is never "fine").
    #>
    param([AllowNull()][object[]]$Rows, [AllowNull()][object]$Stored)
    $bad = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $id = "$($r.id)"
        $own = ($r.PSObject.Properties['carried'] -and [bool]$r.carried) -or ($r -is [System.Collections.IDictionary] -and $r.Contains('carried') -and [bool]$r['carried'])
        $st = $null; if ($null -ne $Stored -and $null -ne $Stored.rows -and $Stored.rows.ContainsKey($id)) { $st = $Stored.rows[$id] }
        if ($own -or $null -ne $st) { $bad.Add([ordered]@{ id = $id; lastReadUtc = $(if ($null -ne $st) { "$($st.carriedFromUtc)" } else { "$($r.carriedFromUtc)" }) }) }
    }
    if ($null -ne $Stored -and -not [bool]$Stored.known) {
        return [ordered]@{ status = 409; body = [ordered]@{ ok = $false; carried = $true; refusedCount = @($Rows).Count
            error = "Whether these rows are current could not be checked ($($Stored.error)) -- nothing was queued. Refresh the page and try again." } }
    }
    if (-not $bad.Count) { return $null }
    $when = @($bad | ForEach-Object { "$($_.lastReadUtc)" } | Where-Object { $_ } | Sort-Object | Select-Object -First 1)
    return [ordered]@{ status = 409; body = [ordered]@{ ok = $false; carried = $true; refusedCount = $bad.Count; refused = $bad.ToArray()
        error = ("{0} row(s) are not from today: they could not be read this time and are shown from the last complete read{1}. Nothing was queued -- revoke them once they are read again." -f $bad.Count, $(if ($when.Count) { " ($($when[0]))" } else { '' })) } }
}

function Get-PimActiveAssignmentsRowCounts {
    # PURE. The header's counts of a row set (the snapshot's own rule: per type, and how many are eligible).
    param([AllowNull()][object[]]$Rows)
    $n = @{ 'entra-role' = 0; 'azure-rbac' = 0; 'pim-for-groups' = 0; 'app-permission' = 0 }; $el = 0; $tot = 0
    foreach ($r in @($Rows)) { if ($null -eq $r) { continue }; $tot++; $t = "$($r.type)"; if ($n.ContainsKey($t)) { $n[$t]++ }; if ("$($r.state)" -eq 'eligible') { $el++ } }
    return [ordered]@{ total = $tot; 'entra-role' = $n['entra-role']; 'azure-rbac' = $n['azure-rbac']; 'pim-for-groups' = $n['pim-for-groups']; 'app-permission' = $n['app-permission']; eligible = $el }
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
      🔴 TRUST-1 (points 1, 2, 3, 7; gaps 1 + 4): a surface the install does not have = UNKNOWN (header 'unknown', a stable
         code), the run TRUSTED. A surface that failed THIS TIME = PARTIAL: its rows carried from the previous complete
         generation (header 'carried', the part's last good read time; 'missing' when there is nothing to carry), the other
         surfaces' rows this run's, ran=$true + warning=$true + trusted=$false. EVERY surface failed (no row read) = NOT
         written: the previous snapshot stays with 'lastRun' on its header (a new install stores the failure WITHOUT rows,
         Save-PimActiveAssignmentsSnapshotFailure), and the job THROWS (run failed, the engine-failure alert can fire).
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

    # Owner split cadence (2026-11-11): Azure (active + eligible) is read at most once a night and after PIM changed an Azure
    # assignment; between those its rows are carried forward from the stored generation (Get-PimSnapshotAzurePlan; no table
    # store = Azure is read). Passed only to a snapshot that takes it -- a stand-in without -AzurePlan still runs.
    $azCtx = $null
    try { $azCtx = New-PimSnapshotAzureContext } catch { $azCtx = $null }
    $azPlan = Get-PimSnapshotAzurePlan -Context $azCtx -NowUtc $NowUtc
    # TRUST-1: what was stored when this run STARTED -- the previous complete generation's header (what a failed surface is
    # carried from, and whether a part was read before) and the header's identity (a failing run never overwrites a header
    # a newer run wrote meanwhile). Unreadable = $null: nothing is carried and nothing is guarded beyond "not newer".
    # Round 3 item 5: the header is read in BOTH store forms (Get-PimSqlActiveAssignmentsHeaderStamp, JSON values only); a
    # header that cannot be read makes every failure count as failed THIS time (never absent).
    $prevHead = $null; $prevUnreadable = $false
    $startStamp = $null
    if (Get-Command Get-PimSqlActiveAssignmentsHeaderStamp -ErrorAction SilentlyContinue) {
        try { $startStamp = Get-PimSqlActiveAssignmentsHeaderStamp -ConnectionString "$(Get-PimTenantCacheStoreCs)" } catch { $startStamp = $null; $prevUnreadable = $true }
        if ($null -ne $startStamp -and [bool]$startStamp.exists) { $prevHead = $startStamp }
    } elseif ($null -ne $azCtx) { try { $prevHead = & $azCtx.ReadHeader $azCtx } catch { $prevHead = $null; $prevUnreadable = $true } }
    # Named parameters, never a hashtable splat: @{ Fresh = $true } reaches a wrapper as '-Fresh:', $true and the bare $true
    # then binds BY POSITION to the next parameter (VM gate 2026-10-20, Test-PimActiveAssignmentsSnapshot B6).
    $sc = Get-Command Invoke-PimActiveAssignmentsSnapshot -ErrorAction SilentlyContinue
    $useAz = [bool]($sc -and $sc.Parameters.ContainsKey('AzurePlan'))
    # the groups defined in PIM (the managed list) -- read only where the row store answers; else the naming rule alone finds PIM's own
    $mgIds = @(); if ($null -ne $azCtx) { $mgIds = @(Get-PimActiveAssignmentsManagedGroupIds -ConnectionString "$($azCtx.cs)") }
    $snap = if ($useAz) { Invoke-PimActiveAssignmentsSnapshot -Fresh -AzurePlan $azPlan -ManagedGroupIds $mgIds } else { Invoke-PimActiveAssignmentsSnapshot -Fresh }
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
    # Owner split cadence: when each part was read (header fields, so the page can say "as of" per part). azureReadUtc + azureRows
    # are also what the next run carries Azure forward from.
    if ($snap.Contains('parts') -and $null -ne $snap['parts']) {
        foreach ($pk in 'entraReadUtc', 'azureReadUtc', 'azureMode', 'azureReason', 'azureRows', 'groupsReadUtc', 'groupsRead', 'appPermissionsReadUtc') {
            if ($snap['parts'].Contains($pk)) { $entry[$pk] = $snap['parts'][$pk] }
        }
    }
    # 100.68: the Dashboard's "Activations handled" ledger -- every time-bound active assignment seen, recorded once
    # (insert-only, engine/_shared/PIM-ImpactCounters.ps1). Never fails the snapshot: a ledger error is said in the detail.
    # TRUST-1 review finding 7: kept BEFORE the trust decision on purpose -- it records only rows this run SAW (each a real
    # observation, insert-only, never counted twice), never a carried row; a surface that failed only means fewer were seen.
    $ledTxt = ''
    if (Get-Command Update-PimImpactActivationLedger -ErrorAction SilentlyContinue) {
        $led = Update-PimImpactActivationLedger -ConnectionString (Get-PimTenantCacheStoreCs) -Rows $snap.rows
        $ledTxt = if ($led.ok) { "; activation ledger +$($led.added)" } else { "; activation ledger NOT updated ($($led.error))" }
    }
    # TRUST-1 (framework points 1, 2, 3, 7). A surface the install does NOT HAVE (Split-...: Azure with no subscription, never
    # read before) is named UNKNOWN with a stable code and the run stays TRUSTED. A surface that FAILED THIS TIME makes the run
    # PARTIAL (a WARNING run, trusted = $false): its rows are CARRIED from the previous complete generation with their last
    # good read time (gap 4), the readable surfaces' rows are this run's -- held per surface, never all. A new install keeps
    # what it read of the failed surface, flagged 'missing'. Only when EVERY surface that should be read failed (no row read)
    # is the read not written at all: the previous snapshot stays with the failure on its header, the run FAILS (throw).
    $split = Split-PimActiveAssignmentsSurfaceErrors -SurfaceErrors $errs -PreviousHeader $prevHead -PreviousUnreadable:$prevUnreadable
    $errs = @($split.failed)
    $entry['surfaceErrors'] = $errs
    if (@($split.absent).Count) { $entry['unknown'] = @($split.absent) }
    $rowsRead = @($snap.rows).Count
    $allFailed = ($errs.Count -gt 0 -and $rowsRead -eq 0)
    $entry['ok'] = -not $allFailed
    $entry['partial'] = ($errs.Count -gt 0 -and -not $allFailed)
    if (-not $allFailed -and -not $entry['partial'] -and "$($entry['error'])".Trim() -and @($split.absent).Count) { $entry['error'] = '' }   # only an absent source: nothing failed
    if ($allFailed) {
        $fs = Save-PimActiveAssignmentsSnapshotFailure -Entry $entry -Start $startStamp -NowUtc $NowUtc
        $entry['rows'] = $null; $snap['rows'] = $null
        # Round 5 G2 / G3: the kept snapshot's parts that BECAME stale on this run open ONE fix request -- a part the kept header
        # already names stale (its lastRun.stale from an earlier all-failed run, or its own 'stale' list) is not new
        # round 6 F6: EVERY stale part is handed to the register on every run -- the stall-report list decides "already asked for"
        # (one request per part and since-date), so a registration that failed yesterday is made today; never a header flag
        if ($fs.kept -and @($fs.stale).Count) { Register-PimActiveAssignmentsStaleParts -Stale @($fs.stale) -NowUtc $NowUtc }
        $keptTxt = if ($fs.kept) { "the previous complete snapshot$(if ($fs.keptRefreshedUtc) { " (as of $($fs.keptRefreshedUtc))" }) stays in use; the failure is recorded on it -> $($fs.where)" }
                   elseif ($fs.newer) { "a newer snapshot was stored while this run read the tenant -- it is left as it is" }
                   else { "no complete snapshot is stored yet; the failure was stored without rows so the Revoke tab shows it -> $($fs.where)" }
        throw ("[$type] active assignments could not be read from any surface; this read was NOT stored as the snapshot -- $keptTxt. " + "$($entry.error)")
    }
    $carryTxt = ''
    if ($entry['partial']) {
        $mc = Merge-PimActiveAssignmentsCarriedRows -Rows $snap.rows -Failed $errs -PreviousHeader $prevHead -Context $azCtx -NowUtc $NowUtc
        $snap['rows'] = $mc.rows; $entry['rows'] = $mc.rows
        $entry['counts'] = Get-PimActiveAssignmentsRowCounts -Rows $mc.rows; $snap['counts'] = $entry['counts']
        $parts = Get-PimActiveAssignmentsSurfaceParts
        foreach ($cr in @($mc.carried)) {
            # the carried part keeps its last good read time -- round 5 G6: NOT for a subset of PIM-for-Groups (the part WAS read
            # this run; only some groups' rows are carried, each with its own carriedFromUtc)
            if (-not [bool]$cr.subset) { $entry[$parts["$($cr.surface)"].stamp] = "$($cr.readUtc)" }
            # round 6 F1: the part's read time IS this run's (the snapshot leaves it '' when any group failed) -- else the next run
            # finds no read time and carries nothing; each carried group keeps its own date on its rows (+ groupsFrom)
            else { $entry[$parts["$($cr.surface)"].stamp] = "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value $entry['refreshedUtc'])" }
            if ("$($cr.type)" -eq 'azure-rbac' -and [bool]$cr.subset) {
                # TRUST-1-NEXT (b): Azure WAS read, only some subscriptions not -- the header's Azure count is every Azure row stored
                # (what the next run carries forward / checks against), the part named read with those subscriptions unknown
                $entry['azureRows'] = [long]$entry['counts']['azure-rbac']; $entry['azureMode'] = 'read'
                $entry['azureReason'] = "$(@($cr.subscriptionIds).Count) subscription(s) could not be read this run [AA-AZURE-SUBSCRIPTION-NOT-READ] -- their last good rows are carried"
            }
            elseif ("$($cr.type)" -eq 'azure-rbac') { $entry['azureRows'] = [long]$cr.rows; $entry['azureMode'] = 'carried'; $entry['azureReason'] = 'the Azure read failed this run -- the last good rows are carried' }
        }
        if (@($mc.carried).Count) { $entry['carried'] = @($mc.carried) }
        if (@($mc.missing).Count) { $entry['missing'] = @($mc.missing) }
        # TRUST-1 point 8: a part carried longer than Get-PimTrustCarryMaxAgeDays is STALE -- still listed with its date, named
        # with AA-SOURCE-STALE, and ONE fix request opens for it on the run where it BECOMES stale (never one per run)
        if (@($mc.stale).Count) {
            $entry['stale'] = @($mc.stale)
            Register-PimActiveAssignmentsStaleParts -Stale @($mc.stale) -NowUtc $NowUtc   # round 6 F6: every run, the list decides
        }
        $plainTxt = Get-PimActiveAssignmentsPartialText -Errors @($errs) -Carried @($mc.carried) -Missing @($mc.missing)
        $carryTxt = $(if (@($mc.carried).Count) { "; carried from the last complete read: " + (@($mc.carried | ForEach-Object { "$($_.surface) ($($_.rows) row(s), read $($_.readUtc))" }) -join ', ') } else { '' }) +
                    $(if (@($mc.missing).Count) { "; NOT read and nothing to carry: " + (@($mc.missing | ForEach-Object { "$($_.surface)" }) -join ', ') } else { '' })
    }
    # Round 3 item 4: what the uplink must NOT count as today's -- the parts with no data this run (missing) or carried past the
    # age limit (stale) -- and the parts this install does not have (absent). Header fields, read by Get-PimUplinkAdoptionQueries.
    $pu = @(@($entry['missing']) + @($entry['stale']) | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.surface)" } | Select-Object -Unique)
    $pa = @(@($entry['unknown']) | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.surface)" } | Select-Object -Unique)
    if ($pu.Count) { $entry['partsUnread'] = [string[]]$pu }
    if ($pa.Count) { $entry['partsAbsent'] = [string[]]$pa }
    # REQ 100.114 (2) / 100.110: THE ROWS GO INTO A TABLE, IN BATCHES (pim.ActiveAssignmentRows); pim.TenantCache keeps the
    # small header that names the generation. The one-row write of the whole snapshot (22 MB at 38,000 assignments) is
    # what timed out. A failed batch write THROWS from here: the run is recorded failed and the previous complete
    # snapshot stays in place and readable. Only a store that cannot hold the table at all (.stored = $false) still gets
    # the one-document form below.
    $where = ''; $formTxt = ''
    # TRUST-1 round 4 item 7: the header switch refuses an OLDER generation while a NEWER one is stored (THROW 51115 in
    # Complete-PimSqlActiveAssignmentSnapshot) -- this run lost a race it must lose: ran, the newer snapshot kept, no failure, no alert
    try { $tbl = Save-PimActiveAssignmentsSnapshotRows -Entry $entry }
    catch {
        if ("$($_.Exception.Message)" -match 'newer active-assignments snapshot') {
            $entry['rows'] = $null; $snap['rows'] = $null
            return [pscustomobject]@{ ran = $true; whatIf = $false; total = 0; partial = $false; newerKept = $true
                detail = "$type`: a newer snapshot was stored meanwhile -- kept (this run's read is not stored)$ledTxt" }
        }
        throw
    }
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
    if ($useAz) { $formTxt += "; azure $(if ($azPlan.read) { 'read' } else { 'carried forward' }) ($($azPlan.reason))" }
    $c = $snap.counts
    $sum = "{0} total ({1} entra-role, {2} azure-rbac, {3} pim-for-groups, {4} app-permission; {5} eligible) in {6}s -> {7}{8}" -f $c.total, $c['entra-role'], $c['azure-rbac'], $c['pim-for-groups'], [int]$c['app-permission'], [int]$c['eligible'], $snap.elapsedSec, $where, $formTxt

    $partialTxt = if ($errs.Count) { " PARTIAL -- could not read: " + (@($errs | ForEach-Object { "$($_.surface)" }) -join ', ') + $carryTxt } else { '' }
    $unkTxt = if (@($split.absent).Count) { " | UNKNOWN (not part of this install's check): " + (@($split.absent | ForEach-Object { "$($_.surface) [$($_.code)]" }) -join ', ') } else { '' }
    $out = [pscustomobject]@{ ran = $true; whatIf = $false; total = [int]$c.total; partial = [bool]$entry['partial']
        detail = "$type`: $sum$partialTxt$unkTxt$ledTxt" }
    # TRUST-1: a surface that failed this time = a WARNING run, not trusted (the scheduler records 'warning', never 'completed')
    if ([bool]$entry['partial']) {
        $out | Add-Member -NotePropertyName 'warning' -NotePropertyValue $true; $out | Add-Member -NotePropertyName 'trusted' -NotePropertyValue $false
        # round 3 item 11: the scheduler records 'warningSummary' (PIM-Scheduler.ps1 Write-PimJobRunRecord)
        # AA-WARN-PLAIN (owner 2026-11-16, on the mail "active assignments partial: not read this time: pim-for-groups; carried
        # ... (0 row(s) ...)"): the mail says in plain words WHAT was not read (all of a part, or N groups of it), WHY (the
        # first error), what is kept instead, and that it usually clears by itself; the technical line stays in the run detail.
        $out | Add-Member -NotePropertyName 'warningSummary' -NotePropertyValue $(if ($plainTxt) { $plainTxt } else { "active assignments partial: not read this time: " + (@($errs | ForEach-Object { "$($_.surface)" }) -join ', ') + $carryTxt })
    }
    return $out
}

function Get-PimActiveAssignmentsPartialText {
    <#
      AA-WARN-PLAIN (owner 2026-11-16): one plain sentence for a partial active-assignments read -- the warning mail's "What it
      is about". Per part: what was not read (the whole part, or N groups of PIM for Groups), why (the first error, short),
      and what is kept instead. '' when there is nothing to say.
    #>
    param([AllowNull()][object[]]$Errors, [AllowNull()][object[]]$Carried, [AllowNull()][object[]]$Missing)
    $names = @{ 'entra-role' = 'Entra roles'; 'azure-rbac' = 'Azure roles'; 'pim-for-groups' = 'PIM for Groups'; 'app-permission' = 'app permissions' }
    $fld = { param($o, $n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return $o[$n] }; return $null }; if ($o.PSObject.Properties[$n]) { return $o.$n }; $null }
    $parts = [System.Collections.Generic.List[string]]::new()
    foreach ($e in @($Errors)) {
        if ($null -eq $e) { continue }
        $s = "$(& $fld $e 'surface')"; if (-not $s) { continue }
        $nm = if ($names.ContainsKey($s)) { $names[$s] } else { $s }
        $gids = @(@(& $fld $e 'groupIds') | Where-Object { "$_".Trim() })
        $why = "$(& $fld $e 'error')".Trim()
        $why = ($why -replace '^the schedules of \d+ group\(s\) could not be read:?\s*', '' -replace '^\d+ of \d+ subscription\(s\) could not be read:?\s*', '' -split "`n")[0].Trim()
        if ($why.Length -gt 160) { $why = $why.Substring(0, 157) + '...' }
        # TRUST-1-NEXT (b): SOME Azure subscriptions not read -- named as such, never as all of Azure
        $sids = @(@(& $fld $e 'subscriptionIds') | Where-Object { "$_".Trim() })
        $c = @(@($Carried) | Where-Object { $null -ne $_ -and "$(& $fld $_ 'surface')" -eq $s }) | Select-Object -First 1
        $isMissing = @(@($Missing) | Where-Object { $null -ne $_ -and "$(& $fld $_ 'surface')" -eq $s }).Count -gt 0
        $what = if ($gids.Count) { "$nm`: $($gids.Count) group(s) could not be read this time; every other group was read" }
                elseif ($sids.Count) { "$nm`: $($sids.Count) subscription(s) could not be read this time; every other subscription was read" }
                else { "$nm could not be read this time" }
        if ($why) { $what += " ($why)" }
        if ($c) {
            $rows = [long](& $fld $c 'rows'); $rd = "$(& $fld $c 'readUtc')"
            $what += if ($gids.Count -or $sids.Count) { ". Their $rows assignment(s) from the last read ($rd) are kept as they were" } else { ". The $rows assignment(s) from the last complete read ($rd) are kept as they were" }
        } elseif ($isMissing) { $what += '. There is no earlier read to show instead, so this part is missing from the list until the next run' }
        $parts.Add($what)
    }
    if (-not $parts.Count) { return '' }
    return (($parts -join '. ') + '. This usually clears on the next run; if a part stays unread for days, PIM opens a support request by itself.')
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
            counts          = [ordered]@{ total = 0; 'entra-role' = 0; 'azure-rbac' = 0; 'pim-for-groups' = 0; 'app-permission' = 0; eligible = 0 }
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
            counts          = [ordered]@{ total = 0; 'entra-role' = 0; 'azure-rbac' = 0; 'pim-for-groups' = 0; 'app-permission' = 0; eligible = 0 }
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
    # DELEGATION-SCOPE-1 split cadence: when each part was read ('' = not read completely in this generation; absent in a
    # snapshot stored before the change)
    foreach ($pk in 'entraReadUtc', 'azureReadUtc', 'azureMode', 'azureReason', 'groupsReadUtc', 'appPermissionsReadUtc') {
        $pv = $null
        if ($Entry -is [System.Collections.IDictionary]) { if ($Entry.Contains($pk)) { $pv = $Entry[$pk] } } elseif ($Entry.PSObject.Properties[$pk]) { $pv = $Entry.$pk }
        if ($null -ne $pv) { $view[$pk] = $(if ($pk -like '*Utc') { "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value $pv)" } else { "$pv" }) }
    }
    # TRUST-1 gap 4 / point 7: the parts carried from the last complete read (with their read time), the parts not read with
    # nothing to carry, and the sources this install does not have -- handed to the page and said in the hint.
    $hf = { param($n) if ($Entry -is [System.Collections.IDictionary]) { if ($Entry.Contains($n)) { return $Entry[$n] }; return $null }; if ($Entry.PSObject.Properties[$n]) { return $Entry.$n }; return $null }
    $cv = @(@(& $hf 'carried') | Where-Object { $null -ne $_ }); $mv = @(@(& $hf 'missing') | Where-Object { $null -ne $_ }); $uv = @(@(& $hf 'unknown') | Where-Object { $null -ne $_ })
    if ($cv.Count) { $view['carried'] = $cv; $view['hint'] = "$($view['hint']); not read this time, shown from the last complete read: " + (@($cv | ForEach-Object { "$($_.surface) (read $(ConvertTo-PimActiveAssignmentsIsoStamp -Value $_.readUtc))" }) -join ', ') }
    if ($mv.Count) { $view['missing'] = $mv; $view['hint'] = "$($view['hint']); not read this time and nothing earlier to show: " + (@($mv | ForEach-Object { "$($_.surface)" }) -join ', ') }
    $sv = @(@(& $hf 'stale') | Where-Object { $null -ne $_ })
    if ($sv.Count) { $view['stale'] = $sv; $view['hint'] = "$($view['hint']); NOT READ for more than $(Get-PimTrustCarryMaxAgeDays) days (a fix request is open), still shown from the last complete read: " + (@($sv | ForEach-Object { "$($_.surface) (since $(ConvertTo-PimActiveAssignmentsIsoStamp -Value $_.sinceUtc))" }) -join ', ') }
    if ($uv.Count) { $view['unknown'] = $uv; $view['hint'] = "$($view['hint']); not part of this install: " + (@($uv | ForEach-Object { "$($_.surface) [$($_.code)]" }) -join ', ') }
    # TRUST-1 gap 1: the latest read was NOT whole, so it was not stored as the snapshot (Save-PimActiveAssignmentsSnapshotFailure);
    # the rows above are the last complete read. Said here -- lastRun* fields, the hint, and its surface errors when the kept
    # read has none of its own (the page lists them whenever it has no rows to show) -- never by serving the partial rows.
    $lr = $null
    if ($Entry -is [System.Collections.IDictionary]) { if ($Entry.Contains('lastRun')) { $lr = $Entry['lastRun'] } } elseif ($Entry.PSObject.Properties['lastRun']) { $lr = $Entry.lastRun }
    if ($null -ne $lr) {
        $lrGet = { param($n) if ($lr -is [System.Collections.IDictionary]) { if ($lr.Contains($n)) { return $lr[$n] }; return $null }; if ($lr.PSObject.Properties[$n]) { return $lr.$n }; return $null }
        $lrTrusted = & $lrGet 'trusted'
        if ($null -ne $lrTrusted -and -not [bool]$lrTrusted) {
            $lrUtc = "$(ConvertTo-PimActiveAssignmentsIsoStamp -Value (& $lrGet 'utc'))"
            $lrErrs = @(@(& $lrGet 'surfaceErrors') | Where-Object { $null -ne $_ })
            $view['lastRunTrusted'] = $false
            $view['lastRunUtc'] = $lrUtc
            $view['lastRunError'] = "$(& $lrGet 'error')"
            $view['lastRunSurfaceErrors'] = $lrErrs
            if ($errs.Count -eq 0 -and $lrErrs.Count) { $view['surfaceErrors'] = $lrErrs }
            $lrSurf = (@($lrErrs | ForEach-Object { "$($_.surface)" }) -join ', ')
            $view['hint'] = "$($view['hint']); the latest read$(if ($lrUtc) { " ($lrUtc)" }) was not complete$(if ($lrSurf) { " (could not read: $lrSurf)" }) and was not stored$(if ($storedOk) { ' -- these rows are the last complete read' } else { ' -- no complete read is stored yet' })"
        }
    }
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
