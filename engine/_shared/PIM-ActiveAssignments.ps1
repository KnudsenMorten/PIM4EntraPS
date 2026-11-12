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
      Returns { items (List, in subscription order); failed; error (the first failure); parallel (bool) }. Never throws.
      -ChunkReader: test seam ( { param([string[]]$subIds) } returning @{ sub; ok; items; error } per subscription ).
    #>
    param([string[]]$SubscriptionIds = @(), [ValidateRange(1, 64)][int]$Parallel = 16, [scriptblock]$ChunkReader = $null)
    $subsIn = @($SubscriptionIds | Where-Object { "$_".Trim() })
    $items = New-Object System.Collections.Generic.List[object]
    $failed = 0; $firstErr = ''
    $readOne = { param($sid) @(Invoke-PimArm -Path "/subscriptions/$sid/providers/Microsoft.Authorization/roleEligibilitySchedules" -ApiVersion '2020-10-01' -All) }
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
            if (-not $firstErr) { $firstErr = "$($_.Exception.Message)" }
            Write-Warning ("  [revoke] ARM role-eligibility schedules for /subscriptions/{0} failed: {1}" -f $sid, $_.Exception.Message)
        }
    }
    return [pscustomobject]@{ items = $items; failed = $failed; error = $firstErr; parallel = $usePar }
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
                foreach ($s in $subs) {
                    $scope = "/subscriptions/$($s.subscriptionId)"
                    try {
                        foreach ($ri in @(Invoke-PimArm -Path "$scope/providers/Microsoft.Authorization/roleAssignmentScheduleInstances" -ApiVersion '2020-10-01-preview' -All)) {
                            $p = $ri.properties
                            $rdId = "$($p.roleDefinitionId)"
                            $azRows += [pscustomobject]@{ Id = "$($ri.id)"; PrincipalId = "$($p.principalId)"; RoleDefinitionId = $rdId
                                RoleDefinitionName = ($rdId -split '/' | Select-Object -Last 1); Scope = "$($p.scope)"; PrincipalType = "$($p.principalType)" }
                        }
                    } catch { Write-Warning ("  [revoke] ARM role-assignment instances for {0} failed: {1}" -f $scope, $_.Exception.Message) }
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
                if ($eligFailedSubs -gt 0) { throw ("{0} of {1} subscription(s) could not be read: {2}" -f $eligFailedSubs, $eSubs.Count, $eligErr) }
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
    $azureReadUtc = if (-not $azRead) { $azPrevUtc } elseif ($azOk) { $runUtc } else { '' }

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
        $script:__gFail++
        if (-not $script:__gFirstErr -and ($status -eq 401 -or $status -eq 403 -or $errText -match 'HTTP (401|403)\b')) { $script:__gFirstErr = $errText }
        if ($script:__gFail -le 3) { Write-Warning ("  [revoke] {0} for group '{1}' failed: {2}" -f $(if ($pi % 2 -eq 0) { 'assignmentSchedules' } else { 'eligibilitySchedules' }), $pimGroupsToRead[[int][Math]::Floor($pi / 2)].DisplayName, $errText) }
    }
    $script:__gFail = 0; $script:__gFirstErr = $null
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

    # Owner split cadence (2026-11-11): Azure (active + eligible) is read at most once a night and after PIM changed an Azure
    # assignment; between those its rows are carried forward from the stored generation (Get-PimSnapshotAzurePlan; no table
    # store = Azure is read). Passed only to a snapshot that takes it -- a stand-in without -AzurePlan still runs.
    $azCtx = $null
    try { $azCtx = New-PimSnapshotAzureContext } catch { $azCtx = $null }
    $azPlan = Get-PimSnapshotAzurePlan -Context $azCtx -NowUtc $NowUtc
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
    if ($useAz) { $formTxt += "; azure $(if ($azPlan.read) { 'read' } else { 'carried forward' }) ($($azPlan.reason))" }
    $c = $snap.counts
    $sum = "{0} total ({1} entra-role, {2} azure-rbac, {3} pim-for-groups, {4} app-permission; {5} eligible) in {6}s -> {7}{8}" -f $c.total, $c['entra-role'], $c['azure-rbac'], $c['pim-for-groups'], [int]$c['app-permission'], [int]$c['eligible'], $snap.elapsedSec, $where, $formTxt
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
