#Requires -Version 5.1
<#
  PIM-TEMPLATE-IMPORT (TEMPLATE-IMPORT-GUI, owner 2026-11-03: "yes build template import after freeze"; a customer: "i want to
  have a custom template with groups, delegations, admins accounts for pim").

  WHAT THIS FILE IS. The PURE half of Settings > Import template and Settings > Export template. A TEMPLATE FILE is the
  shape the shipped permission packs already use (templates\<id>.template.json) -- no second format:
      { "id": "...", "name": "...", "version": 1, "groupNamePattern": "...", "description": "...",
        "rows": { "<entity>": [ { column: value, ... }, ... ], ... } }
  with any of the entities the Manager's grids know (Get-PimTemplatePackKnownBases, without companies): departments, every
  group definition, AUs, every delegation (memberships, nestings, role bindings, Azure, workloads) and admin accounts. A
  policy-template link is the PolicyTemplate column of the rows that carry one.

    ConvertFrom-PimTemplateFileText   parse + FILE-level checks (every error with its entity, row and reason):
                                      not JSON / no rows section / an entity that is not part of a template / a column
                                      the entity does not have / a row without its key / a key twice / a store key twice
                                      / one group tag defined in two entities.
    Get-PimTemplateFilePlan           what the import would do against the CURRENT rows: create (the pack planner,
                                      Get-PimTemplatePackPlan -- the SAME planner the Templates card and the import script
                                      use: tenant naming, adoption, placeholders, one row per store key), change (a row
                                      whose key exists and whose named columns differ), left (unchanged, adopted, a
                                      placeholder, a store key already taken). Plus the staged changes in the shared
                                      pending shape { key; op = add|modify; row; before }.
    Get-PimTemplateFileValidationView the rows the validator must judge (stored rows with the plan applied) and which of
                                      them came from the file (so an error is reported on the FILE's row).
    ConvertTo-PimTemplateFileExport   the export: definitions only, no Owner=MSP rows, no runtime columns (TAP start,
                                      account status, offboarding date, RFA window), no secret-like column, the tenant id
                                      (so the tenant root management group) and every Azure subscription id written as
                                      the all-zero placeholder.

  The Manager owns the routes (GET /api/template-file/export, POST /api/template-file/import): role checks, the store,
  the validator, staging into the SHARED pending changes. Nothing here writes anything.
  Requires PIM-TemplatePacks.ps1 (loaded below when the caller has not), PIM-SharedPending.ps1 (the row key), and
  PIM-SqlStore.ps1 (Get-PimStoreRowKey, optional). PS 5.1-safe. ASCII only.
#>

Set-StrictMode -Off
if (-not (Get-Command Get-PimTemplatePackPlan -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-TemplatePacks.ps1') }
if (-not (Get-Command Get-PimSharedPendingRowKey -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-SharedPending.ps1') }

$script:PimTemplateFileZeroGuid = '00000000-0000-0000-0000-000000000000'
# Columns that describe what happens to an account at run time, never what it IS: an export never carries them, and an
# import refuses them (an imported CreateTAP=TRUE would hand out access passes).
$script:PimTemplateFileRuntimeColumns = @{
    'Account-Definitions-Admins' = @('CreateTAP', 'TAPStartDate', 'AccountStatus', 'AutoDisableDate', 'RfaWindowEndUtc')
}
$script:PimTemplateFileMaxRows = 20000

function Get-PimTemplateFileBases {
    # The entities a template file may carry, definitions before delegations (the order Review & Save commits them in):
    # the pack entities, without companies -- a consultant company is not part of the owner's template (departments,
    # groups, delegations, admin accounts, policy-template links), and the page stages it under no row key.
    @(Get-PimTemplatePackKnownBases | Where-Object { $_ -ne 'Account-Definitions-Companies' })
}

function New-PimTemplateFileError {
    param([string]$Code, [string]$Entity = '', [AllowNull()][object]$Row = $null, [string]$Column = '', [string]$Key = '', [string]$Message, [string]$Suggestion = '')
    [ordered]@{ code = $Code; entity = $Entity; row = $Row; column = $Column; key = $Key; message = $Message; suggestion = $Suggestion; severity = 'error' }
}

function Get-PimTemplateFileField {
    param([AllowNull()][object]$Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return $Row[$Name] }; return $null }
    $p = $Row.PSObject.Properties[$Name]; if ($p) { return $p.Value }; return $null
}

function Get-PimTemplateFileRowColumns {
    param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return @() }
    if ($Row -is [System.Collections.IDictionary]) { return @($Row.Keys | ForEach-Object { "$_" }) }
    return @($Row.PSObject.Properties | ForEach-Object { $_.Name })
}

function ConvertTo-PimTemplateFileCell {
    # A cell as text: $null -> '', a boolean -> TRUE / FALSE (the store's spelling), a date -> round-trip ISO.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { if ($Value) { return 'TRUE' } else { return 'FALSE' } }
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) { return $Value.ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    return "$Value"
}

function ConvertFrom-PimTemplateFileText {
    <#
      PURE. -Text: the file as text. -Schema: ordered entity -> its columns (the Manager's grid headers; Get-PimCsvEntitySchema
      reads the same list from the code). Returns [ordered]@{ ok; errors[]; id; name; version; description; groupNamePattern;
      rowsByBase = ordered entity -> rows (pscustomobject, cells as text, in file order); rowCount }.
      Every error carries the entity, the 1-based row number within that entity's list, the column and a plain reason.
      ok = $false on ANY error: the caller stages nothing.
    #>
    param([AllowNull()][string]$Text, [Parameter(Mandatory)][System.Collections.IDictionary]$Schema, [int]$MaxRows = $script:PimTemplateFileMaxRows)
    $errors = New-Object System.Collections.Generic.List[object]
    $out = [ordered]@{ ok = $false; errors = @(); id = ''; name = ''; version = $null; description = ''; groupNamePattern = ''; rowsByBase = [ordered]@{}; rowCount = 0 }
    $t = "$Text"
    if ($t.Length -gt 0 -and [int][char]$t[0] -eq 0xFEFF) { $t = $t.Substring(1) }
    if (-not $t.Trim()) {
        $errors.Add((New-PimTemplateFileError -Code 'TPL-FILE-001' -Message 'The file is empty.' -Suggestion 'Choose a template file (.json) made by Export template, or a shipped sample.'))
        $out.errors = @($errors.ToArray()); return $out
    }
    $doc = $null
    try {
        if (Get-Command ConvertFrom-PimSharedPendingJson -ErrorAction SilentlyContinue) { $doc = ConvertFrom-PimSharedPendingJson -Json $t }
        else { $doc = $t | ConvertFrom-Json }
    } catch {
        $errors.Add((New-PimTemplateFileError -Code 'TPL-FILE-001' -Message "The file is not valid JSON: $($_.Exception.Message)" -Suggestion 'A template file is JSON. Export one from another installation to see the shape.'))
        $out.errors = @($errors.ToArray()); return $out
    }
    if ($null -eq $doc -or $doc -is [array] -or $doc -is [string] -or $doc.GetType().IsValueType) {
        $errors.Add((New-PimTemplateFileError -Code 'TPL-FILE-002' -Message 'The file is not a template: it must be one JSON object with a "rows" section.'))
        $out.errors = @($errors.ToArray()); return $out
    }
    $rowsObj = Get-PimTemplateFileField $doc 'rows'
    if ($null -eq $rowsObj -or $rowsObj -is [array] -or $rowsObj -is [string]) {
        $errors.Add((New-PimTemplateFileError -Code 'TPL-FILE-002' -Message 'The file has no "rows" section: a template lists its rows per part, for example "rows": { "PIM-Definitions-Roles": [ ... ] }.'))
        $out.errors = @($errors.ToArray()); return $out
    }
    $out.id = "$(Get-PimTemplateFileField $doc 'id')"; $out.name = "$(Get-PimTemplateFileField $doc 'name')"
    $out.version = Get-PimTemplateFileField $doc 'version'; $out.description = "$(Get-PimTemplateFileField $doc 'description')"
    $out.groupNamePattern = "$(Get-PimTemplateFileField $doc 'groupNamePattern')".Trim()
    $known = @(Get-PimTemplateFileBases | Where-Object { $Schema.Contains($_) })
    $total = 0
    $defTagAt = @{}   # group tag (lower) -> "entity row n"
    foreach ($bp in @(Get-PimTemplateFileRowColumns $rowsObj)) {
        $base = "$bp"
        $match = @($known | Where-Object { $_ -ieq $base }) | Select-Object -First 1
        if (-not $match) {
            $near = ''
            if (Get-Command Get-PimLevenshteinDistance -ErrorAction SilentlyContinue) {
                $best = 99; foreach ($k in $known) { $d = Get-PimLevenshteinDistance -A $base.ToLowerInvariant() -B $k.ToLowerInvariant(); if ($d -lt $best) { $best = $d; $near = $k } }
                if ($best -gt 4) { $near = '' }
            }
            $errors.Add((New-PimTemplateFileError -Code 'TPL-ENTITY-001' -Entity $base -Message ("'{0}' is not a part a template can carry." -f $base) `
                -Suggestion $(if ($near) { "Did you mean '$near'?" } else { 'A template carries departments, group definitions, administrative units, delegations and admin accounts.' })))
            continue
        }
        $base = $match
        # Read straight off the object, assigned inside the branch: through a function's (or an if-expression's) output a
        # list of ONE row is unrolled into that row.
        $list = $null
        if ($rowsObj -is [System.Collections.IDictionary]) { $list = $rowsObj[$bp] } else { $list = $rowsObj.PSObject.Properties[$bp].Value }
        if ($null -eq $list) { $list = @() }
        if ($list -isnot [array] -and $list -isnot [System.Collections.IList]) {
            $errors.Add((New-PimTemplateFileError -Code 'TPL-ENTITY-002' -Entity $base -Message ("'{0}' must be a list of rows ([ ... ])." -f $base)))
            continue
        }
        $cols = @{}; foreach ($c in @($Schema[$base])) { $cols["$c".ToLowerInvariant()] = "$c" }
        $runtime = @{}; if ($script:PimTemplateFileRuntimeColumns.ContainsKey($base)) { foreach ($c in $script:PimTemplateFileRuntimeColumns[$base]) { $runtime[$c.ToLowerInvariant()] = $true } }
        $rows = New-Object System.Collections.Generic.List[object]
        $keys = @{}; $storeKeys = @{}
        $n = 0
        foreach ($r in @($list)) {
            $n++; $total++
            if ($null -eq $r -or $r -is [string] -or $r -is [array] -or $r.GetType().IsValueType) {
                $errors.Add((New-PimTemplateFileError -Code 'TPL-ROW-001' -Entity $base -Row $n -Message "Row $n is not a row (an object with columns)."))
                continue
            }
            $row = [ordered]@{}
            $bad = $false
            foreach ($cn in @(Get-PimTemplateFileRowColumns $r)) {
                $lc = "$cn".ToLowerInvariant()
                if ($lc -eq 'owner') { continue }   # provenance is never imported (a template's rows are always local)
                if (-not $cols.ContainsKey($lc)) {
                    $errors.Add((New-PimTemplateFileError -Code 'TPL-COL-001' -Entity $base -Row $n -Column "$cn" -Message ("Column '{0}' is not a column of {1}." -f $cn, $base) -Suggestion 'Remove the column, or correct its name.'))
                    $bad = $true; continue
                }
                if ($runtime.ContainsKey($lc)) {
                    $errors.Add((New-PimTemplateFileError -Code 'TPL-COL-002' -Entity $base -Row $n -Column $cols[$lc] -Message ("Column '{0}' describes what happens to an account at run time and cannot be imported." -f $cols[$lc]) -Suggestion 'Remove the column. Set it on Admin accounts after the import if you need it.'))
                    $bad = $true; continue
                }
                $row[$cols[$lc]] = ConvertTo-PimTemplateFileCell (Get-PimTemplateFileField $r $cn)
            }
            if ($bad) { continue }
            $po = [pscustomobject]$row
            $k = Get-PimSharedPendingRowKey -Base $base -Row $po
            if (-not $k) {
                $errors.Add((New-PimTemplateFileError -Code 'TPL-KEY-001' -Entity $base -Row $n -Message "Row $n has no key: it needs the column(s) that name it (GroupTag for a group, UserName for an admin, AdministrativeUnitTag for an administrative unit, the tag and role for a delegation)." -Suggestion 'Fill in the key column(s).'))
                continue
            }
            if ($keys.ContainsKey($k)) {
                $errors.Add((New-PimTemplateFileError -Code 'TPL-KEY-002' -Entity $base -Row $n -Key $k -Message ("Row {0} has the same key as row {1} ('{2}'). Each row must be there once." -f $n, $keys[$k], $k) -Suggestion 'Merge the two rows, or delete one.'))
                continue
            }
            $keys[$k] = $n
            if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) {
                $sk = "$(Get-PimStoreRowKey -Base $base -Row $po)".ToLowerInvariant()
                if ($sk -and $storeKeys.ContainsKey($sk)) {
                    $errors.Add((New-PimTemplateFileError -Code 'TPL-KEY-003' -Entity $base -Row $n -Key $sk -Message ("Row {0} and row {1} are stored as ONE row ('{2}'): PIM keeps one {3} row per group, so one of them would be lost." -f $n, $storeKeys[$sk], $sk, $base) -Suggestion 'Keep one row per group in this part.'))
                    continue
                }
                if ($sk) { $storeKeys[$sk] = $n }
            }
            if ($base -like 'PIM-Definitions-*' -and $base -ne 'PIM-Definitions-AU') {
                $gt = "$($row['GroupTag'])".Trim().ToLowerInvariant()
                if ($gt) {
                    if ($defTagAt.ContainsKey($gt) -and $defTagAt[$gt].entity -ne $base) {
                        $errors.Add((New-PimTemplateFileError -Code 'TPL-KEY-004' -Entity $base -Row $n -Column 'GroupTag' -Key $gt -Message ("Group tag '{0}' is also defined in {1} row {2}. A group is defined once." -f $row['GroupTag'], $defTagAt[$gt].entity, $defTagAt[$gt].row) -Suggestion 'Keep the group in one part only.'))
                        continue
                    }
                    $defTagAt[$gt] = @{ entity = $base; row = $n }
                }
            }
            $rows.Add($po)
        }
        if ($rows.Count) { $out.rowsByBase[$base] = $rows.ToArray() }
    }
    if ($total -gt $MaxRows) { $errors.Add((New-PimTemplateFileError -Code 'TPL-FILE-003' -Message ("The file holds {0} rows; a template holds at most {1}." -f $total, $MaxRows) -Suggestion 'Split it into smaller templates.')) }
    if ($errors.Count -eq 0 -and $total -eq 0) { $errors.Add((New-PimTemplateFileError -Code 'TPL-FILE-004' -Message 'The file has no rows.')) }
    $out.rowCount = $total
    $out.errors = @($errors.ToArray())
    $out.ok = ($errors.Count -eq 0)
    return $out
}

function Set-PimTemplateFileTenantRoot {
    # PURE. The export writes the tenant root management group as the all-zero placeholder; the import gives it back THIS
    # tenant's id (the tenant root management group's id is the tenant id). A subscription placeholder stays one (the
    # planner skips it: a subscription is never guessed). Returns a COPY of the rows.
    param([AllowNull()][object[]]$Rows, [string]$TenantId)
    $tid = "$TenantId".Trim()
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $sc = "$(Get-PimTemplateFileField $r 'AzScope')"
        if ($tid -and $sc -match ('(?i)/managementGroups/' + [regex]::Escape($script:PimTemplateFileZeroGuid) + '$')) {
            $c = [ordered]@{}; foreach ($p in $r.PSObject.Properties) { $c[$p.Name] = $p.Value }
            $c['AzScope'] = [regex]::Replace($sc, '(?i)(/managementGroups/)0{8}-0{4}-0{4}-0{4}-0{12}$', ('${1}' + $tid))
            $out.Add([pscustomobject]$c)
        } else { $out.Add($r) }
    }
    return @($out.ToArray())
}

function Get-PimTemplateFilePlan {
    <#
      PURE. -Parsed: ConvertFrom-PimTemplateFileText's answer (ok). -CurrentRowsByBase: entity -> the CURRENT stored rows,
      for EVERY entity of Get-PimTemplateFileBases (an unread entity is not an empty one -- the planner refuses it).
      -TenantGroupPattern: this tenant's PimGroupPattern. -TenantId: this tenant (the tenant root placeholder becomes it).
      Group names: a file that states a groupNamePattern other than this tenant's is re-expressed in this tenant's naming
      (as a shipped pack is); a file without one, or with this tenant's, keeps its names exactly as written.
      Returns [ordered]@{
        bases   = ordered entity -> [ordered]@{ create = rows; change = @( { key; row; before; columns } ); unchanged; left = @( { key; reason } ) }
        changes = ordered entity -> @( shared pending changes { key; op; row; before } )
        counts  = { create; change; unchanged; left; placeholder }
        adopted; keyTaken; fileRowOf = entity -> @{ key -> file row number } }
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Parsed, [Parameter(Mandatory)][hashtable]$CurrentRowsByBase,
          [AllowEmptyString()][string]$TenantGroupPattern = '', [string]$TenantId = '', [string[]]$KnownBases)
    $known = if ($PSBoundParameters.ContainsKey('KnownBases')) { @($KnownBases) } else { @(Get-PimTemplateFileBases) }
    $filePat = "$($Parsed.groupNamePattern)".Trim()
    $convert = [bool]($filePat -and "$TenantGroupPattern".Trim() -and ($filePat -ine "$TenantGroupPattern".Trim()))
    $packRows = [ordered]@{}
    $fileRowOf = @{}
    foreach ($b in @($Parsed.rowsByBase.Keys)) {
        $rs = @(Set-PimTemplateFileTenantRoot -Rows @($Parsed.rowsByBase[$b]) -TenantId $TenantId)
        $packRows[$b] = $rs
        $m = @{}; $i = 0
        foreach ($r in $rs) { $i++; $k = Get-PimSharedPendingRowKey -Base $b -Row $r; if ($k -and -not $m.ContainsKey($k)) { $m[$k] = $i } }
        $fileRowOf[$b] = $m
    }
    $pack = [pscustomobject][ordered]@{ id = "$($Parsed.id)"; name = "$($Parsed.name)"; version = $Parsed.version; description = "$($Parsed.description)"
        groupNamePattern = $(if ($convert) { $filePat } else { 'PIM-{Role}' }); rows = [pscustomobject]$packRows }
    $current = @{}
    foreach ($b in $known) { $current[$b] = @(if ($CurrentRowsByBase.ContainsKey($b)) { @($CurrentRowsByBase[$b]) | Where-Object { $null -ne $_ } | ForEach-Object { [pscustomobject]$_ } } else { @() }) }
    $allDefs = New-Object System.Collections.Generic.List[object]
    foreach ($b in $known) { if ("$b" -like 'PIM-Definitions-*' -and "$b" -ne 'PIM-Definitions-AU') { foreach ($r in @($current[$b])) { $allDefs.Add($r) } } }
    # Without conversion the planner is handed this tenant's pattern as the pack's own; its re-expression is then undone
    # below by giving every created definition its name exactly as the file wrote it.
    $plannerPattern = if ($convert) { "$TenantGroupPattern" } else { 'PIM-{Role}' }
    $plan = Get-PimTemplatePackPlan -Pack $pack -CurrentRowsByBase $current -TenantGroupPattern $plannerPattern -KnownBases $known -ExistingDefinitionRows @($allDefs.ToArray())
    $nameByTag = @{}
    if (-not $convert) {
        foreach ($b in @($packRows.Keys)) {
            if ("$b" -notlike 'PIM-Definitions-*' -or "$b" -eq 'PIM-Definitions-AU') { continue }
            foreach ($r in @($packRows[$b])) { $t = "$($r.GroupTag)".Trim().ToLowerInvariant(); if ($t) { $nameByTag[$t] = "$($r.GroupName)" } }
        }
    }
    $bases = [ordered]@{}; $changes = [ordered]@{}
    $cnt = [ordered]@{ create = 0; change = 0; unchanged = 0; left = 0; placeholder = [int]$plan.placeholderSkipped }
    foreach ($b in $known) {
        if (-not $packRows.Contains($b)) { continue }
        $entry = [ordered]@{ create = @(); change = @(); unchanged = 0; left = @() }
        $chg = New-Object System.Collections.Generic.List[object]
        $created = @{}
        $crRows = New-Object System.Collections.Generic.List[object]
        foreach ($mr in @($plan.missing[$b])) {
            if ($null -eq $mr) { continue }
            $row = $mr
            if (-not $convert -and $b -like 'PIM-Definitions-*' -and $b -ne 'PIM-Definitions-AU') {
                $t = "$($row.GroupTag)".Trim().ToLowerInvariant()
                if ($t -and $nameByTag.ContainsKey($t) -and $row.PSObject.Properties['GroupName']) {
                    $c = [ordered]@{}; foreach ($p in $row.PSObject.Properties) { $c[$p.Name] = $p.Value }; $c['GroupName'] = $nameByTag[$t]; $row = [pscustomobject]$c
                }
            }
            $k = Get-PimSharedPendingRowKey -Base $b -Row $row
            if (-not $k) { continue }
            $created[$k] = $true
            $crRows.Add($row)
            $chg.Add([ordered]@{ key = $k; op = 'add'; row = (ConvertTo-PimSharedPendingRowMap $row) })
        }
        $storedByKey = @{}
        foreach ($s in @($current[$b])) { $sk = Get-PimSharedPendingRowKey -Base $b -Row $s; if ($sk -and -not $storedByKey.ContainsKey($sk)) { $storedByKey[$sk] = $s } }
        $chRows = New-Object System.Collections.Generic.List[object]
        $leftRows = New-Object System.Collections.Generic.List[object]
        $unch = 0
        foreach ($fr in @($packRows[$b])) {
            if (Test-PimTemplatePlaceholderRow -Row $fr) { $leftRows.Add([ordered]@{ key = (Get-PimSharedPendingRowKey -Base $b -Row $fr); reason = 'placeholder subscription -- add your own subscription after the import' }); continue }
            $conv = if ($convert) { ConvertTo-PimTemplatePackRow -Base $b -Row $fr -PackPattern $filePat -TenantPattern $TenantGroupPattern } else { $fr }
            $k = Get-PimSharedPendingRowKey -Base $b -Row $conv
            if (-not $k -or $created.ContainsKey($k)) { continue }
            if (-not $storedByKey.ContainsKey($k)) {
                # A row the pack planner cannot key (a department owner row has no GroupTag, a company is keyed on its name):
                # the planner never offers it, so it is created here when nothing stored has its key.
                if (-not (Get-PimTemplateRowKey -Base $b -Row $conv)) {
                    $created[$k] = $true
                    $crRows.Add($conv)
                    $chg.Add([ordered]@{ key = $k; op = 'add'; row = (ConvertTo-PimSharedPendingRowMap $conv) })
                    continue
                }
                $leftRows.Add([ordered]@{ key = $k; reason = 'already defined here under another tag or name, or its store key is taken -- left as it is' }); continue
            }
            $st = $storedByKey[$k]
            $stMap = ConvertTo-PimSharedPendingRowMap $st
            $stLc = @{}; foreach ($kv in $stMap.GetEnumerator()) { $stLc["$($kv.Key)".ToLowerInvariant()] = @{ name = "$($kv.Key)"; value = "$($kv.Value)" } }
            $diff = New-Object System.Collections.Generic.List[string]
            $newRow = [ordered]@{}; foreach ($kv in $stMap.GetEnumerator()) { $newRow["$($kv.Key)"] = "$($kv.Value)" }
            foreach ($p in $conv.PSObject.Properties) {
                $lc = $p.Name.ToLowerInvariant()
                # (a definition's GroupName under re-expression is not compared: the stored group keeps its name)
                if ($convert -and $lc -eq 'groupname') { continue }
                $sv = if ($stLc.ContainsKey($lc)) { "$($stLc[$lc].value)" } else { '' }
                $fv = "$($p.Value)"
                if ($fv.Trim() -cne $sv.Trim()) {
                    $diff.Add($p.Name)
                    $nm = if ($stLc.ContainsKey($lc)) { $stLc[$lc].name } else { $p.Name }
                    $newRow[$nm] = $fv
                }
            }
            if ($diff.Count) {
                $chRows.Add([ordered]@{ key = $k; row = $newRow; before = $stMap; columns = @($diff.ToArray()) })
                $chg.Add([ordered]@{ key = $k; op = 'modify'; row = $newRow; before = $stMap })
            } else { $unch++ }
        }
        $entry.change = @($chRows.ToArray()); $entry.unchanged = $unch; $entry.left = @($leftRows.ToArray())
        $entry.create = @($crRows.ToArray())
        $cnt.create += $crRows.Count; $cnt.change += $chRows.Count; $cnt.unchanged += $unch; $cnt.left += $leftRows.Count
        $bases[$b] = $entry
        if ($chg.Count) { $changes[$b] = @($chg.ToArray()) }
    }
    # placeholder rows were counted in left per entity already
    $cnt.placeholder = [int]$plan.placeholderSkipped
    return [ordered]@{ bases = $bases; changes = $changes; counts = $cnt; adopted = @($plan.adopted); keyTaken = @($plan.keyTaken); fileRowOf = $fileRowOf; renamed = $convert }
}

function Get-PimTemplateFileValidationView {
    <#
      PURE. The rows the validator must judge per touched entity: the CURRENT rows with the plan's changes applied
      (a modify replaces its stored row in place, an add is appended), and for each index whether it came from the file
      and its row number there. Returns [ordered]@{ pendingRows = @{ entity -> rows }; origin = @{ entity -> @{ index -> @{ fileRow; key } } } }.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Plan, [Parameter(Mandatory)][hashtable]$CurrentRowsByBase)
    $pending = @{}; $origin = @{}
    foreach ($b in @($Plan.changes.Keys)) {
        $mods = @{}; $adds = New-Object System.Collections.Generic.List[object]
        foreach ($c in @($Plan.changes[$b])) { if ($c.op -eq 'modify') { $mods["$($c.key)"] = $c } elseif ($c.op -eq 'add') { $adds.Add($c) } }
        $rows = New-Object System.Collections.Generic.List[object]
        $o = @{}
        $fr = if ($Plan.fileRowOf.ContainsKey($b)) { $Plan.fileRowOf[$b] } else { @{} }
        foreach ($s in @($CurrentRowsByBase[$b])) {
            if ($null -eq $s) { continue }
            $k = Get-PimSharedPendingRowKey -Base $b -Row $s
            if ($k -and $mods.ContainsKey($k)) {
                $o[$rows.Count] = @{ fileRow = $(if ($fr.ContainsKey($k)) { $fr[$k] } else { $null }); key = $k }
                $rows.Add([pscustomobject]$mods[$k].row)
            } else { $rows.Add([pscustomobject](ConvertTo-PimSharedPendingRowMap $s)) }
        }
        foreach ($a in $adds) {
            $o[$rows.Count] = @{ fileRow = $(if ($fr.ContainsKey("$($a.key)")) { $fr["$($a.key)"] } else { $null }); key = "$($a.key)" }
            $rows.Add([pscustomobject]$a.row)
        }
        $pending[$b] = @($rows.ToArray()); $origin[$b] = $o
    }
    return [ordered]@{ pendingRows = $pending; origin = $origin }
}

function Select-PimTemplateFileValidationErrors {
    <#
      PURE. The validator's findings (Csv, Row = index into the judged rows, Severity, Code, Column, Message, Suggestion)
      split into: errors ON A ROW THE FILE BRINGS (block the import, reported with the FILE's row number), warnings on those
      rows, and findings elsewhere (already in this installation; shown, never blocking).
    #>
    param([AllowNull()][object[]]$Violations, [Parameter(Mandatory)][System.Collections.IDictionary]$View)
    $err = New-Object System.Collections.Generic.List[object]; $warn = New-Object System.Collections.Generic.List[object]; $other = 0
    foreach ($v in @($Violations)) {
        if ($null -eq $v) { continue }
        $b = "$($v.Csv)"; $sev = "$($v.Severity)"
        $ix = $null; if ($null -ne $v.Row -and "$($v.Row)" -match '^\d+$') { $ix = [int]$v.Row }
        $hit = $null
        if ($View.origin.ContainsKey($b) -and $null -ne $ix -and $View.origin[$b].ContainsKey($ix)) { $hit = $View.origin[$b][$ix] }
        if (-not $hit) { if ($sev -in @('error', 'warning')) { $other++ }; continue }
        $e = [ordered]@{ code = "$($v.Code)"; entity = $b; row = $hit.fileRow; key = "$($hit.key)"; column = "$($v.Column)"; message = "$($v.Message)"; suggestion = "$($v.Suggestion)"; severity = $sev }
        if ($sev -eq 'error') { $err.Add($e) } elseif ($sev -eq 'warning') { $warn.Add($e) }
    }
    return [ordered]@{ errors = @($err.ToArray()); warnings = @($warn.ToArray()); elsewhere = $other }
}

function ConvertTo-PimTemplateFileExport {
    <#
      PURE. -RowsByBase: entity -> the stored rows. -Schema: entity -> columns. Returns the template document (ordered):
      definitions only (only the entities a template carries, only their schema columns), never a row the managing tenant
      sent (Owner = MSP), never a runtime column, never a secret-like column; the tenant id anywhere (so the tenant root
      management group too) and every Azure subscription id written as the all-zero placeholder (an import gives the tenant root back as
      the importing tenant's id; a subscription is added there by hand).
    #>
    param([Parameter(Mandatory)][hashtable]$RowsByBase, [Parameter(Mandatory)][System.Collections.IDictionary]$Schema,
          [string]$TenantId = '', [AllowEmptyString()][string]$GroupNamePattern = '', [string]$Name = 'Exported template',
          [datetime]$NowUtc = [datetime]::UtcNow)
    $tid = "$TenantId".Trim()
    # A subscription id is this customer's; a management group named by the TENANT id is the tenant root (the tenant id is
    # replaced everywhere below). Both become the all-zero placeholder. Any other management group keeps its name: the
    # customer chose it, and mapping it to the root on import would WIDEN the delegation.
    $guidRx = '(?i)(/subscriptions/)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    $rows = [ordered]@{}
    $count = 0
    foreach ($b in @(Get-PimTemplateFileBases)) {
        if (-not $Schema.Contains($b) -or -not $RowsByBase.ContainsKey($b)) { continue }
        $runtime = @{}; if ($script:PimTemplateFileRuntimeColumns.ContainsKey($b)) { foreach ($c in $script:PimTemplateFileRuntimeColumns[$b]) { $runtime[$c.ToLowerInvariant()] = $true } }
        $cols = @(@($Schema[$b]) | Where-Object { -not $runtime.ContainsKey("$_".ToLowerInvariant()) -and "$_" -notmatch '(?i)(secret|password|passphrase|token|thumbprint|clientid|objectid|tenantid)' })
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($r in @($RowsByBase[$b])) {
            if ($null -eq $r) { continue }
            if ("$(Get-PimTemplateFileField $r 'Owner')".Trim() -ieq 'msp') { continue }
            $o = [ordered]@{}
            $any = $false
            foreach ($c in $cols) {
                $v = Get-PimTemplateFileField $r $c
                if ($null -eq $v) { continue }
                $s = ConvertTo-PimTemplateFileCell $v
                if ($tid) { $s = [regex]::Replace($s, [regex]::Escape($tid), $script:PimTemplateFileZeroGuid, 'IgnoreCase') }
                if ($s -match $guidRx) { $s = [regex]::Replace($s, $guidRx, ('${1}' + $script:PimTemplateFileZeroGuid)) }
                $o[$c] = $s
                if ($s.Trim()) { $any = $true }
            }
            if ($any) { $list.Add($o); $count++ }
        }
        if ($list.Count) { $rows[$b] = $list.ToArray() }
    }
    $doc = [ordered]@{
        id = 'exported-template'; name = "$Name"; version = 1
        description = 'Exported from a PIM Manager installation: departments, group definitions, delegations, admin accounts and policy-template links. Definitions only -- no secrets and no tenant or subscription ids.'
        exportedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        rowCount = $count
        rows = $rows
    }
    if ("$GroupNamePattern".Trim()) { $doc['groupNamePattern'] = "$GroupNamePattern".Trim() }
    return $doc
}
