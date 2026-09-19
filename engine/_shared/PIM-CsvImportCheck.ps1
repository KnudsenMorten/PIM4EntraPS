#Requires -Version 5.1
<#
  PIM4EntraPS -- PRE-IMPORT CHECK FOR v1 CSV DEFINITION FILES (REQ-G, 2026-09-19).

  Operator: "did you build the new import script that validate the csv files before importing them
  for issues ?" -- and, for EFIF: "import the efif definitions when validated".

  setup/Migrate-PimToSql.ps1 imported v1 CSVs straight into pim.Rows. The Manager's validator
  (tools/pim-manager/_validator.ps1) only ever ran over data ALREADY in SQL, so a broken file was
  found after it had been written. This file checks a folder of v1 CSVs BEFORE anything is imported.

  PURE / OFFLINE: no SQL, no network, no Graph, no file writes. It reads the files and nothing else.

  WHAT IT CHECKS
    * file level  -- encoding (UTF-8 with or without BOM is fine; anything else is an ERROR),
                     delimiter (';' or ','), header vs the entity's schema (unknown / missing /
                     unnamed / duplicate columns; trailing empty columns are tolerated with an info
                     note), header-only files (fine, 0 rows), a natural key on every row and no
                     duplicate natural keys within a file (Get-PimStoreRowKey / Get-PimDuplicateStoreKeys,
                     the store's own key rule -- two rows with one key COLLAPSE on import).
    * skipped     -- the engine's STATE files (*_Delta.csv, *_LastApplied.csv) are never imported and
                     are reported as such; any other unknown file name is reported as not an entity.
    * row level   -- the SAME rules the Manager runs: Invoke-PimPreflightValidation from
                     tools/pim-manager/_validator.ps1, fed the parsed rows through the same Read-PimRows /
                     Get-PimCsvBases seams the Manager uses (the rules are CALLED, never copied). Cross-file
                     references (a GroupTag used in an assignment must be defined) come from there.
    * replication -- the EFFECTIVE Replicate of every replicable row (Get-PimReplicateMode), and what an
                     MSP master would actually put in the signed bundle, computed by the producer's own
                     pure function (Select-PimBaselineBundleContent). Every row that would reach managed
                     tenants is a WARNING. -ForceLocal is the import-side rule (Replicate=No on rows /
                     ManagementMode=local on admins, unless the file sets them explicitly); the report
                     always lists what -ForceLocal would change.

  THE ENTITY SCHEMA is the Manager's own header map ($script:PimCsvBases in
  tools/pim-manager/Open-PimManager.ps1 -- "in SQL mode this defaultHeader IS the grid's header"). It is
  read from that file with the PowerShell parser and evaluated only after proving it is pure literal
  data, so there is ONE definition of an entity's columns, not a second copy that drifts.

  Fail closed: if the schema, the validator or the replication rule cannot be loaded, the check THROWS.
  A check that could not run is never reported as a clean file set.

  PS 5.1 compatible. ASCII only.
#>

Set-StrictMode -Off

$script:PimCsvImportSchemaCache = $null

function Get-PimCsvImportSolutionRoot {
    # engine/_shared -> solution root
    return (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
}

function Get-PimCsvEntitySchema {
    <#
      The Manager's entity schema: ordered base -> @(defaultHeader). Read from Open-PimManager.ps1's
      `$script:PimCsvBases = @( ... )` assignment with the PowerShell parser. The right-hand side is
      evaluated ONLY when it is pure literal data (hashtables, arrays, strings, [ordered]); anything
      else -- a command, a variable, a sub-expression -- refuses. Throws when it cannot be read.
    #>
    [CmdletBinding()] param([string]$ManagerPath)
    if (-not "$ManagerPath".Trim()) { $ManagerPath = Join-Path (Get-PimCsvImportSolutionRoot) 'tools\pim-manager\Open-PimManager.ps1' }
    if ($script:PimCsvImportSchemaCache -and $script:PimCsvImportSchemaCache.path -eq $ManagerPath) { return $script:PimCsvImportSchemaCache.schema }
    if (-not (Test-Path -LiteralPath $ManagerPath)) { throw "Get-PimCsvEntitySchema: the Manager ('$ManagerPath') is not there, so the entity schema cannot be read -- refusing to guess the columns." }
    $tokens = $null; $perr = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($ManagerPath, [ref]$tokens, [ref]$perr)
    $assign = $ast.Find({
        param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        "$($n.Left.VariablePath.UserPath)" -ieq 'script:PimCsvBases'
    }, $true)
    if (-not $assign) { throw "Get-PimCsvEntitySchema: no `$script:PimCsvBases assignment in '$ManagerPath' -- refusing to guess the columns." }
    $unsafe = @($assign.Right.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.CommandAst] -or
        $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
        $n -is [System.Management.Automation.Language.VariableExpressionAst] -or
        $n -is [System.Management.Automation.Language.SubExpressionAst] -or
        $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -or
        $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst]
    }, $true))
    if ($unsafe.Count) { throw "Get-PimCsvEntitySchema: `$script:PimCsvBases in '$ManagerPath' is no longer pure literal data ($($unsafe[0].GetType().Name) at line $($unsafe[0].Extent.StartLineNumber)) -- refusing to evaluate it." }
    $value = & ([scriptblock]::Create($assign.Right.Extent.Text))
    $schema = [ordered]@{}
    foreach ($spec in @($value)) {
        if ($null -eq $spec) { continue }
        $b = "$($spec['base'])".Trim()
        if (-not $b) { continue }
        $schema[$b] = @($spec['defaultHeader'] | ForEach-Object { "$_" })
    }
    if ($schema.Count -eq 0) { throw "Get-PimCsvEntitySchema: `$script:PimCsvBases in '$ManagerPath' yielded no entities -- refusing to guess the columns." }
    $script:PimCsvImportSchemaCache = @{ path = $ManagerPath; schema = $schema }
    return $schema
}

function New-PimCsvImportFinding {
    param(
        [Parameter(Mandatory)][ValidateSet('error','warning','info')][string]$Severity,
        [Parameter(Mandatory)][string]$Code,
        [string]$File, [string]$Entity,
        [AllowNull()][object]$Row = $null, [AllowNull()][object]$Line = $null,
        [string]$Column,
        [Parameter(Mandatory)][string]$Message,
        [string]$Suggestion,
        [string]$Source = 'file'
    )
    [pscustomobject][ordered]@{
        file = $File; entity = $Entity; row = $Row; line = $Line; column = $Column
        code = $Code; severity = $Severity; message = $Message; suggestion = $Suggestion; source = $Source
    }
}

function Get-PimCsvImportFileSet {
    <#
      Classify every *.csv in -Path. Returns @{ entities = ordered base -> FileInfo; skipped = @( @{ file; status; reason; nearest } ) }.
        status 'state'      -- *_Delta / *_LastApplied: the engine's working state, NEVER imported
        status 'superseded' -- another file for the same entity takes precedence
        status 'not-entity' -- not a PIM entity name
      Precedence per entity (unchanged from Migrate-PimToSql): <base>.custom.csv, then <base>.csv, then <base>.locked.csv.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$Entities)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Get-PimCsvImportFileSet: '$Path' is not a folder." }
    $byBase = [ordered]@{}
    $skipped = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-ChildItem -LiteralPath $Path -Filter '*.csv' -File | Sort-Object Name)) {
        $b = $f.BaseName -replace '\.(custom|locked)$', ''
        if ($b -match '_(Delta|LastApplied)$') {
            $skipped.Add([ordered]@{ file = $f.Name; status = 'state'; reason = "engine state file ($($Matches[1])), not imported -- it is the engine's working copy, not desired state"; nearest = '' }) | Out-Null
            continue
        }
        $match = @($Entities | Where-Object { $_ -ieq $b }) | Select-Object -First 1
        if (-not $match) {
            $near = ''
            if (Get-Command Get-PimLevenshteinDistance -ErrorAction SilentlyContinue) {
                $best = 99
                foreach ($e in $Entities) { $d = Get-PimLevenshteinDistance -A $b.ToLowerInvariant() -B $e.ToLowerInvariant(); if ($d -lt $best) { $best = $d; $near = $e } }
                if ($best -gt 3) { $near = '' }
            }
            $skipped.Add([ordered]@{ file = $f.Name; status = 'not-entity'; reason = 'not a PIM entity, not imported'; nearest = $near }) | Out-Null
            continue
        }
        $rank = if ($f.BaseName -match '\.custom$') { 0 } elseif ($f.BaseName -match '\.locked$') { 2 } else { 1 }
        if (-not $byBase.Contains($match)) { $byBase[$match] = @{ file = $f; rank = $rank }; continue }
        if ($rank -lt $byBase[$match].rank) {
            $skipped.Add([ordered]@{ file = $byBase[$match].file.Name; status = 'superseded'; reason = "superseded by $($f.Name)"; nearest = '' }) | Out-Null
            $byBase[$match] = @{ file = $f; rank = $rank }
        } else {
            $skipped.Add([ordered]@{ file = $f.Name; status = 'superseded'; reason = "superseded by $($byBase[$match].file.Name)"; nearest = '' }) | Out-Null
        }
    }
    $ent = [ordered]@{}
    foreach ($k in $byBase.Keys) { $ent[$k] = $byBase[$k].file }
    return @{ entities = $ent; skipped = @($skipped.ToArray()) }
}

function ConvertFrom-PimCsvImportText {
    <#
      RFC 4180 reader: quoted fields ("" = a quote), the delimiter, CR / LF / CRLF, and line breaks
      inside quotes. Returns @{ records = @( @{ fields = string[]; line = <1-based physical line> } ); unterminatedAt }.
      Values are kept exactly as written (no trimming) -- the same values Import-Csv produces.
    #>
    param([AllowEmptyString()][string]$Text, [Parameter(Mandatory)][char]$Delimiter)
    $records = New-Object System.Collections.Generic.List[object]
    $fields = New-Object System.Collections.Generic.List[string]
    $sb = New-Object System.Text.StringBuilder
    $inQ = $false; $line = 1; $recLine = 1; $i = 0; $n = $Text.Length
    $q = [int][char]'"'; $d = [int]$Delimiter; $cr = 13; $lf = 10
    $quoteStart = 0
    while ($i -lt $n) {
        $c = [int]$Text[$i]
        if ($inQ) {
            if ($c -eq $q) {
                if ($i + 1 -lt $n -and [int]$Text[$i + 1] -eq $q) { [void]$sb.Append('"'); $i += 2; continue }
                $inQ = $false; $i++; continue
            }
            if ($c -eq $lf) { $line++ }
            [void]$sb.Append($Text[$i]); $i++; continue
        }
        if ($c -eq $q -and $sb.Length -eq 0) { $inQ = $true; $quoteStart = $line; $i++; continue }
        if ($c -eq $d) { $fields.Add($sb.ToString()); [void]$sb.Clear(); $i++; continue }
        if ($c -eq $cr -or $c -eq $lf) {
            $fields.Add($sb.ToString()); [void]$sb.Clear()
            $records.Add(@{ fields = $fields.ToArray(); line = $recLine }) | Out-Null
            $fields.Clear()
            if ($c -eq $cr -and $i + 1 -lt $n -and [int]$Text[$i + 1] -eq $lf) { $i++ }
            $i++; $line++; $recLine = $line; continue
        }
        [void]$sb.Append($Text[$i]); $i++
    }
    if ($sb.Length -gt 0 -or $fields.Count -gt 0 -or $inQ) {
        $fields.Add($sb.ToString())
        $records.Add(@{ fields = $fields.ToArray(); line = $recLine }) | Out-Null
    }
    return @{ records = @($records.ToArray()); unterminatedAt = $(if ($inQ) { $quoteStart } else { 0 }) }
}

function Read-PimCsvImportFile {
    <#
      Read ONE entity file. Returns @{ encoding; bom; delimiter; header; rawHeaderCount; trailingEmpty;
      rows = @(pscustomobject); rowLines = @(int); rowNumbers = @(int); blankRows; findings; parsed }.
      `rows` holds the NON-BLANK data rows only, as ordered objects keyed by the cleaned header.
    #>
    param([Parameter(Mandatory)][System.IO.FileInfo]$File, [Parameter(Mandatory)][string]$Entity, [string[]]$SchemaHeader = @())
    $fn = $File.Name
    $F = New-Object System.Collections.Generic.List[object]
    $out = @{ encoding = ''; bom = $false; delimiter = ''; header = @(); rawHeaderCount = 0; trailingEmpty = 0
              rows = @(); rowLines = @(); rowNumbers = @(); blankRows = 0; findings = $null; parsed = $false }
    $bytes = $null
    try { $bytes = [System.IO.File]::ReadAllBytes($File.FullName) } catch {
        $F.Add((New-PimCsvImportFinding -Severity error -Code 'CSVIMP-FILE-004' -File $fn -Entity $Entity -Message "cannot read the file: $($_.Exception.Message)")) | Out-Null
        $out.findings = @($F.ToArray()); return $out
    }
    # --- encoding --------------------------------------------------------------------------------
    $text = $null; $offset = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $out.bom = $true; $offset = 3; $out.encoding = 'UTF-8 (BOM)' }
    elseif ($bytes.Length -ge 2 -and (($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) -or ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF))) {
        $enc = if ($bytes[0] -eq 0xFF) { [System.Text.Encoding]::Unicode } else { [System.Text.Encoding]::BigEndianUnicode }
        $out.encoding = if ($bytes[0] -eq 0xFF) { 'UTF-16 LE' } else { 'UTF-16 BE' }
        $F.Add((New-PimCsvImportFinding -Severity error -Code 'CSVIMP-ENC-001' -File $fn -Entity $Entity -Message "the file is $($out.encoding), not UTF-8. The import reads UTF-8; save the file as UTF-8 (with or without BOM) first." -Suggestion 'In Excel: Save As -> "CSV UTF-8 (Comma delimited)". In an editor: re-save as UTF-8.')) | Out-Null
        $text = $enc.GetString($bytes, 2, $bytes.Length - 2)
    }
    if ($null -eq $text) {
        $strict = New-Object System.Text.UTF8Encoding($false, $true)
        try {
            $text = $strict.GetString($bytes, $offset, $bytes.Length - $offset)
            if (-not $out.encoding) {
                $ascii = $true; for ($b = 0; $b -lt $bytes.Length; $b++) { if ($bytes[$b] -gt 0x7F) { $ascii = $false; break } }
                $out.encoding = if ($ascii) { 'UTF-8 (no BOM, ASCII)' } else { 'UTF-8 (no BOM)' }
            }
        } catch {
            # Find the first invalid byte so the operator can go to it.
            $bad = -1; $dec = [System.Text.Encoding]::UTF8
            $lineNo = 1; $pos = $offset
            while ($pos -lt $bytes.Length) {
                $bt = $bytes[$pos]
                $len = if ($bt -lt 0x80) { 1 } elseif (($bt -band 0xE0) -eq 0xC0) { 2 } elseif (($bt -band 0xF0) -eq 0xE0) { 3 } elseif (($bt -band 0xF8) -eq 0xF0) { 4 } else { 0 }
                $ok = ($len -gt 0 -and $pos + $len -le $bytes.Length)
                if ($ok) { for ($k = 1; $k -lt $len; $k++) { if (($bytes[$pos + $k] -band 0xC0) -ne 0x80) { $ok = $false; break } } }
                if (-not $ok) { $bad = $pos; break }
                if ($bt -eq 0x0A) { $lineNo++ }
                $pos += $len
            }
            $out.encoding = 'not UTF-8'
            $where = if ($bad -ge 0) { " (first invalid byte 0x{0:X2} at byte offset {1}, line {2})" -f $bytes[$bad], $bad, $lineNo } else { '' }
            $F.Add((New-PimCsvImportFinding -Severity error -Code 'CSVIMP-ENC-002' -File $fn -Entity $Entity -Line $(if ($bad -ge 0) { $lineNo } else { $null }) `
                -Message "the file is not valid UTF-8$where -- most likely ANSI / Windows-1252. Imported as UTF-8, every non-ASCII character (Danish letters, accents) would be corrupted." `
                -Suggestion 'Re-save the file as UTF-8 (with or without BOM) and run the check again.')) | Out-Null
            $text = [System.Text.Encoding]::GetEncoding(1252).GetString($bytes, $offset, $bytes.Length - $offset)
        }
    }
    if ($text.Length -gt 0 -and [int]$text[0] -eq 0xFEFF) { $text = $text.Substring(1) }
    if ($text.IndexOf([char]0) -ge 0) {
        $F.Add((New-PimCsvImportFinding -Severity error -Code 'CSVIMP-ENC-001' -File $fn -Entity $Entity -Message 'the file contains NUL characters -- it is not a UTF-8 text file (UTF-16 without a BOM, or binary).' -Suggestion 'Re-save the file as UTF-8.')) | Out-Null
        $out.findings = @($F.ToArray()); return $out
    }
    if (-not $text.Trim()) {
        $F.Add((New-PimCsvImportFinding -Severity warning -Code 'CSVIMP-FILE-005' -File $fn -Entity $Entity -Message 'the file is empty (no header line) -- nothing to import.' -Suggestion 'Delete the file, or add the header line.')) | Out-Null
        $out.findings = @($F.ToArray()); return $out
    }

    # --- delimiter: counted on the header line, outside quotes -------------------------------------
    $firstLine = ($text -split "`r?`n", 2)[0]
    $semi = 0; $comma = 0; $inQ = $false
    foreach ($ch in $firstLine.ToCharArray()) { if ($ch -eq '"') { $inQ = -not $inQ } elseif (-not $inQ) { if ($ch -eq ';') { $semi++ } elseif ($ch -eq ',') { $comma++ } } }
    $delim = if ($semi -ge $comma) { ';' } else { ',' }
    $out.delimiter = $delim
    if ($semi -eq 0 -and $comma -eq 0) {
        $F.Add((New-PimCsvImportFinding -Severity warning -Code 'CSVIMP-DELIM-001' -File $fn -Entity $Entity -Line 1 -Message "the header has ONE column ('$firstLine'), so the delimiter cannot be detected; read with ';'." -Suggestion "Check the file: a PIM entity has several columns, separated by ';' or ','.")) | Out-Null
    }

    $parsed = ConvertFrom-PimCsvImportText -Text $text -Delimiter ([char]$delim)
    if ($parsed.unterminatedAt) {
        $F.Add((New-PimCsvImportFinding -Severity error -Code 'CSVIMP-PARSE-001' -File $fn -Entity $Entity -Line $parsed.unterminatedAt -Message "a quoted field that starts on line $($parsed.unterminatedAt) is never closed -- everything after it would be read as ONE value." -Suggestion 'Close the quote (a quote inside a quoted value is written as two quotes: "").')) | Out-Null
    }
    $recs = @($parsed.records)
    if (-not $recs.Count) { $out.findings = @($F.ToArray()); return $out }

    # --- header ------------------------------------------------------------------------------------
    $raw = @($recs[0].fields | ForEach-Object { "$_".Trim() })
    $out.rawHeaderCount = $raw.Count
    $last = $raw.Count - 1
    while ($last -ge 0 -and -not $raw[$last]) { $last-- }
    $out.trailingEmpty = $raw.Count - 1 - $last
    $hdr = if ($last -ge 0) { @($raw[0..$last]) } else { @() }
    if ($out.trailingEmpty -gt 0) {
        $F.Add((New-PimCsvImportFinding -Severity info -Code 'CSVIMP-COL-002' -File $fn -Entity $Entity -Line 1 -Message "$($out.trailingEmpty) trailing empty column(s) in the header -- ignored (a spreadsheet export artefact). A value in one of them on a data row is reported separately.")) | Out-Null
    }
    $schemaLc = @{}; foreach ($s in @($SchemaHeader)) { $schemaLc["$s".ToLowerInvariant()] = "$s" }
    $seen = @{}; $clean = New-Object System.Collections.Generic.List[string]; $usable = New-Object System.Collections.Generic.List[bool]
    for ($c = 0; $c -lt $hdr.Count; $c++) {
        $h = $hdr[$c]
        if (-not $h) {
            $F.Add((New-PimCsvImportFinding -Severity error -Code 'CSVIMP-COL-003' -File $fn -Entity $Entity -Line 1 -Column ("#{0}" -f ($c + 1)) -Message "column $($c + 1) has no name, but columns after it do. Its values cannot be stored under a name (a plain import would invent one, 'H$($c + 1)')." -Suggestion 'Name the column, or delete it.')) | Out-Null
            $clean.Add(''); $usable.Add($false); continue
        }
        $name = $h
        if ($schemaLc.ContainsKey($h.ToLowerInvariant()) -and $schemaLc[$h.ToLowerInvariant()] -cne $h) {
            $name = $schemaLc[$h.ToLowerInvariant()]
            $F.Add((New-PimCsvImportFinding -Severity info -Code 'CSVIMP-COL-007' -File $fn -Entity $Entity -Line 1 -Column $h -Message "column '$h' is stored as '$name' (the schema's spelling). The Manager's grid matches column names exactly, so the file's spelling would show as an empty column.")) | Out-Null
        }
        if ($seen.ContainsKey($name.ToLowerInvariant())) {
            $F.Add((New-PimCsvImportFinding -Severity error -Code 'CSVIMP-COL-005' -File $fn -Entity $Entity -Line 1 -Column $h -Message "column '$h' appears twice (columns $($seen[$name.ToLowerInvariant()]) and $($c + 1)); only one value per row can be stored." -Suggestion 'Remove or rename one of the two columns.')) | Out-Null
            $clean.Add(''); $usable.Add($false); continue
        }
        $seen[$name.ToLowerInvariant()] = $c + 1
        $clean.Add($name); $usable.Add($true)
        if ($SchemaHeader.Count -and -not $schemaLc.ContainsKey($h.ToLowerInvariant())) {
            # A likely intended schema column (a v1 name that v2 renamed, a typo): named in the suggestion only --
            # which column a value belongs to is the operator's decision, never renamed here.
            $near = @($SchemaHeader | Where-Object { $s = "$_"; $s.StartsWith($h, [StringComparison]::OrdinalIgnoreCase) -or $h.StartsWith($s, [StringComparison]::OrdinalIgnoreCase) -or
                        ((Get-Command Get-PimLevenshteinDistance -ErrorAction SilentlyContinue) -and (Get-PimLevenshteinDistance -A $h.ToLowerInvariant() -B $s.ToLowerInvariant()) -le 3) })
            $sug = if ($near.Count) { "Did you mean $(($near | ForEach-Object { "'$_'" }) -join ' or ')? Rename the column if it holds that value, or drop it." } else { "Rename it to the schema column it means, or drop it. Schema columns: " + ($SchemaHeader -join ', ') }
            $F.Add((New-PimCsvImportFinding -Severity warning -Code 'CSVIMP-COL-001' -File $fn -Entity $Entity -Line 1 -Column $h -Message "column '$h' is not in the $Entity schema. It is stored with the row, but the Manager does not show or edit it." -Suggestion $sug)) | Out-Null
        }
    }
    $out.header = @($clean.ToArray() | Where-Object { $_ })
    if ($SchemaHeader.Count) {
        $missing = @($SchemaHeader | Where-Object { -not $seen.ContainsKey("$_".ToLowerInvariant()) })
        if ($missing.Count) {
            $F.Add((New-PimCsvImportFinding -Severity info -Code 'CSVIMP-COL-006' -File $fn -Entity $Entity -Line 1 -Message ("{0} schema column(s) are not in the file and import as blank (the default): {1}" -f $missing.Count, ($missing -join ', ')))) | Out-Null
        }
    }

    # --- rows --------------------------------------------------------------------------------------
    $rows = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[int]
    $nums = New-Object System.Collections.Generic.List[int]
    $blank = 0
    for ($r = 1; $r -lt $recs.Count; $r++) {
        $fields = @($recs[$r].fields)
        $isBlank = $true; foreach ($v in $fields) { if ("$v".Length -gt 0) { $isBlank = $false; break } }
        if ($isBlank) { $blank++; continue }
        $o = [ordered]@{}
        for ($c = 0; $c -lt $clean.Count; $c++) {
            if (-not $usable[$c]) { continue }
            $o[$clean[$c]] = if ($c -lt $fields.Count) { "$($fields[$c])" } else { '' }
        }
        # A value beyond the named columns -- or under an unnamed/duplicate one -- has nowhere to go.
        for ($c = 0; $c -lt $fields.Count; $c++) {
            $lost = ($c -ge $clean.Count) -or (-not $usable[$c])
            if ($lost -and "$($fields[$c])".Length -gt 0) {
                $F.Add((New-PimCsvImportFinding -Severity error -Code 'CSVIMP-COL-004' -File $fn -Entity $Entity -Row $r -Line $recs[$r].line -Column ("#{0}" -f ($c + 1)) -Message ("row {0} has the value '{1}' in column {2}, which has no (usable) header -- it would be LOST on import." -f $r, $fields[$c], ($c + 1)) -Suggestion 'Give the column a name, or move the value into the column it belongs to.')) | Out-Null
            }
        }
        $rows.Add([pscustomobject]$o) | Out-Null
        $lines.Add([int]$recs[$r].line) | Out-Null
        $nums.Add($r) | Out-Null
    }
    $out.blankRows = $blank
    if ($blank -gt 0) {
        $F.Add((New-PimCsvImportFinding -Severity info -Code 'CSVIMP-ROW-001' -File $fn -Entity $Entity -Message "$blank blank separator row(s) (every cell empty) -- skipped, as the engine and the store skip them.")) | Out-Null
    }
    $out.rows = @($rows.ToArray()); $out.rowLines = @($lines.ToArray()); $out.rowNumbers = @($nums.ToArray())
    $out.parsed = $true
    $out.findings = @($F.ToArray())
    return $out
}

function Copy-PimCsvImportRow {
    param([Parameter(Mandatory)][object]$Row)
    $o = [ordered]@{}
    foreach ($p in $Row.PSObject.Properties) { $o[$p.Name] = $p.Value }
    return [pscustomobject]$o
}

function Get-PimCsvImportForceLocalPlan {
    <#
      THE IMPORT-SIDE RULE (-ForceLocal). An imported row stays on the master unless the FILE says
      otherwise:
        * an admin (Account-Definitions-Admins) with no ManagementMode AND no Replicate gets ManagementMode=local;
        * every other replicable row (Get-PimReplicationEntities) with no Replicate gets Replicate=No.
      A value the file sets explicitly is never changed. Returns @{ rows = transformed copies; changes = @( @{ index; column; from; to } ) }.
    #>
    param([Parameter(Mandatory)][string]$Entity, [AllowEmptyCollection()][object[]]$Rows = @())
    $kind = Get-PimReplicationKindForEntity -Entity $Entity
    $outRows = New-Object System.Collections.Generic.List[object]
    $changes = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt @($Rows).Count; $i++) {
        $r = Copy-PimCsvImportRow -Row $Rows[$i]
        if ($kind) {
            $rep = "$(Get-PimDownlinkValue -Object $r -Key 'Replicate')".Trim()
            if ($kind -eq 'admin') {
                $mmProp = $r.PSObject.Properties['ManagementMode']
                $mm = if ($mmProp) { "$($mmProp.Value)".Trim() } else { '' }
                if (-not $mm -and -not $rep) {
                    $from = if ($mmProp) { '' } else { '<no column>' }
                    $r | Add-Member -NotePropertyName 'ManagementMode' -NotePropertyValue 'local' -Force
                    $changes.Add([ordered]@{ index = $i; column = 'ManagementMode'; from = $from; to = 'local' }) | Out-Null
                }
            } elseif (-not $rep) {
                $from = if ($r.PSObject.Properties['Replicate']) { '' } else { '<no column>' }
                $r | Add-Member -NotePropertyName 'Replicate' -NotePropertyValue 'No' -Force
                $changes.Add([ordered]@{ index = $i; column = 'Replicate'; from = $from; to = 'No' }) | Out-Null
            }
        }
        $outRows.Add($r) | Out-Null
    }
    return @{ rows = @($outRows.ToArray()); changes = @($changes.ToArray()) }
}

function Get-PimCsvImportReplication {
    <#
      Per replicable row: the EFFECTIVE Replicate (Get-PimReplicateMode) and whether an MSP master would
      PUBLISH it, decided by the producer's own pure function (Select-PimBaselineBundleContent) over the
      rows. -EntityRows: base -> @(rows). Returns @{ rows = @(...); bundle = counts; notPublished; dependencyIncluded }.
      Computed over the given rows ALONE: rows already in the target store can make a Follow row travel too.
    #>
    param([Parameter(Mandatory)][hashtable]$EntityRows)
    $lc = { param($s) "$s".Trim().ToLowerInvariant() }
    $ents = @{}
    foreach ($e in @(Get-PimReplicationEntities)) {
        if ($EntityRows.ContainsKey($e)) { $ents[$e] = @(@($EntityRows[$e]) | ForEach-Object { Copy-PimCsvImportRow -Row $_ }) }
    }
    $b = Select-PimBaselineBundleContent -RegistryRows @() -RegistryReplicate @{} -Entities $ents
    $pubAdmins = @{}; foreach ($a in @($b.rows)) { $pubAdmins[(& $lc (Get-PimDownlinkValue -Object $a -Key 'UserName'))] = $true }
    $pubMem = @{}; foreach ($a in @($b.assignments)) { $pubMem["$(& $lc $a.UserName)|$(& $lc $a.GroupTag)"] = $true }
    $defs = $b.definitions
    $pubGrp = @{}; foreach ($g in @($defs.groups)) { $pubGrp[(& $lc $g.GroupTag)] = $true }
    $pubNest = @{}; foreach ($n in @($defs.nestings)) { $pubNest["$(& $lc $n.TargetGroupTag)|$(& $lc $n.SourceGroupTag)"] = $true }
    $pubBind = @{}; foreach ($x in @($defs.roleBindings)) { $pubBind["$(& $lc $x.GroupTag)|$(& $lc $x.RoleDefinitionName)"] = $true }
    $pubRes = @{}
    $resList = @(); if ($defs.Contains('resourceBindings')) { $resList = @($defs['resourceBindings']) }
    foreach ($x in $resList) { $pubRes["$($x.Entity)|$(& $lc (Get-PimStoreRowKey -Base "$($x.Entity)" -Row ([pscustomobject]$x)))"] = $true }
    $depGroups = @{}; foreach ($d in @($b.report.dependencyIncluded)) { if ("$($d.kind)" -in @('group','department')) { $depGroups[(& $lc $d.name)] = "$($d.reason)" } }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in @(Get-PimReplicationEntities)) {
        if (-not $EntityRows.ContainsKey($e)) { continue }
        $kind = Get-PimReplicationKindForEntity -Entity $e
        $rows = @($EntityRows[$e])
        for ($i = 0; $i -lt $rows.Count; $i++) {
            $r = $rows[$i]
            $m = Get-PimReplicateMode -Row $r -Kind $kind -AdminSource Definition   # CSV admins are definition rows
            $pub = $false; $why = ''
            switch ($kind) {
                'admin' {
                    $un = "$(Get-PimDownlinkValue -Object $r -Key 'UserName')".Trim()
                    if (-not $un) { $un = ("$(Get-PimDownlinkValue -Object $r -Key 'UserPrincipalName')".Trim() -split '@')[0] }
                    $pub = $pubAdmins.ContainsKey((& $lc $un))
                    if ($pub) { $why = "published: $($m.reason), Ring $("$(Get-PimDownlinkValue -Object $r -Key 'Ring')".Trim())" }
                    else {
                        $ns = @(@($b.report.defAdmins.notSynced) + @($b.report.defAdmins.mspWithoutRing) + @($b.report.defAdmins.adOnly) | Where-Object { (& $lc $_.UserName) -eq (& $lc $un) }) | Select-Object -First 1
                        $why = if ($ns -and $ns.Contains('masterOnly') -and $ns['masterOnly']) { 'not published: ManagementMode blank -- master tenant only' }
                               elseif ($ns) { "not published: $($ns.reason)" } else { 'not published' }
                    }
                }
                'membership' {
                    $u = "$(Get-PimDownlinkValue -Object $r -Key 'Username')".Trim(); if (-not $u) { $u = "$(Get-PimDownlinkValue -Object $r -Key 'UserName')".Trim() }
                    $at = $u.IndexOf('@'); if ($at -gt 0) { $u = $u.Substring(0, $at) }
                    $pub = $pubMem.ContainsKey("$(& $lc $u)|$(& $lc (Get-PimDownlinkValue -Object $r -Key 'GroupTag'))")
                    $why = if ($pub) { 'published: its admin is published and the membership is not Replicate=No' } else { 'not published: its admin is not published (a membership follows its admin)' }
                }
                'group' {
                    $t = & $lc (Get-PimDownlinkValue -Object $r -Key 'GroupTag')
                    $pub = $pubGrp.ContainsKey($t)
                    if ($pub) { $why = if ($m.mode -eq 'Yes') { 'published: Replicate=Yes seeds it' } elseif ($depGroups.ContainsKey($t)) { "published as a dependency: $($depGroups[$t])" } else { 'published: a replicated row needs it (Follow)' } }
                    else { $why = "not published: $($m.reason)" }
                }
                'nesting' {
                    $pub = $pubNest.ContainsKey("$(& $lc (Get-PimDownlinkValue -Object $r -Key 'TargetGroupTag'))|$(& $lc (Get-PimDownlinkValue -Object $r -Key 'SourceGroupTag'))")
                    $why = if ($pub) { $(if ($m.mode -eq 'Yes') { 'published: Replicate=Yes seeds it' } else { 'published: its target group is replicated (Follow)' }) } else { "not published: $($m.reason)" }
                }
                'binding' {
                    $pub = $pubBind.ContainsKey("$(& $lc (Get-PimDownlinkValue -Object $r -Key 'GroupTag'))|$(& $lc (Get-PimDownlinkValue -Object $r -Key 'RoleDefinitionName'))")
                    $why = if ($pub) { $(if ($m.mode -eq 'Yes') { 'published: Replicate=Yes seeds it' } else { 'published: its group is replicated (Follow)' }) } else { "not published: $($m.reason)" }
                }
                'resource' {
                    $pub = $pubRes.ContainsKey("$e|$(& $lc (Get-PimStoreRowKey -Base $e -Row $r))")
                    $why = if ($pub) { 'published: explicitly Follow/Yes and its group is replicated' } else { "not published: $($m.reason)" }
                }
            }
            $mmCell = ''
            if ($kind -eq 'admin') { $mmp = $r.PSObject.Properties['ManagementMode']; $mmCell = if ($mmp) { "$($mmp.Value)" } else { '<no column>' } }
            $out.Add([ordered]@{
                entity = $e; index = $i; kind = $kind; key = "$(Get-PimStoreRowKey -Base $e -Row $r)"
                replicate = "$(Get-PimDownlinkValue -Object $r -Key 'Replicate')"; managementMode = $mmCell
                ring = "$(Get-PimDownlinkValue -Object $r -Key 'Ring')"; target = "$(Get-PimDownlinkValue -Object $r -Key 'Target')"
                mode = "$($m.mode)"; valid = [bool]$m.valid; reason = "$($m.reason)"; published = [bool]$pub; publishReason = $why
            }) | Out-Null
        }
    }
    return @{
        rows = @($out.ToArray())
        bundle = [ordered]@{
            admins = @($b.rows).Count; memberships = @($b.assignments).Count; groups = @($defs.groups).Count
            nestings = @($defs.nestings).Count; roleBindings = @($defs.roleBindings).Count; resourceBindings = $resList.Count
            aus = $(if ($defs.Contains('aus')) { @($defs['aus']).Count } else { 0 })
        }
        notPublished = @($b.report.notPublished)
        dependencyIncluded = @($b.report.dependencyIncluded)
    }
}

function Invoke-PimCsvImportCheck {
    <#
    .SYNOPSIS
        Validate every v1 CSV in -Path BEFORE anything is imported. Pure and offline.
    .OUTPUTS
        [ordered] @{ path; ranAtUtc; forceLocal; targetIsMspMaster; verdict (PASS|FAIL); errors; warnings; infos;
                     files = @(per-file summary); findings = @(...); replication = @{ ... }; import = @{ base = @{ file; rows; rawRows; keys; lines; rowNumbers } } }
        `import` is what an importer writes (blank rows dropped, headers cleaned, -ForceLocal applied).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        # The entities to take. Default: every entity in the Manager's schema.
        [string[]]$Entities,
        # The import-side replication rule (see Get-PimCsvImportForceLocalPlan). Reported either way.
        [switch]$ForceLocal,
        # The target is NOT an MSP master (a single or managed tenant): the replication fields mean nothing there.
        [switch]$NotMspMaster,
        # The target's default UPN domain, so admin rows without a UserPrincipalName resolve as the engine resolves them.
        [string]$DefaultDomain
    )
    $solRoot = Get-PimCsvImportSolutionRoot
    $shared = Join-Path $solRoot 'engine\_shared'
    $schema = Get-PimCsvEntitySchema
    if (-not $Entities -or -not @($Entities).Count) { $Entities = @($schema.Keys) }

    # --- the engine's own predicates, loaded into THIS function's scope (they vanish on return) ---------
    . (Join-Path $shared 'PIM-DateSafe.ps1')
    if (-not (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue)) { . (Join-Path $shared 'PIM-SqlStore.ps1') }
    if (-not (Get-Command Get-PimAdminMailRecipientPlan -ErrorAction SilentlyContinue)) { . (Join-Path $shared 'PIM-Rest.ps1') }
    . (Join-Path $shared 'PIM-Naming.ps1')
    . (Join-Path $shared 'PIM-Downlink.ps1')
    . (Join-Path $shared 'PIM-PolicyTemplateStore.ps1')
    . (Join-Path $solRoot 'tools\pim-manager\_validator.ps1')
    foreach ($need in 'Invoke-PimPreflightValidation','Get-PimReplicateMode','Get-PimReplicationKindForEntity','Get-PimReplicationEntities',
                      'Select-PimBaselineBundleContent','Get-PimStoreRowKey','Get-PimDuplicateStoreKeys','Test-PimReplicationRowFields','Test-PimGroupName') {
        if (-not (Get-Command $need -ErrorAction SilentlyContinue)) { throw "Invoke-PimCsvImportCheck: '$need' did not load -- the check cannot run, and a check that did not run is not a pass." }
    }

    $findings = New-Object System.Collections.Generic.List[object]
    $files = New-Object System.Collections.Generic.List[object]
    $set = Get-PimCsvImportFileSet -Path $Path -Entities @($Entities)
    foreach ($s in @($set.skipped)) {
        $sev = 'info'; $code = 'CSVIMP-FILE-001'; $msg = "$($s.reason)"; $sug = ''
        if ($s.status -eq 'not-entity') {
            $code = 'CSVIMP-FILE-002'
            if ($s.nearest) { $sev = 'warning'; $msg = "not a PIM entity, not imported -- did you mean '$($s.nearest)'?"; $sug = "Rename the file to $($s.nearest).csv if it holds that entity's rows." }
        } elseif ($s.status -eq 'superseded') { $code = 'CSVIMP-FILE-003' }
        $findings.Add((New-PimCsvImportFinding -Severity $sev -Code $code -File $s.file -Message $msg -Suggestion $sug)) | Out-Null
        $files.Add([ordered]@{ file = $s.file; entity = ''; status = $s.status; encoding = ''; delimiter = ''; rows = 0; blankRows = 0; errors = 0; warnings = $(if ($sev -eq 'warning') { 1 } else { 0 }); infos = $(if ($sev -eq 'info') { 1 } else { 0 }) }) | Out-Null
    }

    # --- file level ------------------------------------------------------------------------------------
    $import = [ordered]@{}
    $fileOf = @{}
    foreach ($base in $set.entities.Keys) {
        $fi = $set.entities[$base]
        $fileOf[$base] = $fi.Name
        $hdr = if ($schema.Contains($base)) { @($schema[$base]) } else { @() }
        $rd = Read-PimCsvImportFile -File $fi -Entity $base -SchemaHeader $hdr
        foreach ($x in @($rd.findings)) { $findings.Add($x) | Out-Null }
        $raw = @($rd.rows)
        $keys = @($raw | ForEach-Object { "$(Get-PimStoreRowKey -Base $base -Row $_)" })
        for ($i = 0; $i -lt $raw.Count; $i++) {
            if (-not $keys[$i]) {
                $findings.Add((New-PimCsvImportFinding -Severity error -Code 'CSVIMP-KEY-001' -File $fi.Name -Entity $base -Row $rd.rowNumbers[$i] -Line $rd.rowLines[$i] `
                    -Message "row $($rd.rowNumbers[$i]) has no natural key -- the store keys $base rows on its key column(s), and a row without one is DROPPED on import." `
                    -Suggestion 'Fill in the key column(s) (GroupTag for definitions, UserName for admins, the tag / role pair for assignments), or delete the row.')) | Out-Null
            }
        }
        foreach ($dup in @(Get-PimDuplicateStoreKeys -Base $base -Rows $raw)) {
            $at = @($dup.rows | ForEach-Object { $rd.rowNumbers[$_ - 1] })
            $ln = @($dup.rows | ForEach-Object { $rd.rowLines[$_ - 1] })
            $findings.Add((New-PimCsvImportFinding -Severity error -Code 'CSVIMP-KEY-002' -File $fi.Name -Entity $base -Row $at[1] -Line $ln[1] `
                -Message ("key '{0}' is on {1} rows (rows {2}; lines {3}). The store holds ONE row per key, so the import keeps the last and silently drops the others." -f $dup.key, $dup.count, ($at -join ', '), ($ln -join ', ')) `
                -Suggestion 'Merge the rows, or delete the duplicates.')) | Out-Null
        }
        $import[$base] = @{ file = $fi.Name; rawRows = $raw; rows = $raw; keys = $keys; lines = @($rd.rowLines); rowNumbers = @($rd.rowNumbers)
                             header = @($rd.header); encoding = $rd.encoding; delimiter = $rd.delimiter; blankRows = $rd.blankRows; forceLocalChanges = @() }
    }

    # --- -ForceLocal: computed always (reported), applied only when asked --------------------------------
    $flChanges = New-Object System.Collections.Generic.List[object]
    foreach ($base in @($import.Keys)) {
        $pl = Get-PimCsvImportForceLocalPlan -Entity $base -Rows @($import[$base].rawRows)
        $im = $import[$base]
        foreach ($c in @($pl.changes)) {
            $flChanges.Add([ordered]@{ file = $im.file; entity = $base; row = $im.rowNumbers[$c.index]; line = $im.lines[$c.index]; key = $im.keys[$c.index]; column = $c.column; from = $c.from; to = $c.to }) | Out-Null
        }
        $im.forceLocalChanges = @($pl.changes)
        if ($ForceLocal) { $im.rows = @($pl.rows) }
        if (@($pl.changes).Count) {
            $cols = @($pl.changes | ForEach-Object { "$($_.column)=$($_.to)" } | Sort-Object -Unique) -join ', '
            $verb = if ($ForceLocal) { '-ForceLocal SETS' } else { '-ForceLocal would set' }
            $findings.Add((New-PimCsvImportFinding -Severity info -Code 'CSVIMP-REP-003' -File $im.file -Entity $base -Source 'replication' `
                -Message ("{0} {1} on {2} row(s) that do not set it explicitly." -f $verb, $cols, @($pl.changes).Count))) | Out-Null
        }
    }

    # --- row level: the Manager's validator, over the rows that would be imported ------------------------
    $prevNc = $global:PIM_NamingConventions; $prevMaster = $global:PIM_ValidatorIsMspMaster
    $prevTags = $global:PIM_ValidatorKnownTenantTags; $prevDom = $global:DefaultDomainUPN
    $valFindings = @()
    try {
        $global:PIM_NamingConventions = $null
        . (Join-Path $solRoot 'config\PIM4EntraPS.NamingConventions.locked.ps1')
        if ($global:PIM_NamingConventions -isnot [System.Collections.IDictionary]) { throw 'Invoke-PimCsvImportCheck: the shipped naming conventions did not load.' }
        $tpl = Read-PimShippedPolicyTemplates -TemplateDir (Join-Path $solRoot 'templates\policy')
        $global:PIM_NamingConventions['PolicyTemplates'] = @{ templates = $tpl }
        $global:PIM_ValidatorIsMspMaster = (-not $NotMspMaster)
        $global:PIM_ValidatorKnownTenantTags = @{ known = $false; tags = @() }
        # 🔴 NO PLACEHOLDER DOMAIN (2.4.377). This used to stand in 'default-domain.invalid' so a UserName-only v1 admin
        # resolved -- and that is exactly what HID the validator bug the hosted Manager then hit: there no domain is
        # pinned, the validator indexed admins by UPN only, and all 15 EFIF memberships failed PIM-FK-002 after an
        # import this check had passed. The validator now indexes an admin by its UserName (the identity; the UPN is
        # composed at create), so the check runs with the SAME domain state as the Manager: -DefaultDomain if given,
        # else none.
        $global:DefaultDomainUPN = if ("$DefaultDomain".Trim()) { "$DefaultDomain".Trim() } else { $null }

        $vRows = @{}
        foreach ($b in @($schema.Keys)) {
            $vRows[$b] = if ($import.Contains($b)) { @{ header = @($import[$b].header); rows = @($import[$b].rows) } } else { @{ header = @($schema[$b]); rows = @() } }
        }
        # The Manager's read seams, pointed at the parsed files. Function-scoped: gone when this returns.
        function Get-PimCsvBases { return ,@(@($vRows.Keys) | ForEach-Object { [pscustomobject]@{ base = $_ } }) }
        function Read-PimRows { param([string]$BaseName, [switch]$NoScope)
            if ($vRows.ContainsKey($BaseName)) { return @{ header = @($vRows[$BaseName].header); rows = @($vRows[$BaseName].rows); source = 'csv-import'; path = "csv:$BaseName" } }
            return @{ header = @(); rows = @(); source = 'none'; path = $null }
        }
        function Get-PimNamingConventions { return $global:PIM_NamingConventions }
        function Read-PimTenantListCache { return [ordered]@{ entraRoles = $null; aus = $null; pimGroups = $null; azureScopes = $null; azureRbacRoles = $null } }
        $vr = Invoke-PimPreflightValidation
        $valFindings = @($vr.violations)
    } finally {
        $global:PIM_NamingConventions = $prevNc; $global:PIM_ValidatorIsMspMaster = $prevMaster
        $global:PIM_ValidatorKnownTenantTags = $prevTags; $global:DefaultDomainUPN = $prevDom
    }
    foreach ($v in $valFindings) {
        $base = "$($v.Csv)"
        $fn = if ($fileOf.ContainsKey($base)) { $fileOf[$base] } else { '' }
        $rowNo = $null; $line = $null
        if ($null -ne $v.Row -and "$($v.Row)" -match '^\d+$' -and $import.Contains($base)) {
            $ix = [int]$v.Row
            if ($ix -lt @($import[$base].rowNumbers).Count) { $rowNo = $import[$base].rowNumbers[$ix]; $line = $import[$base].lines[$ix] }
        }
        $findings.Add((New-PimCsvImportFinding -Severity "$($v.Severity)" -Code "$($v.Code)" -File $fn -Entity $base -Row $rowNo -Line $line -Column "$($v.Column)" `
            -Message "$($v.Message)" -Suggestion "$($v.Suggestion)" -Source 'validator')) | Out-Null
    }
    $findings.Add((New-PimCsvImportFinding -Severity info -Code 'CSVIMP-VAL-000' -Source 'validator' `
        -Message ("The Manager's validator ran offline over the parsed files: naming rules use the SHIPPED defaults, policy templates are the SHIPPED templates, the target is treated as {0}, admins without a UserPrincipalName are matched {1}, managed-tenant tags are not known, and no tenant cache is available (cache-driven rules report that they did not run). Rows already in the target store are NOT seen: a reference to a row that exists only there is reported as missing." -f $(if ($NotMspMaster) { 'NOT an MSP master' } else { 'an MSP master' }), $(if ("$DefaultDomain".Trim()) { "as UserName@$("$DefaultDomain".Trim())" } else { 'by UserName (no -DefaultDomain given)' })))) | Out-Null

    # --- replication: the effective Replicate of every row, and what the master would publish -------------
    $asFiles = @{}; $asImported = @{}
    foreach ($b in @($import.Keys)) { $asFiles[$b] = @($import[$b].rawRows); $asImported[$b] = @($import[$b].rows) }
    $repFiles = Get-PimCsvImportReplication -EntityRows $asFiles
    $repLocal = $null
    $flAll = @{}
    foreach ($b in @($import.Keys)) { $flAll[$b] = @((Get-PimCsvImportForceLocalPlan -Entity $b -Rows @($import[$b].rawRows)).rows) }
    $repLocal = Get-PimCsvImportReplication -EntityRows $flAll
    $repEff = if ($ForceLocal) { $repLocal } else { $repFiles }
    foreach ($rr in @($repEff.rows)) {
        $im = $import[$rr.entity]
        $fn = $im.file; $rowNo = $im.rowNumbers[$rr.index]; $line = $im.lines[$rr.index]
        if (-not $NotMspMaster -and $rr.published) {
            $findings.Add((New-PimCsvImportFinding -Severity warning -Code 'CSVIMP-REP-001' -File $fn -Entity $rr.entity -Row $rowNo -Line $line -Column 'Replicate' -Source 'replication' `
                -Message ("{0} '{1}' WOULD BE REPLICATED to managed tenants by this MSP master -- {2}." -f $rr.kind, $rr.key, $rr.publishReason) `
                -Suggestion 'If it must stay on the master, set Replicate=No (admins: ManagementMode=local) in the file, or import with -ForceLocal.')) | Out-Null
        }
        # REP-002: an admin with a BLANK ManagementMode (no column, as in a v1 file, or an empty value) and no Replicate
        # stays on the master tenant only. Through 2.4.377 Get-PimReplicateMode read the no-column case as Yes while the
        # bundle did not publish it, and this warning named that disagreement; both now say No (-AdminSource Definition),
        # so what remains worth a warning on an MSP master is the plain fact: a v1 admin will NOT reach managed tenants.
        $mmBlank = ("$($rr.managementMode)" -eq '<no column>') -or -not "$($rr.managementMode)".Trim()
        if (-not $NotMspMaster -and $rr.kind -eq 'admin' -and $mmBlank -and -not "$($rr.replicate)".Trim() -and -not $rr.published) {
            $findings.Add((New-PimCsvImportFinding -Severity warning -Code 'CSVIMP-REP-002' -File $fn -Entity $rr.entity -Row $rowNo -Line $line -Column 'ManagementMode' -Source 'replication' `
                -Message ("admin '{0}' has {1}: a blank ManagementMode means MASTER TENANT ONLY, so this MSP master will NOT replicate it to any managed tenant ({2})." -f $rr.key, $(if ("$($rr.managementMode)" -eq '<no column>') { 'NO ManagementMode column' } else { 'an empty ManagementMode' }), $rr.reason) `
                -Suggestion 'If it must reach managed tenants, set ManagementMode=msp and a Ring in the file. To state that it stays on the master, set ManagementMode=local or import with -ForceLocal.')) | Out-Null
        }
    }
    $findings.Add((New-PimCsvImportFinding -Severity info -Code 'CSVIMP-REP-000' -Source 'replication' `
        -Message 'Replication is computed over the files alone with the producer''s own rules. Rows already in the target store can still pull a Follow row (or a Replicate=No group that a replicated row depends on -- carried as a dependency, warned) into the bundle.')) | Out-Null

    # --- summary -----------------------------------------------------------------------------------------
    $all = @($findings.ToArray())
    foreach ($base in @($import.Keys)) {
        $im = $import[$base]
        $mine = @($all | Where-Object { $_.file -eq $im.file })
        $files.Add([ordered]@{ file = $im.file; entity = $base; status = 'entity'; encoding = $im.encoding; delimiter = $im.delimiter
            rows = @($im.rows).Count; blankRows = $im.blankRows
            errors = @($mine | Where-Object { $_.severity -eq 'error' }).Count; warnings = @($mine | Where-Object { $_.severity -eq 'warning' }).Count
            infos = @($mine | Where-Object { $_.severity -eq 'info' }).Count }) | Out-Null
    }
    $errs = @($all | Where-Object { $_.severity -eq 'error' }).Count
    $repSummary = { param($rep)
        $s = [ordered]@{}
        foreach ($k in 'admin','membership','group','nesting','binding','resource') {
            $rk = @(@($rep.rows) | Where-Object { $_.kind -eq $k })
            if (-not $rk.Count) { continue }
            $s[$k] = [ordered]@{ rows = $rk.Count; yes = @($rk | Where-Object { $_.mode -eq 'Yes' }).Count; follow = @($rk | Where-Object { $_.mode -eq 'Follow' }).Count
                                 no = @($rk | Where-Object { $_.mode -eq 'No' }).Count; published = @($rk | Where-Object { $_.published }).Count }
        }
        $s
    }
    $rowRef = { param($rep)
        @(@($rep.rows) | ForEach-Object {
            $im = $import[$_.entity]
            $o = [ordered]@{ file = $im.file; row = $im.rowNumbers[$_.index]; line = $im.lines[$_.index] }
            foreach ($k in @($_.Keys)) { if ($k -ne 'index') { $o[$k] = $_[$k] } }
            [pscustomobject]$o
        })
    }
    return [ordered]@{
        path = (Resolve-Path -LiteralPath $Path).Path
        ranAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        forceLocal = [bool]$ForceLocal
        targetIsMspMaster = (-not $NotMspMaster)
        verdict = $(if ($errs) { 'FAIL' } else { 'PASS' })
        errors = $errs
        warnings = @($all | Where-Object { $_.severity -eq 'warning' }).Count
        infos = @($all | Where-Object { $_.severity -eq 'info' }).Count
        files = @($files.ToArray() | ForEach-Object { [pscustomobject]$_ } | Sort-Object file)
        findings = $all
        replication = [ordered]@{
            appliedForceLocal = [bool]$ForceLocal
            withoutForceLocal = [ordered]@{ summary = (& $repSummary $repFiles); bundle = $repFiles.bundle; notPublished = @($repFiles.notPublished); dependencyIncluded = @($repFiles.dependencyIncluded) }
            withForceLocal    = [ordered]@{ summary = (& $repSummary $repLocal); bundle = $repLocal.bundle; notPublished = @($repLocal.notPublished); dependencyIncluded = @($repLocal.dependencyIncluded) }
            rows = (& $rowRef $repEff)
            forceLocalChanges = @($flChanges.ToArray() | ForEach-Object { [pscustomobject]$_ })
        }
        import = $import
    }
}

function Write-PimCsvImportReport {
    <# Console report. Errors in full; warnings and infos grouped by code (every one with -ShowAll). #>
    param([Parameter(Mandatory)][object]$Result, [switch]$ShowAll, [int]$Examples = 5)
    $loc = { param($f) $p = @(); if ($f.file) { $p += $f.file }; if ($null -ne $f.row) { $p += "row $($f.row)" }; if ($null -ne $f.line) { $p += "line $($f.line)" }; if ($f.column) { $p += "col $($f.column)" }; if ($p.Count) { $p -join ' / ' } else { '<global>' } }
    Write-Host ''
    Write-Host ("CSV PRE-IMPORT CHECK -- {0}" -f $Result.path) -ForegroundColor Cyan
    Write-Host ("  target: {0}; -ForceLocal: {1}" -f $(if ($Result.targetIsMspMaster) { 'MSP master' } else { 'not an MSP master' }), $(if ($Result.forceLocal) { 'APPLIED' } else { 'not applied (changes it would make are listed)' })) -ForegroundColor DarkGray
    Write-Host ''
    Write-Host ("  {0,-48} {1,-11} {2,-28} {3,5} {4,6} {5,6} {6,6}" -f 'FILE', 'STATUS', 'ENCODING / DELIM', 'ROWS', 'ERR', 'WARN', 'INFO') -ForegroundColor White
    foreach ($f in @($Result.files)) {
        $enc = if ($f.encoding) { "$($f.encoding) '$($f.delimiter)'" } else { '' }
        $col = if ($f.errors) { 'Red' } elseif ($f.warnings) { 'Yellow' } elseif ($f.status -ne 'entity') { 'DarkGray' } else { 'Green' }
        Write-Host ("  {0,-48} {1,-11} {2,-28} {3,5} {4,6} {5,6} {6,6}" -f $f.file, $f.status, $enc, $f.rows, $f.errors, $f.warnings, $f.infos) -ForegroundColor $col
    }
    $all = @($Result.findings)
    $errs = @($all | Where-Object { $_.severity -eq 'error' })
    if ($errs.Count) {
        Write-Host ''
        Write-Host ("  ERRORS ({0}):" -f $errs.Count) -ForegroundColor Red
        foreach ($e in $errs) {
            Write-Host ("    [{0}] {1}: {2}" -f $e.code, (& $loc $e), $e.message) -ForegroundColor Red
            if ($e.suggestion) { Write-Host ("        -> {0}" -f $e.suggestion) -ForegroundColor DarkRed }
        }
    }
    foreach ($sev in 'warning', 'info') {
        $set = @($all | Where-Object { $_.severity -eq $sev })
        if (-not $set.Count) { continue }
        $color = if ($sev -eq 'warning') { 'Yellow' } else { 'DarkGray' }
        Write-Host ''
        Write-Host ("  {0}S ({1}), by code:" -f $sev.ToUpperInvariant(), $set.Count) -ForegroundColor $color
        foreach ($g in @($set | Group-Object code | Sort-Object Count -Descending)) {
            Write-Host ("    {0,-26} x{1}" -f $g.Name, $g.Count) -ForegroundColor $color
            $show = if ($ShowAll) { @($g.Group) } else { @($g.Group | Select-Object -First $Examples) }
            foreach ($x in $show) { Write-Host ("        {0}: {1}" -f (& $loc $x), $x.message) -ForegroundColor $color }
            if (-not $ShowAll -and $g.Count -gt $Examples) { Write-Host ("        ... and {0} more (-ShowAll lists every one)" -f ($g.Count - $Examples)) -ForegroundColor $color }
        }
    }
    $rep = $Result.replication
    Write-Host ''
    Write-Host '  REPLICATION to managed tenants (what this MSP master would publish; producer rules, files only):' -ForegroundColor Cyan
    foreach ($label in 'withoutForceLocal', 'withForceLocal') {
        $r = $rep[$label]
        $bb = $r.bundle
        Write-Host ("    {0,-18} bundle: {1} admin(s), {2} membership(s), {3} group(s), {4} nesting(s), {5} role binding(s), {6} resource binding(s)" -f $(if ($label -eq 'withoutForceLocal') { 'as the files are:' } else { 'with -ForceLocal:' }), $bb.admins, $bb.memberships, $bb.groups, $bb.nestings, $bb.roleBindings, $bb.resourceBindings) -ForegroundColor White
        foreach ($k in @($r.summary.Keys)) {
            $s = $r.summary[$k]
            Write-Host ("        {0,-11} rows {1,4}: Yes {2,4}  Follow {3,4}  No {4,4}  -> published {5,4}" -f $k, $s.rows, $s.yes, $s.follow, $s.no, $s.published) -ForegroundColor DarkGray
        }
    }
    $fl = @($rep.forceLocalChanges)
    Write-Host ("    -ForceLocal {0} {1} value(s):" -f $(if ($Result.forceLocal) { 'SETS' } else { 'would set' }), $fl.Count) -ForegroundColor White
    foreach ($g in @($fl | Group-Object file, column, to)) {
        $x = $g.Group[0]
        Write-Host ("        {0}: {1} '{2}' -> '{3}' on {4} row(s)" -f $x.file, $x.column, $x.from, $x.to, $g.Count) -ForegroundColor DarkGray
    }
    Write-Host ''
    $vc = if ($Result.verdict -eq 'PASS') { 'Green' } else { 'Red' }
    Write-Host ("  VERDICT: {0} -- {1} error(s), {2} warning(s), {3} info(s)" -f $Result.verdict, $Result.errors, $Result.warnings, $Result.infos) -ForegroundColor $vc
    Write-Host ''
}

function ConvertTo-PimCsvImportReportObject {
    # The machine-readable shape (-AsJson): everything except the import payload itself.
    param([Parameter(Mandatory)][object]$Result)
    $o = [ordered]@{}
    foreach ($k in @($Result.Keys)) { if ($k -ne 'import') { $o[$k] = $Result[$k] } }
    return $o
}
