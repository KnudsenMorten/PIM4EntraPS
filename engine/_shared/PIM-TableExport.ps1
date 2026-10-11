#Requires -Version 5.1
<#
.SYNOPSIS
  PIM REQUIREMENTS 100.67 -- export what a PIM Manager view shows to Excel (.xlsx) or PDF.

.DESCRIPTION
  The page builds ONE payload from the view's own data model (the arrays it renders, after its filters / sort / search):
      { view, title, format: 'pdf'|'xlsx', sections: [ { heading, columns: [..], rows: [[..], ..] } ] }
  and POSTs it to /api/export. The Manager checks the caller's role against the view (Get-PimTableExportViewRole), caps the
  size (Get-PimTableExportLimits), builds the model here (ConvertTo-PimTableExportModel) and returns the file.

  * xlsx: .NET only -- System.IO.Compression ZipArchive + a minimal SpreadsheetML package ([Content_Types].xml, _rels,
    workbook + its rels, styles (bold header), one worksheet per section with inline strings, a frozen header row and an
    autofilter). No module, no third-party library.
  * PDF: PDFsharp + MigraDoc (MIT), the same assemblies + font the as-built document (100.61) loads from
    $env:PIM_PDF_DLL_DIR / $env:PIM_PDF_FONT_DIR, through PIM-AsBuilt.ps1's own loader (Import-PimAsBuiltPdfLibrary) --
    one font resolver per process serves both documents.
    Landscape A4 when the table is wide, a header row that repeats on every page. No library = Test-PimTableExportPdfAvailable
    says why, and the page disables the PDF item; nothing is downloaded.

  The environment label in a file is the caller's decision (the Manager passes the placeholder when the setting
  HideCompanyAndEnvironmentName is on -- the default). Nothing here reads SQL, Graph or ARM.
#>

$script:PimTableExportPlaceholder = 'PIM Manager'
$script:PimTableExportMaxRows = 50000
$script:PimTableExportMaxColumns = 60
$script:PimTableExportMaxSections = 20
$script:PimTableExportMaxCellChars = 32000   # Excel's own cell limit is 32767

function Get-PimTableExportLimits {
    <# PURE. The caps the route applies. #>
    [pscustomobject]@{ maxRows = $script:PimTableExportMaxRows; maxColumns = $script:PimTableExportMaxColumns; maxSections = $script:PimTableExportMaxSections; maxCellChars = $script:PimTableExportMaxCellChars }
}

function Get-PimTableExportPlaceholder { return $script:PimTableExportPlaceholder }

function Test-PimHideNamesValue {
    <#
      PURE. Is the stored HideCompanyAndEnvironmentName value ON (names hidden)? ON BY DEFAULT (owner 2026-10-10: "on by
      def"): only an explicit "off" spelling shows the names -- $false, 0, or the text false / off / 0 / no / disabled. $null
      (never set), '', a typo: hidden. A name shown by accident is the failure this setting exists to prevent.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [bool]) { return [bool]$Value }
    if ($Value -is [int] -or $Value -is [long]) { return ([long]$Value -ne 0) }
    $t = "$Value".Trim().Trim('"')
    return -not ($t -match '^(?i)(false|off|0|no|disabled)$')
}

function Get-PimTableExportEnvironmentLabel {
    <# PURE. The environment label a file names: the placeholder while names are hidden, else the environment name, else the tenant name. #>
    param([bool]$Hide = $true, [AllowEmptyString()][string]$EnvironmentName = '', [AllowEmptyString()][string]$TenantName = '')
    if ($Hide) { return $script:PimTableExportPlaceholder }
    $e = "$EnvironmentName".Trim(); $t = "$TenantName".Trim()
    if ($e -and $t) { return "$e ($t)" }
    if ($e) { return $e }
    if ($t) { return $t }
    return $script:PimTableExportPlaceholder
}

# The views that may be exported and the LOWEST PIM Manager role that may export each. A view not listed is refused (the
# route answers 400) -- an export never names a surface the page does not have. The minimum matches what the page and the
# view's own read route require; it is re-checked on the server because the payload comes from the browser.
$script:PimTableExportViews = [ordered]@{
    home = 'Reader'; impact = 'Reader'
    revoke = 'Reader'; accounts = 'Reader'; approvals = 'Reader'; accessreview = 'Reader'; owner = 'Reader'; accessrequests = 'Reader'
    grid = 'Reader'; departments = 'Reader'; companies = 'Reader'; emergency = 'Reader'; mailtemplates = 'Reader'
    policytemplates = 'Reader'; guards = 'Reader'; workloadtemplates = 'Reader'; customworkloads = 'Reader'; roleperms = 'Reader'
    drift = 'Reader'; coverage = 'Reader'; commithistory = 'Reader'; reports = 'Reader'; conformance = 'Reader'
    downlink = 'Reader'; msptenants = 'Reader'; replication = 'Reader'; jobs = 'Reader'; enginelogs = 'Reader'; jobschedule = 'Reader'
    discovery = 'Reader'; save = 'Reader'; queue = 'Reader'; validate = 'Reader'; map = 'Reader'
    # the audit trail export is Admin (GET /api/audit/export) and Pro evidence (reports.evidence) -- the route checks both
    audit = 'Admin'
    configbackups = 'Admin'; envreport = 'Admin'
    # the role mapping is drawn only for a SuperAdmin (Manager access & roles > Manage)
    manageraccess = 'SuperAdmin'
}

function Get-PimTableExportViewRole {
    <# PURE. The lowest role that may export -View, or $null when the view is not exportable. #>
    param([AllowEmptyString()][string]$View)
    $v = "$View".Trim().ToLowerInvariant()
    if (-not $v -or -not $script:PimTableExportViews.Contains($v)) { return $null }
    return "$($script:PimTableExportViews[$v])"
}

function Get-PimTableExportViews { return @($script:PimTableExportViews.Keys) }

function ConvertTo-PimTableExportCellText {
    <# PURE. One cell as text: null -> '', arrays joined with '; ', control characters (except tab / newline) dropped. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { $s = $Value }
    elseif ($Value -is [bool]) { $s = $(if ($Value) { 'yes' } else { 'no' }) }
    elseif ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [System.Collections.IDictionary])) { $s = (@($Value) | ForEach-Object { ConvertTo-PimTableExportCellText $_ }) -join '; ' }
    elseif ($Value -is [System.IFormattable]) { $s = $Value.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture) }
    else { $s = "$Value" }
    return ($s -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '')
}

function Test-PimTableExportNumber {
    <# PURE. A JSON number (int / long / double / decimal) -- written to Excel as a number, everything else as text. #>
    param([AllowNull()][object]$Value)
    return ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [int16] -or $Value -is [single]) -and -not ($Value -is [double] -and ([double]::IsNaN($Value) -or [double]::IsInfinity($Value)))
}

function ConvertTo-PimTableExportModel {
    <#
      PURE. The browser payload -> the export model. Refuses (throws a plain message) a payload without sections, a
      format other than pdf / xlsx, more than maxSections / maxColumns. Rows over maxRows (all sections together) are cut
      and the model says so (truncated + note) -- the file carries the note, never a silent cut. Cell text is capped at
      maxCellChars.
      -EnvironmentLabel is what the file names as the environment (the caller passes the placeholder when names are hidden).
    #>
    param(
        [Parameter(Mandatory)][object]$Payload,
        [AllowEmptyString()][string]$EnvironmentLabel = '',
        [AllowEmptyString()][string]$Version = '',
        [datetime]$GeneratedUtc = [datetime]::UtcNow,
        [switch]$DemoData,
        [int]$MaxRows = 0
    )
    $lim = Get-PimTableExportLimits
    if ($MaxRows -le 0) { $MaxRows = $lim.maxRows }
    $get = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $fmt = "$(& $get $Payload 'format')".Trim().ToLowerInvariant()
    if ($fmt -notin @('pdf', 'xlsx')) { throw "format must be 'pdf' or 'xlsx'" }
    $view = "$(& $get $Payload 'view')".Trim().ToLowerInvariant()
    $title = (ConvertTo-PimTableExportCellText (& $get $Payload 'title')).Trim()
    if (-not $title) { $title = 'PIM Manager export' }
    if ($title.Length -gt 120) { $title = $title.Substring(0, 120) }
    $secIn = @(& $get $Payload 'sections' | Where-Object { $null -ne $_ })
    if (-not $secIn.Count) { throw 'the export has no sections (nothing to export)' }
    if ($secIn.Count -gt $lim.maxSections) { throw "an export holds at most $($lim.maxSections) sections" }
    $left = $MaxRows; $total = 0; $kept = 0; $truncated = $false
    $sections = New-Object System.Collections.Generic.List[object]
    foreach ($s in $secIn) {
        $cols = @(@(& $get $s 'columns') | ForEach-Object { (ConvertTo-PimTableExportCellText $_).Trim() })
        if (-not $cols.Count) { throw 'every section needs its columns' }
        if ($cols.Count -gt $lim.maxColumns) { throw "a section holds at most $($lim.maxColumns) columns" }
        # read WITHOUT the pipeline: a section with ONE row ([[a, b]]) must stay one row, not unroll into its cells
        # (assigned inside the branches: `$rv = if (...) { $array }` would itself unroll a one-element array)
        $rv = $null
        if ($s -is [System.Collections.IDictionary]) { $rv = $s['rows'] } elseif ($s.PSObject.Properties['rows']) { $rv = $s.PSObject.Properties['rows'].Value }
        $rowsIn = @()
        if ($rv -is [System.Collections.IList]) { $rowsIn = $rv } elseif ($null -ne $rv) { $rowsIn = @(, $rv) }
        $total += $rowsIn.Count
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($r in $rowsIn) {
            if ($left -le 0) { $truncated = $true; break }
            $cells = New-Object object[] $cols.Count
            $src = @($r)
            for ($i = 0; $i -lt $cols.Count; $i++) {
                $v = if ($i -lt $src.Count) { $src[$i] } else { $null }
                if (Test-PimTableExportNumber $v) { $cells[$i] = $v }
                else {
                    $t = ConvertTo-PimTableExportCellText $v
                    if ($t.Length -gt $lim.maxCellChars) { $t = $t.Substring(0, $lim.maxCellChars) + ' [cut]' }
                    $cells[$i] = $t
                }
            }
            $rows.Add($cells); $left--; $kept++
        }
        $h = (ConvertTo-PimTableExportCellText (& $get $s 'heading')).Trim()
        if (-not $h) { $h = $title }
        $sections.Add([pscustomobject]@{ heading = $h; columns = $cols; rows = @($rows.ToArray()) })
    }
    $env = "$EnvironmentLabel".Trim(); if (-not $env) { $env = $script:PimTableExportPlaceholder }
    $note = ''
    if ($truncated) { $note = "Cut at $MaxRows rows (the export limit): $kept of $total rows are in this file. Narrow the view's filter to export the rest." }
    return [pscustomobject]@{
        view = $view; title = $title; format = $fmt; environment = $env
        generatedUtc = $GeneratedUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); version = "$Version".Trim()
        sections = @($sections.ToArray()); rowCount = $kept; totalRows = $total; truncated = $truncated; maxRows = $MaxRows; note = $note
        demoData = [bool]$DemoData
    }
}

function Get-PimTableExportMetaLines {
    <# PURE. The lines under the title in both formats: environment, generated, version, demo marker, cut note. #>
    param([Parameter(Mandatory)][object]$Model)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("Environment: $($Model.environment)")
    $l.Add("Generated: $($Model.generatedUtc) (UTC)")
    if ($Model.version) { $l.Add("PIM Manager version $($Model.version)") }
    $l.Add("Rows: $($Model.rowCount) (export limit $($Model.maxRows) rows)")
    if ($Model.demoData) { $l.Add('Demo data: synthetic demonstration data, not a real environment') }
    if ($Model.note) { $l.Add($Model.note) }
    return @($l.ToArray())
}

function Get-PimTableExportFileName {
    <# PURE. pim-manager-<view>-<yyyyMMdd-HHmmss>.<ext> -- the view key only, never the environment name. #>
    param([Parameter(Mandatory)][object]$Model)
    $v = ("$($Model.view)" -replace '[^a-z0-9-]', '')
    if (-not $v) { $v = 'view' }
    $stamp = ([datetime]::Parse($Model.generatedUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)).ToString('yyyyMMdd-HHmmss')
    return "pim-manager-$v-$stamp.$($Model.format)"
}

# ---------------------------------------------------------------------------------------------------------------------
# xlsx (SpreadsheetML, .NET packaging only)
# ---------------------------------------------------------------------------------------------------------------------
function ConvertTo-PimXmlText {
    <# PURE. XML-escaped text with every character XML 1.0 forbids removed (lone surrogates included). #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $sb = New-Object System.Text.StringBuilder ($Text.Length + 16)
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]; $n = [int]$c
        if ([char]::IsHighSurrogate($c)) {
            if ($i + 1 -lt $Text.Length -and [char]::IsLowSurrogate($Text[$i + 1])) { [void]$sb.Append($c).Append($Text[$i + 1]); $i++ }
            continue
        }
        if ([char]::IsLowSurrogate($c)) { continue }
        if ($n -lt 0x20 -and $n -ne 0x09 -and $n -ne 0x0A -and $n -ne 0x0D) { continue }
        if ($n -eq 0xFFFE -or $n -eq 0xFFFF) { continue }
        switch ($c) {
            '&' { [void]$sb.Append('&amp;') }
            '<' { [void]$sb.Append('&lt;') }
            '>' { [void]$sb.Append('&gt;') }
            '"' { [void]$sb.Append('&quot;') }
            "'" { [void]$sb.Append('&apos;') }
            default { [void]$sb.Append($c) }
        }
    }
    return $sb.ToString()
}

function Get-PimXlsxSheetName {
    <#
      PURE. A worksheet name Excel accepts: none of \ / ? * [ ] :, no leading / trailing apostrophe, at most 31 characters,
      not empty, not 'History' (reserved), unique (case-insensitive) against -Used (a HashSet the caller keeps).
    #>
    param([AllowEmptyString()][string]$Name, [System.Collections.Generic.HashSet[string]]$Used = $null)
    $n = ("$Name" -replace '[\\/\?\*\[\]:]', ' ' -replace '[\x00-\x1F\x7F]', '' -replace '\s+', ' ').Trim().Trim("'").Trim()
    if (-not $n -or $n -ieq 'History') { $n = 'Sheet' }
    if ($n.Length -gt 31) { $n = $n.Substring(0, 31).TrimEnd().TrimEnd("'") }
    if ($null -eq $Used) { return $n }
    $cand = $n; $k = 2
    while ($Used.Contains($cand.ToLowerInvariant())) {
        $suffix = " ($k)"
        $base = $n; if ($base.Length + $suffix.Length -gt 31) { $base = $base.Substring(0, 31 - $suffix.Length).TrimEnd().TrimEnd("'") }
        $cand = "$base$suffix"; $k++
    }
    [void]$Used.Add($cand.ToLowerInvariant())
    return $cand
}

function Get-PimXlsxColumnName {
    <# PURE. 1 -> A, 26 -> Z, 27 -> AA. #>
    param([Parameter(Mandatory)][int]$Index)
    $s = ''; $n = $Index
    while ($n -gt 0) { $m = ($n - 1) % 26; $s = [char](65 + $m) + $s; $n = [int][math]::Floor(($n - 1) / 26) }
    return $s
}

function New-PimTableExportSheetXml {
    <# PURE. One worksheet: title row, meta rows, a blank row, the bold header (frozen, autofilter), the rows. Returns @{ xml; filterRef }. #>
    param([Parameter(Mandatory)][object]$Section, [Parameter(Mandatory)][string[]]$MetaLines, [Parameter(Mandatory)][string]$Title)
    $cols = @($Section.columns); $nc = $cols.Count
    $sb = New-Object System.Text.StringBuilder
    $r = 0
    $cellStr = { param([string]$ref, [string]$text, [int]$style) $st = if ($style) { " s=`"$style`"" } else { '' }; "<c r=`"$ref`" t=`"inlineStr`"$st><is><t xml:space=`"preserve`">$(ConvertTo-PimXmlText $text)</t></is></c>" }
    $rowsXml = New-Object System.Text.StringBuilder
    $r++; [void]$rowsXml.Append("<row r=`"$r`">").Append((& $cellStr "A$r" $Title 2)).Append('</row>')
    $r++; [void]$rowsXml.Append("<row r=`"$r`">").Append((& $cellStr "A$r" "$($Section.heading)" 1)).Append('</row>')
    foreach ($m in $MetaLines) { $r++; [void]$rowsXml.Append("<row r=`"$r`">").Append((& $cellStr "A$r" $m 0)).Append('</row>') }
    $r++   # blank row
    $r++; $headerRow = $r
    [void]$rowsXml.Append("<row r=`"$r`">")
    for ($i = 0; $i -lt $nc; $i++) { [void]$rowsXml.Append((& $cellStr ("$(Get-PimXlsxColumnName ($i + 1))$r") "$($cols[$i])" 1)) }
    [void]$rowsXml.Append('</row>')
    foreach ($row in @($Section.rows)) {
        $r++
        [void]$rowsXml.Append("<row r=`"$r`">")
        for ($i = 0; $i -lt $nc; $i++) {
            $v = $row[$i]; $ref = "$(Get-PimXlsxColumnName ($i + 1))$r"
            if (Test-PimTableExportNumber $v) { [void]$rowsXml.Append("<c r=`"$ref`"><v>$(([double]$v).ToString('R', [System.Globalization.CultureInfo]::InvariantCulture))</v></c>") }
            elseif ("$v" -ne '') { [void]$rowsXml.Append((& $cellStr $ref "$v" 0)) }
        }
        [void]$rowsXml.Append('</row>')
    }
    $lastCol = Get-PimXlsxColumnName ([Math]::Max(1, $nc))
    $filterRef = "A${headerRow}:$lastCol$([Math]::Max($headerRow, $r))"
    # column widths from the header + the first rows (8..60 characters)
    $colsXml = New-Object System.Text.StringBuilder
    [void]$colsXml.Append('<cols>')
    for ($i = 0; $i -lt $nc; $i++) {
        $w = "$($cols[$i])".Length
        $k = 0; foreach ($row in @($Section.rows)) { if ($k++ -ge 200) { break }; $len = "$($row[$i])".Length; if ($len -gt $w) { $w = $len } }
        $w = [Math]::Min(60, [Math]::Max(8, $w + 2))
        [void]$colsXml.Append("<col min=`"$($i + 1)`" max=`"$($i + 1)`" width=`"$w`" customWidth=`"1`"/>")
    }
    [void]$colsXml.Append('</cols>')
    [void]$sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    [void]$sb.Append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">')
    [void]$sb.Append("<dimension ref=`"A1:$lastCol$r`"/>")
    [void]$sb.Append("<sheetViews><sheetView workbookViewId=`"0`"><pane ySplit=`"$headerRow`" topLeftCell=`"A$($headerRow + 1)`" activePane=`"bottomLeft`" state=`"frozen`"/><selection pane=`"bottomLeft`" activeCell=`"A$($headerRow + 1)`" sqref=`"A$($headerRow + 1)`"/></sheetView></sheetViews>")
    [void]$sb.Append('<sheetFormatPr defaultRowHeight="15"/>')
    [void]$sb.Append($colsXml.ToString())
    [void]$sb.Append('<sheetData>').Append($rowsXml.ToString()).Append('</sheetData>')
    [void]$sb.Append("<autoFilter ref=`"$filterRef`"/>")
    [void]$sb.Append('</worksheet>')
    return @{ xml = $sb.ToString(); filterRef = $filterRef; headerRow = $headerRow }
}

function ConvertTo-PimXlsxBytes {
    <# PURE (.NET packaging in memory). The model -> the bytes of an .xlsx workbook, one worksheet per section. #>
    param([Parameter(Mandatory)][object]$Model)
    try { Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue } catch { }
    $meta = @(Get-PimTableExportMetaLines -Model $Model)
    $used = New-Object 'System.Collections.Generic.HashSet[string]'
    $sheets = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($s in @($Model.sections)) {
        $i++
        $name = Get-PimXlsxSheetName -Name "$($s.heading)" -Used $used
        $x = New-PimTableExportSheetXml -Section $s -MetaLines $meta -Title "$($Model.title)"
        $sheets.Add([pscustomobject]@{ index = $i; name = $name; xml = $x.xml; filterRef = $x.filterRef })
    }
    $ct = New-Object System.Text.StringBuilder
    [void]$ct.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">')
    [void]$ct.Append('<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>')
    [void]$ct.Append('<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>')
    [void]$ct.Append('<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>')
    [void]$ct.Append('<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>')
    foreach ($sh in $sheets) { [void]$ct.Append("<Override PartName=`"/xl/worksheets/sheet$($sh.index).xml`" ContentType=`"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml`"/>") }
    [void]$ct.Append('</Types>')
    $rootRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>'
    $wb = New-Object System.Text.StringBuilder
    [void]$wb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>')
    foreach ($sh in $sheets) { [void]$wb.Append("<sheet name=`"$(ConvertTo-PimXmlText $sh.name)`" sheetId=`"$($sh.index)`" r:id=`"rId$($sh.index)`"/>") }
    [void]$wb.Append('</sheets><definedNames>')
    foreach ($sh in $sheets) {
        $abs = ($sh.filterRef -replace '([A-Z]+)(\d+)', '$$$1$$$2')
        $q = "'" + ($sh.name -replace "'", "''") + "'"
        [void]$wb.Append("<definedName name=`"_xlnm._FilterDatabase`" localSheetId=`"$($sh.index - 1)`" hidden=`"1`">$(ConvertTo-PimXmlText "$q!$abs")</definedName>")
    }
    [void]$wb.Append('</definedNames></workbook>')
    $wbRels = New-Object System.Text.StringBuilder
    [void]$wbRels.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">')
    foreach ($sh in $sheets) { [void]$wbRels.Append("<Relationship Id=`"rId$($sh.index)`" Type=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet`" Target=`"worksheets/sheet$($sh.index).xml`"/>") }
    [void]$wbRels.Append("<Relationship Id=`"rId$($sheets.Count + 1)`" Type=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles`" Target=`"styles.xml`"/>")
    [void]$wbRels.Append('</Relationships>')
    # styles: 0 normal, 1 bold (header / section), 2 bold 14pt (title)
    $styles = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
        '<fonts count="3"><font><sz val="11"/><name val="Calibri"/><family val="2"/></font><font><b/><sz val="11"/><name val="Calibri"/><family val="2"/></font><font><b/><sz val="14"/><name val="Calibri"/><family val="2"/></font></fonts>' +
        '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>' +
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' +
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
        '<cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/><xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>' +
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'
    $core = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' +
        "<dc:title>$(ConvertTo-PimXmlText "$($Model.title)")</dc:title><dc:creator>PIM Manager</dc:creator>" +
        "<dcterms:created xsi:type=`"dcterms:W3CDTF`">$($Model.generatedUtc)</dcterms:created></cp:coreProperties>"
    $ms = New-Object System.IO.MemoryStream
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($ms, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            $add = {
                param([string]$entryName, [string]$content)
                $e = $zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
                $st = $e.Open(); try { $b = $utf8.GetBytes($content); $st.Write($b, 0, $b.Length) } finally { $st.Dispose() }
            }
            & $add '[Content_Types].xml' $ct.ToString()
            & $add '_rels/.rels' $rootRels
            & $add 'docProps/core.xml' $core
            & $add 'xl/workbook.xml' $wb.ToString()
            & $add 'xl/_rels/workbook.xml.rels' $wbRels.ToString()
            & $add 'xl/styles.xml' $styles
            foreach ($sh in $sheets) { & $add "xl/worksheets/sheet$($sh.index).xml" $sh.xml }
        } finally { $zip.Dispose() }
        return , $ms.ToArray()
    } finally { $ms.Dispose() }
}

# ---------------------------------------------------------------------------------------------------------------------
# PDF (PDFsharp + MigraDoc, bundled in the image for the as-built document, 100.61) -- loaded through PIM-AsBuilt.ps1's
# own loader (Resolve-PimAsBuiltPdfPaths / Import-PimAsBuiltPdfLibrary): one library path, one font resolver per process.
# ---------------------------------------------------------------------------------------------------------------------
$script:PimTableExportAsBuiltLib = Join-Path $PSScriptRoot 'PIM-AsBuilt.ps1'
if (-not (Get-Command Import-PimAsBuiltPdfLibrary -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $script:PimTableExportAsBuiltLib)) { . $script:PimTableExportAsBuiltLib }

function Test-PimTableExportPdfAvailable {
    <# PURE (file-system read only). @{ available; reason } -- the page disables Export > PDF with the reason when not available. #>
    param([string]$DllDir = "$env:PIM_PDF_DLL_DIR", [string]$FontDir = "$env:PIM_PDF_FONT_DIR")
    if (-not (Get-Command Resolve-PimAsBuiltPdfPaths -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ available = $false; reason = 'PDF export needs the PDF module of this PIM Manager (PIM-AsBuilt), which is not present. Excel export works.' } }
    $p = Resolve-PimAsBuiltPdfPaths -DllDir $DllDir -FontDir $FontDir
    if (-not $p.libraryPresent) { return [pscustomobject]@{ available = $false; reason = 'PDF export needs the PDF library, which this PIM Manager image does not include. Excel export works.' } }
    if (-not $p.regular) { return [pscustomobject]@{ available = $false; reason = 'PDF export needs the PDF font, which this PIM Manager image does not include. Excel export works.' } }
    return [pscustomobject]@{ available = $true; reason = '' }
}

function Import-PimTableExportPdfLibrary {
    <# Loads PDFsharp + MigraDoc and the font resolver with the as-built loader. Throws a plain message when anything is missing. #>
    param([string]$DllDir = "$env:PIM_PDF_DLL_DIR", [string]$FontDir = "$env:PIM_PDF_FONT_DIR")
    if (-not (Get-Command Import-PimAsBuiltPdfLibrary -ErrorAction SilentlyContinue)) { throw 'the PDF library loader (engine/_shared/PIM-AsBuilt.ps1) is not present' }
    $pa = Test-PimTableExportPdfAvailable -DllDir $DllDir -FontDir $FontDir
    if (-not $pa.available) { throw "$($pa.reason)" }
    Import-PimAsBuiltPdfLibrary -DllDir $DllDir -FontDir $FontDir
}
function Get-PimTableExportPdfLayout {
    <# PURE. Orientation + font size + column widths (cm) for a section: landscape above 5 columns, smaller type as columns grow. #>
    param([Parameter(Mandatory)][int]$Columns)
    $landscape = ($Columns -gt 5)
    $usable = if ($landscape) { 29.7 - 2.4 } else { 21.0 - 2.4 }
    $font = if ($Columns -le 6) { 8.5 } elseif ($Columns -le 10) { 7.5 } elseif ($Columns -le 16) { 6.5 } else { 5.5 }
    $w = [math]::Round($usable / [Math]::Max(1, $Columns), 2)
    return [pscustomobject]@{ landscape = $landscape; usableCm = $usable; fontSize = $font; widthCm = $w }
}

function ConvertTo-PimTableExportPdf {
    <# The model -> PDF bytes (A4; landscape when any section is wide; repeating header row; page x of y in the footer). #>
    param([Parameter(Mandatory)][object]$Model, [string]$DllDir = "$env:PIM_PDF_DLL_DIR", [string]$FontDir = "$env:PIM_PDF_FONT_DIR")
    Import-PimTableExportPdfLibrary -DllDir $DllDir -FontDir $FontDir
    $U = [MigraDoc.DocumentObjectModel.Unit]
    $maxCols = 1; foreach ($s in @($Model.sections)) { if (@($s.columns).Count -gt $maxCols) { $maxCols = @($s.columns).Count } }
    $lay = Get-PimTableExportPdfLayout -Columns $maxCols
    $doc = New-Object MigraDoc.DocumentObjectModel.Document
    $doc.Info.Title = "$($Model.title)"
    $doc.Info.Author = 'PIM Manager'
    $normal = $doc.Styles['Normal']; $normal.Font.Name = 'PimSans'; $normal.Font.Size = $lay.fontSize
    $sec = $doc.AddSection()
    $base = $null; try { $base = $doc.DefaultPageSetup } catch { $base = $null }
    if ($null -eq $base) { try { $base = [MigraDoc.DocumentObjectModel.PageSetup]::DefaultPageSetup } catch { $base = $null } }
    $ps = if ($null -ne $base) { $base.Clone() } else { $sec.PageSetup }
    $ps.PageFormat = [MigraDoc.DocumentObjectModel.PageFormat]::A4
    $ps.Orientation = $(if ($lay.landscape) { [MigraDoc.DocumentObjectModel.Orientation]::Landscape } else { [MigraDoc.DocumentObjectModel.Orientation]::Portrait })
    $ps.TopMargin = $U::FromCentimeter(1.5); $ps.BottomMargin = $U::FromCentimeter(1.5)
    $ps.LeftMargin = $U::FromCentimeter(1.2); $ps.RightMargin = $U::FromCentimeter(1.2)
    $sec.PageSetup = $ps
    $foot = $sec.Footers.Primary.AddParagraph()
    $foot.Format.Font.Size = 7
    $demoTxt = if ($Model.demoData) { ' - Demo data' } else { '' }
    [void]$foot.AddText("$($Model.title) - $($Model.environment) - $($Model.generatedUtc) - PIM Manager $($Model.version)$demoTxt - page ")
    [void]$foot.AddPageField(); [void]$foot.AddText(' of '); [void]$foot.AddNumPagesField()
    $h = $sec.AddParagraph("$($Model.title)")
    $h.Format.Font.Size = 15; $h.Format.Font.Bold = $true; $h.Format.SpaceAfter = $U::FromPoint(3)
    foreach ($m in @(Get-PimTableExportMetaLines -Model $Model)) { $p = $sec.AddParagraph($m); $p.Format.Font.Size = 8 }
    foreach ($s in @($Model.sections)) {
        $hp = $sec.AddParagraph("$($s.heading)"); $hp.Format.Font.Size = 11; $hp.Format.Font.Bold = $true
        $hp.Format.SpaceBefore = $U::FromPoint(10); $hp.Format.SpaceAfter = $U::FromPoint(4); $hp.Format.KeepWithNext = $true
        $cols = @($s.columns)
        $sl = Get-PimTableExportPdfLayout -Columns $cols.Count
        $w = [math]::Round($lay.usableCm / [Math]::Max(1, $cols.Count), 2)
        $t = $sec.AddTable()
        $t.Borders.Width = 0.4; $t.Borders.Color = [MigraDoc.DocumentObjectModel.Colors]::Gray
        $t.Format.Font.Size = $sl.fontSize
        foreach ($c in $cols) { [void]$t.AddColumn($U::FromCentimeter($w)) }
        $hr = $t.AddRow(); $hr.HeadingFormat = $true; $hr.Format.Font.Bold = $true
        $hr.Shading.Color = [MigraDoc.DocumentObjectModel.Colors]::LightGray
        for ($i = 0; $i -lt $cols.Count; $i++) { [void]$hr.Cells[$i].AddParagraph("$($cols[$i])") }
        foreach ($row in @($s.rows)) {
            $r = $t.AddRow()
            for ($i = 0; $i -lt $cols.Count; $i++) {
                $v = $row[$i]
                $txt = if (Test-PimTableExportNumber $v) { ([double]$v).ToString('G', [System.Globalization.CultureInfo]::InvariantCulture) } else { "$v" }
                [void]$r.Cells[$i].AddParagraph($txt)
            }
        }
        if (-not @($s.rows).Count) { $np = $sec.AddParagraph('(no rows)'); $np.Format.Font.Size = 8 }
    }
    $renderer = New-Object MigraDoc.Rendering.PdfDocumentRenderer
    $renderer.Document = $doc
    $renderer.RenderDocument()
    $ms = New-Object System.IO.MemoryStream
    try { $renderer.PdfDocument.Save($ms, $false); return , $ms.ToArray() } finally { $ms.Dispose() }
}
