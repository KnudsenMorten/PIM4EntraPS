<#
  PIM-Xlsx.ps1 -- a minimal .xlsx WRITER with no module and no Office (§79.14, operator 2026-09-25: "i need this email
  to include a detailed excel file with all changes, policy change (before, new) - i need to be able to get approval
  from their CAB / change board").

  An .xlsx is a zip of a handful of XML parts. This writes exactly those parts with System.IO.Compression (present on
  pwsh 7 and Windows PowerShell 5.1): inline strings (no shared-string table), one bold header style, the header row
  frozen and filterable, column widths from the content. Enough for a change board to sort, filter and sign off.

  New-PimXlsxBytes -Sheets @( @{ name = 'Changes'; rows = @( @('Policy','Setting',...), @('PIM-A','...',...) ) }, ... )
    -> [byte[]] of a valid workbook. The first row of every sheet is its header.

  New-PimPolicyHoldWorkbook -Hold <hold record> [-Provider] [-Environment] -> [byte[]]: the CAB file for a held
  policy mass change -- one row per policy x setting (current -> new, tightens/loosens), plus a Summary sheet.
#>

Set-StrictMode -Off

function ConvertTo-PimXlsxCellRef {
    param([int]$Col, [int]$Row)   # 1-based
    $s = ''; $c = $Col
    while ($c -gt 0) { $m = ($c - 1) % 26; $s = [char](65 + $m) + $s; $c = [int][math]::Floor(($c - 1) / 26) }
    return "$s$Row"
}

function ConvertTo-PimXlsxText {
    # XML-escape, and drop the control characters XML 1.0 forbids (a stray one makes Excel refuse the whole file).
    param([AllowNull()][object]$Value)
    $t = if ($null -eq $Value) { '' } else { "$Value" }
    $t = [regex]::Replace($t, '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')
    if ($t.Length -gt 32000) { $t = $t.Substring(0, 32000) }   # Excel's cell limit is 32,767
    return [System.Security.SecurityElement]::Escape($t)
}

function New-PimXlsxSheetXml {
    param([object[]]$Rows)
    $sb = New-Object System.Text.StringBuilder
    $rows = @($Rows)
    $nCols = 0; foreach ($r in $rows) { $nCols = [Math]::Max($nCols, @($r).Count) }
    if ($nCols -lt 1) { $nCols = 1 }
    [void]$sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
    [void]$sb.Append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>')
    [void]$sb.Append('<cols>')
    for ($c = 0; $c -lt $nCols; $c++) {
        $w = 10
        foreach ($r in ($rows | Select-Object -First 300)) { $v = @($r); if ($c -lt $v.Count) { $w = [Math]::Max($w, [Math]::Min(80, ("$($v[$c])").Length + 2)) } }
        [void]$sb.Append(('<col min="{0}" max="{0}" width="{1}" customWidth="1"/>' -f ($c + 1), $w))
    }
    [void]$sb.Append('</cols><sheetData>')
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $rn = $i + 1
        [void]$sb.Append("<row r=""$rn"">")
        $vals = @($rows[$i])
        for ($c = 0; $c -lt $vals.Count; $c++) {
            $ref = ConvertTo-PimXlsxCellRef -Col ($c + 1) -Row $rn
            $style = if ($i -eq 0) { ' s="1"' } else { '' }
            [void]$sb.Append("<c r=""$ref"" t=""inlineStr""$style><is><t xml:space=""preserve"">$(ConvertTo-PimXlsxText $vals[$c])</t></is></c>")
        }
        [void]$sb.Append('</row>')
    }
    [void]$sb.Append('</sheetData>')
    if ($rows.Count -gt 1) { [void]$sb.Append(('<autoFilter ref="A1:{0}"/>' -f (ConvertTo-PimXlsxCellRef -Col $nCols -Row $rows.Count))) }
    [void]$sb.Append('</worksheet>')
    return $sb.ToString()
}

function New-PimXlsxBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Sheets)
    try { Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop } catch { }
    $ms = New-Object System.IO.MemoryStream
    $zip = New-Object System.IO.Compression.ZipArchive($ms, [System.IO.Compression.ZipArchiveMode]::Create, $true)
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $add = {
        param($name, $text)
        $e = $zip.CreateEntry($name)
        $w = New-Object System.IO.StreamWriter($e.Open(), $utf8)
        $w.Write($text); $w.Dispose()
    }
    $sheets = @($Sheets)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($s in $sheets) {
        $n = ("$($s.name)" -replace '[\[\]\*\?/\\:]', ' ').Trim(); if (-not $n) { $n = "Sheet$($names.Count + 1)" }
        if ($n.Length -gt 31) { $n = $n.Substring(0, 31) }
        $names.Add($n)
    }
    $ct = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>' +
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
    for ($i = 1; $i -le $sheets.Count; $i++) { $ct += "<Override PartName=""/xl/worksheets/sheet$i.xml"" ContentType=""application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml""/>" }
    $ct += '</Types>'
    & $add '[Content_Types].xml' $ct
    & $add '_rels/.rels' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
    $wb = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
    $rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    for ($i = 1; $i -le $sheets.Count; $i++) {
        $wb += ('<sheet name="{0}" sheetId="{1}" r:id="rId{1}"/>' -f (ConvertTo-PimXlsxText $names[$i - 1]), $i)
        $rels += ('<Relationship Id="rId{0}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{0}.xml"/>' -f $i)
    }
    $wb += '</sheets></workbook>'
    $rels += ('<Relationship Id="rId{0}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>' -f ($sheets.Count + 1))
    & $add 'xl/workbook.xml' $wb
    & $add 'xl/_rels/workbook.xml.rels' $rels
    & $add 'xl/styles.xml' ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>' +
        '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>' +
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' +
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
        '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>' +
        '</styleSheet>')
    for ($i = 1; $i -le $sheets.Count; $i++) { & $add "xl/worksheets/sheet$i.xml" (New-PimXlsxSheetXml -Rows @($sheets[$i - 1].rows)) }
    $zip.Dispose()
    return ,$ms.ToArray()
}

function New-PimPolicyHoldWorkbook {
    <#
      The CAB workbook for a held policy mass change. Sheet 'Changes': one row per policy x setting -- the policy, its
      member/owner side, the setting, CURRENT value, NEW value, effect (tightens/loosens/neutral), whether it is the first
      application of the template, the template. Sheet 'Summary': what, where, totals, why, the plan hash and how to
      approve. Reads the hold's WhatIf 'impact' (Get-PimPolicyImpactReport shape: groups{policies[], changes[]}).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Hold, [string]$Provider = '', [string]$Environment = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $prov = if ("$Provider".Trim()) { "$Provider".Trim() } elseif ($Hold.PSObject.Properties['provider']) { "$($Hold.provider)" } else { 'policies' }
    $imp = if ($Hold.PSObject.Properties['impact'] -and $Hold.impact) { $Hold.impact } else { $null }
    $rows = New-Object System.Collections.Generic.List[object]
    $rows.Add(@('Policy', 'Member / owner', 'Setting', 'Current value', 'New value', 'Effect', 'First application of the template', 'Template'))
    foreach ($g in @(if ($imp) { $imp.groups })) {
        foreach ($p in @($g.policies)) {
            $name = "$p"; $side = 'member'
            if ($name -match '^(?<n>.+?) \((?<s>owner|member)\)$') { $name = $Matches['n']; $side = $Matches['s'] }
            if ($prov -ne 'GroupsPolicies') { $side = '' }
            if (Get-Command Format-PimPolicyHoldName -ErrorAction SilentlyContinue) { $name = Format-PimPolicyHoldName $name }
            foreach ($c in @($g.changes)) {
                $rows.Add(@($name, $side, "$($c.setting)", $(if ("$($c.before)") { "$($c.before)" } else { '-' }), $(if ("$($c.after)") { "$($c.after)" } else { '-' }), "$($c.direction)", $(if ($g.firstApplication) { 'yes' } else { 'no' }), "$($g.template)"))
            }
        }
    }
    $t = if ($imp) { $imp.totals } else { $null }
    $sum = New-Object System.Collections.Generic.List[object]
    $sum.Add(@('Item', 'Value'))
    $sum.Add(@('What', "A held mass change of $prov -- NOTHING has been changed; it waits for approval."))
    $sum.Add(@('Environment', $(if ("$Environment".Trim()) { $Environment } else { "$($global:PIM_TenantName)" })))
    $sum.Add(@('Generated (UTC)', $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')))
    $sum.Add(@('Plan hash', "$($Hold.planHash)"))
    $sum.Add(@('Policies that would change', "$($Hold.changes)"))
    $sum.Add(@('Policies checked', "$($Hold.checked)"))
    $sum.Add(@('Weakening changes', "$($Hold.weakening)"))
    if ($t) {
        $sum.Add(@('Setting changes', "$($t.settings)")); $sum.Add(@('Tighten', "$($t.tightens)")); $sum.Add(@('Loosen', "$($t.loosens)")); $sum.Add(@('Neutral', "$($t.neutral)"))
    }
    foreach ($r in @(if ($imp) { $imp.reasons })) { $sum.Add(@('Why', "$r")) }
    $sum.Add(@('Rows in the Changes sheet', "$($rows.Count - 1)"))
    $sum.Add(@('How to approve', "PIM Manager > Reviews & controls > Approvals > 'Approve this change set' (Admin role), valid only while this plan hash is the one held. If it is not intended, change the template or the rows instead."))
    # The comma keeps it ONE byte[]: 'return (...)' would unroll it into one pipeline object per byte.
    return ,(New-PimXlsxBytes -Sheets @(@{ name = 'Summary'; rows = $sum.ToArray() }, @{ name = 'Changes'; rows = $rows.ToArray() }))
}
