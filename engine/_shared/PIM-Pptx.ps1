<#
  PIM-Pptx.ps1 -- a minimal .pptx WRITER with no module and no Office (MGMT-REPORT, owner 2026-10-29: "a wizard for mgmt.
  reporting, where i can select what i want to export and then get a powerpoint with the exported data ? A nice looking
  powerpoint").

  A .pptx is a zip of XML parts. This writes exactly the parts PowerPoint needs with System.IO.Compression (present on pwsh 7
  and Windows PowerShell 5.1), in the pattern of PIM-Xlsx.ps1:
    [Content_Types].xml, _rels/.rels, docProps/core.xml + app.xml,
    ppt/presentation.xml (+ rels), presProps.xml, viewProps.xml, tableStyles.xml,
    ppt/slideMasters/slideMaster1.xml (+ rels), ppt/slideLayouts/slideLayout1.xml (+ rels), ppt/theme/theme1.xml,
    ppt/slides/slideN.xml (+ rels), ppt/media/image1.png (the logo, when one is given).
  16:9 (13.333 x 7.5 in). One blank layout; every slide draws its own shapes -- KPI tiles, real (editable) tables, bar charts
  drawn as rectangles (no chart parts), a header band in the PIM Manager brand gradient and a footer on every slide.

  New-PimPptxBytes -Slides @( <slide>, ... ) [-Footer 'env | period | PIM Manager'] [-LogoPng <byte[]>] [-Title] [-TableRowsPerSlide 12]
    -> [byte[]] of a valid presentation. A <slide> is a hashtable / object:
       kind     'title' | 'content'
       title    the slide title;  subtitle  one line under it
       lines    (title slide) the lines under the title band
       kpis     @( @{ label; value; sub; tone = good|bad|neutral|na; arrow = up|down|flat|none; note } )  -- up to 8 tiles
       table    @{ columns = @('A','B'); rows = @( @('a','b'), ... ); note }  -- split over as many slides as it needs
       bars     @{ orientation = 'h'|'v'; items = @( @{ label; value; tone } ); note; unit }
       bullets  @( 'line', ... )
       note     a small line at the bottom of the content area
  Every text is XML-escaped and the control characters XML 1.0 forbids are dropped (a stray one makes PowerPoint refuse the
  whole file). Source is ASCII; the few symbols (arrows, the dash) are built from their code points.
  PS 5.1 + 7: no ternary / ?? / ?., lists returned with .ToArray(), the bytes with a leading comma.
#>

Set-StrictMode -Off

$script:PimPptxEmuPerInch = 914400
$script:PimPptxSlideW = 13.333
$script:PimPptxSlideCx = 12192000   # 16:9 widescreen in EMU, exact (the layout math above uses inches)
$script:PimPptxSlideCy = 6858000
$script:PimPptxSlideH = 7.5
$script:PimPptxNs = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"'

function Get-PimPptxBrand {
    # The PIM Manager brand (BRAND-2.1, the same tokens as Get-PimMailBrand / the Manager page): blue -> sky gradient, ink.
    [ordered]@{
        blue = '1B4FE4'; sky = '18B4F2'; ink = '0B1633'; heading = '24292F'; text = '1A1A1A'; muted = '57606A'
        surface = 'FFFFFF'; surfaceAlt = 'F6F8FA'; border = 'D0D7DE'; grid = 'EAEEF2'
        good = '1A7F37'; bad = 'CF222E'; warn = '9A6700'; goodBg = 'DAFBE1'; badBg = 'FFEBE9'
        font = 'Segoe UI'
    }
}

function ConvertTo-PimPptxText {
    # XML-escape, and drop the characters XML 1.0 forbids (C0 controls except tab/LF/CR, lone surrogates, U+FFFE/U+FFFF).
    param([AllowNull()][object]$Value, [int]$Max = 2000)
    $t = if ($null -eq $Value) { '' } else { "$Value" }
    $t = [regex]::Replace($t, '[\x00-\x08\x0B\x0C\x0E-\x1F' + [char]0xFFFE + [char]0xFFFF + ']', '')
    $t = [regex]::Replace($t, '[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]', '')
    if ($Max -gt 0 -and $t.Length -gt $Max) { $t = $t.Substring(0, $Max - 3) + '...' }
    return [System.Security.SecurityElement]::Escape($t)
}

function ConvertTo-PimPptxEmu {
    param([double]$Inches)
    return [long][math]::Round($Inches * $script:PimPptxEmuPerInch)
}

function Get-PimPptxField {
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } else { return $null } }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-PimPptxList {
    <#
      A list field (table rows) WITHOUT a pipeline in between: a function that returns a list unrolls it, and a list of ONE
      row (itself an array) would come back as that row's cells. Read straight from the object, returned with a leading comma.
    #>
    param([AllowNull()][object]$Object, [string]$Name)
    $v = $null
    if ($null -ne $Object) {
        if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { $v = $Object[$Name] } }
        else { $p = $Object.PSObject.Properties[$Name]; if ($p) { $v = $p.Value } }
    }
    if ($null -eq $v) { return , (New-Object object[] 0) }
    if ($v -is [System.Collections.IList] -and -not ($v -is [string])) {
        $a = New-Object object[] $v.Count
        for ($i = 0; $i -lt $v.Count; $i++) { $a[$i] = $v[$i] }
        return , $a
    }
    $one = New-Object object[] 1; $one[0] = $v
    return , $one
}

function Get-PimPptxSymbol {
    # The arrows and the dash, from their code points (the source stays ASCII).
    param([ValidateSet('up', 'down', 'flat', 'dash', 'dot')][string]$Name)
    switch ($Name) { 'up' { return [string][char]0x25B2 } 'down' { return [string][char]0x25BC } 'flat' { return [string][char]0x25B6 } 'dash' { return [string][char]0x2014 } default { return [string][char]0x00B7 } }
}

function New-PimPptxRunXml {
    param([AllowNull()][string]$Text, [int]$Size = 1400, [switch]$Bold, [string]$Color = '1A1A1A', [string]$Font = 'Segoe UI', [int]$Max = 2000)
    $b = if ($Bold) { ' b="1"' } else { '' }
    return ('<a:r><a:rPr lang="en-US" sz="{0}"{1} dirty="0"><a:solidFill><a:srgbClr val="{2}"/></a:solidFill><a:latin typeface="{3}"/><a:cs typeface="{3}"/></a:rPr><a:t>{4}</a:t></a:r>' -f $Size, $b, $Color, (ConvertTo-PimPptxText $Font), (ConvertTo-PimPptxText $Text -Max $Max))
}

function New-PimPptxParaXml {
    # One paragraph of runs. -Runs: @( @{ text; size; bold; color } ). An empty paragraph keeps the size (endParaRPr).
    param([object[]]$Runs = @(), [ValidateSet('l', 'ctr', 'r')][string]$Align = 'l', [int]$Size = 1400, [string]$Font = 'Segoe UI', [int]$SpaceBefore = 0)
    $sb = New-Object System.Text.StringBuilder
    $spc = if ($SpaceBefore -gt 0) { ('<a:spcBef><a:spcPts val="{0}"/></a:spcBef>' -f $SpaceBefore) } else { '' }
    [void]$sb.Append(('<a:p><a:pPr algn="{0}">{1}</a:pPr>' -f $Align, $spc))
    foreach ($r in @($Runs)) {
        if ($null -eq $r) { continue }
        $rs = Get-PimPptxField $r 'size'; if (-not $rs) { $rs = $Size }
        $rc = Get-PimPptxField $r 'color'; if (-not $rc) { $rc = '1A1A1A' }
        [void]$sb.Append((New-PimPptxRunXml -Text "$(Get-PimPptxField $r 'text')" -Size ([int]$rs) -Bold:([bool](Get-PimPptxField $r 'bold')) -Color "$rc" -Font $Font))
    }
    [void]$sb.Append(('<a:endParaRPr lang="en-US" sz="{0}" dirty="0"/></a:p>' -f $Size))
    return $sb.ToString()
}

function New-PimPptxShapeXml {
    <#
      One shape: a rectangle (or rounded rectangle) at x/y/w/h inches with an optional fill, gradient, outline and text.
      -Paragraphs: the <a:p> XML of the text ('' = no text, an empty paragraph is written -- txBody needs one).
    #>
    param([int]$Id, [string]$Name = 'Shape', [double]$X, [double]$Y, [double]$W, [double]$H,
          [string]$Fill = '', [string[]]$Gradient = @(), [string]$Line = '', [int]$LineW = 9525,
          [ValidateSet('rect', 'roundRect')][string]$Geom = 'rect', [string]$Paragraphs = '',
          [ValidateSet('t', 'ctr', 'b')][string]$Anchor = 't', [double]$Inset = 0.08, [switch]$NoWrap)
    $fillXml = if (@($Gradient).Count -ge 2) {
        '<a:gradFill rotWithShape="1"><a:gsLst><a:gs pos="0"><a:srgbClr val="' + $Gradient[0] + '"/></a:gs><a:gs pos="100000"><a:srgbClr val="' + $Gradient[1] + '"/></a:gs></a:gsLst><a:lin ang="0" scaled="0"/></a:gradFill>'
    } elseif ($Fill) { '<a:solidFill><a:srgbClr val="' + $Fill + '"/></a:solidFill>' } else { '<a:noFill/>' }
    $lnXml = if ($Line) { '<a:ln w="' + $LineW + '"><a:solidFill><a:srgbClr val="' + $Line + '"/></a:solidFill></a:ln>' } else { '<a:ln><a:noFill/></a:ln>' }
    $geomXml = if ($Geom -eq 'roundRect') { '<a:prstGeom prst="roundRect"><a:avLst><a:gd name="adj" fmla="val 8000"/></a:avLst></a:prstGeom>' } else { '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom>' }
    $ins = ConvertTo-PimPptxEmu $Inset
    $wrap = if ($NoWrap) { 'none' } else { 'square' }
    $paras = if ("$Paragraphs") { $Paragraphs } else { '<a:p><a:endParaRPr lang="en-US" dirty="0"/></a:p>' }
    return ('<p:sp><p:nvSpPr><p:cNvPr id="{0}" name="{1} {0}"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="{2}" y="{3}"/><a:ext cx="{4}" cy="{5}"/></a:xfrm>{6}{7}{8}</p:spPr>' +
            '<p:txBody><a:bodyPr wrap="{9}" lIns="{10}" tIns="{10}" rIns="{10}" bIns="{10}" rtlCol="0" anchor="{11}"><a:noAutofit/></a:bodyPr><a:lstStyle/>{12}</p:txBody></p:sp>') -f
            $Id, (ConvertTo-PimPptxText $Name), (ConvertTo-PimPptxEmu $X), (ConvertTo-PimPptxEmu $Y), (ConvertTo-PimPptxEmu ([math]::Max(0.01, $W))), (ConvertTo-PimPptxEmu ([math]::Max(0.01, $H))),
            $geomXml, $fillXml, $lnXml, $wrap, $ins, $Anchor, $paras
}

function New-PimPptxTextXml {
    # A text box (no fill, no line): one or more lines of the same style.
    param([int]$Id, [double]$X, [double]$Y, [double]$W, [double]$H, [AllowNull()][object]$Text, [int]$Size = 1400, [switch]$Bold,
          [string]$Color = '1A1A1A', [ValidateSet('l', 'ctr', 'r')][string]$Align = 'l', [ValidateSet('t', 'ctr', 'b')][string]$Anchor = 't',
          [string]$Font = 'Segoe UI', [double]$Inset = 0.04, [int]$Max = 2000)
    $paras = New-Object System.Text.StringBuilder
    foreach ($line in @("$Text" -split "`r?`n")) {
        [void]$paras.Append((New-PimPptxParaXml -Runs @(@{ text = $line; size = $Size; bold = [bool]$Bold; color = $Color }) -Align $Align -Size $Size -Font $Font))
    }
    return (New-PimPptxShapeXml -Id $Id -Name 'Text' -X $X -Y $Y -W $W -H $H -Paragraphs $paras.ToString() -Anchor $Anchor -Inset $Inset)
}

function New-PimPptxPictureXml {
    param([int]$Id, [string]$RelId, [double]$X, [double]$Y, [double]$W, [double]$H, [string]$Descr = 'PIM Manager')
    return ('<p:pic><p:nvPicPr><p:cNvPr id="{0}" name="Logo {0}" descr="{1}"/><p:cNvPicPr><a:picLocks noChangeAspect="1"/></p:cNvPicPr><p:nvPr/></p:nvPicPr>' +
            '<p:blipFill><a:blip r:embed="{2}"/><a:stretch><a:fillRect/></a:stretch></p:blipFill>' +
            '<p:spPr><a:xfrm><a:off x="{3}" y="{4}"/><a:ext cx="{5}" cy="{6}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr></p:pic>') -f
            $Id, (ConvertTo-PimPptxText $Descr), $RelId, (ConvertTo-PimPptxEmu $X), (ConvertTo-PimPptxEmu $Y), (ConvertTo-PimPptxEmu $W), (ConvertTo-PimPptxEmu $H)
}

function Get-PimPptxPngSize {
    # PURE. A PNG's width / height from its IHDR chunk; $null when the bytes are not a PNG.
    param([AllowNull()][byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -lt 24) { return $null }
    if ($Bytes[0] -ne 0x89 -or $Bytes[1] -ne 0x50 -or $Bytes[2] -ne 0x4E -or $Bytes[3] -ne 0x47) { return $null }
    $w = ([long]$Bytes[16] -shl 24) -bor ([long]$Bytes[17] -shl 16) -bor ([long]$Bytes[18] -shl 8) -bor [long]$Bytes[19]
    $h = ([long]$Bytes[20] -shl 24) -bor ([long]$Bytes[21] -shl 16) -bor ([long]$Bytes[22] -shl 8) -bor [long]$Bytes[23]
    if ($w -le 0 -or $h -le 0) { return $null }
    return [pscustomobject]@{ width = $w; height = $h }
}

function New-PimPptxTableXml {
    <#
      A real PowerPoint table (graphicFrame / a:tbl), header row in the brand ink with white bold text, light row bands, a thin
      grid line under every row. Column widths follow the content (proportional, clamped). Cells longer than -CellMax are cut.
    #>
    param([int]$Id, [double]$X, [double]$Y, [double]$W, [object[]]$Columns = @(), [object[]]$Rows = @(), [double]$RowH = 0.34, [int]$Size = 1050, [int]$CellMax = 160)
    $br = Get-PimPptxBrand
    $cols = @($Columns | ForEach-Object { "$_" })
    if ($cols.Count -lt 1) { $cols = @('') }
    $n = $cols.Count
    $weights = New-Object 'double[]' $n
    for ($c = 0; $c -lt $n; $c++) {
        $len = [math]::Max(4, $cols[$c].Length)
        foreach ($r in @($Rows)) { $v = @($r); if ($c -lt $v.Count) { $len = [math]::Max($len, [math]::Min(60, ("$($v[$c])").Length)) } }
        $weights[$c] = [math]::Max(6, $len)
    }
    $sum = 0.0; foreach ($wt in $weights) { $sum += $wt }
    $tbl = New-Object System.Text.StringBuilder
    [void]$tbl.Append('<a:tbl><a:tblPr firstRow="1" bandRow="1"/><a:tblGrid>')
    $gridW = New-Object 'long[]' $n
    $totalEmu = ConvertTo-PimPptxEmu $W; $used = 0L
    for ($c = 0; $c -lt $n; $c++) {
        $cw = if ($c -eq $n - 1) { $totalEmu - $used } else { [long][math]::Floor($totalEmu * $weights[$c] / $sum) }
        $gridW[$c] = $cw; $used += $cw
        [void]$tbl.Append(('<a:gridCol w="{0}"/>' -f $cw))
    }
    [void]$tbl.Append('</a:tblGrid>')
    $cell = {
        param($text, $isHead, $band)
        $color = if ($isHead) { 'FFFFFF' } else { $br.text }
        $fill = if ($isHead) { $br.ink } elseif ($band) { $br.surfaceAlt } else { 'FFFFFF' }
        $run = New-PimPptxRunXml -Text "$text" -Size $Size -Bold:([bool]$isHead) -Color $color -Font $br.font -Max $CellMax
        $m = ConvertTo-PimPptxEmu 0.06
        return ('<a:tc><a:txBody><a:bodyPr/><a:lstStyle/><a:p>{0}<a:endParaRPr lang="en-US" sz="{1}" dirty="0"/></a:p></a:txBody><a:tcPr marL="{2}" marR="{2}" marT="{3}" marB="{3}" anchor="ctr">' +
                '<a:lnL w="0"><a:noFill/></a:lnL><a:lnR w="0"><a:noFill/></a:lnR><a:lnT w="0"><a:noFill/></a:lnT><a:lnB w="6350"><a:solidFill><a:srgbClr val="{4}"/></a:solidFill></a:lnB>' +
                '<a:solidFill><a:srgbClr val="{5}"/></a:solidFill></a:tcPr></a:tc>') -f $run, $Size, $m, (ConvertTo-PimPptxEmu 0.03), $br.border, $fill
    }
    $rh = ConvertTo-PimPptxEmu $RowH
    [void]$tbl.Append(('<a:tr h="{0}">' -f $rh))
    foreach ($h in $cols) { [void]$tbl.Append((& $cell $h $true $false)) }
    [void]$tbl.Append('</a:tr>')
    $i = 0
    foreach ($r in @($Rows)) {
        $v = @($r)
        [void]$tbl.Append(('<a:tr h="{0}">' -f $rh))
        for ($c = 0; $c -lt $n; $c++) { $t = if ($c -lt $v.Count) { $v[$c] } else { '' }; [void]$tbl.Append((& $cell $t $false (($i % 2) -eq 1))) }
        [void]$tbl.Append('</a:tr>')
        $i++
    }
    [void]$tbl.Append('</a:tbl>')
    $totalH = ConvertTo-PimPptxEmu ($RowH * (@($Rows).Count + 1))
    return ('<p:graphicFrame><p:nvGraphicFramePr><p:cNvPr id="{0}" name="Table {0}"/><p:cNvGraphicFramePr><a:graphicFrameLocks noGrp="1"/></p:cNvGraphicFramePr><p:nvPr/></p:nvGraphicFramePr>' +
            '<p:xfrm><a:off x="{1}" y="{2}"/><a:ext cx="{3}" cy="{4}"/></p:xfrm><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/table">{5}</a:graphicData></a:graphic></p:graphicFrame>') -f
            $Id, (ConvertTo-PimPptxEmu $X), (ConvertTo-PimPptxEmu $Y), $totalEmu, $totalH, $tbl.ToString()
}

function Expand-PimPptxSlides {
    <#
      PURE. A table longer than -RowsPerSlide is split over as many slides as it needs: the same title with " (2 of 3)", the
      header row repeated, the note on the last part only. Every other slide passes through. Returns the expanded list.
    #>
    param([object[]]$Slides = @(), [int]$RowsPerSlide = 12)
    if ($RowsPerSlide -lt 1) { $RowsPerSlide = 12 }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($Slides)) {
        if ($null -eq $s) { continue }
        $t = Get-PimPptxField $s 'table'
        $rows = Get-PimPptxList $t 'rows'
        if (-not $t -or $rows.Count -le $RowsPerSlide) { $out.Add($s); continue }
        $parts = [int][math]::Ceiling($rows.Count / [double]$RowsPerSlide)
        for ($p = 0; $p -lt $parts; $p++) {
            $from = $p * $RowsPerSlide; $to = [math]::Min($rows.Count, $from + $RowsPerSlide) - 1
            $chunk = New-Object System.Collections.Generic.List[object]
            for ($i = $from; $i -le $to; $i++) { $chunk.Add($rows[$i]) }
            $copy = [ordered]@{}
            foreach ($k in @('kind', 'title', 'subtitle', 'bullets')) { $copy[$k] = Get-PimPptxField $s $k }
            $copy['title'] = ('{0} ({1} of {2})' -f "$(Get-PimPptxField $s 'title')", ($p + 1), $parts)
            $copy['table'] = [ordered]@{ columns = @(Get-PimPptxField $t 'columns'); rows = $chunk.ToArray(); note = $(if ($p -eq $parts - 1) { Get-PimPptxField $t 'note' } else { '' }) }
            $copy['note'] = $(if ($p -eq $parts - 1) { Get-PimPptxField $s 'note' } else { '' })
            $out.Add([pscustomobject]$copy)
        }
    }
    return , $out.ToArray()
}

function New-PimPptxSlideXml {
    <#
      One slide's XML. -Index / -Count number the footer; -LogoRel is the relationship id of the logo ('' = text wordmark);
      -LogoAspect is its width / height.
    #>
    param([Parameter(Mandatory)][object]$Slide, [int]$Index = 1, [int]$Count = 1, [string]$Footer = '', [string]$LogoRel = '', [double]$LogoAspect = 3.8)
    $br = Get-PimPptxBrand
    $W = $script:PimPptxSlideW; $H = $script:PimPptxSlideH
    $sp = New-Object System.Text.StringBuilder
    $script:__pptxId = 1
    $nid = { $script:__pptxId++; return $script:__pptxId }
    $kind = "$(Get-PimPptxField $Slide 'kind')"; if (-not $kind) { $kind = 'content' }
    $title = "$(Get-PimPptxField $Slide 'title')"
    $subtitle = "$(Get-PimPptxField $Slide 'subtitle')"
    $wordmark = {
        param($x, $y, $h, $color)
        $paras = (New-PimPptxParaXml -Runs @(@{ text = 'INVARDIA'; size = [int](700 * $h / 0.5); color = $color; bold = $false }) -Size ([int](700 * $h / 0.5))) +
                 (New-PimPptxParaXml -Runs @(@{ text = 'PIM MANAGER'; size = [int](1500 * $h / 0.5); color = $br.blue; bold = $true }) -Size ([int](1500 * $h / 0.5)))
        return (New-PimPptxShapeXml -Id (& $nid) -Name 'Wordmark' -X $x -Y $y -W ($h * 4) -H $h -Paragraphs $paras -Inset 0 -NoWrap)
    }
    if ($kind -eq 'title') {
        if ($LogoRel) { $lh = 0.95; [void]$sp.Append((New-PimPptxPictureXml -Id (& $nid) -RelId $LogoRel -X 0.6 -Y 0.55 -W ($lh * $LogoAspect) -H $lh)) }
        else { [void]$sp.Append((& $wordmark 0.6 0.6 0.8 $br.heading)) }
        $paras = (New-PimPptxParaXml -Runs @(@{ text = $title; size = 4000; bold = $true; color = 'FFFFFF' }) -Size 4000) +
                 $(if ($subtitle) { New-PimPptxParaXml -Runs @(@{ text = $subtitle; size = 1800; color = 'FFFFFF' }) -Size 1800 -SpaceBefore 600 } else { '' })
        [void]$sp.Append((New-PimPptxShapeXml -Id (& $nid) -Name 'Title band' -X 0 -Y 2.45 -W $W -H 2.1 -Gradient @($br.blue, $br.sky) -Paragraphs $paras -Anchor 'ctr' -Inset 0.6))
        $lines = @(@(Get-PimPptxField $Slide 'lines') | Where-Object { "$_".Trim() })
        if ($lines.Count) { [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X 0.6 -Y 4.85 -W ($W - 1.2) -H 1.7 -Text ($lines -join "`n") -Size 1400 -Color $br.muted)) }
    } else {
        # header: the brand band, the title, the subtitle, the logo top right
        [void]$sp.Append((New-PimPptxShapeXml -Id (& $nid) -Name 'Brand band' -X 0 -Y 0 -W $W -H 0.09 -Gradient @($br.blue, $br.sky)))
        [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X 0.5 -Y 0.28 -W ($W - 3.6) -H 0.6 -Text $title -Size 2600 -Bold -Color $br.ink -Anchor 'ctr' -Max 140))
        if ($subtitle) { [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X 0.5 -Y 0.86 -W ($W - 3.6) -H 0.36 -Text $subtitle -Size 1300 -Color $br.muted -Max 220)) }
        if ($LogoRel) { $lh = 0.42; $lw = $lh * $LogoAspect; [void]$sp.Append((New-PimPptxPictureXml -Id (& $nid) -RelId $LogoRel -X ($W - 0.5 - $lw) -Y 0.32 -W $lw -H $lh)) }
        else { [void]$sp.Append((& $wordmark ($W - 2.3) 0.3 0.45 $br.heading)) }
        $top = 1.35; $bottom = 6.6; $left = 0.5; $cw = $W - 1.0
        $note = "$(Get-PimPptxField $Slide 'note')"
        if ($note) { $bottom = 6.25; [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X $left -Y 6.28 -W $cw -H 0.34 -Text $note -Size 1000 -Color $br.muted -Max 400)) }
        # KPI tiles
        $kpis = @(@(Get-PimPptxField $Slide 'kpis') | Where-Object { $null -ne $_ } | Select-Object -First 8)
        if ($kpis.Count) {
            $perRow = if ($kpis.Count -le 4) { $kpis.Count } else { [int][math]::Ceiling($kpis.Count / 2.0) }
            $gap = 0.22; $tw = ($cw - $gap * ($perRow - 1)) / $perRow; $th = 1.62
            for ($i = 0; $i -lt $kpis.Count; $i++) {
                $k = $kpis[$i]; $row = [int][math]::Floor($i / $perRow); $col = $i % $perRow
                $x = $left + $col * ($tw + $gap); $y = $top + $row * ($th + $gap)
                $tone = "$(Get-PimPptxField $k 'tone')"
                $val = "$(Get-PimPptxField $k 'value')"
                $isNa = ($tone -eq 'na')
                $toneColor = switch ($tone) { 'good' { $br.good } 'bad' { $br.bad } 'warn' { $br.warn } default { $br.muted } }
                $arrow = switch ("$(Get-PimPptxField $k 'arrow')") { 'up' { (Get-PimPptxSymbol up) + ' ' } 'down' { (Get-PimPptxSymbol down) + ' ' } 'flat' { (Get-PimPptxSymbol flat) + ' ' } default { '' } }
                $sub = "$(Get-PimPptxField $k 'sub')"
                $knote = "$(Get-PimPptxField $k 'note')"
                $paras = (New-PimPptxParaXml -Runs @(@{ text = "$(Get-PimPptxField $k 'label')"; size = 1100; color = $br.muted }) -Size 1100) +
                         (New-PimPptxParaXml -Runs @(@{ text = $val; size = $(if ($isNa) { 1500 } else { 3000 }); bold = (-not $isNa); color = $(if ($isNa) { $br.muted } else { $br.ink }) }) -Size $(if ($isNa) { 1500 } else { 3000 }) -SpaceBefore 200) +
                         $(if ($sub) { New-PimPptxParaXml -Runs @(@{ text = ($arrow + $sub); size = 1050; color = $toneColor; bold = ($tone -in @('good', 'bad')) }) -Size 1050 -SpaceBefore 200 } else { '' }) +
                         $(if ($knote) { New-PimPptxParaXml -Runs @(@{ text = $knote; size = 850; color = $br.muted }) -Size 850 -SpaceBefore 100 } else { '' })
                $accent = if ($isNa) { $br.border } elseif ($tone -eq 'bad') { $br.bad } elseif ($tone -eq 'good') { $br.good } else { $br.blue }
                [void]$sp.Append((New-PimPptxShapeXml -Id (& $nid) -Name 'KPI tile' -X $x -Y $y -W $tw -H $th -Fill $br.surfaceAlt -Line $br.border -Geom 'roundRect' -Paragraphs $paras -Inset 0.14))
                [void]$sp.Append((New-PimPptxShapeXml -Id (& $nid) -Name 'KPI accent' -X ($x + 0.02) -Y ($y + 0.14) -W 0.06 -H ($th - 0.28) -Fill $accent))
            }
            $top = $top + [math]::Ceiling($kpis.Count / [double]$perRow) * ($th + $gap) + 0.05
        }
        # a table
        $tb = Get-PimPptxField $Slide 'table'
        if ($tb) {
            $trows = Get-PimPptxList $tb 'rows'
            $tnote = "$(Get-PimPptxField $tb 'note')"
            if ($trows.Count -eq 0) {
                [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X $left -Y $top -W $cw -H 0.5 -Text $(if ($tnote) { $tnote } else { 'Nothing to list for this period.' }) -Size 1300 -Color $br.muted))
            } else {
                $rh = [math]::Min(0.36, [math]::Max(0.26, ($bottom - $top - 0.3) / ($trows.Count + 1)))
                [void]$sp.Append((New-PimPptxTableXml -Id (& $nid) -X $left -Y $top -W $cw -Columns @(Get-PimPptxField $tb 'columns') -Rows $trows -RowH $rh))
                $top = $top + $rh * ($trows.Count + 1) + 0.1
                if ($tnote -and $top -lt $bottom) { [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X $left -Y $top -W $cw -H 0.32 -Text $tnote -Size 1000 -Color $br.muted -Max 300)) }
            }
        }
        # a bar chart drawn as shapes
        $bars = Get-PimPptxField $Slide 'bars'
        if ($bars) {
            $items = @(@(Get-PimPptxField $bars 'items') | Where-Object { $null -ne $_ } | Select-Object -First 12)
            $btitle = "$(Get-PimPptxField $bars 'title')"
            if ($btitle) { [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X $left -Y $top -W $cw -H 0.36 -Text $btitle -Size 1300 -Bold -Color $br.heading)); $top += 0.42 }
            $num = @($items | ForEach-Object { $v = 0.0; if ([double]::TryParse("$(Get-PimPptxField $_ 'value')", [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v)) { $v } else { 0.0 } })
            $max = 0.0; foreach ($v in $num) { if ($v -gt $max) { $max = $v } }
            if ($max -le 0) { $max = 1.0 }
            $unit = "$(Get-PimPptxField $bars 'unit')"
            $avail = [math]::Max(0.6, $bottom - $top - 0.35)
            if ($items.Count -eq 0) {
                [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X $left -Y $top -W $cw -H 0.5 -Text 'Nothing to chart for this period.' -Size 1300 -Color $br.muted))
            } elseif ("$(Get-PimPptxField $bars 'orientation')" -eq 'v') {
                $slot = $cw / $items.Count; $bw = [math]::Min(1.1, $slot * 0.6); $plotH = $avail - 0.55
                for ($i = 0; $i -lt $items.Count; $i++) {
                    $it = $items[$i]; $bh = [math]::Max(0.02, $plotH * $num[$i] / $max)
                    $bx = $left + $i * $slot + ($slot - $bw) / 2; $by = $top + 0.3 + ($plotH - $bh)
                    $fill = switch ("$(Get-PimPptxField $it 'tone')") { 'bad' { $br.bad } 'good' { $br.good } 'muted' { $br.border } default { $br.blue } }
                    [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X ($left + $i * $slot) -Y ($by - 0.3) -W $slot -H 0.28 -Text ("{0}{1}" -f "$(Get-PimPptxField $it 'value')", $unit) -Size 1200 -Bold -Color $br.ink -Align 'ctr'))
                    [void]$sp.Append((New-PimPptxShapeXml -Id (& $nid) -Name 'Bar' -X $bx -Y $by -W $bw -H $bh -Fill $fill))
                    [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X ($left + $i * $slot) -Y ($top + 0.32 + $plotH) -W $slot -H 0.5 -Text "$(Get-PimPptxField $it 'label')" -Size 1000 -Color $br.muted -Align 'ctr' -Max 60))
                }
                [void]$sp.Append((New-PimPptxShapeXml -Id (& $nid) -Name 'Axis' -X $left -Y ($top + 0.3 + $plotH) -W $cw -H 0.01 -Fill $br.border))
                $top = $top + $avail
            } else {
                $rowH = [math]::Min(0.46, $avail / $items.Count); $labW = 3.4; $plotW = $cw - $labW - 1.2
                for ($i = 0; $i -lt $items.Count; $i++) {
                    $it = $items[$i]; $y = $top + $i * $rowH; $bw = [math]::Max(0.02, $plotW * $num[$i] / $max)
                    $fill = switch ("$(Get-PimPptxField $it 'tone')") { 'bad' { $br.bad } 'good' { $br.good } 'muted' { $br.border } default { $br.blue } }
                    [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X $left -Y $y -W ($labW - 0.15) -H $rowH -Text "$(Get-PimPptxField $it 'label')" -Size 1150 -Color $br.text -Align 'r' -Anchor 'ctr' -Max 70))
                    [void]$sp.Append((New-PimPptxShapeXml -Id (& $nid) -Name 'Bar' -X ($left + $labW) -Y ($y + $rowH * 0.18) -W $bw -H ($rowH * 0.64) -Fill $fill))
                    [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X ($left + $labW + $bw + 0.08) -Y $y -W 1.1 -H $rowH -Text ("{0}{1}" -f "$(Get-PimPptxField $it 'value')", $unit) -Size 1150 -Bold -Color $br.ink -Anchor 'ctr'))
                }
                $top = $top + $rowH * $items.Count + 0.1
            }
            $bnote = "$(Get-PimPptxField $bars 'note')"
            if ($bnote -and $top -lt $bottom) { [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X $left -Y $top -W $cw -H 0.32 -Text $bnote -Size 1000 -Color $br.muted -Max 300)); $top += 0.36 }
        }
        # bullets
        $bul = @(@(Get-PimPptxField $Slide 'bullets') | Where-Object { "$_".Trim() } | Select-Object -First 14)
        if ($bul.Count -and $top -lt $bottom - 0.3) {
            $paras = New-Object System.Text.StringBuilder
            foreach ($b in $bul) { [void]$paras.Append((New-PimPptxParaXml -Runs @(@{ text = ((Get-PimPptxSymbol dot) + '  '); size = 1400; color = $br.blue; bold = $true }, @{ text = "$b"; size = 1400; color = $br.text }) -Size 1400 -SpaceBefore 400)) }
            [void]$sp.Append((New-PimPptxShapeXml -Id (& $nid) -Name 'Bullets' -X $left -Y $top -W $cw -H ($bottom - $top) -Paragraphs $paras.ToString() -Inset 0.05))
        }
    }
    # footer on every slide: environment | period | PIM Manager, and the slide number
    [void]$sp.Append((New-PimPptxShapeXml -Id (& $nid) -Name 'Footer line' -X 0.5 -Y 6.95 -W ($W - 1.0) -H 0.01 -Fill $br.border))
    [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X 0.5 -Y 7.0 -W ($W - 2.6) -H 0.32 -Text $Footer -Size 950 -Color $br.muted -Max 200))
    [void]$sp.Append((New-PimPptxTextXml -Id (& $nid) -X ($W - 2.0) -Y 7.0 -W 1.5 -H 0.32 -Text ("{0} / {1}" -f $Index, $Count) -Size 950 -Color $br.muted -Align 'r'))
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sld ' + $script:PimPptxNs + '><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>' +
            '<p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>' + $sp.ToString() +
            '</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>')
}

function Get-PimPptxThemeXml {
    $br = Get-PimPptxBrand
    $f = ConvertTo-PimPptxText $br.font
    $clr = { param($n, $v) "<a:$n><a:srgbClr val=""$v""/></a:$n>" }
    $fill3 = '<a:solidFill><a:schemeClr val="phClr"/></a:solidFill>' * 3
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="PIM Manager"><a:themeElements>' +
        '<a:clrScheme name="PIM Manager">' + (& $clr 'dk1' $br.ink) + (& $clr 'lt1' 'FFFFFF') + (& $clr 'dk2' $br.heading) + (& $clr 'lt2' $br.surfaceAlt) +
        (& $clr 'accent1' $br.blue) + (& $clr 'accent2' $br.sky) + (& $clr 'accent3' $br.good) + (& $clr 'accent4' $br.warn) + (& $clr 'accent5' $br.bad) + (& $clr 'accent6' $br.muted) +
        (& $clr 'hlink' $br.blue) + (& $clr 'folHlink' '6639BA') + '</a:clrScheme>' +
        '<a:fontScheme name="PIM Manager"><a:majorFont><a:latin typeface="' + $f + '"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont><a:minorFont><a:latin typeface="' + $f + '"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme>' +
        '<a:fmtScheme name="PIM Manager"><a:fillStyleLst>' + $fill3 + '</a:fillStyleLst>' +
        '<a:lnStyleLst>' + ('<a:ln w="6350"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>' * 3) + '</a:lnStyleLst>' +
        '<a:effectStyleLst>' + ('<a:effectStyle><a:effectLst/></a:effectStyle>' * 3) + '</a:effectStyleLst>' +
        '<a:bgFillStyleLst>' + $fill3 + '</a:bgFillStyleLst></a:fmtScheme></a:themeElements><a:objectDefaults/><a:extraClrSchemeLst/></a:theme>')
}

function Get-PimPptxMasterXml {
    $tree = '<p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree>'
    $lvl = { param($sz) '<a:lvl1pPr><a:defRPr sz="' + $sz + '" kern="1200"><a:solidFill><a:schemeClr val="tx1"/></a:solidFill><a:latin typeface="+mn-lt"/><a:ea typeface="+mn-ea"/><a:cs typeface="+mn-cs"/></a:defRPr></a:lvl1pPr>' }
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldMaster ' + $script:PimPptxNs + '><p:cSld><p:bg><p:bgRef idx="1001"><a:schemeClr val="bg1"/></p:bgRef></p:bg>' + $tree + '</p:cSld>' +
        '<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>' +
        '<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>' +
        '<p:txStyles><p:titleStyle>' + (& $lvl 3200) + '</p:titleStyle><p:bodyStyle>' + (& $lvl 1800) + '</p:bodyStyle><p:otherStyle>' + (& $lvl 1800) + '</p:otherStyle></p:txStyles></p:sldMaster>')
}

function Get-PimPptxLayoutXml {
    $tree = '<p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree>'
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldLayout ' + $script:PimPptxNs + ' type="blank" preserve="1"><p:cSld name="Blank">' + $tree + '</p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>')
}

function Get-PimPptxContentTypes {
    # PURE. [Content_Types].xml for -SlideCount slides (+ the png default when a logo is embedded).
    param([int]$SlideCount, [switch]$HasPng)
    $pml = 'application/vnd.openxmlformats-officedocument.presentationml'
    $ct = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
    if ($HasPng) { $ct += '<Default Extension="png" ContentType="image/png"/>' }
    $ct += "<Override PartName=""/ppt/presentation.xml"" ContentType=""$pml.presentation.main+xml""/>" +
           "<Override PartName=""/ppt/presProps.xml"" ContentType=""$pml.presProps+xml""/>" +
           "<Override PartName=""/ppt/viewProps.xml"" ContentType=""$pml.viewProps+xml""/>" +
           "<Override PartName=""/ppt/tableStyles.xml"" ContentType=""$pml.tableStyles+xml""/>" +
           "<Override PartName=""/ppt/slideMasters/slideMaster1.xml"" ContentType=""$pml.slideMaster+xml""/>" +
           "<Override PartName=""/ppt/slideLayouts/slideLayout1.xml"" ContentType=""$pml.slideLayout+xml""/>" +
           '<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>' +
           '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>' +
           '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
    for ($i = 1; $i -le $SlideCount; $i++) { $ct += "<Override PartName=""/ppt/slides/slide$i.xml"" ContentType=""$pml.slide+xml""/>" }
    return ($ct + '</Types>')
}

function New-PimPptxBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Slides, [string]$Footer = 'PIM Manager', [AllowNull()][byte[]]$LogoPng = $null, [string]$Title = 'PIM Manager report',
          [int]$TableRowsPerSlide = 12, [datetime]$NowUtc = [datetime]::UtcNow)
    try { Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop } catch { }
    # assigned, never @()-wrapped: the function returns its list with a leading comma
    $slides = Expand-PimPptxSlides -Slides $Slides -RowsPerSlide $TableRowsPerSlide
    if ($null -eq $slides -or $slides.Count -eq 0) { $slides = @([pscustomobject]@{ kind = 'title'; title = $Title }) }
    $png = Get-PimPptxPngSize -Bytes $LogoPng
    $hasLogo = ($null -ne $png)
    $aspect = if ($hasLogo) { [double]$png.width / [double]$png.height } else { 3.8 }
    $ms = New-Object System.IO.MemoryStream
    $zip = New-Object System.IO.Compression.ZipArchive($ms, [System.IO.Compression.ZipArchiveMode]::Create, $true)
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $add = { param($name, $text) $e = $zip.CreateEntry($name); $w = New-Object System.IO.StreamWriter($e.Open(), $utf8); $w.Write($text); $w.Dispose() }
    $rel = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
    $relsHead = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    $n = $slides.Count
    & $add '[Content_Types].xml' (Get-PimPptxContentTypes -SlideCount $n -HasPng:$hasLogo)
    & $add '_rels/.rels' ($relsHead + "<Relationship Id=""rId1"" Type=""$rel/officeDocument"" Target=""ppt/presentation.xml""/>" +
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>' +
        "<Relationship Id=""rId3"" Type=""$rel/extended-properties"" Target=""docProps/app.xml""/></Relationships>")
    $stamp = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    & $add 'docProps/core.xml' ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">' +
        '<dc:title>' + (ConvertTo-PimPptxText $Title -Max 250) + '</dc:title><dc:creator>PIM Manager</dc:creator><cp:lastModifiedBy>PIM Manager</cp:lastModifiedBy>' +
        '<dcterms:created xsi:type="dcterms:W3CDTF">' + $stamp + '</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">' + $stamp + '</dcterms:modified></cp:coreProperties>')
    & $add 'docProps/app.xml' ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">' +
        '<Application>PIM Manager</Application><PresentationFormat>Widescreen</PresentationFormat><Slides>' + $n + '</Slides></Properties>')
    # presentation: master rId1, slides rId2..rId(n+1), then presProps / viewProps / theme / tableStyles
    $pres = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentation ' + $script:PimPptxNs + ' saveSubsetFonts="1"><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst><p:sldIdLst>'
    $prels = $relsHead + "<Relationship Id=""rId1"" Type=""$rel/slideMaster"" Target=""slideMasters/slideMaster1.xml""/>"
    for ($i = 1; $i -le $n; $i++) {
        $pres += ('<p:sldId id="{0}" r:id="rId{1}"/>' -f (255 + $i), ($i + 1))
        $prels += ("<Relationship Id=""rId{0}"" Type=""$rel/slide"" Target=""slides/slide{1}.xml""/>" -f ($i + 1), $i)
    }
    # the EXACT 16:9 size in EMU (13.333 in x 914400 would be 12191995 -- PowerPoint's widescreen is 12192000 x 6858000)
    $pres += ('</p:sldIdLst><p:sldSz cx="{0}" cy="{1}"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>' -f $script:PimPptxSlideCx, $script:PimPptxSlideCy)
    $prels += ("<Relationship Id=""rId{0}"" Type=""$rel/presProps"" Target=""presProps.xml""/><Relationship Id=""rId{1}"" Type=""$rel/viewProps"" Target=""viewProps.xml""/>" -f ($n + 2), ($n + 3)) +
              ("<Relationship Id=""rId{0}"" Type=""$rel/theme"" Target=""theme/theme1.xml""/><Relationship Id=""rId{1}"" Type=""$rel/tableStyles"" Target=""tableStyles.xml""/></Relationships>" -f ($n + 4), ($n + 5))
    & $add 'ppt/presentation.xml' $pres
    & $add 'ppt/_rels/presentation.xml.rels' $prels
    & $add 'ppt/presProps.xml' ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentationPr ' + $script:PimPptxNs + '/>')
    & $add 'ppt/viewProps.xml' ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:viewPr ' + $script:PimPptxNs + '><p:gridSpacing cx="76200" cy="76200"/></p:viewPr>')
    & $add 'ppt/tableStyles.xml' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a:tblStyleLst xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" def="{5C22544A-7EE6-4342-B048-85BDC9FD1C3A}"/>'
    & $add 'ppt/theme/theme1.xml' (Get-PimPptxThemeXml)
    & $add 'ppt/slideMasters/slideMaster1.xml' (Get-PimPptxMasterXml)
    & $add 'ppt/slideMasters/_rels/slideMaster1.xml.rels' ($relsHead + "<Relationship Id=""rId1"" Type=""$rel/slideLayout"" Target=""../slideLayouts/slideLayout1.xml""/><Relationship Id=""rId2"" Type=""$rel/theme"" Target=""../theme/theme1.xml""/></Relationships>")
    & $add 'ppt/slideLayouts/slideLayout1.xml' (Get-PimPptxLayoutXml)
    & $add 'ppt/slideLayouts/_rels/slideLayout1.xml.rels' ($relsHead + "<Relationship Id=""rId1"" Type=""$rel/slideMaster"" Target=""../slideMasters/slideMaster1.xml""/></Relationships>")
    if ($hasLogo) {
        $e = $zip.CreateEntry('ppt/media/image1.png', [System.IO.Compression.CompressionLevel]::NoCompression)
        $st = $e.Open(); $st.Write($LogoPng, 0, $LogoPng.Length); $st.Dispose()
    }
    for ($i = 1; $i -le $n; $i++) {
        & $add "ppt/slides/slide$i.xml" (New-PimPptxSlideXml -Slide $slides[$i - 1] -Index $i -Count $n -Footer $Footer -LogoRel $(if ($hasLogo) { 'rId2' } else { '' }) -LogoAspect $aspect)
        $srels = $relsHead + "<Relationship Id=""rId1"" Type=""$rel/slideLayout"" Target=""../slideLayouts/slideLayout1.xml""/>"
        if ($hasLogo) { $srels += "<Relationship Id=""rId2"" Type=""$rel/image"" Target=""../media/image1.png""/>" }
        & $add "ppt/slides/_rels/slide$i.xml.rels" ($srels + '</Relationships>')
    }
    $zip.Dispose()
    # The comma keeps it ONE byte[]: 'return (...)' would unroll it into one pipeline object per byte.
    return , $ms.ToArray()
}
