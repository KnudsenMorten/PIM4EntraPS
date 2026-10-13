#Requires -Version 5.1
<#
  PIM-MailLayout.ps1 -- the ONE designed mail / report layout (framework DOCS/REQUIREMENTS.md §12.11 MAIL-2 items 1, 4, 7;
  PIM REQUIREMENTS §100.5). PURE: strings in, HTML out; no network, no store.

  Every designed PIM mail and its print-ready report copy is built from these pieces:
    * a BRAND-2 header: the PIM Manager logo (inline CID image 'cid:pim-logo' in a mail -- the chokepoint
      Send-PimNotifyMail attaches docs/img/brand/pim-manager-512w.png -- or the inline SVG in a printed report),
      the environment name, and the 3 px brand-blue line;
    * a summary first (tiles + one sentence), then sections with readable tables;
    * ONE clear blue call-to-action button (bulletproof: a table cell with bgcolor, so Outlook draws it too) that
      deep-links to the page for the recipient's audience;
    * a footer (class "pim-env-footer", so the chokepoint does not add a second one) with the environment, tenant,
      version, a PLAIN "Open PIM Manager" link to the Manager home, and where to change your notifications.
  The printed copy (-Print) is a whole HTML document with @page rules: page numbers, date and tenant on every page.

  Colours are the BRAND-2.1 tokens (Get-PimMailBrand). ASCII only; PS 5.1-safe.
#>
Set-StrictMode -Off

function Get-PimMailBrand {
    # BRAND-2.1 colour tokens (light) + the mail font stack. One place, so a mail and a printed report cannot drift.
    [ordered]@{
        blue = '#1B4FE4'; sky = '#18B4F2'; ink = '#0B1633'; wordmark = '#9FC3FF'
        accent = '#0969da'; accentFill = '#0969da'
        text = '#1a1a1a'; heading = '#24292f'; muted = '#57606a'
        surface = '#ffffff'; surfaceAlt = '#f6f8fa'; border = '#d0d7de'; grid = '#eaeef2'
        danger = '#cf222e'; warning = '#9a6700'; good = '#1a7f37'
        dangerBg = '#ffebe9'; warningBg = '#fff8c5'; goodBg = '#dafbe1'
        font = "-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
    }
}

function ConvertTo-PimMailText {
    # HTML-encode one value (null-safe). WebUtility, not System.Web: works headless and in the container.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode("$Value")
}

function Test-PimMailLinkUrl {
    # A link in a mail is https://, or http://localhost / 127.0.0.1 for a local Manager. Anything else is dropped --
    # a mail never carries a javascript: or a plain-http public link.
    param([AllowEmptyString()][string]$Url)
    return ("$Url".Trim() -match '^(?i)(https://[^\s"<>]+|http://(localhost|127\.0\.0\.1)(:\d+)?(/[^\s"<>]*)?)$')
}

function Get-PimMailToneColors {
    param([string]$Tone = 'neutral')
    $b = Get-PimMailBrand
    switch ("$Tone") {
        'danger'  { return @{ fg = $b.danger;  bg = $b.dangerBg;  line = '#ff8182' } }
        'warning' { return @{ fg = $b.warning; bg = $b.warningBg; line = '#d4a72c' } }
        'good'    { return @{ fg = $b.good;    bg = $b.goodBg;    line = '#4ac26b' } }
        'accent'  { return @{ fg = $b.accent;  bg = '#ddf4ff';    line = '#54aeff' } }
        default   { return @{ fg = $b.heading; bg = $b.surfaceAlt; line = $b.border } }
    }
}

function New-PimMailButton {
    <#
      The BLUE call-to-action (MAIL-2 item 1). Bulletproof for Outlook: the colour sits on a table CELL (bgcolor + style),
      the link fills it, so a client that ignores padding on <a> still shows a blue button. '' for an unusable URL -- a
      mail is sent without a button rather than with a broken one.
    #>
    param([AllowEmptyString()][string]$Url, [Parameter(Mandatory)][string]$Label, [ValidateSet('primary', 'secondary')][string]$Tone = 'primary')
    if (-not (Test-PimMailLinkUrl -Url $Url)) { return '' }
    $b = Get-PimMailBrand
    $bg = if ($Tone -eq 'primary') { $b.accentFill } else { $b.surface }
    $fg = if ($Tone -eq 'primary') { '#ffffff' } else { $b.accent }
    $u = ConvertTo-PimMailText $Url.Trim()
    return ('<table role="presentation" class="pim-mail-button" cellspacing="0" cellpadding="0" border="0" style="margin:18px 0 6px 0;border-collapse:separate;"><tr>' +
            # PIM 100.105 ("the button's text is squeezed"): the padding sits on the CELL -- Outlook ignores padding on a link
            '<td align="center" bgcolor="' + $bg + '" style="border-radius:6px;background:' + $bg + ';border:1px solid ' + $b.accentFill + ';padding:11px 24px;">' +
            '<a href="' + $u + '" target="_blank" style="display:inline-block;font-family:' + $b.font + ';font-size:15px;font-weight:600;line-height:20px;color:' + $fg + ';text-decoration:none;white-space:nowrap;">' +
            (ConvertTo-PimMailText $Label) + ' &rarr;</a></td></tr></table>')
}

function New-PimMailSummaryTiles {
    <#
      The summary FIRST (MAIL-2 item 7): a row of count tiles. Each tile @{ label; value; tone = neutral|accent|good|
      warning|danger; hint }. Up to four per row; more wrap to a new row.
    #>
    param([object[]]$Tiles = @())
    $b = Get-PimMailBrand
    $list = @($Tiles | Where-Object { $_ })
    if (-not $list.Count) { return '' }
    $rows = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $list.Count; $i += 4) {
        $cells = for ($j = $i; $j -lt [Math]::Min($i + 4, $list.Count); $j++) {
            $t = $list[$j]; $c = Get-PimMailToneColors -Tone "$($t.tone)"
            '<td class="pim-mail-tile" valign="top" style="width:25%;padding:10px 12px;background:' + $c.bg + ';border:1px solid ' + $c.line + ';border-radius:6px;">' +
            '<div style="font-family:' + $b.font + ';font-size:11px;letter-spacing:.5px;text-transform:uppercase;color:' + $b.muted + ';">' + (ConvertTo-PimMailText $t.label) + '</div>' +
            '<div style="font-family:' + $b.font + ';font-size:24px;font-weight:700;line-height:30px;color:' + $c.fg + ';">' + (ConvertTo-PimMailText $t.value) + '</div>' +
            $(if ("$($t.hint)".Trim()) { '<div style="font-family:' + $b.font + ';font-size:11.5px;color:' + $b.muted + ';">' + (ConvertTo-PimMailText $t.hint) + '</div>' } else { '' }) + '</td>'
        }
        $rows.Add('<tr>' + (@($cells) -join '<td style="width:8px;font-size:1px;">&nbsp;</td>') + '</tr>')
    }
    return '<table role="presentation" class="pim-mail-tiles" cellspacing="0" cellpadding="0" border="0" width="100%" style="border-collapse:separate;margin:14px 0 4px 0;">' + ($rows.ToArray() -join '<tr><td style="height:8px;font-size:1px;">&nbsp;</td></tr>') + '</table>'
}

function New-PimMailCallout {
    # A boxed note in a tone (danger = "needs a look"). -Html is already safe HTML (the caller encoded its values).
    param([string]$Tone = 'neutral', [string]$Title = '', [string]$Html = '')
    $b = Get-PimMailBrand; $c = Get-PimMailToneColors -Tone $Tone
    return ('<div class="pim-mail-callout pim-mail-callout-' + $Tone + '" style="margin:14px 0;padding:10px 14px;background:' + $c.bg + ';border:1px solid ' + $c.line + ';border-left:4px solid ' + $c.fg + ';border-radius:6px;font-family:' + $b.font + ';font-size:13.5px;color:' + $b.text + ';">' +
            $(if ("$Title".Trim()) { '<div style="font-weight:700;color:' + $c.fg + ';margin-bottom:4px;">' + (ConvertTo-PimMailText $Title) + '</div>' } else { '' }) + $Html + '</div>')
}

function New-PimMailTable {
    <#
      A readable table (MAIL-2 item 7). -Columns: @(@{ key; label; html = $false; width = '' }) -- a column with html=$true
      takes its cell as ready HTML (the caller encoded it); every other cell is encoded here. -Rows: objects or hashtables.
      -MaxRows caps the rows shown; the rest are counted in a last line (with -MoreUrl as a link to the full list).
    #>
    param([object[]]$Columns = @(), [object[]]$Rows = @(), [string]$EmptyText = 'Nothing to show.', [int]$MaxRows = 0, [string]$MoreUrl = '', [string]$MoreLabel = 'See all of them in PIM Manager')
    $b = Get-PimMailBrand
    $cols = @($Columns | Where-Object { $_ })
    $all = @($Rows | Where-Object { $null -ne $_ })
    if (-not $all.Count) { return '<p class="pim-mail-empty" style="font-family:' + $b.font + ';font-size:13px;color:' + $b.muted + ';margin:6px 0;">' + (ConvertTo-PimMailText $EmptyText) + '</p>' }
    $show = if ($MaxRows -gt 0 -and $all.Count -gt $MaxRows) { @($all[0..($MaxRows - 1)]) } else { $all }
    $get = { param($row, $k) if ($row -is [System.Collections.IDictionary]) { if ($row.Contains($k)) { $row[$k] } else { $null } } else { $p = $row.PSObject.Properties[$k]; if ($p) { $p.Value } else { $null } } }
    $th = foreach ($c in $cols) {
        '<th align="left" style="padding:7px 8px;background:' + $b.surfaceAlt + ';border-bottom:1px solid ' + $b.border + ';font-family:' + $b.font + ';font-size:12px;font-weight:600;color:' + $b.heading + ';text-align:left;' + $(if ("$($c.width)".Trim()) { 'width:' + $c.width + ';' } else { '' }) + '">' + (ConvertTo-PimMailText $c.label) + '</th>'
    }
    $i = 0
    $tr = foreach ($r in $show) {
        $bg = if ($i % 2) { '#fbfcfd' } else { $b.surface }; $i++
        $tds = foreach ($c in $cols) {
            $v = & $get $r "$($c.key)"
            $cell = if ($c.html) { "$v" } else { ConvertTo-PimMailText $v }
            if (-not "$cell".Trim()) { $cell = '<span style="color:' + $b.muted + ';">&mdash;</span>' }
            '<td valign="top" style="padding:6px 8px;border-bottom:1px solid ' + $b.grid + ';font-family:' + $b.font + ';font-size:13px;color:' + $b.text + ';background:' + $bg + ';">' + $cell + '</td>'
        }
        '<tr>' + (@($tds) -join '') + '</tr>'
    }
    $more = ''
    if ($show.Count -lt $all.Count) {
        $n = $all.Count - $show.Count
        $more = '<p class="pim-mail-more" style="font-family:' + $b.font + ';font-size:12.5px;color:' + $b.muted + ';margin:6px 0 0 0;">... and ' + $n + ' more' +
                $(if (Test-PimMailLinkUrl -Url $MoreUrl) { ' &mdash; <a href="' + (ConvertTo-PimMailText $MoreUrl) + '" style="color:' + $b.accent + ';">' + (ConvertTo-PimMailText $MoreLabel) + '</a>' } else { '' }) + '.</p>'
    }
    return '<table role="presentation" class="pim-mail-table" cellspacing="0" cellpadding="0" border="0" width="100%" style="border-collapse:collapse;border:1px solid ' + $b.border + ';margin:6px 0 4px 0;"><thead><tr>' + (@($th) -join '') + '</tr></thead><tbody>' + (@($tr) -join '') + '</tbody></table>' + $more
}

function New-PimMailSection {
    # A section: heading + content, with an optional small link to the page that holds the full view.
    param([Parameter(Mandatory)][string]$Title, [string]$Html = '', [string]$LinkUrl = '', [string]$LinkLabel = 'Open in PIM Manager', [string]$Note = '')
    $b = Get-PimMailBrand
    $link = if (Test-PimMailLinkUrl -Url $LinkUrl) { ' <a href="' + (ConvertTo-PimMailText $LinkUrl) + '" style="font-size:12px;font-weight:400;color:' + $b.accent + ';text-decoration:none;">' + (ConvertTo-PimMailText $LinkLabel) + ' &rarr;</a>' } else { '' }
    return ('<div class="pim-mail-section" style="margin:22px 0 0 0;">' +
            '<h2 style="margin:0 0 4px 0;font-family:' + $b.font + ';font-size:16px;font-weight:700;color:' + $b.heading + ';">' + (ConvertTo-PimMailText $Title) + $link + '</h2>' +
            $(if ("$Note".Trim()) { '<div style="font-family:' + $b.font + ';font-size:12.5px;color:' + $b.muted + ';margin:0 0 4px 0;">' + (ConvertTo-PimMailText $Note) + '</div>' } else { '' }) +
            $Html + '</div>')
}

function Get-PimMailBrandDir {
    # docs/img/brand of this solution -- the logos the page and the docs already ship (BRAND-1). '' when not present.
    if ("$($global:PIM_BrandDir)".Trim()) { return "$($global:PIM_BrandDir)" }
    if ($PSScriptRoot) { return (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'docs\img\brand') }
    return ''
}

function Get-PimMailLogoAttachment {
    <#
      The logo as an INLINE attachment for a mail (Content-ID 'pim-logo', referenced as <img src="cid:pim-logo">). The colour
      logo PNG (BRAND-1, docs/img/brand/pim-manager-512w.png). PNG, not SVG: Outlook and most webmail do not draw SVG in mail.
      $null when the file is not shipped -- the chokepoint then puts the text wordmark in its place. Cached per process.
    #>
    if ($script:PimMailLogoCache) { return $script:PimMailLogoCache }
    $dir = Get-PimMailBrandDir
    if (-not $dir) { return $null }
    $p = Join-Path $dir 'pim-manager-512w.png'
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($p)
        if ($bytes.Length -lt 8 -or $bytes[0] -ne 0x89 -or $bytes[1] -ne 0x50) { return $null }   # not a PNG -- never attach garbage
        $script:PimMailLogoCache = @{ name = 'pim-manager.png'; contentType = 'image/png'; bytes = $bytes; contentId = 'pim-logo'; isInline = $true }
        return $script:PimMailLogoCache
    } catch { return $null }
}

function Get-PimMailLogoSvg {
    # The colour logo as inline SVG for a PRINTED report (a browser draws SVG; it stays sharp in a PDF). '' when missing.
    $dir = Get-PimMailBrandDir
    if (-not $dir) { return '' }
    $p = Join-Path $dir 'pim-manager.svg'
    if (-not (Test-Path -LiteralPath $p)) { return '' }
    try {
        $t = [System.IO.File]::ReadAllText($p)
        $t = [regex]::Replace($t, '(?s)^.*?(<svg\b)', '$1')   # drop an XML prolog / comments before <svg
        if ($t -notmatch '^<svg\b') { return '' }
        if ($t -match '(?i)<script|\son[a-z]+\s*=') { return '' }   # never inline active content
        return $t
    } catch { return '' }
}

function Get-PimMailWordmarkHtml {
    # The text stand-in for the logo (when the PNG is not available): INVARDIA over PIM MANAGER in the brand blue.
    $b = Get-PimMailBrand
    return ('<span class="pim-mail-wordmark" style="font-family:' + $b.font + ';"><span style="display:block;font-size:10px;letter-spacing:2px;color:' + $b.heading + ';">INVARDIA</span>' +
            '<span style="display:block;font-size:20px;font-weight:700;letter-spacing:1px;color:' + $b.blue + ';">PIM MANAGER</span></span>')
}

function ConvertTo-PimMailCssString {
    # A value inside a CSS content: "..." string (the @page margin boxes): quotes, backslashes and line breaks removed.
    param([AllowNull()][string]$Value)
    return ("$Value" -replace '["\\\r\n<>]', ' ').Trim()
}

# =====================================================================================================================
# PIM 100.105 -- THE ALERT MAIL IS ONE TABLE (owner 2026-10-12: "it is too much text. we like tables. short and easy
# format - make things bold"; "action (who), status (error, warning, etc), problem (summary), action (what)"; "you know
# the name of the customer, the environment, solution ... put that in"; "tell where they can get support").
# Every mail of type 'alert-notice' is: Customer | Environment | Solution | Who acts | Status | Problem | What to do |
# the findings (one row each, kind | name) | When | Support -- labels left, values bold -- then the button.
# PURE (tokens in, HTML / text out), so the body is tested without sending. The callers pass four plain-text tokens
# (AlertWho, AlertStatus, AlertProblem, AlertTodo) and, when the alert has a list, AlertFindings = @(@{ kind; name }).
# A caller that passes none of them still gets a whole table (Who acts "Not known", Status "Warning", Problem = its
# title, What to do = its old action text in one line).
# =====================================================================================================================
$script:PimAlertWhoValues     = @('Customer', 'PIM Manager team', 'Not known')
$script:PimAlertStatusValues  = @('Error', 'Warning', 'Held back', "Needs customer's action")
# Literals behind functions, never $script: values: a $script: default is $null when this file was loaded once and one of its
# functions is called from a child script (BUG-79-6b) -- the mail would carry an empty support address.
function Get-PimAlertSupportMail   { 'support@invardia.com' }
function Get-PimAlertSupportPortal { 'https://portal.invardia.com' }
$script:PimAlertRowLabels     = @('Customer', 'Environment', 'Solution', 'Who acts', 'Status', 'Problem', 'What to do', 'When', 'Support')

function ConvertTo-PimAlertPlainText {
    # HTML (or plain text) -> plain text on ONE line: tags dropped, entities decoded, white space collapsed.
    param([AllowNull()][string]$Text)
    $t = "$Text" -replace '(?s)<!--.*?-->', ' '
    $t = $t -replace '(?i)<br\s*/?>', ' ' -replace '(?i)</(p|div|li|tr|h[1-6])>', ' '
    $t = $t -replace '</?[A-Za-z][^<>]*>', ''
    $t = [System.Net.WebUtility]::HtmlDecode($t)
    return (($t -replace '\s+', ' ').Trim())
}

function ConvertTo-PimAlertTitleText {
    # The heading / subject of an alert as a person reads it: no "--" (a colon, or a comma when the title already has a
    # colon) and the product's own name. The CALLER's title is untouched (the debounce key is built from it).
    param([AllowNull()][string]$Title)
    $t = "$Title".Trim() -replace 'PIM4EntraPS', 'PIM Manager'
    $m = [regex]::Match($t, '\s+--\s+')
    while ($m.Success) {
        $sep = if ($t.Substring(0, $m.Index).Contains(':')) { ', ' } else { ': ' }
        $t = $t.Substring(0, $m.Index) + $sep + $t.Substring($m.Index + $m.Length)
        $m = [regex]::Match($t, '\s+--\s+')
    }
    return $t
}

function ConvertTo-PimAlertOneLine {
    <#
      ONE line for the Problem / What to do row. -FromHtml: the text is an old HTML token (AlertAction, AlertTitle) -- tags
      are dropped and only its first sentence is kept. Without it the text is the caller's plain line, kept whole. Never
      "--", never the old product name, at most -MaxLength characters, no full stop at the end.
    #>
    param([AllowNull()][string]$Text, [switch]$FromHtml, [int]$MaxLength = 300)
    $t = if ($FromHtml) { ConvertTo-PimAlertPlainText $Text } else { ("$Text" -replace '\s+', ' ').Trim() }
    $t = ($t -replace 'PIM4EntraPS', 'PIM Manager') -replace '\s+--\s+', ', '
    if ($FromHtml) {
        $m = [regex]::Match($t, '^(.{12,}?[.!?])(\s|$)')
        if ($m.Success) { $t = $m.Groups[1].Value }
    }
    $t = $t.Trim().TrimEnd('.').Trim()
    if ($MaxLength -gt 3 -and $t.Length -gt $MaxLength) { $t = $t.Substring(0, $MaxLength - 3).TrimEnd() + '...' }
    return $t
}

function Resolve-PimAlertWho {
    # One of Customer / PIM Manager team / Not known. Anything else (a sentence, an empty value) is "Not known".
    param([AllowNull()][string]$Value)
    $v = "$Value".Trim()
    foreach ($k in $script:PimAlertWhoValues) { if ($v -ieq $k) { return $k } }
    return 'Not known'
}

function Resolve-PimAlertStatus {
    # One of Error / Warning / Held back / Needs customer's action. Anything else is "Warning". A LABEL in the mail only:
    # it never changes what a guard blocks, holds or asks approval for.
    param([AllowNull()][string]$Value)
    $v = "$Value".Trim()
    foreach ($k in $script:PimAlertStatusValues) { if ($v -ieq $k) { return $k } }
    return 'Warning'
}

function ConvertTo-PimAlertFindingList {
    # AlertFindings as a clean list of { kind; name }, GROUPED by kind (kinds in the order they first appear). Entries
    # without a name are dropped. Accepts hashtables, objects, or $null.
    param([AllowNull()][object]$Findings)
    $order = New-Object System.Collections.Generic.List[string]
    $by = @{}
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $kind = ''; $name = ''
        if ($f -is [System.Collections.IDictionary]) { if ($f.Contains('kind')) { $kind = "$($f['kind'])" }; if ($f.Contains('name')) { $name = "$($f['name'])" } }
        elseif ($f -is [string]) { $name = $f }
        else { if ($f.PSObject.Properties['kind']) { $kind = "$($f.kind)" }; if ($f.PSObject.Properties['name']) { $name = "$($f.name)" } }
        $kind = ($kind -replace '\s+', ' ').Trim(); $name = ($name -replace '\s+', ' ').Trim()
        if (-not $name) { continue }
        if (-not $kind) { $kind = 'Finding' }
        $key = $kind.ToLowerInvariant()
        if (-not $by.ContainsKey($key)) { $by[$key] = New-Object System.Collections.Generic.List[object]; $order.Add($key) }
        $by[$key].Add([pscustomobject]@{ kind = $kind; name = $name })
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($key in $order) { foreach ($x in $by[$key]) { $out.Add($x) } }
    return @($out.ToArray())
}

function Get-PimAlertRowHtml {
    # One table row: the label left, the value right. -ValueHtml is ready HTML (already encoded by the caller).
    param([string]$Label, [string]$ValueHtml, [string]$Class = 'pim-alert-row', [string]$Color = '', [switch]$NotBold)
    $b = Get-PimMailBrand
    $col = if ("$Color".Trim()) { "$Color" } else { $b.text }
    $val = if ($NotBold) { $ValueHtml } else { '<b>' + $ValueHtml + '</b>' }
    return ('<tr class="' + $Class + '">' +
            '<td valign="top" style="font-family:' + $b.font + ';font-size:13px;line-height:20px;color:' + $b.muted + ';padding:7px 16px 7px 0;white-space:nowrap;border-bottom:1px solid ' + $b.grid + ';">' + (ConvertTo-PimMailText $Label) + '</td>' +
            '<td valign="top" style="font-family:' + $b.font + ';font-size:14px;line-height:20px;color:' + $col + ';padding:7px 0;border-bottom:1px solid ' + $b.grid + ';">' + $val + '</td></tr>')
}

function ConvertTo-PimAlertFindingRows {
    <#
      PURE. THE one function that turns an alert's findings into table rows: one row per finding, the kind left and the
      name (bold) right, grouped by kind. '' for no findings. More than -MaxRows: the first -MaxRows, then one row that
      says how many more there are. Never one paragraph joined with ";", never "[Kind] Workload: name".
    #>
    param([AllowNull()][object]$Findings, [int]$MaxRows = 50)
    $list = @(ConvertTo-PimAlertFindingList -Findings $Findings)
    if (-not $list.Count) { return '' }
    # @(...) around the WHOLE if: an if-expression unrolls a one-element array to a scalar, and a scalar object has no
    # .Count -- one finding then got a false "and 1 more" row
    $show = @(if ($MaxRows -gt 0 -and $list.Count -gt $MaxRows) { $list[0..($MaxRows - 1)] } else { $list })
    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($f in $show) { $rows.Add((Get-PimAlertRowHtml -Label $f.kind -ValueHtml (ConvertTo-PimMailText $f.name) -Class 'pim-alert-finding')) }
    if ($show.Count -lt $list.Count) { $rows.Add((Get-PimAlertRowHtml -Label '' -ValueHtml (ConvertTo-PimMailText ("and {0} more in PIM Manager" -f ($list.Count - $show.Count))) -Class 'pim-alert-finding-more')) }
    return ($rows.ToArray() -join '')
}

function Get-PimAlertMailModel {
    <#
      PURE. What ONE alert mail says, from the caller's tokens and what the product knows of this environment
      (-Environment = Get-PimMailEnvironmentInfo: name, tenantName, tenantId, version). Returns
        @{ title; customer; environment; solution; who; status; problem; todo; findings; detailHtml; when; support }
      customer / environment are '' when not known (their row is then left out -- never an empty value, never
      "scheduler"). detailHtml is '' when the alert has findings or the detail says nothing beyond the problem.
      -NowUtc: used when the caller passed no time.
    #>
    param([hashtable]$Tokens = @{}, [hashtable]$Environment = @{}, [datetime]$NowUtc = [datetime]::UtcNow)
    $tk = if ($Tokens) { $Tokens } else { @{} }
    $ev = if ($Environment) { $Environment } else { @{} }
    $get = { param($n) if ($tk.ContainsKey($n) -and $null -ne $tk[$n]) { "$($tk[$n])" } else { '' } }
    $title = ConvertTo-PimAlertTitleText (& $get 'AlertTitle')
    if (-not $title) { $title = 'PIM Manager alert' }
    $customer = "$($ev['tenantName'])".Trim()
    if (-not $customer) { $customer = ConvertTo-PimAlertPlainText (& $get 'TenantName') }
    $envName = "$($ev['name'])".Trim()
    # the environment's own NAME only: when nothing names it, Get-PimMailEnvironmentInfo falls back to the tenant -- that
    # is the Customer row, so the Environment row is left out instead of saying the same thing twice
    if ($envName -and ($envName -ieq $customer -or $envName -ieq "$($ev['tenantId'])".Trim() -or $envName -ieq ("tenant " + "$($ev['tenantId'])".Trim()))) { $envName = '' }
    $ver = "$($ev['version'])".Trim()
    $solution = ('PIM Manager ' + $ver).Trim()
    $problem = ConvertTo-PimAlertOneLine (& $get 'AlertProblem')
    if (-not $problem) { $problem = ConvertTo-PimAlertOneLine (ConvertTo-PimAlertPlainText $title) }
    $todo = ConvertTo-PimAlertOneLine (& $get 'AlertTodo')
    if (-not $todo) { $todo = ConvertTo-PimAlertOneLine (& $get 'AlertAction') -FromHtml }
    if (-not $todo) { $todo = 'Open PIM Manager and look at this alert' }
    $findings = @(); if ($tk.ContainsKey('AlertFindings')) { $findings = @(ConvertTo-PimAlertFindingList -Findings $tk['AlertFindings']) }
    $detail = (& $get 'AlertDetail') -replace 'PIM4EntraPS', 'PIM Manager'
    $detailPlain = ConvertTo-PimAlertPlainText $detail
    if ($findings.Count -or -not $detailPlain -or $detailPlain.TrimEnd('.') -ieq $problem -or $detailPlain.TrimEnd('.') -ieq $title.TrimEnd('.')) { $detail = '' }
    # When: the product keeps no time zone for an environment (the page shows times in the browser's), so a mail says UTC
    # -- to the minute, never with seconds.
    $when = ''
    $wm = [regex]::Match((& $get 'WhenUtc'), '(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})')
    if ($wm.Success) { $when = $wm.Groups[1].Value + ' ' + $wm.Groups[2].Value + ' UTC' }
    else { $when = $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC' }
    return [ordered]@{
        title = $title; customer = $customer; environment = $envName; solution = $solution
        who = (Resolve-PimAlertWho (& $get 'AlertWho')); status = (Resolve-PimAlertStatus (& $get 'AlertStatus'))
        problem = $problem; todo = $todo; findings = @($findings); detailHtml = $detail; when = $when
        support = ((Get-PimAlertSupportMail) + ' - customer portal ' + (Get-PimAlertSupportPortal))
    }
}

function New-PimAlertMailTable {
    # PURE. The model as THE table of the alert mail (HTML). -MaxFindings caps the finding rows shown.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Model, [int]$MaxFindings = 50)
    $b = Get-PimMailBrand
    $tone = switch ("$($Model.status)") { 'Error' { $b.danger; break } 'Warning' { $b.warning; break } 'Held back' { $b.warning; break } default { $b.accent } }
    $rows = New-Object System.Collections.Generic.List[string]
    if ("$($Model.customer)".Trim())    { $rows.Add((Get-PimAlertRowHtml -Label 'Customer' -ValueHtml (ConvertTo-PimMailText $Model.customer))) }
    if ("$($Model.environment)".Trim()) { $rows.Add((Get-PimAlertRowHtml -Label 'Environment' -ValueHtml (ConvertTo-PimMailText $Model.environment))) }
    $rows.Add((Get-PimAlertRowHtml -Label 'Solution' -ValueHtml (ConvertTo-PimMailText $Model.solution)))
    $rows.Add((Get-PimAlertRowHtml -Label 'Who acts' -ValueHtml (ConvertTo-PimMailText $Model.who)))
    $rows.Add((Get-PimAlertRowHtml -Label 'Status' -ValueHtml (ConvertTo-PimMailText $Model.status) -Color $tone))
    $rows.Add((Get-PimAlertRowHtml -Label 'Problem' -ValueHtml (ConvertTo-PimMailText $Model.problem)))
    $rows.Add((Get-PimAlertRowHtml -Label 'What to do' -ValueHtml (ConvertTo-PimMailText $Model.todo)))
    $fr = ConvertTo-PimAlertFindingRows -Findings $Model.findings -MaxRows $MaxFindings
    if ($fr) { $rows.Add($fr) }
    elseif ("$($Model.detailHtml)".Trim()) { $rows.Add((Get-PimAlertRowHtml -Label 'Details' -ValueHtml "$($Model.detailHtml)" -Class 'pim-alert-detail' -NotBold)) }
    $rows.Add((Get-PimAlertRowHtml -Label 'When' -ValueHtml (ConvertTo-PimMailText $Model.when)))
    $sup = '<a href="mailto:' + (Get-PimAlertSupportMail) + '" style="color:' + $b.accent + ';">' + (Get-PimAlertSupportMail) + '</a> - customer portal ' +
           '<a href="' + (Get-PimAlertSupportPortal) + '" style="color:' + $b.accent + ';">' + (Get-PimAlertSupportPortal) + '</a>'
    $rows.Add((Get-PimAlertRowHtml -Label 'Support' -ValueHtml $sup))
    return ('<table role="presentation" class="pim-alert-table" cellspacing="0" cellpadding="0" border="0" width="100%" style="border-collapse:collapse;margin:8px 0 6px 0;">' + ($rows.ToArray() -join '') + '</table>')
}

function ConvertTo-PimAlertMailText {
    # PURE. The same rows as the plain-text part of the mail: "Label: value", one per line.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Model, [int]$MaxFindings = 50)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add("$($Model.title)"); $l.Add('')
    if ("$($Model.customer)".Trim())    { $l.Add('Customer: ' + $Model.customer) }
    if ("$($Model.environment)".Trim()) { $l.Add('Environment: ' + $Model.environment) }
    $l.Add('Solution: ' + $Model.solution)
    $l.Add('Who acts: ' + $Model.who)
    $l.Add('Status: ' + $Model.status)
    $l.Add('Problem: ' + $Model.problem)
    $l.Add('What to do: ' + $Model.todo)
    $list = @($Model.findings)
    if ($list.Count) {
        $show = @(if ($MaxFindings -gt 0 -and $list.Count -gt $MaxFindings) { $list[0..($MaxFindings - 1)] } else { $list })
        foreach ($f in $show) { $l.Add("$($f.kind): $($f.name)") }
        if ($show.Count -lt $list.Count) { $l.Add("and $($list.Count - $show.Count) more in PIM Manager") }
    } elseif ("$($Model.detailHtml)".Trim()) {
        $d = "$($Model.detailHtml)" -replace '(?i)<br\s*/?>', "`n" -replace '(?i)</(p|div|li|tr|h[1-6])>', "`n" -replace '(?i)</t[dh]>', ' '
        $d = [System.Net.WebUtility]::HtmlDecode(($d -replace '</?[A-Za-z][^<>]*>', ''))
        $dl = @($d -split "`r?`n" | ForEach-Object { ($_ -replace '[ \t]+', ' ').Trim() } | Where-Object { $_ })
        if ($dl.Count -eq 1) { $l.Add('Details: ' + $dl[0]) } elseif ($dl.Count) { $l.Add('Details:'); foreach ($x in $dl) { $l.Add('  ' + $x) } }
    }
    $l.Add('When: ' + $Model.when)
    $l.Add('Support: ' + $Model.support)
    return ($l.ToArray() -join "`r`n")
}

function Add-PimAlertMailTokens {
    <#
      PURE. The caller's tokens plus what the alert template renders: AlertTable (the whole table) and, for a template a
      customer wrote themselves, each value on its own (AlertCustomer, AlertEnvironment, AlertSolution, AlertWho,
      AlertStatus, AlertProblem, AlertTodo, AlertFindingRows, AlertWhen, AlertSupport -- HTML-encoded). AlertTitle is
      the title as a person reads it (no "--"). Returns @{ tokens; model }. The caller's hashtable is not changed.
    #>
    param([hashtable]$Tokens = @{}, [hashtable]$Environment = @{}, [datetime]$NowUtc = [datetime]::UtcNow)
    $m = Get-PimAlertMailModel -Tokens $Tokens -Environment $Environment -NowUtc $NowUtc
    $t = @{}; if ($Tokens) { foreach ($k in @($Tokens.Keys)) { $t[$k] = $Tokens[$k] } }
    [void]$t.Remove('AlertFindings')
    $t['AlertTitle']       = $m.title
    $t['AlertTable']       = New-PimAlertMailTable -Model $m
    $t['AlertCustomer']    = ConvertTo-PimMailText $m.customer
    $t['AlertEnvironment'] = ConvertTo-PimMailText $m.environment
    $t['AlertSolution']    = ConvertTo-PimMailText $m.solution
    $t['AlertWho']         = ConvertTo-PimMailText $m.who
    $t['AlertStatus']      = ConvertTo-PimMailText $m.status
    $t['AlertProblem']     = ConvertTo-PimMailText $m.problem
    $t['AlertTodo']        = ConvertTo-PimMailText $m.todo
    $t['AlertFindingRows'] = ConvertTo-PimAlertFindingRows -Findings $m.findings
    $t['AlertWhen']        = ConvertTo-PimMailText $m.when
    $t['AlertSupport']     = ConvertTo-PimMailText $m.support
    return @{ tokens = $t; model = $m }
}

function Get-PimAlertMailArgs {
    <#
      The four alert words (and the findings) as a SPLAT for one of the alert senders (Send-PimJobAlertViaNotify,
      Send-PimManagerAlert, Send-PimSafetyAlert) -- only the parameters THAT sender declares, so a sender that does not
      know them yet (an older one, a test double) is called exactly as before. Empty values are left out.
    #>
    param([Parameter(Mandatory)][string]$Command, [string]$Who = '', [string]$Status = '', [string]$Problem = '', [string]$Todo = '', [AllowNull()][object[]]$Findings = $null)
    $out = @{}
    $cmd = Get-Command -Name $Command -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd -or -not $cmd.Parameters) { return $out }
    $want = [ordered]@{ Who = $Who; Status = $Status; Problem = $Problem; Todo = $Todo }
    foreach ($k in @($want.Keys)) { if ("$($want[$k])".Trim() -and $cmd.Parameters.ContainsKey($k)) { $out[$k] = "$($want[$k])" } }
    if ($null -ne $Findings -and @($Findings).Count -and $cmd.Parameters.ContainsKey('Findings')) { $out['Findings'] = @($Findings) }
    return $out
}

function ConvertTo-PimMailLayoutFrame {
    <#
      PURE. §100.5 MAIL-2 leftover (b), 2.4.555: an ALERT or TRANSACTIONAL mail (a template that is not itself built with
      New-PimMailDocument) is put in the ONE designed layout -- logo header with the environment, the subject as the heading,
      the template's own body content unchanged, the blue button and the designed footer (environment / tenant / version,
      Open PIM Manager, Change what you receive). A customer-EDITED template keeps every word: only its <html>/<body>
      wrapper is replaced by the frame. Returns the new body HTML, or the input unchanged when:
        * the body is already a designed mail (class="pim-mail"),
        * the template opts out with <!-- pim-no-layout --> (e.g. a mail that must stay plain).
      -Subject: the rendered subject; leading [..] tags ("[PIM Alert]", the environment) are dropped for the heading.
    #>
    param([AllowEmptyString()][string]$BodyHtml, [string]$Subject = '', [hashtable]$Button = $null, [string]$HomeUrl = '', [string]$NotificationsUrl = '',
          [hashtable]$Environment = @{},
          # PIM 100.105: the footer's home link shows its words only ("Open PIM Manager"), not the raw hosting address
          [switch]$HomeLinkAsWords)
    $h = "$BodyHtml"
    if ($h -match 'class="pim-mail"' -or $h -match '<!--\s*pim-no-layout\s*-->') { return $h }
    $inner = $h
    $m = [regex]::Match($h, '(?is)<body\b[^>]*>(.*)</body>')
    if ($m.Success) { $inner = $m.Groups[1].Value }
    else { $inner = [regex]::Replace($inner, '(?is)</?html\b[^>]*>', '') }
    $inner = [regex]::Replace($inner, '(?s)<!--.*?-->', '').Trim()   # template comments (subject / tokens) are not content
    $title = ("$Subject" -replace '^\s*(\[[^\]]*\]\s*)+', '').Trim()
    if (-not $title) { $title = 'PIM Manager' }
    # the button goes AFTER the content (an alert reads first, then "Open ..."); none when the content already links there
    $btn = ''
    if ($Button -and "$($Button.url)".Trim() -and $inner -notmatch [regex]::Escape(("$($Button.url)" -split '\?')[0])) {
        $btn = New-PimMailButton -Url "$($Button.url)" -Label $(if ("$($Button.label)".Trim()) { "$($Button.label)" } else { 'Open in PIM Manager' })
    }
    $b = Get-PimMailBrand
    return (New-PimMailDocument -Title $title -Preheader $title -BodyHtml ('<div class="pim-mail-content" style="margin:14px 0 0 0;font-family:' + $b.font + ';font-size:14px;line-height:1.5;color:' + $b.text + ';">' + $inner + '</div>' + $btn) `
                -HomeUrl $HomeUrl -NotificationsUrl $NotificationsUrl -Environment $Environment -HomeLinkAsWords:$HomeLinkAsWords)
}

function New-PimMailDocument {
    <#
      The whole designed mail (or, with -Print, the print-ready report document). Returns HTML.
        -Title / -Subtitle      the heading and the window / scope line under it
        -Preheader              the hidden first line most clients show in the inbox list
        -SummaryHtml            tiles + headline (New-PimMailSummaryTiles / New-PimMailCallout)
        -Button                 @{ url; label } -- the ONE blue audience button (MAIL-2 item 1)
        -BodyHtml               the sections
        -HomeUrl                the Manager home (MAIL-2 item 4: a PLAIN link, in addition to the button)
        -NotificationsUrl       where the recipient changes what they get (Settings > Mail & alerting > Notifications)
        -Environment            @{ name; tenantName; tenantId; version }
        -AudienceLabel          'SOC analyst' / 'Posture' / 'Manager' -- said in the footer ("you get this as ...")
        -GeneratedUtc           the report time (printed reports carry it on every page)
      A mail is a fragment for the template's <body> (the template carries {{ReportHtml}}); -Print is a full document.
    #>
    param(
        [Parameter(Mandatory)][string]$Title, [string]$Subtitle = '', [string]$Preheader = '',
        [string]$SummaryHtml = '', [hashtable]$Button = $null, [string]$BodyHtml = '',
        [string]$HomeUrl = '', [string]$NotificationsUrl = '', [hashtable]$Environment = @{}, [string]$AudienceLabel = '',
        [datetime]$GeneratedUtc = [datetime]::UtcNow, [switch]$Print,
        # PIM 100.105 (the alert mail): the home link in the footer is the words "Open PIM Manager", not the raw address
        [switch]$HomeLinkAsWords
    )
    $b = Get-PimMailBrand
    $env = if ($Environment) { $Environment } else { @{} }
    $envName = "$($env.name)".Trim(); $tn = "$($env.tenantName)".Trim(); $tid = "$($env.tenantId)".Trim(); $ver = "$($env.version)".Trim()
    $gen = $GeneratedUtc.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $btn = if ($Button -and "$($Button.url)".Trim()) { New-PimMailButton -Url "$($Button.url)" -Label $(if ("$($Button.label)".Trim()) { "$($Button.label)" } else { 'Open in PIM Manager' }) } else { '' }
    $logo = if ($Print) { $svg = Get-PimMailLogoSvg; if ($svg) { '<span class="pim-mail-logo" style="display:inline-block;width:200px;">' + $svg + '</span>' } else { Get-PimMailWordmarkHtml } }
            else { '<!--pim-logo--><img src="cid:pim-logo" width="180" height="46" alt="Invardia PIM Manager" style="display:block;border:0;outline:none;width:180px;height:auto;"><!--/pim-logo-->' }
    $envCell = if ($envName) { '<div style="font-family:' + $b.font + ';font-size:9.5px;letter-spacing:.6px;text-transform:uppercase;color:' + $b.muted + ';">Environment</div><div style="font-family:' + $b.font + ';font-size:13px;font-weight:600;color:' + $b.heading + ';">' + (ConvertTo-PimMailText $envName) + '</div>' } else { '' }

    $foot = New-Object System.Collections.Generic.List[string]
    $envBits = New-Object System.Collections.Generic.List[string]
    if ($envName) { $envBits.Add('Environment: <b>' + (ConvertTo-PimMailText $envName) + '</b>') }
    if ($tn -or $tid) { $envBits.Add('tenant ' + (ConvertTo-PimMailText $tn) + $(if ($tid) { ' (' + (ConvertTo-PimMailText $tid) + ')' } else { '' })) }
    if ($ver) { $envBits.Add('PIM Manager ' + (ConvertTo-PimMailText $ver)) }
    if ($envBits.Count) { $foot.Add($envBits.ToArray() -join ' &middot; ') }
    if (Test-PimMailLinkUrl -Url $HomeUrl) {
        if ($HomeLinkAsWords) { $foot.Add('<a href="' + (ConvertTo-PimMailText $HomeUrl.Trim()) + '" style="color:' + $b.accent + ';">Open PIM Manager</a>') }
        else { $foot.Add('Open PIM Manager: <a href="' + (ConvertTo-PimMailText $HomeUrl.Trim()) + '" style="color:' + $b.accent + ';">' + (ConvertTo-PimMailText $HomeUrl.Trim()) + '</a>') }
    }
    $why = if ("$AudienceLabel".Trim()) { 'You get this report as <b>' + (ConvertTo-PimMailText $AudienceLabel) + '</b>.' } else { '' }
    if (Test-PimMailLinkUrl -Url $NotificationsUrl) { $why = ($why + ' <a href="' + (ConvertTo-PimMailText $NotificationsUrl.Trim()) + '" style="color:' + $b.accent + ';">Change what you receive</a>.').Trim() }
    if ($why) { $foot.Add($why) }
    if ($Print) { $foot.Add('Generated ' + (ConvertTo-PimMailText $gen) + '.') }
    $footer = '<div class="pim-env-footer" style="margin:26px 0 0 0;padding-top:10px;border-top:1px solid ' + $b.border + ';font-family:' + $b.font + ';font-size:12px;line-height:18px;color:' + $b.muted + ';">' + ($foot.ToArray() -join '<br>') + '</div>'

    $inner = '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;"><tr>' +
             '<td valign="middle" style="padding:0 0 10px 0;">' + $logo + '</td>' +
             '<td valign="middle" align="right" style="padding:0 0 10px 0;text-align:right;">' + $envCell + '</td></tr>' +
             '<tr><td colspan="2" style="height:3px;line-height:3px;font-size:1px;background:' + $b.blue + ';">&nbsp;</td></tr></table>' +
             '<h1 style="margin:18px 0 2px 0;font-family:' + $b.font + ';font-size:22px;font-weight:700;color:' + $b.heading + ';">' + (ConvertTo-PimMailText $Title) + '</h1>' +
             $(if ("$Subtitle".Trim()) { '<div style="font-family:' + $b.font + ';font-size:13px;color:' + $b.muted + ';">' + (ConvertTo-PimMailText $Subtitle) + '</div>' } else { '' }) +
             $SummaryHtml + $btn + $BodyHtml + $footer

    if (-not $Print) {
        $pre = if ("$Preheader".Trim()) { '<div class="pim-mail-preheader" style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:1px;line-height:1px;color:' + $b.surfaceAlt + ';">' + (ConvertTo-PimMailText $Preheader) + '</div>' } else { '' }
        return ($pre + '<table role="presentation" class="pim-mail" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="' + $b.surfaceAlt + '" style="background:' + $b.surfaceAlt + ';border-collapse:collapse;"><tr><td align="center" style="padding:20px 10px;">' +
                '<table role="presentation" width="640" cellspacing="0" cellpadding="0" border="0" bgcolor="' + $b.surface + '" style="width:100%;max-width:640px;background:' + $b.surface + ';border:1px solid ' + $b.border + ';border-radius:8px;border-collapse:separate;"><tr><td style="padding:22px 26px 20px 26px;font-family:' + $b.font + ';color:' + $b.text + ';">' +
                $inner + '</td></tr></table></td></tr></table>')
    }
    # The print-ready document: @page puts the tenant + environment, the date and "Page x of y" on EVERY page (MAIL-2 item 7).
    $left = ConvertTo-PimMailCssString ((@($tn, $envName) | Where-Object { "$_".Trim() }) -join ' - ')
    $right = ConvertTo-PimMailCssString ('Generated ' + $gen)
    $css = '@page{size:A4;margin:16mm 14mm 18mm 14mm;@bottom-left{content:"' + $left + '";font-size:9pt;color:#57606a;}' +
           '@bottom-right{content:"Page " counter(page) " of " counter(pages);font-size:9pt;color:#57606a;}@top-right{content:"' + $right + '";font-size:9pt;color:#57606a;}}' +
           'html,body{margin:0;padding:0;background:#ffffff;color:' + $b.text + ';font-family:' + $b.font + ';-webkit-print-color-adjust:exact;print-color-adjust:exact;}' +
           '.pim-report{max-width:900px;margin:0 auto;padding:18px;}.pim-mail-table{page-break-inside:auto;}.pim-mail-table tr{page-break-inside:avoid;}' +
           '.pim-mail-section h2{page-break-after:avoid;}.pim-mail-button{display:none;}.pim-mail-logo svg{width:200px;height:auto;}' +
           '@media screen{.pim-report-printhint{display:block;margin:0 0 12px;padding:8px 12px;border:1px solid #54aeff;background:#ddf4ff;border-radius:6px;font-size:12.5px;}}' +
           '@media print{.pim-report-printhint{display:none;}}'
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + (ConvertTo-PimMailText $Title) + $(if ($envName) { ' - ' + (ConvertTo-PimMailText $envName) } else { '' }) + '</title><style>' + $css + '</style></head>' +
            '<body><div class="pim-report"><div class="pim-report-printhint">Print this page and choose <b>Save as PDF</b> to keep it as a PDF (page numbers, date and tenant are added on every page).</div>' + $inner + '</div></body></html>')
}
