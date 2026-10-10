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
            '<td align="center" bgcolor="' + $bg + '" style="border-radius:6px;background:' + $bg + ';border:1px solid ' + $b.accentFill + ';">' +
            '<a href="' + $u + '" target="_blank" style="display:inline-block;padding:11px 22px;font-family:' + $b.font + ';font-size:15px;font-weight:600;line-height:20px;color:' + $fg + ';text-decoration:none;border-radius:6px;">' +
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
          [hashtable]$Environment = @{})
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
                -HomeUrl $HomeUrl -NotificationsUrl $NotificationsUrl -Environment $Environment)
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
        [datetime]$GeneratedUtc = [datetime]::UtcNow, [switch]$Print
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
    if (Test-PimMailLinkUrl -Url $HomeUrl) { $foot.Add('Open PIM Manager: <a href="' + (ConvertTo-PimMailText $HomeUrl.Trim()) + '" style="color:' + $b.accent + ';">' + (ConvertTo-PimMailText $HomeUrl.Trim()) + '</a>') }
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
