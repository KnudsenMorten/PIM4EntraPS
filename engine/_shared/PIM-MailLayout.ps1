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
            '<td align="center" bgcolor="' + $bg + '" style="border-radius:6px;background:' + $bg + ';border:1px solid ' + $b.accentFill + ';padding:11px 24px;font-family:' + $b.font + ';">' +
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
# PIM 100.135 -- THE MAIL FORMAT FROM INVARDIA (owner 2026-10-13 on a job-failure mail: "example of mail that must be
# rewritten. ask invardia about format"; Invardia's answer = its DESIGN §14 + framework §12.11 MAIL-2 items 1, 4, 7).
# EVERY PIM Manager mail has ONE structure, in this order:
#   logo -> heading "PIM Manager for <environment> - <topic>" (never the subject again) -> a calm summary panel (1-3
#   sentences: what happened / is anything lost or changed / does anyone need to act; no CRITICAL or FAILED) -> facts
#   (Environment, Product + version, Job, When, Items affected; an empty value is LEFT OUT) -> a per-cause list (plain
#   cause + plain fix, grouped, with counts; unclassified = "Not recognised yet - PIM support looks at it") -> ONE solid
#   blue button to the exact page (+ at most one outlined) -> a small "Details for support" block, the ONLY place for raw
#   lines, URLs, ids and class codes -> footer (site + support) -- and a plain-text part with the same content.
# Subject "<environment name>: <what happened, in plain words>" ("tenant <id>" only when there is no name).
# PURE: a model in, strings out (New-PimEventMail), so every rule is tested offline (tests/Test-PimMailFormat.ps1).
# =====================================================================================================================
function Get-PimMailTimeZoneId {
    <#
      The time zone a mail shows its times in. A mail cannot know its reader's zone, so the ENVIRONMENT's configured zone
      is used when there is one: $global:PIM_MailTimeZone, else the 'TimeZone' setting (pim.Settings, hydrated into
      $global:PIM_NamingConventions), else env PIM_TIMEZONE. '' = none configured -> the mail says UTC (labelled).
    #>
    if ("$($global:PIM_MailTimeZone)".Trim()) { return "$($global:PIM_MailTimeZone)".Trim() }
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains('TimeZone') -and "$($global:PIM_NamingConventions['TimeZone'])".Trim()) {
        return "$($global:PIM_NamingConventions['TimeZone'])".Trim()
    }
    if ("$($env:PIM_TIMEZONE)".Trim()) { return "$($env:PIM_TIMEZONE)".Trim() }
    return ''
}

function Format-PimMailWhen {
    <#
      PURE. A time for a mail, to the minute: in -TimeZoneId when this runtime knows that zone ("2026-10-13 22:31
      Europe/Copenhagen"), else UTC, said as UTC ("2026-10-13 20:31 UTC"). -Value: a [datetime] (UTC) or text such as
      "2026-10-13 20:31:07 UTC" / ISO. '' when it is neither.
    #>
    param([AllowNull()][object]$Value, [string]$TimeZoneId = '')
    $utc = $null
    if ($Value -is [datetime]) { $utc = ([datetime]$Value).ToUniversalTime() }
    else {
        $m = [regex]::Match("$Value", '(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})')
        if ($m.Success) {
            try { $utc = [datetime]::SpecifyKind([datetime]::ParseExact(($m.Groups[1].Value + ' ' + $m.Groups[2].Value), 'yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture), [System.DateTimeKind]::Utc) } catch { $utc = $null }
        }
    }
    if ($null -eq $utc) { return '' }
    $tz = "$TimeZoneId".Trim()
    if ($tz -and $tz -notmatch '^(?i)(utc|etc/utc|gmt|z)$') {
        try {
            $zi = [System.TimeZoneInfo]::FindSystemTimeZoneById($tz)
            return ([System.TimeZoneInfo]::ConvertTimeFromUtc($utc, $zi).ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' ' + $tz)
        } catch { }
    }
    return ($utc.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC')
}

function Get-PimMailSeverityWord {
    <#
      PURE. Framework §12.11a MAIL-3 (CR6): the ONE severity word a subject may carry -- 'Failed', 'Warning' or 'Action
      needed' -- from any spelling a sender uses (failure / error / critical, warning / rolledback, action / guard /
      held back). '' for anything else, and for 'none' / 'info' (a normal report or information mail has no word).
    #>
    param([AllowNull()][string]$Value)
    switch -Regex ("$Value".Trim()) {
        '^(?i)(failed|failure|error|critical)$'                          { return 'Failed' }
        '^(?i)(warning|rolledback|rolled back)$'                         { return 'Warning' }
        '^(?i)(action needed|action|guard|held back|needs customer.s action)$' { return 'Action needed' }
    }
    return ''
}

function Get-PimMailSubjectLine {
    <#
      PURE. Framework §12.11a MAIL-3 (CR6, owner + Thomas approved 2026-10-14), the ONE subject format of every PIM mail:
        [<Environment>] <severity word: >what happened [<ticket>] [PIM Manager]
      * <Environment> = the name the Manager header shows; "tenant <id>" only when there is no name; none when neither.
      * the severity word only when relevant (Get-PimMailSeverityWord: Failed / Warning / Action needed).
      * [<ticket>] only when there is one.
      * at most -MaxLength (120) characters: ONLY "what happened" is shortened (with "..."); brackets, severity word and
        ticket are always kept.
      Idempotent: a subject already in this format (the chokepoint formats a second time), or in the old
      "<environment>: <what>" format (a template a customer stored), is taken apart and rebuilt, never prefixed twice; its
      severity word and ticket are kept when the caller gives none. Leading [..] tags ("[PIM Alert]"), "--" and the old
      product name are removed; no full stop at the end of "what happened".
    #>
    param([string]$EnvironmentName = '', [string]$TenantId = '', [AllowEmptyString()][string]$What = '',
          [string]$Severity = '', [string]$Ticket = '', [int]$MaxLength = 120)
    $w = ("$What" -replace '\s+', ' ').Trim()
    # take an already formatted subject apart: the product tag, the ticket, the environment tag, the severity word
    $w = [regex]::Replace($w, '(\s*\[(?i:PIM Manager|PIM4EntraPS)\])+$', '')
    $tk = "$Ticket".Trim()
    $tm = [regex]::Match($w, '\s*\[([A-Za-z]{2,12}-\d+)\]$')
    if ($tm.Success) { if (-not $tk) { $tk = $tm.Groups[1].Value }; $w = $w.Substring(0, $tm.Index) }
    $w = [regex]::Replace($w, '^(\[[^\]]*\]\s*)+', '')
    $n = ("$EnvironmentName" -replace '\s+', ' ').Trim()
    if (-not $n -and "$TenantId".Trim()) { $n = 'tenant ' + "$TenantId".Trim() }
    if ($n -and $w.StartsWith($n + ':', [System.StringComparison]::OrdinalIgnoreCase)) { $w = $w.Substring($n.Length + 1).Trim() }
    $sev = Get-PimMailSeverityWord $Severity
    $sm = [regex]::Match($w, '^(?i)(Failed|Warning|Action needed)\s*:\s*')
    if ($sm.Success) { if (-not $sev) { $sev = Get-PimMailSeverityWord $sm.Groups[1].Value }; $w = $w.Substring($sm.Length) }
    # one full stop at the end goes; an ellipsis ("...", a subject shortened before) stays
    $w = (($w -replace '\s+--\s+', ', ' -replace 'PIM4EntraPS', 'PIM Manager').Trim() -replace '(?<!\.)\.$', '').Trim()
    # "Action needed" already says what an action subject's own tail said
    if ($sev -eq 'Action needed') { $w = [regex]::Replace($w, '\s+-\s+it waits for your decision$', '') }
    if (-not $w) { $w = 'Message from PIM Manager' }
    $pre = ''
    if ($n) { $pre = '[' + $n + '] ' }
    if ($sev) { $pre += $sev + ': ' }
    $post = ''
    if ($tk) { $post = ' [' + $tk + ']' }
    $post += ' [PIM Manager]'
    $room = $MaxLength - $pre.Length - $post.Length
    if ($w.Length -gt $room) {
        # an approval's deadline (" - decide by <when>", PIM 100.135) is kept: the words before it are shortened instead
        $tail = ''
        $dm = [regex]::Match($w, '\s+-\s+decide by .+$')
        if ($dm.Success -and $dm.Length -lt ($room - 10)) { $tail = $dm.Value; $w = $w.Substring(0, $dm.Index) }
        $r2 = $room - $tail.Length
        if ($w.Length -gt $r2) {
            if ($r2 -le 3) { $w = '...' }
            else {
                $cut = $w.Substring(0, $r2 - 3)
                # at a word boundary when one is near -- a cut that already ends a whole word ("... is not") keeps it
                $sp = $cut.LastIndexOf(' ')
                if ($w[$r2 - 3] -ne ' ' -and $sp -gt ($cut.Length / 2)) { $cut = $cut.Substring(0, $sp) }
                $w = $cut.TrimEnd(' ', ',', ';', ':', '-') + '...'
            }
        }
        $w += $tail
    }
    return ($pre + $w + $post)
}

function Get-PimMailHeadingLine {
    # PURE. "PIM Manager for <environment> - <topic>" ("PIM Manager - <topic>" when the environment has no name).
    param([string]$EnvironmentName = '', [string]$Topic = '')
    $t = ("$Topic" -replace '\s+', ' ').Trim()
    if (-not $t) { $t = 'Notice' }
    $t = $t.Substring(0, 1).ToUpperInvariant() + $t.Substring(1)
    $n = ("$EnvironmentName" -replace '\s+', ' ').Trim()
    if ($n) { return ('PIM Manager for ' + $n + ' - ' + $t) }
    return ('PIM Manager - ' + $t)
}

function Test-PimMailTenantIdLabel {
    # PURE. Is this environment label only "tenant <id>" (Get-PimMailEnvironmentInfo's last resort)? Such a label may be in
    # the SUBJECT, never in the body (a GUID belongs in Details for support).
    param([AllowNull()][string]$Label)
    return [bool]("$Label".Trim() -match '^(?i)(tenant\s+)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
}

function Split-PimMailBodyText {
    <#
      PURE. A line for the BODY of a mail without what belongs only in "Details for support": web addresses, GUIDs /
      object ids and class codes ([UNCLASSIFIED], [AZ-POLICY-MASS-HOLD]). Returns @{ text; moved } -- moved = the raw values
      taken out, for the details block. Shouting words (FAILED, CRITICAL, ERROR, STUCK) are lower-cased.
    #>
    param([AllowNull()][string]$Text)
    $t = "$Text"
    $moved = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($t, '(?i)\bhttps?://[^\s<>"'']+')) { $v = $m.Value.TrimEnd('.', ',', ';', ')'); if (-not $moved.Contains($v)) { $moved.Add($v) } }
    $t = [regex]::Replace($t, '(?i)\s*\(?\bhttps?://[^\s<>"'']+\)?', '')
    foreach ($m in [regex]::Matches($t, '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')) { if (-not $moved.Contains($m.Value)) { $moved.Add($m.Value) } }
    $t = [regex]::Replace($t, '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '(id in the details)')
    foreach ($m in [regex]::Matches($t, '\[[A-Z][A-Z0-9]{2,}(?:-[A-Z0-9]+)*\]')) { if (-not $moved.Contains($m.Value)) { $moved.Add($m.Value) } }
    $t = [regex]::Replace($t, '\s*\[[A-Z][A-Z0-9]{2,}(?:-[A-Z0-9]+)*\]', '')
    $t = [regex]::Replace($t, '\bUNCLASSIFIED\b', 'not recognised')
    $t = [regex]::Replace($t, '\b(FAILED|CRITICAL|ERROR|STUCK|WARNING|HELD|ESCALATED|EMERGENCY|ALERT)\b', { param($x) $x.Value.ToLowerInvariant() })
    $t = ($t -replace 'PIM4EntraPS', 'PIM Manager' -replace '[ \t]+', ' ').Trim()
    return @{ text = $t; moved = @($moved.ToArray()) }
}

function Get-PimMailFailureGroups {
    <#
      PURE. The "<n>x <title> [<CODE>][: <raw>]" groups of an engine failure line (Format-PimFailureSummary), counts added
      up per code across scopes, in first-seen order: @(@{ code; count; title; raw }). Empty when the text has none.
    #>
    param([AllowNull()][string]$Text)
    $t = ("$Text" -replace '\s+', ' ')
    $ms = @([regex]::Matches($t, '(\d+)x ([^\[\];]{2,200}?) \[([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*)\]'))
    $order = New-Object System.Collections.Generic.List[string]
    $by = @{}
    for ($i = 0; $i -lt $ms.Count; $i++) {
        $m = $ms[$i]
        $start = $m.Index + $m.Length
        $end = if ($i + 1 -lt $ms.Count) { $ms[$i + 1].Index } else { $t.Length }
        $tail = if ($end -gt $start) { $t.Substring($start, $end - $start) } else { '' }
        $raw = ''
        $rm = [regex]::Match($tail, '^\s*:\s*(.*)$')
        if ($rm.Success) { $raw = $rm.Groups[1].Value }
        $raw = [regex]::Replace($raw, '\.?\s*Open Jobs > Engine logs & errors.*$', '')
        $raw = [regex]::Replace($raw, '\s+--\s+auto-fix available.*$', '')
        $raw = [regex]::Replace($raw, '\s*\d+ item\(s\) (failed|WAITING)\b.*$', '')
        $raw = $raw.Trim().TrimEnd(';').Trim()
        $code = $m.Groups[3].Value.ToUpperInvariant()
        $n = 0; [void][int]::TryParse($m.Groups[1].Value, [ref]$n)
        # ['count'], never .count: on a dictionary .Count is the number of its KEYS
        if (-not $by.ContainsKey($code)) { $by[$code] = [ordered]@{ code = $code; count = 0; title = $m.Groups[2].Value.Trim(); raw = '' }; $order.Add($code) }
        $by[$code]['count'] = [int]$by[$code]['count'] + $n
        if (-not $by[$code]['raw'] -and $raw) { $by[$code]['raw'] = $raw }
    }
    return @($order | ForEach-Object { [pscustomobject]$by[$_] })
}

function Resolve-PimMailCause {
    <#
      The PLAIN cause and the PLAIN fix of one failure class, for the mail body: from the failure catalog when it is loaded
      (Get-PimFailureSolution: its short cause and its first step). An UNCLASSIFIED group whose raw text a catalog rule now
      explains is classified again. Unclassified = "Not recognised yet - PIM support looks at it" (no fix to do).
      Returns @{ code; cause; fix; customer } -- never a class code, never a raw line (the caller keeps those for Details).
    #>
    param([string]$Code, [string]$Title = '', [string]$Raw = '')
    $c = "$Code".Trim().ToUpperInvariant()
    if (($c -eq 'UNCLASSIFIED' -or -not $c) -and "$Raw".Trim() -and (Get-Command Get-PimFailureClassification -ErrorAction SilentlyContinue)) {
        try { $k = Get-PimFailureClassification -Message "$Raw" -Row $null; if ($k -and "$($k.code)".Trim() -and "$($k.code)" -ne 'UNCLASSIFIED') { $c = "$($k.code)".ToUpperInvariant(); $Title = "$($k.title)" } } catch { }
    }
    if ($c -eq 'UNCLASSIFIED' -or -not $c) {
        return [pscustomobject]@{ code = 'UNCLASSIFIED'; cause = 'Not recognised yet - PIM support looks at it'; fix = ''; customer = $false }
    }
    $sol = $null
    if (Get-Command Get-PimFailureSolution -ErrorAction SilentlyContinue) { try { $sol = Get-PimFailureSolution -Code $c } catch { $sol = $null } }
    $fk = ''
    if (Get-Command Get-PimFailureFixKind -ErrorAction SilentlyContinue) { try { $fk = "$(Get-PimFailureFixKind -Code $c)" } catch { $fk = '' } }
    $cause = ''; $fix = ''
    if ($sol -and "$($sol.short)".Trim()) {
        $cause = "$($sol.short)".Trim()
        $fix = "$(@($sol.steps)[0])".Trim()
    } else {
        $cause = ("$Title" -replace '\s+', ' ').Trim()
        if (-not $cause) { $cause = 'A problem PIM Manager knows' }
        $fix = switch ($c) {
            'THROTTLED'     { 'Nothing to do: Microsoft slowed PIM Manager down, and it tries again on its next run.'; break }
            'SERVICE-ERROR' { 'Nothing to do now: it is tried again on the next run. If it keeps coming back, PIM support looks at it.'; break }
            default         { 'Open Jobs > Engine logs & errors in PIM Manager: the item shows its cause and how to fix it.' }
        }
    }
    $cause = $cause.Substring(0, 1).ToUpperInvariant() + $cause.Substring(1)
    return [pscustomobject]@{ code = $c; cause = $cause.TrimEnd('.'); fix = $fix; customer = ($fk -eq 'customer-config') }
}

function New-PimEventMail {
    <#
      PURE. THE builder of a PIM Manager mail in Invardia's format (see the block above). -Model (hashtable):
        environment   the environment's name (Get-PimMailEnvironmentInfo .name; "tenant <id>" is used in the subject only)
        tenantId      the tenant id (subject fallback, and a line in Details for support)
        version       the product version
        subjectWhat   what happened, in plain words (the subject's middle part, Get-PimMailSubjectLine)
        severity      MAIL-3 severity word source ('failure' / 'warning' / 'action' / '' -- Get-PimMailSeverityWord)
        ticket        a ticket number, when there is one ('' = none)
        topic         the heading's last part ("Job delta-workloads", "Safety check", "Approval needed")
        opener        "For your information:" / "Please take a look:" (guard and action mails), '' for none
        summary       1-3 calm sentences
        qa            @(@{ q; a }) -- the guard's "Should you be worried? / Was anything changed? / Do you need to do anything?"
        facts         @(@{ label; value }) -- an empty value is left out
        contentHtml   ready HTML placed after the facts (a template's own content; the caller made it safe)
        sections      @(@{ title; lines = @() }) -- plain lines (e.g. the policies a hold names)
        causesTitle   the heading of the cause list
        causes        @(@{ title; count; fix; names = @() }) -- grouped, one entry per cause
        button        @{ url; label } -- the ONE solid blue button;  secondary @{ url; label } -- at most one outlined
        details       @('raw line', ...) -- Details for support (raw lines, URLs, ids, class codes)
        homeUrl / notificationsUrl   the footer links
      Returns @{ subject; heading; html; text }. Every body string is passed through Split-PimMailBodyText, so a URL, a
      GUID or a class code that slips into a body line moves to Details for support instead of showing in the body.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Model)
    $b = Get-PimMailBrand
    $g = { param($k) if ($Model.Contains($k)) { $Model[$k] } else { $null } }
    $moved = New-Object System.Collections.Generic.List[string]
    $clean = { param($s) $x = Split-PimMailBodyText "$s"; foreach ($v in @($x.moved)) { if ($v -and -not $moved.Contains($v)) { $moved.Add($v) } }; "$($x.text)" }
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
    $envName = ("$(& $g 'environment')" -replace '\s+', ' ').Trim()
    $bodyEnv = if (Test-PimMailTenantIdLabel $envName) { '' } else { $envName }
    $tid = "$(& $g 'tenantId')".Trim()
    $ver = "$(& $g 'version')".Trim()
    $what = & $clean (& $g 'subjectWhat')
    $subject = Get-PimMailSubjectLine -EnvironmentName $envName -TenantId $tid -What $what -Severity "$(& $g 'severity')" -Ticket "$(& $g 'ticket')"
    $heading = Get-PimMailHeadingLine -EnvironmentName $bodyEnv -Topic (& $clean (& $g 'topic'))
    # the heading never repeats the subject
    # "what happened" of the MAIL-3 subject: without [env], the severity word, [ticket] and [PIM Manager]
    $subjWhat = ($subject -replace '(\s*\[[^\]]*\])+$', '')
    if ($envName) { $subjWhat = $subjWhat -replace ('^\[' + [regex]::Escape($envName) + '\]\s*'), '' }
    $subjWhat = $subjWhat -replace '^(Failed|Warning|Action needed):\s*', ''
    if ($subjWhat -and $heading.EndsWith(' - ' + $subjWhat.Substring(0, 1).ToUpperInvariant() + $subjWhat.Substring(1))) { $heading = Get-PimMailHeadingLine -EnvironmentName $bodyEnv -Topic 'Notice' }
    $opener = & $clean (& $g 'opener')
    $summary = & $clean (& $g 'summary')
    $qa = @(@(& $g 'qa') | Where-Object { $_ -and "$($_.q)".Trim() -and "$($_.a)".Trim() } | ForEach-Object { [pscustomobject]@{ q = (& $clean $_.q); a = (& $clean $_.a) } })
    $facts = @(@(& $g 'facts') | Where-Object { $_ -and "$($_.label)".Trim() -and "$($_.value)".Trim() } | ForEach-Object { [pscustomobject]@{ label = "$($_.label)".Trim(); value = (& $clean $_.value) } } | Where-Object { $_.value })
    $sections = @(@(& $g 'sections') | Where-Object { $_ -and "$($_.title)".Trim() -and @($_.lines | Where-Object { "$_".Trim() }).Count } | ForEach-Object {
        [pscustomobject]@{ title = (& $clean $_.title); lines = @(@($_.lines) | Where-Object { "$_".Trim() } | ForEach-Object { & $clean $_ } | Where-Object { $_ }) } })
    $causes = @(@(& $g 'causes') | Where-Object { $_ -and "$($_.title)".Trim() } | ForEach-Object {
        # a hashtable's .count is the number of its KEYS -- read the 'count' key of a dictionary by index
        $cnt = 0; try { $cnt = if ($_ -is [System.Collections.IDictionary]) { [int]$_['count'] } else { [int]$_.count } } catch { $cnt = 0 }
        [pscustomobject]@{ title = (& $clean $_.title); count = $cnt; fix = (& $clean $_.fix); names = @(@($_.names) | Where-Object { "$_".Trim() } | ForEach-Object { & $clean $_ } | Where-Object { $_ }) } })
    $causesTitle = & $clean (& $g 'causesTitle')
    if (-not $causesTitle) { $causesTitle = 'What happened, by cause' }
    $contentHtml = "$(& $g 'contentHtml')"
    $btnM = & $g 'button'; $secM = & $g 'secondary'
    $btnHtml = ''; $btnText = New-Object System.Collections.Generic.List[string]
    if ($btnM -and (Test-PimMailLinkUrl -Url "$($btnM.url)")) {
        $lbl = if ("$($btnM.label)".Trim()) { "$($btnM.label)".Trim() } else { 'Open in PIM Manager' }
        $btnHtml += New-PimMailButton -Url "$($btnM.url)" -Label $lbl
        $btnText.Add($lbl + ': ' + "$($btnM.url)".Trim())
        if ($secM -and (Test-PimMailLinkUrl -Url "$($secM.url)")) {
            $sl = if ("$($secM.label)".Trim()) { "$($secM.label)".Trim() } else { 'Open PIM Manager' }
            $btnHtml += New-PimMailButton -Url "$($secM.url)" -Label $sl -Tone secondary
            $btnText.Add($sl + ': ' + "$($secM.url)".Trim())
        }
    }
    $homeUrl = "$(& $g 'homeUrl')".Trim(); $notifUrl = "$(& $g 'notificationsUrl')".Trim()
    # Details for support: the caller's raw lines, then what was moved out of the body, then the tenant id
    $details = New-Object System.Collections.Generic.List[string]
    foreach ($d in @(& $g 'details')) { $x = ("$d" -replace '\s+', ' ').Trim(); if ($x -and -not $details.Contains($x)) { $details.Add($x) } }
    foreach ($v in $moved) { $hit = $false; foreach ($d in $details) { if ($d.Contains($v)) { $hit = $true; break } }; if (-not $hit) { $details.Add($v) } }
    if ($tid -and -not @($details | Where-Object { $_.Contains($tid) }).Count) { $details.Add('Tenant id: ' + $tid) }

    # ---------------- HTML ----------------
    $f = $b.font
    $logo = '<!--pim-logo--><img src="cid:pim-logo" width="180" height="46" alt="Invardia PIM Manager" style="display:block;border:0;outline:none;width:180px;height:auto;"><!--/pim-logo-->'
    $envCell = if ($bodyEnv) { '<div style="font-family:' + $f + ';font-size:9.5px;letter-spacing:.6px;text-transform:uppercase;color:' + $b.muted + ';">Environment</div><div style="font-family:' + $f + ';font-size:13px;font-weight:600;color:' + $b.heading + ';">' + (& $enc $bodyEnv) + '</div>' } else { '' }
    $h = New-Object System.Collections.Generic.List[string]
    $h.Add('<table role="presentation" class="pim-mail-header" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;"><tr>' +
           '<td valign="middle" style="padding:0 0 10px 0;font-family:' + $f + ';">' + $logo + '</td>' +
           '<td valign="middle" align="right" style="padding:0 0 10px 0;text-align:right;font-family:' + $f + ';">' + $envCell + '</td></tr>' +
           '<tr><td colspan="2" style="height:3px;line-height:3px;font-size:1px;font-family:' + $f + ';background:' + $b.blue + ';">&nbsp;</td></tr></table>')
    $h.Add('<h1 class="pim-mail-heading" style="margin:18px 0 10px 0;font-family:' + $f + ';font-size:20px;line-height:26px;font-weight:700;color:' + $b.heading + ';">' + (& $enc $heading) + '</h1>')
    if ($summary -or $opener -or $qa.Count) {
        $p = New-Object System.Collections.Generic.List[string]
        $lead = (@($(if ($opener) { '<b>' + (& $enc $opener) + '</b>' }), $(if ($summary) { & $enc $summary })) | Where-Object { $_ }) -join ' '
        if ($lead) { $p.Add('<div style="margin:0;">' + $lead + '</div>') }
        if ($qa.Count) {
            $rows = foreach ($x in $qa) { '<tr><td valign="top" style="font-family:' + $f + ';font-size:14px;line-height:20px;color:' + $b.text + ';padding:6px 0 0 0;"><b>' + (& $enc $x.q) + '</b> ' + (& $enc $x.a) + '</td></tr>' }
            $p.Add('<table role="presentation" class="pim-mail-qa" cellspacing="0" cellpadding="0" border="0" width="100%" style="border-collapse:collapse;margin:4px 0 0 0;">' + (@($rows) -join '') + '</table>')
        }
        $h.Add('<div class="pim-mail-summary" style="margin:0 0 16px 0;padding:12px 16px;background:' + $b.surfaceAlt + ';border:1px solid ' + $b.border + ';border-left:4px solid ' + $b.blue + ';border-radius:6px;font-family:' + $f + ';font-size:14px;line-height:21px;color:' + $b.text + ';">' + ($p.ToArray() -join '') + '</div>')
    }
    if ($facts.Count) {
        $rows = foreach ($x in $facts) {
            '<tr class="pim-mail-fact"><td valign="top" style="font-family:' + $f + ';font-size:13px;line-height:20px;color:' + $b.muted + ';padding:5px 18px 5px 0;white-space:nowrap;border-bottom:1px solid ' + $b.grid + ';">' + (& $enc $x.label) + '</td>' +
            '<td valign="top" style="font-family:' + $f + ';font-size:14px;line-height:20px;color:' + $b.text + ';padding:5px 0;border-bottom:1px solid ' + $b.grid + ';">' + (& $enc $x.value) + '</td></tr>'
        }
        $h.Add('<table role="presentation" class="pim-mail-facts" cellspacing="0" cellpadding="0" border="0" width="100%" style="border-collapse:collapse;margin:0 0 14px 0;">' + (@($rows) -join '') + '</table>')
    }
    if ("$contentHtml".Trim()) { $h.Add('<div class="pim-mail-content" style="margin:6px 0 0 0;font-family:' + $f + ';font-size:14px;line-height:1.5;color:' + $b.text + ';">' + $contentHtml + '</div>') }
    foreach ($s in $sections) {
        $lines = foreach ($l in $s.lines) { '<div style="padding:2px 0;">' + (& $enc $l) + '</div>' }
        $h.Add('<div class="pim-mail-section" style="margin:16px 0 0 0;"><h2 style="margin:0 0 6px 0;font-family:' + $f + ';font-size:15px;font-weight:700;color:' + $b.heading + ';">' + (& $enc $s.title) + '</h2>' +
               '<div style="font-family:' + $f + ';font-size:13.5px;line-height:20px;color:' + $b.text + ';">' + (@($lines) -join '') + '</div></div>')
    }
    if ($causes.Count) {
        $rows = foreach ($c in $causes) {
            $cnt = if ($c.count -gt 0) { ' <span style="color:' + $b.muted + ';font-weight:400;">(' + $c.count + ' item' + $(if ($c.count -ne 1) { 's' } else { '' }) + ')</span>' } else { '' }
            $nm = ''
            if ($c.names.Count) {
                $shown = @($c.names | Select-Object -First 8)
                $nm = '<div style="color:' + $b.muted + ';font-size:12.5px;padding-top:2px;">' + (& $enc ($shown -join ', ')) + $(if ($c.names.Count -gt $shown.Count) { ' and ' + ($c.names.Count - $shown.Count) + ' more' } else { '' }) + '</div>'
            }
            $fx = if ($c.fix) { '<div style="padding-top:2px;">What to do: ' + (& $enc $c.fix) + '</div>' } else { '' }
            '<tr class="pim-mail-cause"><td valign="top" style="font-family:' + $f + ';font-size:14px;line-height:20px;color:' + $b.text + ';padding:8px 0;border-bottom:1px solid ' + $b.grid + ';">' +
            '<div><b>' + (& $enc $c.title) + '</b>' + $cnt + '</div>' + $fx + $nm + '</td></tr>'
        }
        $h.Add('<div class="pim-mail-causes" style="margin:16px 0 0 0;"><h2 style="margin:0 0 4px 0;font-family:' + $f + ';font-size:15px;font-weight:700;color:' + $b.heading + ';">' + (& $enc $causesTitle) + '</h2>' +
               '<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="border-collapse:collapse;">' + (@($rows) -join '') + '</table></div>')
    }
    if ($btnHtml) { $h.Add('<div class="pim-mail-buttons" style="margin:8px 0 0 0;">' + $btnHtml + '</div>') }
    if ($details.Count) {
        $dl = foreach ($d in $details) { '<div style="padding:1px 0;word-break:break-all;">' + (& $enc $d) + '</div>' }
        $h.Add('<div class="pim-mail-details" style="margin:22px 0 0 0;padding:8px 12px;background:' + $b.surfaceAlt + ';border:1px solid ' + $b.grid + ';border-radius:6px;font-family:Consolas,Menlo,monospace;font-size:11px;line-height:16px;color:' + $b.muted + ';">' +
               '<div style="font-family:' + $f + ';font-size:11.5px;font-weight:600;margin-bottom:3px;">Details for support</div>' + (@($dl) -join '') + '</div>')
    }
    $foot = New-Object System.Collections.Generic.List[string]
    $prod = ('PIM Manager ' + $ver).Trim()
    $foot.Add((& $enc $prod) + $(if ($bodyEnv) { ' for <b>' + (& $enc $bodyEnv) + '</b>' } else { '' }))
    if (Test-PimMailLinkUrl -Url $homeUrl) { $foot.Add('<a href="' + (& $enc $homeUrl) + '" style="color:' + $b.accent + ';">Open PIM Manager</a>') }
    $foot.Add('Support: <a href="mailto:' + (Get-PimAlertSupportMail) + '" style="color:' + $b.accent + ';">' + (Get-PimAlertSupportMail) + '</a> &middot; <a href="' + (Get-PimAlertSupportPortal) + '" style="color:' + $b.accent + ';">customer portal</a>')
    if (Test-PimMailLinkUrl -Url $notifUrl) { $foot.Add('<a href="' + (& $enc $notifUrl) + '" style="color:' + $b.accent + ';">Change what you receive</a>') }
    $h.Add('<div class="pim-env-footer" style="margin:22px 0 0 0;padding-top:10px;border-top:1px solid ' + $b.border + ';font-family:' + $f + ';font-size:12px;line-height:18px;color:' + $b.muted + ';">' + ($foot.ToArray() -join '<br>') + '</div>')
    $pre = '<div class="pim-mail-preheader" style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:1px;line-height:1px;color:' + $b.surfaceAlt + ';">' + (& $enc $(if ($summary) { $summary } else { $heading })) + '</div>'
    $html = $pre + '<table role="presentation" class="pim-mail" width="100%" cellspacing="0" cellpadding="0" border="0" bgcolor="' + $b.surfaceAlt + '" style="background:' + $b.surfaceAlt + ';border-collapse:collapse;"><tr><td align="center" style="padding:20px 10px;font-family:' + $f + ';">' +
            '<table role="presentation" width="640" cellspacing="0" cellpadding="0" border="0" bgcolor="' + $b.surface + '" style="width:100%;max-width:640px;background:' + $b.surface + ';border:1px solid ' + $b.border + ';border-radius:8px;border-collapse:separate;"><tr><td style="padding:22px 26px 20px 26px;font-family:' + $f + ';color:' + $b.text + ';">' +
            ($h.ToArray() -join '') + '</td></tr></table></td></tr></table>'

    # ---------------- plain text: the same content, in the same order ----------------
    $t = New-Object System.Collections.Generic.List[string]
    $t.Add($heading); $t.Add('')
    $lead = (@($opener, $summary) | Where-Object { "$_".Trim() }) -join ' '
    if ($lead) { $t.Add($lead) }
    foreach ($x in $qa) { $t.Add($x.q + ' ' + $x.a) }
    if ($lead -or $qa.Count) { $t.Add('') }
    foreach ($x in $facts) { $t.Add($x.label + ': ' + $x.value) }
    if ($facts.Count) { $t.Add('') }
    if ("$(& $g 'contentText')".Trim()) { $t.Add("$(& $g 'contentText')".Trim()); $t.Add('') }
    foreach ($s in $sections) { $t.Add($s.title + ':'); foreach ($l in $s.lines) { $t.Add('  ' + $l) }; $t.Add('') }
    if ($causes.Count) {
        $t.Add($causesTitle + ':')
        foreach ($c in $causes) {
            $t.Add('- ' + $c.title + $(if ($c.count -gt 0) { ' (' + $c.count + ' item' + $(if ($c.count -ne 1) { 's' } else { '' }) + ')' } else { '' }))
            if ($c.fix) { $t.Add('  What to do: ' + $c.fix) }
            if ($c.names.Count) { $shown = @($c.names | Select-Object -First 8); $t.Add('  ' + ($shown -join ', ') + $(if ($c.names.Count -gt $shown.Count) { ' and ' + ($c.names.Count - $shown.Count) + ' more' } else { '' })) }
        }
        $t.Add('')
    }
    foreach ($x in $btnText) { $t.Add($x) }
    if ($btnText.Count) { $t.Add('') }
    if ($details.Count) { $t.Add('Details for support:'); foreach ($d in $details) { $t.Add('  ' + $d) }; $t.Add('') }
    $t.Add('--')
    $t.Add('Environment: ' + $(if ($bodyEnv) { $bodyEnv } else { '(no name)' }) + ' | ' + $prod)
    if (Test-PimMailLinkUrl -Url $homeUrl) { $t.Add('Open PIM Manager: ' + $homeUrl) }
    $t.Add('Support: ' + (Get-PimAlertSupportMail) + ' - customer portal ' + (Get-PimAlertSupportPortal))
    if (Test-PimMailLinkUrl -Url $notifUrl) { $t.Add('Change what you receive: ' + $notifUrl) }
    return @{ subject = $subject; heading = $heading; html = $html; text = ($t.ToArray() -join "`r`n") }
}

# =====================================================================================================================
# PIM 100.105 -> 100.135 -- THE ALERT MAIL. The callers pass four plain-text tokens (AlertWho, AlertStatus, AlertProblem,
# AlertTodo; owner 2026-10-12) and, when the alert has a list, AlertFindings = @(@{ kind; name }). Since 100.135 they are
# no longer printed as one table: they are the INPUTS of Invardia's format (New-PimEventMail above) -- the status picks
# the kind of mail (Held back = a guard trip, Error = a failure, Needs customer's action = a decision), the problem is
# what happened (subject + summary), what to do answers "Do you need to do anything?". A caller that passes none of them
# still gets a whole mail (Who acts "Not known", Status "Warning", the problem = its title).
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

function ConvertTo-PimAlertPlainLines {
    # HTML (or plain text) -> plain LINES: <br>, </p>, </tr> ... end a line; tags dropped, entities decoded, blank lines out.
    param([AllowNull()][string]$Text)
    $d = "$Text" -replace '(?s)<!--.*?-->', ' '
    $d = $d -replace '(?i)<br\s*/?>', "`n" -replace '(?i)</(p|div|li|tr|h[1-6])>', "`n" -replace '(?i)</t[dh]>', ' '
    $d = [System.Net.WebUtility]::HtmlDecode(($d -replace '</?[A-Za-z][^<>]*>', ''))
    return @($d -split "`r?`n" | ForEach-Object { ($_ -replace '[ \t]+', ' ').Trim() } | Where-Object { $_ -and $_ -notmatch '^-+$' })
}

function Get-PimAlertMailKind {
    <#
      PURE. Which kind of mail an alert is (PIM 100.135): 'guard' (a safety check held something back), 'failure' (a job
      could not do its work), 'action' (someone has to decide / approve), 'info' (anything else). From the status word the
      sender passed (PIM 100.105) and the page it links to.
    #>
    param([string]$Status = '', [string]$Tab = '')
    switch ("$Status") {
        'Held back' { return 'guard' }
        'Error'     { return 'failure' }
        "Needs customer's action" { return 'action' }
    }
    if ("$Tab" -eq 'approvals') { return 'action' }
    return 'info'
}

function Get-PimAlertMailModel {
    <#
      PURE. What ONE alert mail says (PIM 100.135, Invardia's format), from the caller's tokens and what the product knows of
      this environment (-Environment = Get-PimMailEnvironmentInfo: name, tenantName, tenantId, version). The four words of
      100.105 (AlertWho / AlertStatus / AlertProblem / AlertTodo) are its inputs: the status picks the KIND of mail, the
      problem is what happened, what to do answers "Do you need to do anything?". Optional tokens override a part:
      AlertSubjectWhat, AlertTopic, AlertSummary, AlertWorried, AlertChanged, AlertAct, AlertDeadline, AlertJob.
      -PortalUrl: the deep link of the ONE button; -HomeUrl / -NotificationsUrl: the footer; -TimeZoneId: the environment's
      zone (default: Get-PimMailTimeZoneId; none = UTC, labelled).
      Returns the model (the 100.105 keys title; customer; environment; solution; who; status; problem; todo; findings;
      detailHtml; when; support -- plus kind; job; topic; subjectWhat; summary; opener; qa; facts; causes; sections;
      details; mail = @{ subject; heading; html; text }).
    #>
    param([hashtable]$Tokens = @{}, [hashtable]$Environment = @{}, [datetime]$NowUtc = [datetime]::UtcNow,
          [string]$PortalUrl = '', [string]$HomeUrl = '', [string]$NotificationsUrl = '', [AllowNull()][object]$TimeZoneId = $null)
    $tk = if ($Tokens) { $Tokens } else { @{} }
    $ev = if ($Environment) { $Environment } else { @{} }
    $get = { param($n) if ($tk.ContainsKey($n) -and $null -ne $tk[$n]) { "$($tk[$n])" } else { '' } }
    $rawTitle = & $get 'AlertTitle'
    $title = ConvertTo-PimAlertTitleText $rawTitle
    if (-not $title) { $title = 'PIM Manager alert' }
    $customer = "$($ev['tenantName'])".Trim()
    if (-not $customer) { $customer = ConvertTo-PimAlertPlainText (& $get 'TenantName') }
    $envName = "$($ev['name'])".Trim()
    $tid = "$($ev['tenantId'])".Trim()
    $ver = "$($ev['version'])".Trim()
    $solution = ('PIM Manager ' + $ver).Trim()
    $who = Resolve-PimAlertWho (& $get 'AlertWho')
    $status = Resolve-PimAlertStatus (& $get 'AlertStatus')
    $problem = ConvertTo-PimAlertOneLine (& $get 'AlertProblem')
    if (-not $problem) { $problem = ConvertTo-PimAlertOneLine (ConvertTo-PimAlertPlainText $title) }
    $todo = ConvertTo-PimAlertOneLine (& $get 'AlertTodo')
    if (-not $todo) { $todo = ConvertTo-PimAlertOneLine (& $get 'AlertAction') -FromHtml }
    $findings = @(); if ($tk.ContainsKey('AlertFindings')) { $findings = @(ConvertTo-PimAlertFindingList -Findings $tk['AlertFindings']) }
    $detail = (& $get 'AlertDetail') -replace 'PIM4EntraPS', 'PIM Manager'
    $detailPlain = ConvertTo-PimAlertPlainText $detail
    $detailLines = @(ConvertTo-PimAlertPlainLines $detail)
    $tab = (& $get 'AlertTab').Trim()
    $evt = (& $get 'AlertEvent').Trim()
    $kind = Get-PimAlertMailKind -Status $status -Tab $tab
    $job = (& $get 'AlertJob').Trim()
    if (-not $job) { $jm = [regex]::Match("$rawTitle", "(?i)^\s*Job\s+'([^']+)'"); if ($jm.Success) { $job = $jm.Groups[1].Value.Trim() } }
    # -TimeZoneId is [object], never [string]: a [string] parameter turns $null into '' and the environment's zone was never read
    $tz = if ($null -eq $TimeZoneId) { Get-PimMailTimeZoneId } else { "$TimeZoneId" }
    $whenSrc = (& $get 'WhenUtc')
    $when = Format-PimMailWhen -Value $whenSrc -TimeZoneId $tz
    if (-not $when) { $when = Format-PimMailWhen -Value $NowUtc -TimeZoneId $tz }

    # ---- the per-cause list: a failure's classes from its detail; an alert's findings grouped by kind ----
    $causes = New-Object System.Collections.Generic.List[object]
    $groups = @()
    if ($kind -eq 'failure') { $groups = @(Get-PimMailFailureGroups $detailPlain) }
    $byCode = [ordered]@{}
    foreach ($gr in $groups) {
        $rc = Resolve-PimMailCause -Code $gr.code -Title $gr.title -Raw $gr.raw
        if (-not $byCode.Contains($rc.code)) { $byCode[$rc.code] = [pscustomobject]@{ code = $rc.code; title = $rc.cause; fix = $rc.fix; count = 0; names = @(); customer = [bool]$rc.customer; classes = @() } }
        $byCode[$rc.code].count += [int]$gr.count
        $byCode[$rc.code].classes += ('{0} x{1}' -f $gr.code, $gr.count)
    }
    foreach ($k in @($byCode.Keys)) { $causes.Add($byCode[$k]) }
    $items = 0
    foreach ($c in $causes) { $items += [int]$c.count }
    if ($findings.Count) {
        $fk = [ordered]@{}
        foreach ($f in $findings) { if (-not $fk.Contains($f.kind)) { $fk[$f.kind] = New-Object System.Collections.Generic.List[string] }; $fk[$f.kind].Add($f.name) }
        foreach ($k in @($fk.Keys)) { $causes.Add([pscustomobject]@{ code = ''; title = "$k"; fix = ''; count = $fk[$k].Count; names = @($fk[$k].ToArray()); customer = $true; classes = @() }) }
        if (-not $items) { $items = $findings.Count }
    }
    $trigger = ''
    if ($detailPlain -match '\(triggered run\)') { $trigger = 'triggered' } elseif ($detailPlain -match '\(scheduled run\)') { $trigger = 'scheduled' }
    $plural = { param($n) if ([int]$n -eq 1) { '1 item' } else { "$n items" } }

    # ---- subject, topic, summary, the three answers of a guard ----
    $subjWhat = ConvertTo-PimAlertOneLine (& $get 'AlertSubjectWhat')
    if (-not $subjWhat) {
        if ($kind -eq 'failure' -and $job) { $subjWhat = if ($items) { "The job $job could not finish $(& $plural $items)" } else { "The job $job could not finish" } }
        else { $subjWhat = $problem }
    }
    $deadline = ConvertTo-PimAlertOneLine (& $get 'AlertDeadline')
    if ($kind -eq 'action') { $subjWhat = $subjWhat + $(if ($deadline) { ' - decide by ' + $deadline } else { ' - it waits for your decision' }) }
    # MAIL-3 (framework §12.11a): the subject's severity word. A failure = Failed; a held change or a decision = Action
    # needed; any other alert = Warning (drift, gaps, expiring, throttled) -- except a test mail, which is information.
    # AlertSeverity overrides it ('none' = no word).
    $severity = switch ($kind) { 'failure' { 'failure' } 'guard' { 'action' } 'action' { 'action' } default { 'warning' } }
    if ($evt -eq 'mail-test' -or "$rawTitle" -match '(?i)\btest (mail|alert)\b') { $severity = '' }
    $sevTok = (& $get 'AlertSeverity').Trim()
    if ($sevTok) { $severity = if ($sevTok -ieq 'none') { '' } else { $sevTok } }
    $topic = ConvertTo-PimAlertOneLine (& $get 'AlertTopic')
    if (-not $topic) {
        $topic = switch ($kind) {
            'failure' { if ($job) { "Job $job" } else { 'Engine run' }; break }
            'guard'   { 'Safety check'; break }
            'action'  { 'Your decision is needed'; break }
            default {
                switch -Regex ($evt) {
                    '^coverage$'        { 'Discovery and gaps'; break }
                    '^drift$'           { 'Drift'; break }
                    '^mail-test$'       { 'Test mail'; break }
                    '^expiring-access$' { 'Expiring access'; break }
                    '^break-glass$'     { 'Break-glass accounts'; break }
                    default             { if ($job) { "Job $job" } else { 'Notice' } }
                }
            }
        }
    }
    $summary = ConvertTo-PimAlertOneLine (& $get 'AlertSummary') -MaxLength 600
    $opener = ''
    $qa = @()
    if ($kind -eq 'guard') {
        $opener = if ($who -eq 'Customer') { 'Please take a look:' } else { 'For your information:' }
        $worried = ConvertTo-PimAlertOneLine (& $get 'AlertWorried')
        if (-not $worried) { $worried = 'No. A safety check stopped this on purpose, before anything was changed' }
        $changed = ConvertTo-PimAlertOneLine (& $get 'AlertChanged')
        if (-not $changed) { $changed = 'No. Nothing was changed; it waits until someone decides' }
        $act = ConvertTo-PimAlertOneLine (& $get 'AlertAct')
        if (-not $act) {
            $act = if ($who -eq 'PIM Manager team') { 'No. PIM support handles it' }
                   elseif ($todo) { 'Yes: ' + $todo.Substring(0, 1).ToLowerInvariant() + $todo.Substring(1) }
                   else { 'Yes: a SuperAdmin of your tenant decides in PIM Manager' }
        }
        $qa = @(@{ q = 'Should you be worried?'; a = $worried + '.' }, @{ q = 'Was anything changed?'; a = $changed + '.' }, @{ q = 'Do you need to do anything?'; a = $act + '.' })
        if (-not $summary) { $summary = $problem + '.' }
    } elseif ($kind -eq 'action') {
        $opener = 'Please take a look:'
        if (-not $summary) { $summary = $problem + '.' + $(if ($todo) { ' ' + $todo + '.' } else { '' }) + ' Nothing changes until it is decided.' }
    } elseif ($kind -eq 'failure') {
        if (-not $summary) {
            $s = New-Object System.Collections.Generic.List[string]
            $jobWords = if ($job) { $(if ($trigger -eq 'scheduled') { 'The scheduled job ' } else { 'The job ' }) + $job + $(if ($trigger -eq 'triggered') { ' (started by hand)' } else { '' }) } else { 'An engine run' }
            if ($items) {
                $s.Add("$jobWords could not finish $(& $plural $items); the rest of the run was applied.")
                $s.Add('Nothing was changed for ' + $(if ($items -eq 1) { 'that item' } else { 'those items' }) + ', and PIM Manager tries again on its next run.')
            } else {
                $s.Add("$jobWords stopped before it finished.")
                $s.Add('What it did not reach is tried again on its next run.')
            }
            $cust = @($causes | Where-Object { $_.customer }).Count
            $unk = @($causes | Where-Object { $_.code -eq 'UNCLASSIFIED' }).Count
            if ($causes.Count -and $cust -eq $causes.Count) { $s.Add('Someone in your IT needs to fix the cause below.') }
            elseif ($causes.Count -and $unk -eq $causes.Count) { $s.Add('PIM support looks at it; you do not need to do anything yet.') }
            elseif ($causes.Count) { $s.Add('Please look at each cause below.') }
            else { $s.Add('Please take a look at Jobs > Engine logs & errors in PIM Manager.') }
            $summary = $s.ToArray() -join ' '
        }
    } else {
        if (-not $summary) { $summary = $problem + '.' + $(if ($todo) { ' ' + $todo + '.' } else { '' }) }
    }

    # ---- facts (an empty value is left out by the builder) ----
    $envFact = if (Test-PimMailTenantIdLabel $envName) { '' } else { $envName }
    $facts = @(
        @{ label = 'Environment'; value = $envFact }
        @{ label = 'Product'; value = $solution }
        @{ label = 'Job'; value = $job }
        @{ label = 'When'; value = $when }
        @{ label = 'Items affected'; value = $(if ($items) { "$items" } else { '' }) }
    )
    # ---- an extra section: what a guard held / what an alert found, when the caller gave no findings ----
    $sections = @()
    $problemPlain = $problem.TrimEnd('.')
    $detailAdds = ($detailPlain -and $detailPlain.TrimEnd('.') -ine $problemPlain -and $detailPlain.TrimEnd('.') -ine $title.TrimEnd('.'))
    if ($kind -ne 'failure' -and -not $findings.Count -and $detailAdds -and $detailLines.Count) {
        $show = @($detailLines | Select-Object -First 25)
        if ($detailLines.Count -gt $show.Count) { $show += ('and ' + ($detailLines.Count - $show.Count) + ' more lines in PIM Manager') }
        $sections = @(@{ title = $(if ($kind -eq 'guard') { 'What was held back' } else { 'What it is about' }); lines = $show })
    }
    # ---- the ONE button ----
    $label = switch ($kind) {
        'failure' { if ($tab -eq 'jobs' -or -not $tab) { 'Open Engine logs & errors' } else { 'Open in PIM Manager' }; break }
        'guard'   { 'Review what was held back'; break }
        'action'  { if ($tab -eq 'approvals') { 'Review and approve' } else { 'Open in PIM Manager' }; break }
        default   { 'Open in PIM Manager' }
    }
    # ---- Details for support: the raw words, the class codes, the raw line ----
    $details = New-Object System.Collections.Generic.List[string]
    if ("$rawTitle".Trim()) { $details.Add('Alert: ' + ("$rawTitle".Trim() -replace 'PIM4EntraPS', 'PIM Manager')) }
    if ($evt) { $details.Add('Event: ' + $evt) }
    $cls = @($causes | ForEach-Object { @($_.classes) } | Where-Object { $_ })
    if ($cls.Count) { $details.Add('Classes: ' + ($cls -join ', ')) }
    if ($detailPlain) { $raw = $detailPlain; if ($raw.Length -gt 1500) { $raw = $raw.Substring(0, 1497) + '...' }; $details.Add('Raw: ' + $raw) }
    $inst = (& $get 'Instance').Trim()
    if ($inst) { $details.Add('Sent by: ' + $inst) }
    if ($tz -and $when -notmatch 'UTC$') { $u = Format-PimMailWhen -Value $(if ($whenSrc) { $whenSrc } else { $NowUtc }) -TimeZoneId ''; if ($u) { $details.Add('Time (UTC): ' + $u) } }

    $evModel = [ordered]@{
        environment = $envName; tenantId = $tid; version = $ver; subjectWhat = $subjWhat; severity = $severity; topic = $topic
        opener = $opener; summary = $summary; qa = $qa; facts = $facts; sections = $sections
        causesTitle = $(if ($findings.Count -and $kind -ne 'failure') { 'What was found' } else { 'What happened, by cause' })
        causes = @($causes.ToArray()); details = @($details.ToArray())
        button = $(if ("$PortalUrl".Trim()) { @{ url = "$PortalUrl".Trim(); label = $label } } else { $null })
        homeUrl = $HomeUrl; notificationsUrl = $NotificationsUrl
    }
    $mail = New-PimEventMail -Model $evModel
    return [ordered]@{
        title = $title; customer = $customer; environment = $envName; solution = $solution
        who = $who; status = $status; problem = $problem; todo = $todo; findings = @($findings); detailHtml = $detail; when = $when
        support = ((Get-PimAlertSupportMail) + ' - customer portal ' + (Get-PimAlertSupportPortal))
        kind = $kind; severity = $severity; job = $job; topic = $topic; subjectWhat = $subjWhat; summary = $summary; opener = $opener; qa = $qa
        facts = $facts; causes = @($causes.ToArray()); sections = $sections; details = @($details.ToArray()); items = $items
        subject = $mail.subject; heading = $mail.heading; mail = $mail
    }
}

function New-PimAlertMailTable {
    # PURE. The model as the alert mail's HTML (PIM 100.135: the whole designed mail -- the name is kept from 100.105, when it
    # was one table). -MaxFindings is accepted for older callers; the builder caps the names it shows.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Model, [int]$MaxFindings = 50)
    if ($Model.Contains('mail') -and $Model['mail']) { return "$($Model['mail'].html)" }
    return ''
}

function ConvertTo-PimAlertMailText {
    # PURE. The plain-text part of the alert mail: the same content as the HTML, in the same order.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Model, [int]$MaxFindings = 50)
    if ($Model.Contains('mail') -and $Model['mail']) { return "$($Model['mail'].text)" }
    return ''
}

function Add-PimAlertMailTokens {
    <#
      PURE. The caller's tokens plus what the alert template renders: AlertTable (the WHOLE designed mail, PIM 100.135),
      AlertSubject ("<environment>: <what happened>") and, for a template a customer wrote themselves, each value on its own
      (AlertCustomer, AlertEnvironment, AlertSolution, AlertWho, AlertStatus, AlertProblem, AlertTodo, AlertFindingRows,
      AlertWhen, AlertSupport, AlertSummary, AlertHeading -- HTML-encoded). AlertTitle is the title as a person reads it.
      Returns @{ tokens; model }. The caller's hashtable is not changed.
    #>
    param([hashtable]$Tokens = @{}, [hashtable]$Environment = @{}, [datetime]$NowUtc = [datetime]::UtcNow,
          [string]$PortalUrl = '', [string]$HomeUrl = '', [string]$NotificationsUrl = '', [AllowNull()][object]$TimeZoneId = $null)
    $m = Get-PimAlertMailModel -Tokens $Tokens -Environment $Environment -NowUtc $NowUtc -PortalUrl $PortalUrl -HomeUrl $HomeUrl -NotificationsUrl $NotificationsUrl -TimeZoneId $TimeZoneId
    $t = @{}; if ($Tokens) { foreach ($k in @($Tokens.Keys)) { $t[$k] = $Tokens[$k] } }
    [void]$t.Remove('AlertFindings')
    $t['AlertTitle']       = $m.title
    $t['AlertSubject']     = $m.subject
    $t['AlertHeading']     = ConvertTo-PimMailText $m.heading
    $t['AlertSummary']     = ConvertTo-PimMailText $m.summary
    $t['AlertTable']       = New-PimAlertMailTable -Model $m
    $t['AlertCustomer']    = ConvertTo-PimMailText $m.customer
    $t['AlertEnvironment'] = ConvertTo-PimMailText $(if (Test-PimMailTenantIdLabel $m.environment) { '' } else { $m.environment })
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

function Get-PimMailTypeInfo {
    <#
      PURE. PIM 100.135: what a TEMPLATE mail (one not built by New-PimEventMail / New-PimMailDocument) says in Invardia's
      frame -- @{ topic; summary; label }: the heading's topic, the calm 1-3 sentence summary (what happened / is anything
      changed / does anyone act) and the label of its ONE button. Literals in a function (the BUG-79-6b trap).
    #>
    param([string]$Type)
    switch ("$Type") {
        'access-review-reminder' { return @{ topic = 'Access review'; summary = 'An access review is waiting for your decisions. Nothing changes until you decide; please answer before the review closes.'; label = 'Open the access review' } }
        'ad-password-delivery'   { return @{ topic = 'New on-premises admin account'; summary = 'This mail carries the first password of a new on-premises admin account. Nothing else was changed. Please hand it to the admin safely and delete this mail afterwards.'; label = '' } }
        'approval-request'       { return @{ topic = 'Approval needed'; summary = 'A delegation waits for your approval. Nothing is granted until you decide. Approve or deny it in PIM Manager with the button below; a reply to this mail does not decide it.'; label = 'Review and approve' } }
        'approval-escalation'    { return @{ topic = 'Approval needed'; summary = 'A delegation waits for your approval: the first approver did not decide in time, so it has come to you. Nothing is granted until you decide. Approve or deny it in PIM Manager with the button below; a reply to this mail does not decide it.'; label = 'Review and approve' } }
        'discovery-notice'       { return @{ topic = 'Discovery'; summary = 'Discovery found new items that PIM Manager does not manage yet. Nothing was changed. Please review them when it suits you.'; label = 'Open Discovery and gaps' } }
        'emergency-override'     { return @{ topic = 'Emergency override'; summary = 'An emergency override is active on a group, so approval is switched off for it until the override ends. Nothing else was changed. Please check that it was expected.'; label = 'Open in PIM Manager' } }
        'new-admin'              { return @{ topic = 'Welcome'; summary = 'A new admin account was created. Its sign-in details follow in a separate mail; there is nothing else to do.'; label = 'Open in PIM Manager' } }
        'new-permission'         { return @{ topic = 'Permission change'; summary = 'A permission of a group changed. This is for your information; you do not need to do anything unless you did not expect it.'; label = 'Open in PIM Manager' } }
        'new-role'               { return @{ topic = 'Role assignment'; summary = 'A role was assigned. This is for your information; you do not need to do anything unless you did not expect it.'; label = 'Open in PIM Manager' } }
        'offboarding-notice'     { return @{ topic = 'Admin account disabled'; summary = 'An admin account was disabled, so its access has ended. You do not need to do anything unless you did not expect it.'; label = 'Open in PIM Manager' } }
        'rfa-notice'             { return @{ topic = 'Request for authorization'; summary = ''; label = 'Open in PIM Manager' } }
        'tap-delivery'           { return @{ topic = 'Temporary Access Pass'; summary = 'This mail carries a Temporary Access Pass for an admin account. Nothing else was changed. Please hand it to the admin safely and delete this mail afterwards.'; label = '' } }
        'update-outcome'         { return @{ topic = 'Update'; summary = 'This is the result of a PIM Manager update.'; label = 'Open in PIM Manager' } }
        'alert-notice'           { return @{ topic = 'Alert'; summary = ''; label = 'Open in PIM Manager' } }
        default                  { return @{ topic = 'Notice'; summary = ''; label = 'Open in PIM Manager' } }
    }
}

function Get-PimMailTypeSeverity {
    <#
      PURE. Framework §12.11a MAIL-3: the subject's severity word for a TEMPLATE mail of -Type (the alert mail carries its
      own, Get-PimAlertMailModel). A sender's MailSeverity token wins ('none' = no word): an RFA / company-review mail that
      asks someone to decide passes 'action'. Credentials, reports and information mails carry no word.
    #>
    param([string]$Type = '', [hashtable]$Tokens = @{})
    $tk = if ($Tokens) { $Tokens } else { @{} }
    $o = "$($tk['MailSeverity'])".Trim()
    if ($o) { if ($o -ieq 'none') { return '' }; return (Get-PimMailSeverityWord $o) }
    switch ("$Type") {
        'access-review-reminder'   { return 'Action needed' }
        'approval-request'         { return 'Action needed' }
        'approval-escalation'      { return 'Action needed' }
        'get-started-reminder'     { return 'Action needed' }
        'pending-actions-reminder' { return 'Action needed' }
        'discovery-notice'         { return 'Warning' }
        'emergency-override'       { return 'Warning' }
        'update-outcome'           { return (Get-PimMailSeverityWord "$($tk['Outcome'])") }
    }
    return ''
}

function New-PimFramedMail {
    <#
      PURE. §100.5 MAIL-2 leftover (b) -> PIM 100.135: a TEMPLATE mail (not itself built by New-PimEventMail or
      New-PimMailDocument) is put in Invardia's structure: logo -> "PIM Manager for <environment> - <topic>" -> the calm
      summary of its type -> facts (Environment, Product, When) -> the template's own content, unchanged -> ONE blue button
      -> Details for support (the tenant id) -> footer; plus a text part in the same order. A customer-EDITED template keeps
      every word: only its <html>/<body> wrapper is replaced. Returns @{ html; text } or $null (body unchanged) when:
        * the body is already a designed mail (class="pim-mail"),
        * the template opts out with <!-- pim-no-layout --> (e.g. a mail that must stay plain).
      -Subject: the rendered subject ([..] tags dropped); -BodyText: the template's own text part.
    #>
    param([AllowEmptyString()][string]$BodyHtml, [string]$BodyText = '', [string]$Subject = '', [string]$Type = '', [hashtable]$Button = $null,
          [string]$HomeUrl = '', [string]$NotificationsUrl = '', [hashtable]$Environment = @{}, [datetime]$NowUtc = [datetime]::UtcNow,
          [AllowNull()][object]$TimeZoneId = $null)
    $h = "$BodyHtml"
    if ($h -match 'class="pim-mail"' -or $h -match '<!--\s*pim-no-layout\s*-->') { return $null }
    $inner = $h
    $m = [regex]::Match($h, '(?is)<body\b[^>]*>(.*)</body>')
    if ($m.Success) { $inner = $m.Groups[1].Value }
    else { $inner = [regex]::Replace($inner, '(?is)</?html\b[^>]*>', '') }
    $inner = [regex]::Replace($inner, '(?is)<head\b.*?</head>', '')
    $inner = [regex]::Replace($inner, '(?s)<!--.*?-->', '').Trim()   # template comments (subject / tokens) are not content
    $info = Get-PimMailTypeInfo -Type $Type
    $env = if ($Environment) { $Environment } else { @{} }
    $tz = if ($null -eq $TimeZoneId) { Get-PimMailTimeZoneId } else { "$TimeZoneId" }
    $ver = "$($env['version'])".Trim()
    $envName = "$($env['name'])".Trim()
    # ONE button, after the content; none when the content already links the same page
    $btn = $null
    if ($Button -and "$($Button.url)".Trim() -and $inner -notmatch [regex]::Escape(("$($Button.url)" -split '\?')[0])) {
        $lbl = if ("$($Button.label)".Trim()) { "$($Button.label)" } elseif ("$($info.label)".Trim()) { "$($info.label)" } else { 'Open in PIM Manager' }
        $btn = @{ url = "$($Button.url)".Trim(); label = $lbl }
    }
    $model = [ordered]@{
        environment = $envName; tenantId = "$($env['tenantId'])".Trim(); version = $ver
        subjectWhat = "$Subject"; topic = "$($info.topic)"; summary = "$($info.summary)"
        facts = @(@{ label = 'Environment'; value = $(if (Test-PimMailTenantIdLabel $envName) { '' } else { $envName }) }, @{ label = 'Product'; value = ('PIM Manager ' + $ver).Trim() }, @{ label = 'When'; value = (Format-PimMailWhen -Value $NowUtc -TimeZoneId $tz) })
        contentHtml = $inner; contentText = "$BodyText"
        button = $btn; details = @(); homeUrl = $HomeUrl; notificationsUrl = $NotificationsUrl
    }
    $mail = New-PimEventMail -Model $model
    return @{ html = $mail.html; text = $mail.text; heading = $mail.heading }
}

function ConvertTo-PimMailLayoutFrame {
    # The framed body HTML only (New-PimFramedMail), or the input unchanged when it is designed already / opts out.
    param([AllowEmptyString()][string]$BodyHtml, [string]$Subject = '', [hashtable]$Button = $null, [string]$HomeUrl = '', [string]$NotificationsUrl = '',
          [hashtable]$Environment = @{}, [string]$Type = '',
          # PIM 100.105: kept for older callers -- the footer's home link is always the words "Open PIM Manager" now
          [switch]$HomeLinkAsWords)
    $f = New-PimFramedMail -BodyHtml $BodyHtml -Subject $Subject -Type $Type -Button $Button -HomeUrl $HomeUrl -NotificationsUrl $NotificationsUrl -Environment $Environment
    if ($null -eq $f) { return "$BodyHtml" }
    return $f.html
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

    # PIM 100.135 (Invardia's format): the heading names the product and the environment ("PIM Manager for <environment> -
    # <title>"); the footer is site + support; the tenant id (a GUID) is only in the small "Details for support" block.
    $headTitle = "$Title"
    if (-not $Print -and $headTitle -notmatch '^PIM Manager\b') { $headTitle = Get-PimMailHeadingLine -EnvironmentName $(if (Test-PimMailTenantIdLabel $envName) { '' } else { $envName }) -Topic $Title }
    $foot = New-Object System.Collections.Generic.List[string]
    $envBits = New-Object System.Collections.Generic.List[string]
    if ($envName -and -not (Test-PimMailTenantIdLabel $envName)) { $envBits.Add('Environment: <b>' + (ConvertTo-PimMailText $envName) + '</b>') }
    if ($tn -and $tn -ine $envName) { $envBits.Add('tenant ' + (ConvertTo-PimMailText $tn)) }
    if ($ver) { $envBits.Add('PIM Manager ' + (ConvertTo-PimMailText $ver)) }
    if ($envBits.Count) { $foot.Add($envBits.ToArray() -join ' &middot; ') }
    # the home link is the words "Open PIM Manager" (no raw hosting address in the body); -HomeLinkAsWords is kept for callers
    if (Test-PimMailLinkUrl -Url $HomeUrl) { $foot.Add('<a href="' + (ConvertTo-PimMailText $HomeUrl.Trim()) + '" style="color:' + $b.accent + ';">Open PIM Manager</a>') }
    $foot.Add('Support: <a href="mailto:' + (Get-PimAlertSupportMail) + '" style="color:' + $b.accent + ';">' + (Get-PimAlertSupportMail) + '</a> &middot; <a href="' + (Get-PimAlertSupportPortal) + '" style="color:' + $b.accent + ';">customer portal</a>')
    $why = if ("$AudienceLabel".Trim()) { 'You get this report as <b>' + (ConvertTo-PimMailText $AudienceLabel) + '</b>.' } else { '' }
    if (Test-PimMailLinkUrl -Url $NotificationsUrl) { $why = ($why + ' <a href="' + (ConvertTo-PimMailText $NotificationsUrl.Trim()) + '" style="color:' + $b.accent + ';">Change what you receive</a>.').Trim() }
    if ($why) { $foot.Add($why) }
    if ($Print) { $foot.Add('Generated ' + (ConvertTo-PimMailText $gen) + '.') }
    $detailsBlock = ''
    if ($tid -and -not $Print) {
        $detailsBlock = '<div class="pim-mail-details" style="margin:22px 0 0 0;padding:8px 12px;background:' + $b.surfaceAlt + ';border:1px solid ' + $b.grid + ';border-radius:6px;font-family:Consolas,Menlo,monospace;font-size:11px;line-height:16px;color:' + $b.muted + ';">' +
                        '<div style="font-family:' + $b.font + ';font-size:11.5px;font-weight:600;margin-bottom:3px;">Details for support</div><div>Tenant id: ' + (ConvertTo-PimMailText $tid) + '</div></div>'
    }
    $footer = $detailsBlock + '<div class="pim-env-footer" style="margin:26px 0 0 0;padding-top:10px;border-top:1px solid ' + $b.border + ';font-family:' + $b.font + ';font-size:12px;line-height:18px;color:' + $b.muted + ';">' + ($foot.ToArray() -join '<br>') + '</div>'

    $inner = '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="border-collapse:collapse;"><tr>' +
             '<td valign="middle" style="padding:0 0 10px 0;">' + $logo + '</td>' +
             '<td valign="middle" align="right" style="padding:0 0 10px 0;text-align:right;">' + $envCell + '</td></tr>' +
             '<tr><td colspan="2" style="height:3px;line-height:3px;font-size:1px;background:' + $b.blue + ';">&nbsp;</td></tr></table>' +
             '<h1 class="pim-mail-heading" style="margin:18px 0 2px 0;font-family:' + $b.font + ';font-size:22px;font-weight:700;color:' + $b.heading + ';">' + (ConvertTo-PimMailText $headTitle) + '</h1>' +
             $(if ("$Subtitle".Trim()) { '<div style="font-family:' + $b.font + ';font-size:13px;color:' + $b.muted + ';">' + (ConvertTo-PimMailText $Subtitle) + '</div>' } else { '' }) +
             # PIM 100.135: summary first, then the content, then the ONE button (no longer between the summary and the tables)
             $SummaryHtml + $BodyHtml + $btn + $footer

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
