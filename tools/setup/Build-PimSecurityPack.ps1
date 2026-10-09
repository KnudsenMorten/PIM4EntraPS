#Requires -Version 5.1
<#
.SYNOPSIS
    Build PIM Manager's CISO / security review pack (framework REQUIREMENTS 12.10 SECURITY-PACK-1) and hand it over to
    Invardia: security-pack.json + security-pack.md + a print-designed security-pack.html.

.DESCRIPTION
    ONE SOURCE: docs\security-pack\security-pack.json (chapters[] with id, number, title, body markdown, tables[]). This
    script renders it to Markdown and to a print-designed HTML page (cover, table of contents, version + date, page
    numbers through @page, A4) and writes all three to the hand-over folder Invardia reads:

        C:\ProgramData\Invardia\handover\docs\pim-manager\<VERSION>\security-pack.{json,md,html}

    Invardia renders https://invardia.com/products/pim-manager/security/ and the PDF from the JSON (UPDATE-1.7: the
    product decides WHAT, Invardia renders). Until it does, the HTML prints to a PDF from any browser (Ctrl+P, A4,
    "Save as PDF"; the page carries its own margins and page numbers).

    The pack is product-level: no tenant, no subscription, no customer data. It writes only files -- it signs in to
    nothing and changes nothing in Azure or Entra.

    -WriteSource also refreshes the rendered copies kept next to the JSON in the repository (docs\security-pack\
    security-pack.md and .html), so the repository copy and the JSON never drift (tests\Test-PimSecurityPack.ps1
    fails when they do).

.PARAMETER OutDir
    Hand-over folder. Default C:\ProgramData\Invardia\handover\docs\pim-manager\<VERSION> (VERSION from the solution).
.PARAMETER SourceDir
    Folder holding security-pack.json. Default <solution>\docs\security-pack.
.PARAMETER Version
    Version stamped on the pack. Default: the solution's VERSION file.
.PARAMETER Date
    Date stamped on the pack (yyyy-MM-dd). Default: today (UTC).
.PARAMETER WriteSource
    Also rewrite the rendered security-pack.md / .html in -SourceDir.
.PARAMETER NoHandover
    Render only (with -WriteSource): do not write the hand-over folder.
.EXAMPLE
    .\tools\setup\Build-PimSecurityPack.ps1
.EXAMPLE
    .\tools\setup\Build-PimSecurityPack.ps1 -WriteSource -NoHandover
.LINK
    https://invardia.com/products/pim-manager/security/
#>
[CmdletBinding()]
param(
    [string]$OutDir,
    [string]$SourceDir,
    [string]$Version,
    [string]$Date,
    [switch]$WriteSource,
    [switch]$NoHandover
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $SourceDir) { $SourceDir = Join-Path $solRoot 'docs\security-pack' }
if (-not $Version)   { $Version = "$(Get-Content -Raw -LiteralPath (Join-Path $solRoot 'VERSION'))".Trim() }
if (-not $Date)      { $Date = [DateTime]::UtcNow.ToString('yyyy-MM-dd') }
if (-not $OutDir)    { $OutDir = Join-Path $env:ProgramData ("Invardia\handover\docs\pim-manager\" + $Version) }
$utf8 = New-Object System.Text.UTF8Encoding($false)

function ConvertTo-PimSpHtmlText([string]$s) {
    # HTML-escape, then the inline Markdown subset the pack uses: `code`, **bold**, [text](https://...).
    $e = [System.Net.WebUtility]::HtmlEncode("$s")
    $e = [regex]::Replace($e, '`([^`]+)`', '<code>$1</code>')
    $e = [regex]::Replace($e, '\*\*([^*]+)\*\*', '<strong>$1</strong>')
    $e = [regex]::Replace($e, '\[([^\]]+)\]\((https?://[^)\s]+|mailto:[^)\s]+)\)', '<a href="$2">$1</a>')
    return $e
}

function ConvertTo-PimSpHtmlBlock([string]$md) {
    # Block Markdown subset: paragraphs, "- " bullets (one level, "  - " = nested), "1. " numbered lists, "### " sub-heads,
    # "> " notes. Anything else is a paragraph. Deliberately small: the JSON body is written for it.
    $out = New-Object System.Text.StringBuilder
    $para = New-Object System.Collections.Generic.List[string]
    $list = $null   # 'ul' | 'ol'
    $sub = $false
    $flushPara = {
        if ($para.Count) { [void]$out.Append('<p>' + (ConvertTo-PimSpHtmlText ($para -join ' ')) + "</p>`n"); $para.Clear() }
    }
    foreach ($raw in ("$md" -split "`r?`n")) {
        $line = $raw.TrimEnd()
        if ($line -match '^\s*$') { & $flushPara; if ($sub) { [void]$out.Append("</ul></li>`n"); $sub = $false }; if ($list) { [void]$out.Append("</$list>`n"); $list = $null }; continue }
        if ($line -match '^### (.+)$') { & $flushPara; if ($sub) { [void]$out.Append("</ul></li>`n"); $sub = $false }; if ($list) { [void]$out.Append("</$list>`n"); $list = $null }; [void]$out.Append('<h3>' + (ConvertTo-PimSpHtmlText $Matches[1]) + "</h3>`n"); continue }
        if ($line -match '^> ?(.*)$') { & $flushPara; if ($list) { if ($sub) { [void]$out.Append("</ul></li>`n"); $sub = $false }; [void]$out.Append("</$list>`n"); $list = $null }; [void]$out.Append('<div class="note">' + (ConvertTo-PimSpHtmlText $Matches[1]) + "</div>`n"); continue }
        if ($line -match '^  +- (.+)$' -and $list) {
            if (-not $sub) {
                # reopen the last <li> as a parent: drop its closing tag
                $t = $out.ToString(); if ($t.EndsWith("</li>`n")) { [void]$out.Remove($out.Length - 6, 6) }
                [void]$out.Append("<ul>`n"); $sub = $true
            }
            [void]$out.Append('<li>' + (ConvertTo-PimSpHtmlText $Matches[1]) + "</li>`n"); continue
        }
        if ($line -match '^- (.+)$') {
            & $flushPara
            if ($sub) { [void]$out.Append("</ul></li>`n"); $sub = $false }
            if ($list -ne 'ul') { if ($list) { [void]$out.Append("</$list>`n") }; [void]$out.Append("<ul>`n"); $list = 'ul' }
            [void]$out.Append('<li>' + (ConvertTo-PimSpHtmlText $Matches[1]) + "</li>`n"); continue
        }
        if ($line -match '^\d+\. (.+)$') {
            & $flushPara
            if ($sub) { [void]$out.Append("</ul></li>`n"); $sub = $false }
            if ($list -ne 'ol') { if ($list) { [void]$out.Append("</$list>`n") }; [void]$out.Append("<ol>`n"); $list = 'ol' }
            [void]$out.Append('<li>' + (ConvertTo-PimSpHtmlText $Matches[1]) + "</li>`n"); continue
        }
        if ($list) { if ($sub) { [void]$out.Append("</ul></li>`n"); $sub = $false }; [void]$out.Append("</$list>`n"); $list = $null }
        $para.Add($line.Trim())
    }
    & $flushPara
    if ($sub) { [void]$out.Append("</ul></li>`n") }
    if ($list) { [void]$out.Append("</$list>`n") }
    return $out.ToString()
}

function ConvertTo-PimSpMdCell([string]$s) { return ("$s" -replace '\|', '\|' -replace "`r?`n", ' ') }

function ConvertTo-PimSecurityPackMarkdown {
    param([Parameter(Mandatory)]$Pack, [string]$Version, [string]$Date)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("# $($Pack.title)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("**Product:** $($Pack.productName) &nbsp;|&nbsp; **Version:** $Version &nbsp;|&nbsp; **Date:** $Date")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine($Pack.intro)
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Contents')
    [void]$sb.AppendLine('')
    foreach ($c in @($Pack.chapters)) { [void]$sb.AppendLine("$($c.number). [$($c.title)](#$($c.id))") }
    [void]$sb.AppendLine('')
    foreach ($c in @($Pack.chapters)) {
        [void]$sb.AppendLine("<a id=`"$($c.id)`"></a>")
        [void]$sb.AppendLine("## $($c.number). $($c.title)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine(("$($c.body)").TrimEnd())
        [void]$sb.AppendLine('')
        foreach ($t in @($c.tables)) {
            if (-not $t) { continue }
            if ($t.title) { [void]$sb.AppendLine("**$($t.title)**"); [void]$sb.AppendLine('') }
            [void]$sb.AppendLine('| ' + ((@($t.columns) | ForEach-Object { ConvertTo-PimSpMdCell $_ }) -join ' | ') + ' |')
            [void]$sb.AppendLine('|' + ((@($t.columns) | ForEach-Object { '---' }) -join '|') + '|')
            foreach ($r in @($t.rows)) { [void]$sb.AppendLine('| ' + ((@($r) | ForEach-Object { ConvertTo-PimSpMdCell $_ }) -join ' | ') + ' |') }
            [void]$sb.AppendLine('')
        }
    }
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine($Pack.footer)
    return $sb.ToString()
}

function ConvertTo-PimSecurityPackHtml {
    param([Parameter(Mandatory)]$Pack, [string]$Version, [string]$Date)
    $h = { param($s) [System.Net.WebUtility]::HtmlEncode("$s") }
    $sb = New-Object System.Text.StringBuilder
    $title = & $h $Pack.title
    [void]$sb.Append(@"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PIM Manager Security Pack</title>
<style>
:root { --ink:#1f2328; --muted:#57606a; --line:#d0d7de; --accent:#0969da; --bg:#ffffff; --soft:#f6f8fa; --warn:#9a6700; --warnbg:#fff8c5; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { --ink:#e6edf3; --muted:#9198a1; --line:#3d444d; --accent:#4493f8; --bg:#0d1117; --soft:#151b23; --warn:#d29922; --warnbg:#2b2111; } }
:root[data-theme="dark"] { --ink:#e6edf3; --muted:#9198a1; --line:#3d444d; --accent:#4493f8; --bg:#0d1117; --soft:#151b23; --warn:#d29922; --warnbg:#2b2111; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.55 "Segoe UI", system-ui, -apple-system, Arial, sans-serif; }
main { max-width:900px; margin:0 auto; padding:24px 16px 64px; }
a { color:var(--accent); }
code { font-family:Consolas, "Cascadia Mono", monospace; font-size:12.5px; background:var(--soft); padding:0 3px; border-radius:3px; overflow-wrap:anywhere; }
h1 { font-size:30px; margin:0 0 8px; } h2 { font-size:21px; margin:32px 0 10px; padding-top:8px; border-top:2px solid var(--accent); } h3 { font-size:15.5px; margin:20px 0 6px; }
.cover { min-height:60vh; display:flex; flex-direction:column; justify-content:center; border-bottom:1px solid var(--line); margin-bottom:24px; }
.cover .kicker { color:var(--accent); font-weight:600; letter-spacing:.08em; text-transform:uppercase; font-size:12px; }
.cover .meta { color:var(--muted); margin-top:18px; }
.cover .meta b { color:var(--ink); }
.toc ol { padding-left:22px; } .toc li { margin:3px 0; }
.note { border-left:4px solid var(--warn); background:var(--warnbg); padding:8px 12px; margin:10px 0; border-radius:4px; }
.tablewrap { overflow-x:auto; margin:10px 0 18px; }
table { border-collapse:collapse; width:100%; font-size:12.5px; }
th, td { border:1px solid var(--line); padding:5px 7px; text-align:left; vertical-align:top; }
th { background:var(--soft); }
caption { text-align:left; font-weight:600; padding:4px 0; }
footer { color:var(--muted); font-size:12px; border-top:1px solid var(--line); margin-top:32px; padding-top:10px; }
@page { size:A4; margin:18mm 14mm 18mm 14mm;
  @bottom-left { content:"PIM Manager Security Pack -- version $Version -- $Date"; font-size:8pt; color:#57606a; }
  @bottom-right { content:"Page " counter(page) " of " counter(pages); font-size:8pt; color:#57606a; } }
@page :first { @bottom-left { content:none; } @bottom-right { content:none; } }
@media print {
  :root { --ink:#000; --muted:#444; --line:#bbb; --accent:#0550ae; --bg:#fff; --soft:#f2f2f2; --warn:#7a5200; --warnbg:#fff8dc; }
  body { font-size:10pt; } main { max-width:none; padding:0; }
  .cover { min-height:250mm; page-break-after:always; border:none; }
  .toc { page-break-after:always; }
  h2 { page-break-before:always; border-top:none; } h2, h3 { page-break-after:avoid; }
  table { font-size:8.5pt; } tr, .note { page-break-inside:avoid; } .tablewrap { overflow:visible; }
  a { color:inherit; text-decoration:none; }
}
</style>
</head>
<body>
<main>
<section class="cover">
<div class="kicker">Security review pack</div>
<h1>$title</h1>
<div>$(ConvertTo-PimSpHtmlText $Pack.intro)</div>
<div class="meta"><b>Product:</b> $(& $h $Pack.productName) &nbsp; <b>Version:</b> $(& $h $Version) &nbsp; <b>Date:</b> $(& $h $Date)<br>
<b>Contact:</b> <a href="mailto:$(& $h $Pack.contact)">$(& $h $Pack.contact)</a> &nbsp; <b>Support:</b> <a href="https://$(& $h $Pack.supportPortal)/">$(& $h $Pack.supportPortal)</a><br>
<b>Online:</b> <a href="$(& $h $Pack.url)">$(& $h $Pack.url)</a></div>
</section>
<nav class="toc"><h2 style="page-break-before:auto;border-top:none;">Contents</h2><ol>

"@)
    foreach ($c in @($Pack.chapters)) { [void]$sb.Append("<li><a href=`"#$(& $h $c.id)`">$(& $h $c.title)</a></li>`n") }
    [void]$sb.Append("</ol></nav>`n")
    foreach ($c in @($Pack.chapters)) {
        [void]$sb.Append("<section id=`"$(& $h $c.id)`">`n<h2>$(& $h $c.number). $(& $h $c.title)</h2>`n")
        [void]$sb.Append((ConvertTo-PimSpHtmlBlock $c.body))
        foreach ($t in @($c.tables)) {
            if (-not $t) { continue }
            [void]$sb.Append("<div class=`"tablewrap`"><table>")
            if ($t.title) { [void]$sb.Append("<caption>$(ConvertTo-PimSpHtmlText $t.title)</caption>") }
            [void]$sb.Append('<thead><tr>' + ((@($t.columns) | ForEach-Object { '<th>' + (& $h $_) + '</th>' }) -join '') + "</tr></thead><tbody>`n")
            foreach ($r in @($t.rows)) { [void]$sb.Append('<tr>' + ((@($r) | ForEach-Object { '<td>' + (ConvertTo-PimSpHtmlText $_) + '</td>' }) -join '') + "</tr>`n") }
            [void]$sb.Append("</tbody></table></div>`n")
        }
        [void]$sb.Append("</section>`n")
    }
    [void]$sb.Append("<footer>$(ConvertTo-PimSpHtmlText $Pack.footer)</footer>`n</main>`n</body>`n</html>`n")
    return $sb.ToString()
}

# --- load + validate the one source ---------------------------------------------------------------------------------
$jsonPath = Join-Path $SourceDir 'security-pack.json'
if (-not (Test-Path -LiteralPath $jsonPath)) { throw "security-pack.json not found: $jsonPath" }
$jsonText = [IO.File]::ReadAllText($jsonPath, [Text.Encoding]::UTF8)
$pack = $jsonText | ConvertFrom-Json
$chapters = @($pack.chapters)
if ($chapters.Count -ne 11) { throw "security-pack.json must carry the 11 chapters of framework 12.10 (found $($chapters.Count))" }
foreach ($c in $chapters) { if (-not $c.id -or -not $c.title -or -not $c.body) { throw "chapter '$($c.id)' needs id, title and body" } }

$md   = ConvertTo-PimSecurityPackMarkdown -Pack $pack -Version $Version -Date $Date
$html = ConvertTo-PimSecurityPackHtml     -Pack $pack -Version $Version -Date $Date
# The hand-over JSON carries the version + date it was built for (the repository copy keeps them as written).
$pack | Add-Member -NotePropertyName version -NotePropertyValue $Version -Force
$pack | Add-Member -NotePropertyName date -NotePropertyValue $Date -Force
$outJson = $pack | ConvertTo-Json -Depth 20

if ($WriteSource) {
    [IO.File]::WriteAllText((Join-Path $SourceDir 'security-pack.md'), $md, $utf8)
    [IO.File]::WriteAllText((Join-Path $SourceDir 'security-pack.html'), $html, $utf8)
    Write-Host "refreshed the rendered copies in $SourceDir"
}
if (-not $NoHandover) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    [IO.File]::WriteAllText((Join-Path $OutDir 'security-pack.json'), $outJson, $utf8)
    [IO.File]::WriteAllText((Join-Path $OutDir 'security-pack.md'), $md, $utf8)
    [IO.File]::WriteAllText((Join-Path $OutDir 'security-pack.html'), $html, $utf8)
    Write-Host "security pack $Version ($Date) -> $OutDir"
    Write-Host '  security-pack.json  security-pack.md  security-pack.html (print to PDF: A4, page numbers from the page itself)'
}
