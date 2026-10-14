# =================================================================================================
# PIM-Docs.ps1 -- the documentation SHIPPED inside each release (PIM REQUIREMENTS 100.157; owner 2026-10-15: "pim must also
# ship docs inside the gui"). Source: tools/pim-manager/manual/ -- index.json ([{ page; title; summary }] in reading order)
# + one <page>.md each. The Manager renders a page to HTML with PowerShell 7's IN-BOX ConvertFrom-Markdown (no module), and
# the HTML is sanitised before it reaches the browser: the pages are ours, but a rendering that could ever carry script is
# refused by construction, not by trust.
# PS 5.1 parses this file (no ConvertFrom-Markdown there: the page call says so instead of failing the Manager).
# =================================================================================================

Set-StrictMode -Off

function Get-PimDocsDir {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$SolutionRoot)
    return (Join-Path $SolutionRoot 'tools\pim-manager\manual')
}

function Test-PimDocsSlug {
    <# A page id is ^[a-z0-9-]{1,80}$ -- never a path, so no request can read outside the manual folder. #>
    [CmdletBinding()] param([AllowEmptyString()][string]$Slug)
    return ("$Slug" -cmatch '^[a-z0-9-]{1,80}$')
}

function Get-PimDocsIndex {
    <#
      The shipped pages in reading order: { ok; pages = [{ page; title; summary }]; error }. Only entries whose slug is
      valid AND whose .md exists are listed (a stale index entry is dropped, never a broken link).
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ManualDir)
    $ix = Join-Path $ManualDir 'index.json'
    if (-not (Test-Path -LiteralPath $ix)) { return [pscustomobject]@{ ok = $true; pages = @(); error = '' } }
    try { $raw = @([IO.File]::ReadAllText($ix) | ConvertFrom-Json) } catch { return [pscustomobject]@{ ok = $false; pages = @(); error = "index.json is not valid JSON: $($_.Exception.Message)" } }
    $pages = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($raw | ForEach-Object { $_ })) {
        $s = "$($e.page)"
        if (-not (Test-PimDocsSlug -Slug $s)) { continue }
        if (-not (Test-Path -LiteralPath (Join-Path $ManualDir "$s.md"))) { continue }
        [void]$pages.Add([pscustomobject]@{ page = $s; title = "$($e.title)"; summary = "$($e.summary)" })
    }
    return [pscustomobject]@{ ok = $true; pages = @($pages.ToArray()); error = '' }
}

function ConvertTo-PimDocsSafeHtml {
    <#
      PURE. Removes everything that could execute or embed from rendered HTML: script / style / iframe / object / embed /
      form / input / link / meta / base elements, every on*= attribute, and javascript: / vbscript: / data: URLs
      (data:image/ stays for inline pictures). What remains is text markup only.
    #>
    [CmdletBinding()] param([AllowEmptyString()][string]$Html)
    $h = "$Html"
    $h = [regex]::Replace($h, '(?is)<(script|style|iframe|object|embed|form|template)\b.*?</\1\s*>', '')
    $h = [regex]::Replace($h, '(?is)<\s*/?\s*(script|style|iframe|object|embed|form|input|button|link|meta|base|template|textarea|select)\b[^>]*>', '')
    $h = [regex]::Replace($h, '(?is)\s+on[a-z]+\s*=\s*("[^"]*"|''[^'']*''|[^\s>]+)', '')
    $h = [regex]::Replace($h, '(?is)(href|src|xlink:href|action|formaction)\s*=\s*("|'')?\s*(javascript|vbscript):[^"''\s>]*("|'')?', '$1="#"')
    $h = [regex]::Replace($h, '(?is)(href|src)\s*=\s*("|'')?\s*data:(?!image/)[^"''\s>]*("|'')?', '$1="#"')
    return $h
}

function Get-PimDocsPage {
    <#
      One shipped page as { ok; page; title; html; error }. A bad slug or a missing page is ok = $false with a reason --
      never a file read outside the manual folder. Markdown -> HTML by the in-box ConvertFrom-Markdown (PowerShell 7),
      then ConvertTo-PimDocsSafeHtml. -Render is the test seam (scriptblock: markdown -> html).
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ManualDir, [AllowEmptyString()][string]$Slug, [scriptblock]$Render)
    if (-not (Test-PimDocsSlug -Slug $Slug)) { return [pscustomobject]@{ ok = $false; page = ''; title = ''; html = ''; error = 'not a page id' } }
    $f = Join-Path $ManualDir "$Slug.md"
    if (-not (Test-Path -LiteralPath $f)) { return [pscustomobject]@{ ok = $false; page = $Slug; title = ''; html = ''; error = 'no such page in this version' } }
    $md = [IO.File]::ReadAllText($f)
    if (-not $Render) {
        if (-not (Get-Command ConvertFrom-Markdown -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ok = $false; page = $Slug; title = ''; html = ''; error = 'this host cannot render Markdown (PowerShell 7 needed)' } }
        $Render = { param($m) (ConvertFrom-Markdown -InputObject $m).Html }
    }
    $html = ConvertTo-PimDocsSafeHtml -Html ("$(& $Render $md)")
    $title = ''; $mt = [regex]::Match($md, '(?m)^#\s+(.+?)\s*$'); if ($mt.Success) { $title = $mt.Groups[1].Value }
    return [pscustomobject]@{ ok = $true; page = $Slug; title = $title; html = $html; error = '' }
}
