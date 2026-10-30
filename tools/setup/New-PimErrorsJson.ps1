#Requires -Version 5.1
<#
.SYNOPSIS
    PIM 100.167 / framework DOCS/REQUIREMENTS.md 8.16 UPLINK-CAUSES -- PIM's ERROR CATALOGUE for Invardia: errors.json (one
    entry per stable code pim-<area>-<nnnn>) + SHA256SUMS.txt, built from the product's own failure catalog
    (engine/_shared/PIM-FailureCatalog.ps1: Get-PimFailureCodeTable, the rules' title / cause / remedy, the customer-ready
    solutions). Handed over per release to C:\ProgramData\Invardia\handover\errors\pim-manager\<version>\ (the release step
    copies it there; this script writes only where -OutDir says). Invardia renders a page per code at
    https://invardia.com/docs/pim-manager/errors/<code>, its support agent answers from it, and alerts group by code.

.DESCRIPTION
    The shape is SecurityInsight's (the first catalogue, 2026-10-15): [ { code, title, causeClass, appliesTo { capabilities,
    licences }, customerText, internalNote, whoActs, priority, opensTicket, action, fixedIn, waitForFix, steps [ { who, text }
    | { who, script, params } ], lesson, since } ].
      customerText / steps  CUSTOMER words only -- checked by Test-PimErrorTextCustomerSafe (no GUID, no script or function
                            name, no table name, no internal or customer handle, no class id in brackets, no foreign URL,
                            no mail address); one unsafe text = nothing is written, exit 1.
      internalNote          the class id, its cause and remedy as the engine knows them -- INTERNAL (support, owner).
    Deterministic: the same catalog gives the same bytes (LF line ends, UTF-8 without BOM), so the checksum is stable.

.EXAMPLE
    pwsh -NoProfile -File tools\setup\New-PimErrorsJson.ps1 -OutDir C:\temp\errors\2.4.638
#>
[CmdletBinding()]
param(
    [string]$OutDir = '',
    # the version that carries this catalogue; default: the solution's VERSION file
    [string]$Version = ''
)
$ErrorActionPreference = 'Stop'
$script:PimErrSol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimFailureCodeTable -ErrorAction SilentlyContinue)) { . (Join-Path $script:PimErrSol 'engine\_shared\PIM-FailureCatalog.ps1') }

function Test-PimErrorTextCustomerSafe {
    <#
      PURE. Is a text safe to show a customer? @{ ok; reasons[] }. Refused: a GUID, a script file (.ps1), a PIM function
      (Verb-Pim...), a store table (pim.Settings / pim.Rows / dbo.), a class id in brackets ([SOME-CLASS]), a mail address,
      a URL that is not invardia.com, an internal handle. PIM-local on purpose (never widen the shared
      TOOLS/Test-PublicDocSanitization.ps1 for one solution).
      A script name IS allowed when it is a CUSTOMER-RUN script (-AllowedScripts: the files of tools/setup, published at
      https://invardia.com/support/pim/<Script>.ps1 -- the customer runs it); any other .ps1 name is internal.
    #>
    param([AllowNull()][string]$Text, [string[]]$AllowedScripts = @())
    $t = "$Text"; $why = New-Object System.Collections.Generic.List[string]
    if ($t -match '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b') { $why.Add('a GUID') }
    $okScripts = @{}; foreach ($s in @($AllowedScripts)) { if ("$s".Trim()) { $okScripts["$s".Trim().ToLowerInvariant()] = $true } }
    foreach ($m in [regex]::Matches($t, '(?i)[A-Za-z0-9_.-]+\.ps1\b')) {
        $nm = ($m.Value -split '[/\\]')[-1].ToLowerInvariant()
        if (-not $okScripts.ContainsKey($nm)) { $why.Add("a script file name that is not a customer-run script ($($m.Value))") }
    }
    # a function name -- not the customer-run SCRIPT of the same spelling (Set-PimSqlTier.ps1 is judged by the rule above)
    if ($t -match '\b(Get|Set|Invoke|New|Remove|Approve|Update|Test|Add|Start|Stop|Grant)-Pim[A-Za-z]+\b(?!\.ps1)') { $why.Add('a PIM function name') }
    if ($t -match '(?i)\bpim\.(Settings|Rows|vw_\w+)\b|\bdbo\.') { $why.Add('a store table name') }
    if ($t -match '\[[A-Z][A-Z0-9]*(-[A-Z0-9]+)+\]') { $why.Add('a class id in brackets') }
    if ($t -match '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}') { $why.Add('a mail address') }
    foreach ($m in [regex]::Matches($t, '(?i)https?://[^\s)]+')) { if ($m.Value -notmatch '(?i)^https://(portal\.)?invardia\.com(/|$)') { $why.Add("a URL ($($m.Value))") } }
    # DOC-18: internal handles, customer and person names come from the internal denylist -- no name is written in this
    # file (it ships); Test-PimSourceSanitization scans the whole shipped tree for them, this file included
    foreach ($rx in @(Get-PimErrorPrivateNamePatterns)) { if ([regex]::IsMatch($t, $rx)) { $why.Add('an internal handle'); break } }
    return [pscustomobject]@{ ok = ($why.Count -eq 0); reasons = @($why.ToArray()) }
}

function Get-PimErrorPrivateNamePatterns {
    <#
      DOC-18: the private names (internal/REAL-IDENTIFIERS.md denylist: `word:` any case, `case:` exact case, `value:` a
      substring) as regexes, read once. FAILS CLOSED: without the list no text is judged safe, so nothing is written.
    #>
    if ($script:PimErrPrivateNames) { return $script:PimErrPrivateNames }
    $p = Join-Path "$script:PimErrSol" 'internal\REAL-IDENTIFIERS.md'
    if (-not "$script:PimErrSol" -or -not (Test-Path -LiteralPath $p)) { throw "cannot judge the error texts without the private name list (internal\REAL-IDENTIFIERS.md not found: $p)" }
    $out = New-Object System.Collections.Generic.List[string]
    $in = $false
    foreach ($line in [IO.File]::ReadAllLines($p)) {
        if ($line -match '^##\s*DENYLIST-BEGIN') { $in = $true; continue }
        if ($line -match '^##\s*DENYLIST-END') { $in = $false; continue }
        if (-not $in) { continue }
        $m = [regex]::Match($line, '^\s*(?<k>word|case|value):\s*(?<v>[^#]+?)\s*(?:#.*)?$')
        if (-not $m.Success) { continue }
        $k = $m.Groups['k'].Value; $v = $m.Groups['v'].Value.Trim().Trim('"', "'")
        if ($k -ne 'value' -and $v -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { continue }
        $out.Add($(switch ($k) {
            'word'  { '(?i)(?<![A-Za-z0-9])' + [regex]::Escape($v) + '(?![A-Za-z0-9])' }
            'case'  { '(?<![A-Za-z0-9])' + [regex]::Escape($v) + '(?![A-Za-z0-9])' }
            default { '(?i)' + [regex]::Escape($v) }
        }))
    }
    if (-not $out.Count) { throw "cannot judge the error texts: the private name list ($p) has no entries" }
    $script:PimErrPrivateNames = @($out.ToArray())
    return $script:PimErrPrivateNames
}

function Get-PimErrorCustomerScripts {
    <# The customer-run scripts (the top-level .ps1 files of tools/setup and tools/pim-hybrid-worker -- not the _helpers), names only. #>
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($sub in 'tools\setup', 'tools\pim-hybrid-worker') {
        $d = Join-Path $script:PimErrSol $sub
        if (Test-Path -LiteralPath $d) { foreach ($f in @(Get-ChildItem -LiteralPath $d -Filter '*.ps1' -File | Where-Object { $_.Name -notlike '_*' })) { $out.Add($f.Name) } }
    }
    return @($out.ToArray())
}

function Get-PimErrorCodeArea {
    <# PURE. pim-<area>-<nnnn> -> area. #>
    param([string]$Code)
    if ("$Code" -match '^pim-([a-z]+)-[0-9]{4}$') { return $Matches[1] }
    return ''
}

# Get-PimErrorDefaultText + Get-PimFailureCustomerText live in engine/_shared/PIM-FailureCatalog.ps1 (PIM 100.167, lane G):
# the customer alert mail says the same sentence as errors.json, from ONE source.

function New-PimErrorsCatalogue {
    <#
      PURE (reads the loaded catalog only). The errors.json entries, in the order of Get-PimFailureCodeTable.
    #>
    param([string]$Version = '')
    $rules = @{}; foreach ($r in $script:PimFailureRules) { $rules["$($r.code)"] = $r }
    $sol = Get-PimFailureSolutionCatalog
    $capsByArea = @{ az = @('azureRbac'); def = @('defenderXdr'); pbi = @('powerBi'); ad = @('hybridAd'); tap = @('tapPolicy'); entra = @('entraP2Pim'); grp = @('entraP2Pim') }
    $titleOf = @{ 'CONVERGENCE' = 'A committed change is not in place in the tenant'; 'UNCLASSIFIED' = 'An engine problem PIM Manager has not classified yet' }
    $genericTitle = @{ 'customer-config' = 'A row or setting cannot be applied as written'; 'target-missing' = 'A row names something that does not exist in the tenant'
        'replication-delay' = 'An object is not visible at Microsoft yet'; 'throttled' = 'Microsoft asked PIM Manager to slow down'; 'upstream-error' = 'A Microsoft service error'
        'held-for-approval' = 'A large change is held for approval'; 'not-converged' = 'A committed change is not in place in the tenant'; 'permission' = 'A permission is missing'
        'platform-timeout' = 'A run was stopped before it finished'; 'too-large' = 'The engine job needs more resources'; 'missing-licence' = 'The tenant lacks the Microsoft service a step needs'
        'no-data-source' = 'The tenant lacks the data a step reads'; 'settings-unreachable' = 'A run result could not be saved in the store' }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($row in @(Get-PimFailureCodeTable)) {
        $info = if ("$($row.class)" -like 'GENERIC:*') { Get-PimFailureCodeInfo -Class '' -CauseClass "$($row.causeClass)" } else { Get-PimFailureCodeInfo -Class "$($row.class)" }
        $rule = $rules["$($row.class)"]
        $title = if ($rule) { "$($rule.title)" } elseif ($titleOf.ContainsKey("$($row.class)")) { $titleOf["$($row.class)"] } elseif ($genericTitle.ContainsKey("$($row.causeClass)")) { $genericTitle["$($row.causeClass)"] } else { "$($row.class)" }
        $def = Get-PimErrorDefaultText -CauseClass "$($row.causeClass)" -WhoActs "$($row.whoActs)"
        $ct = if ("$($row.class)" -like 'GENERIC:*') { Get-PimFailureCustomerText -Class '' -CauseClass "$($row.causeClass)" } else { Get-PimFailureCustomerText -Class "$($row.class)" }
        $customer = "$($ct.customerText)"; $steps = New-Object System.Collections.Generic.List[object]
        if ($sol.ContainsKey("$($row.class)")) {
            $s = $sol["$($row.class)"]
            foreach ($st in @($s.steps)) { if ("$st".Trim()) { $steps.Add([ordered]@{ who = 'customer'; text = "$st".Trim() }) } }
            if ("$($s.after)".Trim()) { $steps.Add([ordered]@{ who = 'nobody'; text = "$($s.after)".Trim() }) }
        } else {
            $steps.Add([ordered]@{ who = $(if ("$($row.whoActs)" -eq 'customer') { 'customer' } elseif ("$($row.whoActs)" -in @('support', 'product')) { 'support' } else { 'nobody' }); text = "$($def[1])" })
        }
        $note = "Class $($row.class)."
        if ($rule) { $note += " Cause: $("$($rule.cause)".Trim()) Remedy: $("$($rule.remedy)".Trim())" }
        elseif ("$($row.class)" -eq 'CONVERGENCE') { $note += ' The convergence check (pim-verify-convergence) found definitions in the Manager that are not in the tenant past the grace window; the engine item failures name the cause per item.' }
        elseif ("$($row.class)" -eq 'UNCLASSIFIED') { $note += ' No catalog rule matched the error text: give it its own class and code (framework 8.16: a failure without a cause is a PIM defect).' }
        else { $note += " The generic code of cause class $($row.causeClass): a failure of this kind that has no own code yet." }
        if ($note.Length -gt 1200) { $note = $note.Substring(0, 1197) + '...' }
        $area = Get-PimErrorCodeArea "$($row.code)"
        $prio = switch ("$($row.whoActs)") { 'product' { 'P2' } 'support' { 'P2' } 'customer' { 'P3' } default { 'P4' } }
        $fixedIn = if ("$($row.fixedIn)".Trim()) { "$($row.fixedIn)".Trim() } else { $null }
        $out.Add([ordered]@{
            code = "$($row.code)"; title = $title; causeClass = "$($row.causeClass)"
            appliesTo = [ordered]@{ capabilities = @($(if ($capsByArea.ContainsKey($area)) { $capsByArea[$area] } else { @() })); licences = @() }
            customerText = $customer; internalNote = $note; whoActs = "$($row.whoActs)"; priority = $prio
            opensTicket = [bool]("$($row.whoActs)" -in @('support', 'product')); action = "$($info.action)"
            fixedIn = $fixedIn; waitForFix = [bool]($info.action -eq 'fixed-in'); steps = @($steps.ToArray()); lesson = $null
            since = $(if ("$($row.since)".Trim()) { "$($row.since)".Trim() } else { "$Version" })
        })
    }
    return @($out.ToArray())
}

function Test-PimErrorsCatalogueSafe {
    <# PURE. Every customerText and every step text of the entries -> @{ ok; problems[] } ("<code> customerText: a GUID"). #>
    param([object[]]$Entries, [AllowNull()][string[]]$AllowedScripts = $null)
    if ($null -eq $AllowedScripts) { $AllowedScripts = @(Get-PimErrorCustomerScripts) }
    $p = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($Entries)) {
        $r = Test-PimErrorTextCustomerSafe -Text "$($e.customerText)" -AllowedScripts $AllowedScripts
        foreach ($x in $r.reasons) { $p.Add("$($e.code) customerText: $x") }
        foreach ($s in @($e.steps)) { $r2 = Test-PimErrorTextCustomerSafe -Text "$($s.text)" -AllowedScripts $AllowedScripts; foreach ($x in $r2.reasons) { $p.Add("$($e.code) step: $x") } }
    }
    return [pscustomobject]@{ ok = ($p.Count -eq 0); problems = @($p.ToArray()) }
}

function Write-PimErrorsJson {
    <# Writes errors.json + SHA256SUMS.txt into -OutDir (LF, UTF-8 without BOM). Refuses (throws) on an unsafe customer text. #>
    param([Parameter(Mandatory)][string]$OutDir, [string]$Version = '')
    $entries = @(New-PimErrorsCatalogue -Version $Version)
    $safe = Test-PimErrorsCatalogueSafe -Entries $entries
    if (-not $safe.ok) { throw ("errors.json NOT written -- customer text is not safe: " + (@($safe.problems) -join '; ')) }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $json = (ConvertTo-Json -InputObject @($entries) -Depth 10) -replace "`r`n", "`n"
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $path = Join-Path $OutDir 'errors.json'
    [IO.File]::WriteAllText($path, $json + "`n", $utf8)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = -join ($sha.ComputeHash([IO.File]::ReadAllBytes($path)) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    [IO.File]::WriteAllText((Join-Path $OutDir 'SHA256SUMS.txt'), "$hash *errors.json`n", $utf8)
    return [pscustomobject]@{ path = $path; count = $entries.Count; sha256 = $hash }
}

if ("$OutDir".Trim()) {
    $v = "$Version".Trim()
    if (-not $v) { $vf = Join-Path $script:PimErrSol 'VERSION'; if (Test-Path -LiteralPath $vf) { $v = "$(Get-Content -Raw -LiteralPath $vf)".Trim() } }
    try { $w = Write-PimErrorsJson -OutDir $OutDir -Version $v }
    catch { Write-Host "[errors.json] $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
    Write-Host ("[errors.json] {0} codes -> {1} (sha256 {2})" -f $w.count, $w.path, $w.sha256) -ForegroundColor Green
}
