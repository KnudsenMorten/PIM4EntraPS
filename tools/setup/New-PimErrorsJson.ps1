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
    # internal handles only: customer names are never written in shipped source (SEC-19) -- Test-PimSourceSanitization's
    # denylist scan catches those across the whole shipped tree, this file included
    if ($t -match '(?i)\b(mgmt1|kv-automatit)\b') { $why.Add('an internal handle') }
    return [pscustomobject]@{ ok = ($why.Count -eq 0); reasons = @($why.ToArray()) }
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

function Get-PimErrorDefaultText {
    <# PURE. The customer sentence + the step of a code WITHOUT a customer-ready solution, by its cause class. #>
    param([string]$CauseClass, [string]$WhoActs)
    $next = 'It runs again on the next run by itself.'
    switch ("$CauseClass") {
        'replication-delay'    { return @("Microsoft has not finished creating an object PIM Manager needs, so this step waits. $next", 'Nothing to do.') }
        'throttled'            { return @("Microsoft asked PIM Manager to slow down, so this step waits. $next", 'Nothing to do.') }
        'upstream-error'       { return @("A Microsoft service answered with an error, so this step was not done. $next", $(if ($WhoActs -eq 'nobody') { 'Nothing to do.' } else { 'Nothing to do for you: Invardia support looks at it.' })) }
        'held-for-approval'    { return @('A safety check held a large change for approval. Nothing was changed; an approver in your tenant decides.', 'Open Jobs > Engine logs & errors in PIM Manager, review the held change and approve it, or correct what caused it and commit in Pending changes.') }
        'not-converged'        { return @('A change you committed is not in place in your tenant yet. PIM Manager tries again on every run, and Invardia support looks at why.', 'Nothing to do for you: Invardia support looks at it.') }
        'unclassified'         { return @('PIM Manager met a problem it does not recognise yet. Nothing was changed wrongly; Invardia support looks at it.', 'Nothing to do for you: Invardia support looks at it.') }
        'too-large'            { return @('The engine job needs more resources for this tenant, so part of its work is not done yet.', 'Nothing to do when updates are on: the next update gives the job more resources. Invardia support can do it with you now.') }
        'settings-unreachable' { return @("PIM Manager could not save the result of one run in its own database. $next", $(if ($WhoActs -eq 'nobody') { 'Nothing to do.' } else { 'Nothing to do for you: Invardia support looks at it.' })) }
        'platform-timeout'     { return @("The run was stopped before it finished. $next", 'Nothing to do.') }
        'permission'           { return @('PIM Manager is not allowed to do this step in your tenant.', 'Open Get Started > Engine permissions in PIM Manager and run the shown command as a Global Administrator.') }
        'target-missing'       { return @('A row names something that does not exist in your tenant (any more), so that row is not applied. Everything else is applied.', 'Open Jobs > Engine logs & errors in PIM Manager; the item shows what to correct or remove, then commit in Pending changes.') }
        'customer-config'      { return @('A row or setting cannot be applied as it is written. Everything else is applied.', 'Open Jobs > Engine logs & errors in PIM Manager; the item shows what to change, then commit in Pending changes.') }
        'missing-licence'      { return @('Your tenant does not have the Microsoft service this step needs, so the step does not apply. Nothing is wrong.', 'Nothing to do. If you add the service later, the step starts on its own.') }
        'no-data-source'       { return @('Your tenant does not have the data this step reads, so the step does not apply. Nothing is wrong.', 'Nothing to do.') }
    }
    return @('PIM Manager met a problem. Invardia support looks at it.', 'Nothing to do for you: Invardia support looks at it.')
}

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
        $customer = "$($def[0])"; $steps = New-Object System.Collections.Generic.List[object]
        if ($sol.ContainsKey("$($row.class)")) {
            $s = $sol["$($row.class)"]
            $customer = ("$($s.what)".Replace(': {item}', '').Replace('{item}', 'one or more items').Trim() + ' ' + "$($s.affected)".Trim()).Trim()
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
