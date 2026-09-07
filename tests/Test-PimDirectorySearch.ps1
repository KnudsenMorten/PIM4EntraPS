#Requires -Version 5.1
<#
.SYNOPSIS
    Offline proof for the directory-people lookup (REQUIREMENTS §35.8) -- the
    data source every people-picker in the Manager needs and none of them had.
    Drives the PURE core (engine/_shared/PIM-DirectorySearch.ps1). No Graph, no
    network: the core builds request paths and shapes rows, it never calls.

    Asserts:
      * a BLANK or 1-char query is REFUSED, never broadened to "everyone" --
        the lean-context rule (§22/§35.5) applied at the picker layer;
      * -Top is CLAMPED, not honoured (an unbounded top is the bulk list this
        endpoint exists to avoid), with a sane default for junk input;
      * OData escaping: O'Brien does not terminate the string literal;
      * $search escaping: a double quote / backslash does not break the phrase;
      * the term is URL-ENCODED into the path, so a space or & cannot inject
        another query parameter;
      * both query modes over-fetch Top+1 so "there are more" is distinguishable
        from "that is all", and the page trim reports `truncated`;
      * row shaping is narrow and picks UPN as the stored `value`;
      * every emitted code maps to an explicit HTTP status, with no gaps, and
        an unreachable directory is 503/502 -- NEVER 200-with-empty-list.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared'
$lib    = Join-Path $shared 'PIM-DirectorySearch.ps1'
T 'PIM-DirectorySearch.ps1 present' (Test-Path -LiteralPath $lib)
if (-not (Test-Path -LiteralPath $lib)) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
. $lib

# === a blank query is not "everyone" ========================================
Write-Host "`n-- a blank / too-short query is REFUSED, not broadened --" -ForegroundColor Cyan
$blank = Resolve-PimDirectoryQuery -Query '' -Top 20
T 'empty query -> refused'            (-not $blank.ok)
T 'empty query -> code no-query'      ($blank.code -eq 'no-query')
T 'the refusal says it will not return the whole directory' ($blank.reason -match 'whole directory')
T 'whitespace-only query -> refused'  (-not (Resolve-PimDirectoryQuery -Query "   `t " -Top 20).ok)
T 'null query -> refused'             (-not (Resolve-PimDirectoryQuery -Query $null -Top 20).ok)
$one = Resolve-PimDirectoryQuery -Query 'a' -Top 20
T '1-char query -> refused'           (-not $one.ok)
T '1-char query -> code too-short'    ($one.code -eq 'too-short')
$two = Resolve-PimDirectoryQuery -Query 'ab' -Top 20
T '2-char query -> accepted (the documented minimum)' ($two.ok)
T 'the term is trimmed'               ((Resolve-PimDirectoryQuery -Query '  knud  ' -Top 5).term -eq 'knud')

# === top is clamped, not honoured ===========================================
Write-Host "`n-- -Top is CLAMPED, not honoured --" -ForegroundColor Cyan
T 'top 20 honoured'                   ((Resolve-PimDirectoryQuery -Query 'knud' -Top 20).top -eq 20)
T 'top 5000 clamped to the max (50)'  ((Resolve-PimDirectoryQuery -Query 'knud' -Top 5000).top -eq 50)
T 'top 0 -> default (20), not zero'   ((Resolve-PimDirectoryQuery -Query 'knud' -Top 0).top -eq 20)
T 'negative top -> default'           ((Resolve-PimDirectoryQuery -Query 'knud' -Top -9).top -eq 20)
T 'junk top -> default'               ((Resolve-PimDirectoryQuery -Query 'knud' -Top 'lots').top -eq 20)
T 'absent top -> default'             ((Resolve-PimDirectoryQuery -Query 'knud').top -eq 20)

# === escaping: the apostrophe is a real surname, not a hypothetical =========
Write-Host "`n-- OData escaping (O'Brien must not terminate the literal) --" -ForegroundColor Cyan
T "a single quote is DOUBLED"          ((ConvertTo-PimODataStringLiteral -Term "O'Brien") -eq "O''Brien")
T 'a term with no quote is unchanged'  ((ConvertTo-PimODataStringLiteral -Term 'Knudsen') -eq 'Knudsen')
T 'multiple quotes are all doubled'    ((ConvertTo-PimODataStringLiteral -Term "a'b'c") -eq "a''b''c")
$fp = Get-PimDirectoryPeopleFilterPath -Term "O'Brien" -Top 10
$fpDec = [uri]::UnescapeDataString($fp)
T 'the built filter carries the DOUBLED quote'  ($fpDec -match "startswith\(displayName,'O''Brien'\)")
# 🪤 HOST-SENSITIVE, and the runner caught what a standalone pwsh run hid.
# [uri]::EscapeDataString leaves an apostrophe UNESCAPED on .NET Framework
# (Windows PowerShell 5.1) and percent-encodes it to %27 on .NET (pwsh 7). BOTH
# are correct -- "'" is a legal sub-delim in a query string and Graph parses the
# OData either way -- so "the path contains no apostrophe" is an assertion about
# the HOST, not about this code. It passed under pwsh 7 standalone and failed
# under powershell.exe in the suite, which is the host the ENGINE actually runs
# on. That is framework HOST-1 in miniature (DOCS/REQUIREMENTS.md).
# Assert the property that genuinely matters instead: the characters that could
# INJECT are encoded, whichever host we are on.
T 'the apostrophe is either encoded or left legal-as-is (both hosts correct)' (($fp -match '%27') -or ($fp -match "'"))
$hostile = Get-PimDirectoryPeopleFilterPath -Term 'a b&top=9' -Top 5
T 'a term ampersand is percent-encoded'  ($hostile -match '%26')
T 'a term space is percent-encoded'      ($hostile -notmatch ' ')
T 'only ONE $top parameter survives'     (([regex]::Matches($hostile, '\$top=')).Count -eq 1)

Write-Host "`n-- `$search escaping --" -ForegroundColor Cyan
T 'a double quote is escaped'         ((ConvertTo-PimGraphSearchTerm -Term 'a"b') -eq 'a\"b')
T 'a backslash is escaped'            ((ConvertTo-PimGraphSearchTerm -Term 'a\b') -eq 'a\\b')
T 'backslash escaped BEFORE quote (order matters)' ((ConvertTo-PimGraphSearchTerm -Term '\"') -eq '\\\"')

Write-Host "`n-- the term cannot inject another query parameter --" -ForegroundColor Cyan
$inj = Get-PimDirectoryPeopleSearchPath -Term 'bob&$top=9999' -Top 10
T 'an injected &$top does not appear raw in the path' ($inj -notmatch '&\$top=9999')
T 'the real $top is still present'    ($inj -match '\$top=11')
$injF = Get-PimDirectoryPeopleFilterPath -Term 'bob&$top=9999' -Top 10
T 'same for the filter path'          ($injF -notmatch '&\$top=9999')
T 'a space is encoded, not literal'   ((Get-PimDirectoryPeopleFilterPath -Term 'van der berg' -Top 5) -notmatch ' ')

# === over-fetch so "more" is knowable =======================================
Write-Host "`n-- both modes over-fetch Top+1 --" -ForegroundColor Cyan
T 'search path asks for Top+1'        ((Get-PimDirectoryPeopleSearchPath -Term 'knud' -Top 20) -match '\$top=21')
T 'filter path asks for Top+1'        ((Get-PimDirectoryPeopleFilterPath -Term 'knud' -Top 20) -match '\$top=21')
T 'search path selects only picker fields' ((Get-PimDirectoryPeopleSearchPath -Term 'k' -Top 5) -match 'id,displayName,userPrincipalName,mail,accountEnabled')
T 'search path searches surname too (a surname is what admins type)' ([uri]::UnescapeDataString((Get-PimDirectoryPeopleSearchPath -Term 'knud' -Top 5)) -match 'surname:knud')
T 'the eventual-consistency header is supplied' ((Get-PimDirectorySearchHeaders).ConsistencyLevel -eq 'eventual')

Write-Host "`n-- page trim reports truncation honestly --" -ForegroundColor Cyan
$mk = { param($n) 1..$n | ForEach-Object { [pscustomobject]@{ displayName = "P$_"; userPrincipalName = "p$_@x.io" } } }
$exact = Select-PimDirectoryPeoplePage -People (& $mk 20) -Top 20
T '20 results for top 20 -> not truncated' ((-not $exact.truncated) -and $exact.people.Count -eq 20)
$over = Select-PimDirectoryPeoplePage -People (& $mk 21) -Top 20
T '21 results for top 20 -> truncated'     ($over.truncated)
T '   ...and trimmed back to 20'           ($over.people.Count -eq 20)
$under = Select-PimDirectoryPeoplePage -People (& $mk 3) -Top 20
T '3 results -> not truncated'             ((-not $under.truncated) -and $under.people.Count -eq 3)
$none = Select-PimDirectoryPeoplePage -People @() -Top 20
T 'no results -> not truncated, empty'     ((-not $none.truncated) -and $none.people.Count -eq 0)

# === row shaping ============================================================
Write-Host "`n-- row shaping is narrow, and `value` is the UPN --" -ForegroundColor Cyan
$u = [pscustomobject]@{ id='11'; displayName='Jane Doe'; userPrincipalName='jane@x.io'; mail='j@x.io'; accountEnabled=$true; jobTitle='SECRET'; department='SECRET' }
$p = ConvertTo-PimDirectoryPerson -User $u
T 'displayName carried'               ($p.displayName -eq 'Jane Doe')
T 'value is the UPN (what the fields store)' ($p.value -eq 'jane@x.io')
T 'accountEnabled carried as a bool'  ($p.accountEnabled -is [bool] -and $p.accountEnabled)
T 'no extra directory fields leak'    (@($p.PSObject.Properties.Name) -notcontains 'jobTitle' -and @($p.PSObject.Properties.Name) -notcontains 'department')
T 'exactly the six picker fields'     (@($p.PSObject.Properties.Name).Count -eq 6)
$noUpn = ConvertTo-PimDirectoryPerson -User ([pscustomobject]@{ id='2'; displayName='No UPN' })
T 'a user with no UPN falls back to displayName' ($noUpn.value -eq 'No UPN')
T 'a null user shapes to null'        ($null -eq (ConvertTo-PimDirectoryPerson -User $null))
T 'an empty user shapes to null'      ($null -eq (ConvertTo-PimDirectoryPerson -User ([pscustomobject]@{ id='3' })))

# === status mapping =========================================================
Write-Host "`n-- code -> HTTP status; an unreachable directory is NEVER 200 --" -ForegroundColor Cyan
T 'ok -> 200'                ((Get-PimDirectorySearchHttpStatus -Code 'ok') -eq 200)
T 'no-query -> 400'          ((Get-PimDirectorySearchHttpStatus -Code 'no-query') -eq 400)
T 'too-short -> 400'         ((Get-PimDirectorySearchHttpStatus -Code 'too-short') -eq 400)
T 'graph-unavailable -> 503' ((Get-PimDirectorySearchHttpStatus -Code 'graph-unavailable') -eq 503)
T 'graph-error -> 502'       ((Get-PimDirectorySearchHttpStatus -Code 'graph-error') -eq 502)
T 'unknown code -> 500 (never a 2xx)' ((Get-PimDirectorySearchHttpStatus -Code 'new-reason') -eq 500)
$emitted = @('ok','no-query','too-short','graph-unavailable','graph-error')
T 'every emitted code has an explicit status' (@($emitted | Where-Object { (Get-PimDirectorySearchHttpStatus -Code $_) -eq 500 }).Count -eq 0)

# === the core stays pure, and the endpoint stays honest =====================
Write-Host "`n-- the core is pure; the endpoint never fakes an empty result --" -ForegroundColor Cyan
# 🪤 A source-scanning assert must read CODE, not prose. This file's header
# explains the bulk-list mistake it exists to avoid -- and names `Get-MgUser
# -all:$true` while doing so -- so a naive scan matches the DOCUMENTATION of the
# rule and fails the very file that follows it. That is a documented trap in this
# codebase (see Test-PimAdminTapReset.ps1's bare-$null assert, which hit it too);
# the remedy is to strip comments first, and it is applied here from the start.
$srcRaw = Get-Content -LiteralPath $lib -Raw
$src    = $srcRaw -replace '(?s)<#.*?#>', ''      # block comments (incl. the header)
$src    = $src -replace '(?m)^\s*#.*$', ''        # whole-line comments
T 'the comment-stripper actually removed the header' ($srcRaw -match 'Get-MgUser' -and $src -notmatch 'Get-MgUser')
T 'the core makes no Graph/HTTP call' ($src -notmatch 'Invoke-PimGraph|Invoke-MgGraphRequest|Invoke-RestMethod|Invoke-WebRequest')
T 'the core never bulk-lists'         ($src -notmatch 'Get-MgUser|-all:\$true')

$srvPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\pim-manager\Open-PimManager.ps1'
if (Test-Path -LiteralPath $srvPath) {
    $srv = Get-Content -LiteralPath $srvPath -Raw
    T 'the endpoint is wired'                 ($srv -match "'/api/directory/people'")
    T 'the endpoint is Admin-gated'           ($srv -match "(?s)/api/directory/people.{0,900}?Test-PimManagerRoleAtLeast -Minimum 'Admin'")
    # The load-bearing one: an unreachable directory must be a 503/502, not an
    # empty 200. An empty list reads as a definitive "this person does not exist".
    T 'no-Graph returns 503, not an empty 200' ($srv -match "(?s)/api/directory/people.{0,2600}?graph-unavailable")
    T '   ...and says it is NOT \"no matches\"' ($srv -match 'NOT "no matches" -- the lookup did not run')
    T 'a failed lookup returns 502, not an empty 200' ($srv -match "(?s)/api/directory/people.{0,4000}?graph-error")
    T 'the response reports which match mode answered' ($srv -match 'matchMode\s*=\s*\$mode')
} else {
    T 'Open-PimManager.ps1 present for wiring asserts' $false
}

# === the pickers that consume it (§35.8) ====================================
Write-Host "`n-- the Settings people-pickers --" -ForegroundColor Cyan
$guiP = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\pim-manager\pim-manager.html'
if (Test-Path -LiteralPath $guiP) {
    $g = (Get-Content -LiteralPath $guiP -Raw) -replace '(?m)^\s*//.*$', ''

    T 'a people source exists and calls the endpoint' ($g -match 'pimPeopleSource' -and $g -match "/api/directory/people")
    # §35.6's one-shared-helper rule, and BUG-88's lesson: do NOT invent a second picker.
    T 'it REUSES pimAttachCombo, not a second picker' ($g -match 'function pimAttachPeopleCombo' -and $g -match 'pimAttachCombo\(input, pimPeopleSource')
    T 'no <datalist> was reintroduced for people'     ($g -notmatch 'setApprId[^>]*list=' -and $g -notmatch 'setDeptOwners[^>]*list=')

    # The load-bearing one. A lookup that could not RUN must not render as "no matches" --
    # an empty list reads as a definitive "this person does not exist".
    T 'a failed lookup renders DISTINCTLY from no-matches' ($g -match 'not.{0,12}&ldquo;no matches&rdquo;' -or $g -match 'the lookup did not run')
    T 'the error branch is separate from the empty branch' ($g -match '(?s)if \(error\) \{.*?\} else if \(!shown\.length\)')

    # All three people fields, plus the role combo.
    T 'Approvers -> Identity is wired'   ($g -match "setApprId'\)\.forEach\(pimAttachPeopleCombo" -or $g -match '\.setApprId.*pimAttachPeopleCombo')
    T 'Departments -> Owners is wired'   ($g -match '\.setDeptOwners.*pimAttachChips')
    T 'Departments -> Contact is wired'  ($g -match '\.setDeptContact.*pimAttachPeopleCombo')
    T 'Approvers -> Role gets a combo'   ($g -match '\.setApprRole.*pimAttachCombo')
    # ...and it must NOT invent a taxonomy: nothing in this solution defines valid approver
    # roles, so the options come from values already present in the table.
    T 'the role combo is sourced from EXISTING values, not an invented list' ($g -match 'function pimApproverRoleSource' -and $g -match "querySelectorAll\('#setApprTbl \.setApprRole'\)")

    # Owners is a LIST in one box -- a chip control, not a single-value dropdown.
    T 'Owners uses a multi-value chip control' ($g -match 'function pimAttachChips')
    T 'chips are individually removable'       ($g -match 'pim-chip-x')
    T 'chips de-dup case-insensitively'        ($g -match 'x\.toLowerCase\(\) === v\.toLowerCase\(\)')
    # The save path must not need changing: the original input stays and carries the joined value.
    T 'the chip control writes back to the original input' ($g -match "input\.value = vals\.join\('; '\)")
    T 'the original input is kept (hidden), not replaced'  ($g -match "input\.style\.display = 'none'" -and $g -match 'wrap\.appendChild\(input\)')

    # A new row must not be the only one that still makes you type.
    T 'pickers are re-wired after "+ Add"' (([regex]::Matches($g, 'pimWireSettingsPickers\(\)')).Count -ge 3)
    T 'the async search is debounced'      ($g -match 'setTimeout\(async' )
    T 'a stale response cannot overwrite a newer one' ($g -match 'if \(mine !== seq\) return')
} else { T 'pim-manager.html present for picker asserts' $false }

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
