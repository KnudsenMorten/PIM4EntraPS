#Requires -Version 5.1
<#
.SYNOPSIS
    Isolate ONE function's source text, so a static assertion is scoped to the function it
    claims to be about -- instead of to a hand-guessed character window around it.

.DESCRIPTION
    Almost every static test in this solution asserts something about a named function by
    anchoring a regex on `function <Name>` and then bounding the wildcard, e.g. a `-notmatch`
    against 'function Add-PimJobRunRecord' followed by a 1200-character wildcard and the thing
    being forbidden. That window is a GUESS at the function's length, and it is wrong in both
    directions:

      * TOO SMALL, on a NEGATIVE assertion -- the dangerous one. The forbidden construct sits
        just outside the window, the regex does not match, `-notmatch` is TRUE, and the test is
        GREEN while the thing it forbids is present. It does not fail; it stops testing. Session
        37 hit exactly this: adding a parameter pushed an INSERT past a 1200-character bound. The
        POSITIVE twin failed loudly and correctly -- the negative one would have passed
        VACUOUSLY. A guard that gets weaker as the code grows is not a guard.

      * TOO BIG, on a POSITIVE assertion -- quieter, and it was live in this repo too. The window
        runs off the end of the function and into the NEXT ones, so "function X does Y" actually
        proves only "Y appears somewhere within N characters of where X starts". Move the call
        out of X into its neighbour and the assertion still passes. `Write-PimMutationLog` is 969
        characters and carried a 3000-character window: two thirds of what it "proved" was about
        other functions.

      * TOO SMALL, on a POSITIVE assertion -- safe, because it fails loudly, but it means a
        refactor that merely MOVES the target later in the function turns the suite red for no
        real reason. `Get-PimActiveAssignmentsCached` is 22755 characters behind windows of 1400
        and 3000, so two assertions could see 6% and 13% of the function they named.

    The fix is to stop guessing. Take the function's actual text and assert over THAT: the window
    becomes exactly the claim, it cannot rot as the function grows, and no bound needs choosing.

    Enforced by tests\Test-PimAssertionScope.ps1; the full record is docs/REQUIREMENTS.md §37.3.

.NOTES
    🔒 THIS HELPER THROWS. It never returns an empty string, and that is the whole point.
    A silently-empty body would make every `-notmatch` over it pass -- reintroducing the exact
    vacuous-green defect this file exists to remove, wearing a helper's clothes. So a rename, a
    typo, a nested definition or a duplicate is a LOUD crash, never a quiet pass.

    Boundary is the next COLUMN-0 `function` (or end of file), not brace matching. Brace
    counting miscounts braces inside strings, here-strings and `${...}`; the column-0 rule is
    textual and immune to all three. It holds here because this solution defines top-level
    functions at column 0 (Open-PimManager.ps1 124/130, PIM-SqlStore.ps1 34/34,
    PIM-EngineProviders.ps1 86/86, PIM-Scheduler.ps1 58/58 -- the indented remainder are NESTED
    functions, which correctly stay INSIDE their parent's body).

    🪤 Matching is CASE-INSENSITIVE, because PowerShell's `function` keyword is. This is not
    hypothetical tidiness: PIM-Functions.psm1 -- the file `Write-PimAuditEvent` lives in -- has a
    dozen definitions written `Function` with a capital F. A case-sensitive boundary would run
    straight past one of those and silently return a body several functions too long, which is
    the "too big" failure above, reintroduced by the helper meant to prevent it. (Measured when
    this was fixed: no CURRENT target's boundary changed -- the hazard was latent, not active.)
#>

function Get-PimSourceFunctionBody {
    <#
    .SYNOPSIS
        Return the source text of one top-level function, from its `function` keyword to the
        start of the next top-level function (or end of file). Throws if it cannot.
    .PARAMETER Text
        The source file's full text. Pass the SAME text the caller asserts over -- if the caller
        strips comments first, pass the stripped text, so the body matches what it will scan.
    .PARAMETER Name
        The function name, matched exactly (a trailing-word lookahead keeps
        `Set-PimManagerDownlinkPolicy` from matching `Set-PimManagerDownlinkPolicyMany`).
    .PARAMETER StripComments
        Also drop whole-line `#` comments from the returned body, for callers that did not
        already strip them from $Text.
    .PARAMETER MinLength
        Sanity floor. A body shorter than this is treated as a failed isolation and throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        [switch]$StripComments,
        [int]$MinLength = 40
    )

    $esc    = [regex]::Escape($Name)
    # (?![\w-]) so `Set-PimManagerDownlinkPolicy` does not match `...PolicyMany`.
    $anchor = [regex]::new('(?im)^function\s+' + $esc + '(?![\w-])')
    $m = $anchor.Match($Text)
    if (-not $m.Success) {
        # The likeliest causes, in the order they actually happen: renamed, or indented (nested).
        $nested = [regex]::IsMatch($Text, '(?im)^\s+function\s+' + $esc + '(?![\w-])')
        $hint = if ($nested) {
            "it IS present but INDENTED -- a nested function has no top-level body to isolate"
        } else {
            "no 'function $Name' at column 0 -- renamed, moved to another file, or a typo here"
        }
        throw "Get-PimSourceFunctionBody: cannot isolate '$Name': $hint. Refusing to return an empty body: every -notmatch over it would pass vacuously."
    }

    # Defined twice => 'the body of $Name' has no single answer, and asserting over the first one
    # silently ignores the second. That ambiguity is exactly the shape of bug worth crashing on.
    $dup = $anchor.Match($Text, $m.Index + $m.Length)
    if ($dup.Success) {
        throw "Get-PimSourceFunctionBody: '$Name' is defined more than once at column 0. Assert over the file, or disambiguate -- picking the first definition would hide the second."
    }

    $next = ([regex]::new('(?im)^function\s')).Match($Text, $m.Index + $m.Length)
    $end  = if ($next.Success) { $next.Index } else { $Text.Length }
    $body = $Text.Substring($m.Index, $end - $m.Index)
    if ($StripComments) { $body = $body -replace '(?m)^\s*#.*$', '' }

    if ($body.Trim().Length -lt $MinLength) {
        throw "Get-PimSourceFunctionBody: isolated body for '$Name' is only $($body.Trim().Length) chars (floor $MinLength). That is an isolation failure, not a small function."
    }
    $body
}

<#
.SYNOPSIS
    The JavaScript twin of Get-PimSourceFunctionBody: isolate ONE top-level JS function out of
    pim-manager.html, so an assertion about it is scoped to it.

.DESCRIPTION
    §37.3 fixed the PowerShell half of the bounded-window class and explicitly left this half
    open, because Get-PimSourceFunctionBody isolates top-level POWERSHELL functions (it keys on a
    column-0 `function` and, in the gate, on the Verb-Noun hyphen) and cannot see a JS function
    nested inside a <script> block. Every assertion about the Manager's front end was therefore
    still guessing a window. Measured 2026-09-02 across the 18 JS-anchored assertion sites: the
    window was wrong at every one of them, in both directions -- confExempt carried a 1200-char
    window over an 1177-char function (TOO BIG: it reaches into the next function), and
    injectTabGuidance carried 400 over 409, nine characters from the same fault.

    WHY AN INDENT RULE RATHER THAN BRACE MATCHING. The PowerShell helper uses a column-0 rule
    because brace counting miscounts braces inside strings and here-strings. The same objection
    applies far more strongly to JS, which adds template literals and regex literals. So the
    boundary here is textual too: a top-level function in pim-manager.html is written at indent 2
    (inside <script>), and its body ends at the first following line whose indent-2 character is
    `}`.

    THAT RULE IS MEASURED, NOT ASSUMED. Across all 291 indent-2 function definitions in
    pim-manager.html, the indentation boundary and a string/template/comment-aware brace count
    agree on the closing line 291 times out of 291, with no function lacking a boundary. The
    brace check is retained INSIDE this helper as a verification (see -SkipBraceCheck), so the
    indentation rule cannot quietly go wrong as the file changes: if the two ever disagree, this
    throws instead of returning a body that is silently too long or too short.

.NOTES
    🔒 LIKE ITS POWERSHELL TWIN, THIS THROWS and never returns an empty body -- a silently-empty
    body makes every `-notmatch` over it pass, which is the vacuous-green defect this whole class
    of work exists to remove.

    🪤 A JS name is CASE-SENSITIVE (unlike PowerShell's `function` keyword), and `async function`
    is matched as well as plain `function`. Both matter here: renderAccountGrid, confExempt and
    renderAuthoring are all `async`.

    🪤 THIS IS NOT A CALL-SITE HELPER, and the difference is a real trap. "Function X's body
    contains Y" and "a call to X sits near Y" are DIFFERENT claims, and only the first one should
    be scoped through this. Test-PimAuthoringDropdowns asserts the second kind
    (`collectKnownGroupTags()` near `aBaGroupList`) -- converting those would not tighten them, it
    would change what they mean into something they cannot prove. Left as proximity windows on
    purpose.
#>
function Get-PimSourceJsFunctionBody {
    <#
    .PARAMETER Text
        The full text of pim-manager.html (or any file with the same indent convention).
    .PARAMETER Name
        The JS function name, matched exactly and case-sensitively.
    .PARAMETER Indent
        Column the top-level definition sits at. 2 in pim-manager.html.
    .PARAMETER MinLength
        Sanity floor; a shorter body is treated as a failed isolation and throws.
    .PARAMETER SkipBraceCheck
        Do not cross-check the indentation boundary against a brace count. Only for testing the
        helper itself -- in normal use the cross-check is the reason to trust the indent rule.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Name,
        [int]$Indent = 2,
        [int]$MinLength = 40,
        [switch]$SkipBraceCheck
    )

    $pad    = ' ' * $Indent
    $esc    = [regex]::Escape($Name)
    # Case-SENSITIVE (JS names are). (?![\w$]) so `confExempt` does not match `confExemptRow`.
    $anchor = [regex]::new('(?m)^' + $pad + '(?:async\s+)?function\s+' + $esc + '(?![\w$])\s*\(')
    $m = $anchor.Match($Text)
    if (-not $m.Success) {
        $deeper = [regex]::IsMatch($Text, '(?m)^' + $pad + '\s+(?:async\s+)?function\s+' + $esc + '(?![\w$])')
        $arrow  = [regex]::IsMatch($Text, '(?m)^\s*(?:const|let|var)\s+' + $esc + '\s*=')
        $hint = if ($deeper) {
            "it IS present but nested deeper than indent $Indent -- a nested function has no top-level body to isolate"
        } elseif ($arrow) {
            "it is bound as a const/let/var (arrow function or expression), which this helper does not isolate"
        } else {
            "no 'function $Name' at indent $Indent -- renamed, moved, or a typo here"
        }
        throw "Get-PimSourceJsFunctionBody: cannot isolate '$Name': $hint. Refusing to return an empty body: every -notmatch over it would pass vacuously."
    }

    $dup = $anchor.Match($Text, $m.Index + $m.Length)
    if ($dup.Success) {
        throw "Get-PimSourceJsFunctionBody: '$Name' is defined more than once at indent $Indent. Asserting over the first would silently ignore the second."
    }

    # End of body: the first following line whose character at $Indent is a closing brace.
    $closer = ([regex]::new('(?m)^' + $pad + '\}')).Match($Text, $m.Index + $m.Length)
    if (-not $closer.Success) {
        throw "Get-PimSourceJsFunctionBody: found 'function $Name' but no closing '$pad}' after it. The file's indentation convention does not hold here, so the boundary cannot be trusted."
    }
    $eol = $Text.IndexOf("`n", $closer.Index)
    $end = if ($eol -ge 0) { $eol + 1 } else { $Text.Length }
    $body = $Text.Substring($m.Index, $end - $m.Index)

    if ($body.Trim().Length -lt $MinLength) {
        throw "Get-PimSourceJsFunctionBody: isolated body for '$Name' is only $($body.Trim().Length) chars (floor $MinLength). That is an isolation failure, not a small function."
    }

    # The cross-check that makes the indentation rule trustworthy rather than merely convenient.
    if (-not $SkipBraceCheck) {
        $depth = Get-PimJsBraceBalance -Text $body
        if ($depth -ne 0) {
            throw "Get-PimSourceJsFunctionBody: the body isolated for '$Name' has a brace balance of $depth, not 0. The indent-$Indent boundary and the brace structure DISAGREE, so one of them is wrong -- refusing to return a body that is silently too long or too short."
        }
    }
    $body
}

<#
.SYNOPSIS
    Net brace balance of a JS fragment, ignoring braces inside strings, template literals and
    comments. Used to verify Get-PimSourceJsFunctionBody's indentation boundary.
.NOTES
    Deliberately NOT a JS parser. It handles '...', "...", `...`, // and /* */ -- which is what
    pim-manager.html actually contains. It does NOT understand regex literals; a `{` inside one
    would skew the count. That is the safe direction to be wrong in: the caller THROWS on a
    non-zero balance, so an unhandled construct fails loudly and gets fixed, rather than silently
    widening a scan. (Measured 2026-09-02: zero disagreements across all 291 top-level functions
    in pim-manager.html, so no such literal is in play today.)
#>
function Get-PimJsBraceBalance {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    $depth = 0; $i = 0; $n = $Text.Length
    $inBlock = $false; $inTpl = $false
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($inBlock) {
            if ($c -eq '*' -and $i + 1 -lt $n -and $Text[$i + 1] -eq '/') { $inBlock = $false; $i += 2; continue }
            $i++; continue
        }
        if ($inTpl) {
            if ($c -eq '\') { $i += 2; continue }
            if ($c -eq '`') { $inTpl = $false }
            $i++; continue
        }
        if ($c -eq '/' -and $i + 1 -lt $n -and $Text[$i + 1] -eq '/') {
            $nl = $Text.IndexOf("`n", $i); if ($nl -lt 0) { break }; $i = $nl + 1; continue
        }
        if ($c -eq '/' -and $i + 1 -lt $n -and $Text[$i + 1] -eq '*') { $inBlock = $true; $i += 2; continue }
        if ($c -eq '`') { $inTpl = $true; $i++; continue }
        if ($c -eq "'" -or $c -eq '"') {
            # 🪤 A quoted JS string CANNOT contain a raw newline, so the scan for the closing
            # quote stops at end of line. That is not a shortcut, it is what makes this scanner
            # survive REGEX LITERALS: pim-manager.html contains /[&<>"']/g and /[",\r\n]/, whose
            # quote characters would otherwise open a "string" that swallows every brace until
            # the next matching quote hundreds of lines away. Bounding the scan to the line
            # confines any such confusion to that one line -- and a regex literal's own braces
            # are balanced within it. (Measured: with this bound, all 291 top-level functions in
            # pim-manager.html balance to 0; without it, escapeHtml, csvCell and applyBulkFix do
            # not.)
            $q = $c; $i++
            while ($i -lt $n -and $Text[$i] -ne "`n") {
                if ($Text[$i] -eq '\') { $i += 2; continue }
                if ($Text[$i] -eq $q) { $i++; break }
                $i++
            }
            continue
        }
        if ($c -eq '{') { $depth++ } elseif ($c -eq '}') { $depth-- }
        $i++
    }
    $depth
}
