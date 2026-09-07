#Requires -Version 5.1
<#
.SYNOPSIS
    §37.3 -- a static assertion about a FUNCTION must be scoped to that function, never to a
    guessed character window around it. Offline, no tenant, no store: this reads the test suite
    itself and refuses the pattern that keeps producing guards which stop guarding.

.DESCRIPTION
    THE DEFECT, in the shape it actually appeared. Most static tests here assert something about a
    named function by anchoring on `function <Name>` and bounding the wildcard:

        $src -notmatch '(?s)function Add-PimJobRunRecord' + a bounded wildcard + 'Invoke-PimJobRunAlert'

    That bound is a GUESS at the function's length, and on 2026-09-01 it was measured wrong at
    EVERY ONE of the 18 sites that existed -- in both directions:

      * TOO SMALL on a NEGATIVE assertion is the dangerous one, because it does not fail, it stops
        testing. The forbidden construct sits past the window, the regex does not match,
        `-notmatch` is TRUE, and the suite is GREEN while the thing it forbids is present.
        Session 37 hit this when adding a parameter pushed an INSERT past a 1200-char bound; the
        positive twin failed loudly, the negative one would have passed VACUOUSLY.
        Get-PimSqlAuditEvents was 1907 characters behind a 2000 window -- about five lines of
        headroom before it went silent. DEMONSTRATED, not inferred: with the construct planted
        past the window, the old assertion passed while it was present.

      * TOO BIG on a POSITIVE assertion is quieter, and was also live. The window runs off the end
        of the function into the NEXT ones, so "function X does Y" only ever proved "Y appears
        within N characters of where X starts". Write-PimMutationLog is 969 characters and carried
        a 3000 window: moving its audited call OUT of the function still passed.

      * TOO SMALL on a POSITIVE assertion merely fails loudly, but it is still wrong -- a refactor
        that only MOVES the target later in the function goes red for nothing.
        Get-PimActiveAssignmentsCached is 22755 characters and carried windows of 1400 and 3000,
        so two assertions could see 6% and 13% of the function they named.

    THE RULE. A live (non-comment) line in tests\ may not anchor a bounded wildcard on a
    PowerShell `function Verb-Noun` definition, and may not hand-cut a body with
    IndexOf('function ...') feeding a Substring capped by [Math]::Min. Use
    Get-PimSourceFunctionBody (tests\_shared\PimSourceScope.ps1) instead: the window becomes
    exactly the claim, no bound needs choosing, and it cannot rot as the function grows.

    🔑 NO EXEMPTION LIST, deliberately. Comments are excluded by the scan, so the illustrations in
    this file and in PimSourceScope.ps1 are admitted by the rule itself rather than by a list that
    would need pruning. Session 37's §37 gate needed two lists because its subject (GUI fields) has
    legitimate exceptions; this rule has none, and a list nobody can justify rots into a record of
    problems that no longer exist.

    §37.4 -- THE JAVASCRIPT HALF, which §37.3 recorded as unfixed. Get-PimSourceJsFunctionBody
    isolates a top-level JS function out of pim-manager.html by the file's indent-2 convention,
    cross-checked against a string/template/comment-aware brace count (they agree on all 291
    top-level functions, and the helper THROWS if they ever stop agreeing).

    🔴 READ THIS BEFORE TRUSTING A GREEN RUN: THIS GATE CLAIMS 7 OF THE 16 CONVERSIONS. The rule
    below can only see a window anchored on a literal `function <name>`. Nine of the sites §37.4
    fixed were anchored on a BARE NAME (renderAuthoring[\s\S]{0,400}...), which is textually
    IDENTICAL to the call-site proximity windows that must stay legal. No purely textual rule can
    separate them, so those nine fixes are NOT protected from regression -- see TEST-34 in
    docs/REQUIREMENTS.md. A green run here does not mean the class cannot come back.

    16 JS-anchored windows were measured on 2026-09-02 and the window was wrong at every one:
      * confExempt carried a 1200 window over an 1177-character body -- TOO BIG, reaching into
        confDeploy.
      * injectTabGuidance carried 400 over 410 -- nine characters from the same fault.
      * renderAuthoring carried 400 and 800 over 22633; renderRolePerms 1400 over 22195.
      * The two NEGATIVE assertions in Test-PimDownlinkGui bounded renderDownlink at 6000 over
        11724 -- the direction that does not fail but stops testing. Said precisely: that is NOT
        5723 unscanned characters, because -match retries from every occurrence of the anchor and
        the name recurs inside its own body, so the covered region is the union of windows after
        each mention. It is unknowable without measuring and it moves when the name is added or
        removed. That is the defect: coverage as an emergent property of where a string repeats.
    🪤 AND THE ANCHOR ITSELF WAS OFTEN WRONG, not just the bound. A bare-name anchor matches the
    FIRST mention, and for every render* panel that is switchTab's dispatch table, not the
    definition: renderAuthoring first appears 289387 characters before its own body. Those
    assertions described the dispatcher. (Demonstrated: they do still catch a removed gate today,
    because no matching text happens to sit near the dispatcher -- an accident of layout, not a
    property of the test.)

    §37.4 -- AND SESSION 38'S "IndexOf..IndexOf IS SAFE" REASONING WAS HALF RIGHT. That pair does
    fail loudly on REORDER or REMOVAL (negative length throws). It is SILENT on OVER-REACH, and
    that was live: Test-PimAccountGrid cut its "grid region" from `function renderAccountGrid` to
    `async function renderAccounts` -- 9092 characters against a 5814-character function, swallowing
    acctRevokeSessions and acctFlagForDeletion whole. renderAccountGrid contains no write calls at
    all, so every endpoint the scan credited to the grid came from the swallowed code, and the
    suite's own "the scan is not vacuous" guard was passing on out-of-scope source. It is now an
    explicit union of NAMED functions. That case was found by measuring the pairs, which is what
    session 38 recorded it had NOT done.
    🪤 And naming the surface exposed a SECOND fail-open in the same scan: it knew only ONE CALL
    IDIOM. The grid has three destructive verbs, and resetAdminTap writes with a raw
    `await fetch('/api/admin-tap/reset', { method: 'POST' })` that the `api\(` regex cannot see at
    all. The tell was a DEAD ALLOW-LIST ENTRY -- $allowed already named that endpoint, so the write
    was meant to be scanned and never was. Both idioms are matched now, and the anti-vacuity floor
    is the real verb count rather than "at least one".

    ⚠️ WHAT THIS GATE STILL DOES **NOT** COVER -- stated so nobody reads a pass as more than it is:
      * A hyphen-less PowerShell function name would slip through the PowerShell rule. There are
        none in the scanned assertions today; if one appears, that rule will not see it.
      * Windows anchored on something OTHER than a function definition -- an endpoint path, an
        HTML marker, an element id (Test-PimDirectorySearch, Test-PimPortalProfileSource,
        Test-PimManagerHostedSim, Test-PimAuthoringDropdowns). Same family of risk, different
        anchor, and no "function" to isolate. Still unfixed.
      * CALL-SITE proximity windows are deliberately NOT claimed by either rule and must not be
        "converted". "a call to X sits near Y" is a different claim from "X's body contains Y",
        and scoping the first to a body does not tighten it -- it replaces it with something it
        cannot prove. Test-PimAuthoringDropdowns asserts the call-site kind on purpose.
      * A multi-function region cut with IndexOf..IndexOf is still allowed, because a region
        spanning several functions is sometimes exactly the intent (Test-PimGuiConformanceModal's
        conformance block). Over-reach there cannot be told from intent statically -- section 6
        pins the extents that ARE meant to be one function.

    It also pins the helper's own contract, which is the load-bearing part: it THROWS rather than
    returning an empty body. A silently-empty body makes every `-notmatch` over it pass -- the
    exact vacuous-green defect, reintroduced wearing a helper's clothes.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$testsDir = $PSScriptRoot
. "$testsDir\_shared\PimSourceScope.ps1"

# Comments are not assertions -- but they must be BLANKED IN PLACE, not deleted, or every line
# number this gate reports is wrong by however many comment lines preceded it. (The first draft
# of this file deleted them and pointed at innocent lines.)
function Get-LiveLines([string]$text) {
    $t = [regex]::Replace($text, '(?s)<#.*?#>', { param($m) ($m.Value -replace '[^\r\n]', '') })
    @($t -split "`r`n|`n" | ForEach-Object { if ($_ -match '^\s*#') { '' } else { $_ } })
}

# A bounded wildcard anchored on a PowerShell function DEFINITION (Verb-Noun: the hyphen is what
# separates these from the JavaScript names this rule deliberately does not claim to cover).
# Covers the .{0,N}, [\s\S]{0,N} and `function X \{.{0,N}` forms.
$windowRx = [regex]'function\s+[A-Za-z]\w*-\w[\w-]*\s*(?:\\?\{)?(?:\.|\[\\s\\S\]|\[\^[^\]]*\])\{\d*,\d+\}'
# §37.4 -- the same shape anchored on a JAVASCRIPT function definition. The discriminator is the
# absence of the Verb-Noun hyphen, which is what splits the two rules; `async` is optional and
# common here (renderAuthoring, confExempt and renderAccountGrid are all async).
# 🪤 The gap between the name and the wildcard has to tolerate a whole escaped signature, not one
# optional brace: the live sites wrote `function switchTab\(`, `async function renderAuthoring\(\)`
# and `function X \{`. A first cut allowed only a single `\(` and silently missed the `\(\)` form
# -- a rule with a blind spot reports "0 offenders" exactly like a clean tree does.
$jsWindowRx = [regex]'(?:async\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*(?:\\?[(){}]|\s)*(?:\.|\[\\s\\S\]|\[\^[^\]]*\])\{\d*,\d+\}'
# The hand-cut body: IndexOf("function ...") feeding a Substring capped by Min within 2 lines.
# NOT bare IndexOf("function ...") -- the IndexOf(start)..IndexOf(nextFunction) pairs elsewhere in
# this suite are real isolation, and they fail LOUDLY (negative length throws) rather than
# vacuously. Flagging them would be flagging correct code.
$idxRx = [regex]'IndexOf\(\s*["'']function '
$minRx = [regex]'Substring\([^)]*\[Math\]::Min\('

Write-Host "`n== 1. no live assertion anchors a bounded window on a function ==" -ForegroundColor Cyan

$files = @(Get-ChildItem -LiteralPath $testsDir -Filter '*.ps1' -File) +
         @(Get-ChildItem -LiteralPath (Join-Path $testsDir '_shared') -Filter '*.ps1' -File -ErrorAction SilentlyContinue)

$offenders = New-Object System.Collections.Generic.List[string]
$jsOffenders = New-Object System.Collections.Generic.List[string]
$cutters   = New-Object System.Collections.Generic.List[string]
foreach ($f in $files) {
    $live = Get-LiveLines ([IO.File]::ReadAllText($f.FullName))
    for ($n = 0; $n -lt $live.Count; $n++) {
        if ($windowRx.IsMatch($live[$n]))   { $offenders.Add("$($f.Name):$($n+1)") }
        if ($jsWindowRx.IsMatch($live[$n])) { $jsOffenders.Add("$($f.Name):$($n+1)") }
        if ($idxRx.IsMatch($live[$n])) {
            $look = @($live[$n..([Math]::Min($n + 2, $live.Count - 1))]) -join "`n"
            if ($minRx.IsMatch($look)) { $cutters.Add("$($f.Name):$($n+1)") }
        }
    }
}

foreach ($o in $offenders) { Write-Host "      bounded window: $o" -ForegroundColor Yellow }
T 'no bounded window anchored on a PowerShell function' ($offenders.Count -eq 0)
foreach ($o in $jsOffenders) { Write-Host "      JS window:      $o" -ForegroundColor Yellow }
T 'no bounded window anchored on a JavaScript function' ($jsOffenders.Count -eq 0)
foreach ($o in $cutters) { Write-Host "      hand-cut body:  $o" -ForegroundColor Yellow }
T 'no IndexOf(function)+Substring(Min) hand-cut body'   ($cutters.Count -eq 0)

# "0 offenders" must mean "I looked", not "I read nothing".
T 'the scan actually read the suite'   ($files.Count -ge 20)
T '   ...including the shared helper'  ([bool]($files | Where-Object { $_.Name -eq 'PimSourceScope.ps1' }))
T '   ...and this gate itself'         ([bool]($files | Where-Object { $_.Name -eq 'Test-PimAssertionScope.ps1' }))

Write-Host "`n== 2. the scan is not vacuous: a planted violation IS caught ==" -ForegroundColor Cyan
# A gate that cannot fail is not a gate. These probes are assembled from fragments on purpose --
# written whole they would be violations of this gate's own rule, sitting in this gate.
$fn = 'function Foo-Bar'
T 'a .{0,N} window is detected'      ($windowRx.IsMatch("`$s -notmatch '(?s)$fn" + '.{0,1200}?Baz' + "'"))
T 'a [\s\S]{0,N} window is detected' ($windowRx.IsMatch("`$s -match '$fn" + '[\s\S]{0,900}?Baz' + "'"))
T 'a brace-form window is detected'  ($windowRx.IsMatch("`$s -match '(?s)$fn \{" + '.{0,3000}?Baz' + "'"))
T 'the hand-cut idiom is detected'   ($minRx.IsMatch('$b = $src.Substring($j, [Math]::Min(5000, $src.Length - $j))') -and
                                      $idxRx.IsMatch('    $j = $src.IndexOf("function $fn")'))
# ...and the legitimate forms are NOT flagged, or the rule just moves the problem elsewhere.
T 'a PROXIMITY window (no function anchor) is allowed' (-not $windowRx.IsMatch('$s -match ' + "'(?s)Get-PimManagerRole" + '.{0,300}?New-PimCommitSnapshot' + "'"))
T 'a scoped assertion is allowed'    (-not $windowRx.IsMatch("(Get-PimSourceFunctionBody -Text `$s -Name 'Foo-Bar') -notmatch 'Baz'"))
T 'an IndexOf..IndexOf isolation is allowed' (-not $minRx.IsMatch('$wsBody = $sql.Substring($wsIdx, $wsEnd - $wsIdx)'))

# §37.4 -- the JS rule, which used to be the documented hole. Same construction: assembled from
# fragments, because written whole these lines would violate the rule they are testing.
$jsFn = 'function pimConfirm'
T 'a JS .{0,N} window is detected'        ($jsWindowRx.IsMatch("`$html -match '$jsFn" + '[\s\S]{0,200}return new Promise' + "'"))
T 'an ASYNC JS window is detected'        ($jsWindowRx.IsMatch("`$html -match 'async function confExempt" + '[\s\S]{0,1200}api' + "'"))
T 'a JS window with escaped parens is detected' ($jsWindowRx.IsMatch("`$html -match 'function switchTab\(" + '[\s\S]{0,400}injectTabGuidance' + "'"))
# 🪤 the `\(\)` PAIR, which the first cut of this rule missed entirely
T 'a JS window with an escaped paren PAIR is detected' ($jsWindowRx.IsMatch("`$html -match 'async function renderAuthoring\(\)" + '[\s\S]{0,900}?roleAtLeast' + "'"))
T 'a JS brace-form window is detected'     ($jsWindowRx.IsMatch("`$html -match 'function renderAudit \{" + '[\s\S]{0,400}isServer' + "'"))
# ...and the two rules must stay on their own sides of the hyphen, or one of them is redundant
# and the error messages point at the wrong helper.
T 'the JS rule does NOT claim a PowerShell function' (-not $jsWindowRx.IsMatch("`$s -notmatch '(?s)function Add-PimJobRunRecord" + '.{0,1200}?Invoke' + "'"))
T 'the PowerShell rule does NOT claim a JS function' (-not $windowRx.IsMatch("`$html -match '$jsFn" + '[\s\S]{0,200}return new Promise' + "'"))
T 'a scoped JS assertion is allowed'      (-not $jsWindowRx.IsMatch("(Get-PimSourceJsFunctionBody -Text `$html -Name 'pimConfirm') -match 'return new Promise'"))
# A call-site proximity window is NOT a function window and must stay allowed -- converting those
# would change what they claim rather than tighten it.
T 'a JS CALL-SITE proximity window is allowed' (-not $jsWindowRx.IsMatch("`$html -match 'collectKnownGroupTags\(\)" + '[\s\S]{0,160}aBaGroupList' + "'"))

Write-Host "`n== 3. the helper THROWS rather than returning an empty body ==" -ForegroundColor Cyan
# This is the property everything above rests on. If it ever returns '' instead, every -notmatch
# scoped through it passes and the whole class of defect returns silently.
$sample = "function Alpha-One {`r`n    `$x = 'aaaaaaaaaaaaaaaaaaaa'`r`n    Some-Call`r`n}`r`nfunction Beta-Two {`r`n    `$y = 'bbbbbbbbbbbbbbbbbbbb'`r`n    Other-Call`r`n}`r`n"

$threw = $false
try { $null = Get-PimSourceFunctionBody -Text $sample -Name 'Missing-Fn' } catch { $threw = $true }
T 'a missing function throws'          $threw

$threw = $false
try { $null = Get-PimSourceFunctionBody -Text "function Outer-Fn {`r`n    function Inner-Fn {`r`n        'x'`r`n    }`r`n}`r`n" -Name 'Inner-Fn' } catch { $threw = $true }
T 'a NESTED function throws'           $threw

$dupe = ("function Dup-Fn {`r`n" + ("    `$z = 'xxxxxxxxxx'`r`n" * 6) + "}`r`n") * 2
$threw = $false
try { $null = Get-PimSourceFunctionBody -Text $dupe -Name 'Dup-Fn' } catch { $threw = $true }
T 'a DUPLICATE definition throws'      $threw

$threw = $false
try { $null = Get-PimSourceFunctionBody -Text "function Tiny-Fn { }`r`n" -Name 'Tiny-Fn' } catch { $threw = $true }
T 'an implausibly short body throws'   $threw

Write-Host "`n== 4. the helper isolates the RIGHT text ==" -ForegroundColor Cyan
$a = Get-PimSourceFunctionBody -Text $sample -Name 'Alpha-One'
T 'it returns the named function'      ($a -match 'Some-Call')
T '   ...and STOPS at the next one'    ($a -notmatch 'Other-Call')
T '   ...keeping the header line'      ($a -match '^function Alpha-One')

# A prefix name must not match a longer one -- Set-PimManagerDownlinkPolicy vs ...PolicyMany is a
# real pair in this repo, and getting it wrong asserts about a different function entirely.
$pair = "function Do-Thing {`r`n    `$a = 'first first first'`r`n    Marker-One`r`n}`r`nfunction Do-ThingMany {`r`n    `$b = 'second second'`r`n    Marker-Two`r`n}`r`n"
$one  = Get-PimSourceFunctionBody -Text $pair -Name 'Do-Thing'
T 'a prefix name does not match the longer one'  (($one -match 'Marker-One') -and ($one -notmatch 'Marker-Two'))
$many = Get-PimSourceFunctionBody -Text $pair -Name 'Do-ThingMany'
T '   ...and the longer one resolves to itself'  (($many -match 'Marker-Two') -and ($many -notmatch 'Marker-One'))

# Nested functions belong to their PARENT's body -- excluding them would silently narrow the scan.
$withNested = "function Host-Fn {`r`n    function Helper-Fn {`r`n        Inner-Call`r`n    }`r`n    Outer-Call`r`n}`r`nfunction After-Fn {`r`n    `$q = 'tail tail tail'`r`n    Late-Call`r`n}`r`n"
$h = Get-PimSourceFunctionBody -Text $withNested -Name 'Host-Fn'
T 'a nested function stays INSIDE the parent body' (($h -match 'Inner-Call') -and ($h -match 'Outer-Call') -and ($h -notmatch 'Late-Call'))

# The last function in a file has no following `function` to stop at: it must run to EOF.
$last = Get-PimSourceFunctionBody -Text $sample -Name 'Beta-Two'
T 'the LAST function runs to end of file' ($last -match 'Other-Call')

Write-Host "`n== 5. the real call sites resolve (a rename crashes, it does not pass) ==" -ForegroundColor Cyan
# Every function the suite now scopes to, isolated for real. If one is renamed and a caller is not
# updated, this goes red HERE with a clear message, instead of that caller going quietly green.
$root = Split-Path -Parent $PSScriptRoot
$targets = @(
    @{ f = 'tools\pim-manager\Open-PimManager.ps1';    n = 'Write-PimManagerAuditEvent' }
    @{ f = 'tools\pim-manager\Open-PimManager.ps1';    n = 'Write-PimMutationLog' }
    @{ f = 'tools\pim-manager\Open-PimManager.ps1';    n = 'Set-PimManagerEmergencyOverride' }
    @{ f = 'tools\pim-manager\Open-PimManager.ps1';    n = 'Set-PimManagerWarningOverrides' }
    @{ f = 'tools\pim-manager\Open-PimManager.ps1';    n = 'Set-PimManagerConformanceExemptions' }
    @{ f = 'tools\pim-manager\Open-PimManager.ps1';    n = 'Get-PimActiveAssignmentsCached' }
    @{ f = 'engine\_shared\PIM-SqlStore.ps1';          n = 'Get-PimSqlAuditEvents' }
    @{ f = 'engine\_shared\PIM-Functions.psm1';        n = 'Write-PimAuditEvent' }
    @{ f = 'engine\_shared\PIM-Scheduler.ps1';         n = 'Add-PimJobRunRecord' }
    @{ f = 'engine\_shared\PIM-EngineProviders.ps1';   n = 'Test-PimNameAlreadyLive' }
    @{ f = 'engine\_shared\PIM-EngineProviders.ps1';   n = 'New-PimAdministrativeUnitsProvider' }
    @{ f = 'engine\_shared\PIM-EngineProviders.ps1';   n = 'New-PimGroupsProvider' }
    @{ f = 'engine\_shared\PIM-EngineProviders.ps1';   n = 'New-PimRolesAUsProvider' }
    @{ f = 'engine\_shared\PIM-EngineProviders.ps1';   n = 'New-PimGroupMembersProvider' }
    @{ f = 'engine\_shared\PIM-EngineProviders.ps1';   n = 'New-PimAdminMembersProvider' }
    @{ f = 'engine\_shared\PIM-EngineProviders.ps1';   n = 'New-PimEntraRolesProvider' }
    @{ f = 'engine\_shared\PIM-EngineProviders.ps1';   n = 'New-PimAzResProvider' }
    @{ f = 'engine\_shared\PIM-Downlink.ps1';          n = 'Invoke-PimManagedDownlink' }
    @{ f = 'engine\_shared\PIM-DownlinkManager.ps1';   n = 'Set-PimManagerDownlinkPolicy' }
    @{ f = 'engine\_shared\PIM-DownlinkManager.ps1';   n = 'Set-PimManagerDownlinkPolicyMany' }
    @{ f = 'engine\_shared\PIM-DownlinkManager.ps1';   n = 'Set-PimProjectionReach' }
    @{ f = 'tools\setup\Initialize-PimMailSender.ps1'; n = 'Fail' }
)
$bad = New-Object System.Collections.Generic.List[string]
foreach ($t in $targets) {
    $fp = Join-Path $root $t.f
    if (-not (Test-Path -LiteralPath $fp)) { $bad.Add("$($t.f) MISSING"); continue }
    try { $null = Get-PimSourceFunctionBody -Text ([IO.File]::ReadAllText($fp)) -Name $t.n }
    catch { $bad.Add("$($t.n) in $($t.f): $($_.Exception.Message)") }
}
foreach ($b in $bad) { Write-Host "      $b" -ForegroundColor Yellow }
T "all $($targets.Count) scoped call sites still resolve" ($bad.Count -eq 0)

Write-Host "`n== 6. the JS isolator: contract, then the real call sites ==" -ForegroundColor Cyan
# Same contract as the PowerShell twin, and for the same reason: an empty body makes every
# -notmatch over it pass.
$jsSample = "  function alphaOne(a) {`r`n    const x = 'aaaaaaaaaaaaaaaaaaaa';`r`n    someCall();`r`n  }`r`n  function betaTwo(b) {`r`n    const y = 'bbbbbbbbbbbbbbbbbbbb';`r`n    otherCall();`r`n  }`r`n"

$threw = $false
try { $null = Get-PimSourceJsFunctionBody -Text $jsSample -Name 'missingFn' } catch { $threw = $true }
T 'JS: a missing function throws'        $threw

$threw = $false
try { $null = Get-PimSourceJsFunctionBody -Text ($jsSample + $jsSample) -Name 'alphaOne' } catch { $threw = $true }
T 'JS: a DUPLICATE definition throws'    $threw

$threw = $false
try { $null = Get-PimSourceJsFunctionBody -Text "  function tinyFn() { }`r`n" -Name 'tinyFn' } catch { $threw = $true }
T 'JS: an implausibly short body throws' $threw

$threw = $false
try { $null = Get-PimSourceJsFunctionBody -Text "  function outerFn() {`r`n    function innerFn() {`r`n      const q = 'nested nested nested';`r`n    }`r`n  }`r`n" -Name 'innerFn' } catch { $threw = $true }
T 'JS: a NESTED function throws'         $threw

# The brace cross-check is what makes the indentation boundary trustworthy rather than merely
# convenient. If the two ever disagree the helper must refuse, not guess which one is right.
$skew = "  function skewFn() {`r`n    const a = 'aaaaaaaaaaaaaaaaaaaaaa';`r`n    if (a) {`r`n  }`r`n"
$threw = $false
try { $null = Get-PimSourceJsFunctionBody -Text $skew -Name 'skewFn' } catch { $threw = $true }
T 'JS: an indent/brace DISAGREEMENT throws' $threw

$ja = Get-PimSourceJsFunctionBody -Text $jsSample -Name 'alphaOne'
T 'JS: it returns the named function'    ($ja -match 'someCall')
T 'JS:    ...and STOPS at the next one'  ($ja -notmatch 'otherCall')

# A prefix name must not resolve to a longer one. confExempt / confExemptRow is the shape that
# matters here, and it is the JS twin of Set-PimManagerDownlinkPolicy / ...PolicyMany.
$jsPair = "  function doThing() {`r`n    const a = 'first first first';`r`n    markerOne();`r`n  }`r`n  function doThingMany() {`r`n    const b = 'second second';`r`n    markerTwo();`r`n  }`r`n"
$jOne = Get-PimSourceJsFunctionBody -Text $jsPair -Name 'doThing'
T 'JS: a prefix name does not match the longer one' (($jOne -match 'markerOne') -and ($jOne -notmatch 'markerTwo'))

# 🪤 Case matters in JS (it does not in PowerShell's `function` keyword), so the helper must NOT
# resolve a differently-cased name -- that would silently isolate the wrong function.
$threw = $false
try { $null = Get-PimSourceJsFunctionBody -Text $jsSample -Name 'ALPHAONE' } catch { $threw = $true }
T 'JS: matching is CASE-SENSITIVE'       $threw

# Every JS function the suite now scopes to, isolated against the real file. A rename crashes
# HERE with a clear message instead of the caller going quietly green.
$htmlPath = Join-Path $root 'tools\pim-manager\pim-manager.html'
$jsTargets = @('pimConfirm','pimFormModal','confExempt','confRevoke',
               'renderAccountGrid','wireAccountGrid','acctRevokeSessions','acctFlagForDeletion',
               'renderAuthoring','renderOnboarding','renderCutover','renderAudit','renderRolePerms',
               'renderDownlink','switchTab','injectTabGuidance')
$jsBad = New-Object System.Collections.Generic.List[string]
if (-not (Test-Path -LiteralPath $htmlPath)) {
    $jsBad.Add('pim-manager.html MISSING')
} else {
    $htmlSrc = [IO.File]::ReadAllText($htmlPath)
    foreach ($t in $jsTargets) {
        try { $null = Get-PimSourceJsFunctionBody -Text $htmlSrc -Name $t }
        catch { $jsBad.Add("${t}: $($_.Exception.Message)") }
    }
}
foreach ($b in $jsBad) { Write-Host "      $b" -ForegroundColor Yellow }
T "all $($jsTargets.Count) scoped JS call sites still resolve" ($jsBad.Count -eq 0)

# "0 offenders" must mean "I looked" on this side too: the indent-2 convention the boundary rests
# on has to actually hold across the file, not just at the 16 names above.
if (Test-Path -LiteralPath $htmlPath) {
    $allJs = [regex]::Matches($htmlSrc, '(?m)^  (?:async )?function ([A-Za-z_$][A-Za-z0-9_$]*)\s*\(') |
             ForEach-Object { $_.Groups[1].Value }
    $uniqJs = @($allJs | Group-Object | Where-Object { $_.Count -eq 1 } | ForEach-Object { $_.Name })
    $failed = @($uniqJs | Where-Object {
        try { $null = Get-PimSourceJsFunctionBody -Text $htmlSrc -Name $_; $false } catch { $true }
    })
    foreach ($x in $failed) { Write-Host "      cannot isolate: $x" -ForegroundColor Yellow }
    T "the indent-2 boundary holds for every top-level JS function ($($uniqJs.Count))" ($failed.Count -eq 0 -and $uniqJs.Count -ge 200)
}

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
