#Requires -Version 5.1
<#
.SYNOPSIS
    MSP Downlink Manager surface (control #1/#2, framework MSP-2) -- static + pure
    offline checks that the tab, its endpoints and its safety gates are REALLY wired.

    Why static assertions matter here specifically: this surface writes privilege into
    a tenant the operator does not own. The failure that costs most is not a crash but
    a control that LOOKS wired and is not -- a tab with no render, an endpoint with no
    caller, or a write path missing its SuperAdmin gate. Each of those is asserted.

    All OFFLINE: no HTTP, no SQL, no tenant. The Manager script and HTML are read as
    text; the pure helpers are dot-sourced and exercised over fixtures.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
$html = Get-Content -LiteralPath (Join-Path $root 'tools\pim-manager\pim-manager.html') -Raw
$srv  = Get-Content -LiteralPath (Join-Path $root 'tools\pim-manager\Open-PimManager.ps1') -Raw
$lib  = Join-Path $root 'engine\_shared\PIM-DownlinkManager.ps1'

# ===========================================================================
Write-Host "`n== 1. THE TAB IS REACHABLE (a view nobody can open is not a feature) ==" -ForegroundColor Cyan
# ===========================================================================
T 'the flat strip declares data-tab="downlink"' ($html -match 'data-tab="downlink"')
T '  ...and it carries an unresolved badge' ($html -match 'id="downlinkUnresBadge"')
# IMP-16 (2026-08-30): NAV_GROUPS items became { tab, label, desc } objects spread over several
# lines so each menu entry can carry a plain-language description. The old pattern used `.*`,
# which does not cross newlines in .NET regex, so it broke on formatting rather than on meaning.
# `[^\]]*` spans lines and stops at the array close -- the same idiom Test-PimAdminTapReset.ps1
# already uses. The assertion still means exactly what it did: this tab is inside a NAV_GROUP.
T 'the tab is placed in a NAV_GROUP (or the grouped nav drops it)' ($html -match "items: \[[^\]]*'downlink'")
T 'a panel host exists for it' ($html -match 'id="downlinkTab"' -and $html -match 'id="downlinkBody"')
T 'switchTab dispatches to renderDownlink' ($html -match "name === 'downlink'\) renderDownlink\(\)")
T 'renderDownlink is actually defined' ($html -match 'async function renderDownlink\(\)')
T 'the feature catalog registers the tab id' ((Get-Content -LiteralPath (Join-Path $root 'engine\_shared\PIM-FeatureFlags.ps1') -Raw) -match "id = 'downlink'")

# ===========================================================================
Write-Host "`n== 2. THE ENDPOINTS EXIST AND THE GUI CALLS THEM ==" -ForegroundColor Cyan
# ===========================================================================
T 'GET /api/downlink is served' ($srv -match "\`$path -eq '/api/downlink' -and \`$method -eq 'GET'")
T 'PUT /api/downlink/policy is served' ($srv -match "\`$path -eq '/api/downlink/policy' -and \`$method -eq 'PUT'")
T 'POST /api/downlink/run is served' ($srv -match "\`$path -eq '/api/downlink/run' -and \`$method -eq 'POST'")
T 'the GUI GETs /api/downlink' ($html -match "api\('GET', '/api/downlink'\)")
T 'the GUI PUTs the policy' ($html -match "api\('PUT', '/api/downlink/policy'")
T 'the GUI POSTs a run' ($html -match "api\('POST', '/api/downlink/run'")
T 'the Manager dot-sources the downlink library' ($srv -match 'PIM-DownlinkManager\.ps1')

# ===========================================================================
Write-Host "`n== 3. THE SAFETY GATES (this writes privilege into someone else's tenant) ==" -ForegroundColor Cyan
# ===========================================================================
# Slice each handler so a gate present in a NEIGHBOURING handler cannot satisfy the
# assertion -- that is exactly how a missing gate hides in a 9k-line dispatcher.
function Get-Handler([string]$text, [string]$marker) {
    $i = $text.IndexOf($marker); if ($i -lt 0) { return '' }
    $j = $text.IndexOf("`n        if (`$path -eq", $i + 10)
    if ($j -lt 0) { $j = [Math]::Min($text.Length, $i + 4000) }
    return $text.Substring($i, $j - $i)
}
$hPolicy = Get-Handler $srv "'/api/downlink/policy' -and `$method -eq 'PUT'"
$hRun    = Get-Handler $srv "'/api/downlink/run' -and `$method -eq 'POST'"
T 'the policy WRITE requires SuperAdmin' ($hPolicy -match "Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin'")
T '  ...and is audited' ($hPolicy -match "Write-PimManagerAuditEvent -Action 'downlink\.policy\.save'")
T '  ...and REFUSES an unknown Mode rather than coercing it' ($hPolicy -match "invalid Mode" -and $hPolicy -match "return 400")
T 'a real RUN requires SuperAdmin' ($hRun -match "Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin'")
T '  ...but a DRY RUN does not (it changes nothing)' ($hRun -match '-not \$whatIf -and -not \(Test-PimManagerRoleAtLeast')
T '  ...defaulting to whatIf when the caller omits it' ($hRun -match '\$whatIf = \$true')

# ---------------------------------------------------------------------------
# MSP-3: THE MASTER MUST NOT WRITE INTO A MANAGED TENANT.
# An earlier build of this surface did exactly that -- breaking s22 ("MSP never
# writes to a customer tenant") and the pull-not-push tenet, and authenticating as
# the wrong tenant into the bargain. These assertions exist so it cannot come back.
# ---------------------------------------------------------------------------
$dlm = Get-Content -LiteralPath $lib -Raw
T 'MSP-3: an APPLY is REFUSED, not silently downgraded to a preview' ($dlm -match 'REFUSED: the master does not write into a managed tenant')
T '  ...and the refusal explains the pull model instead of just failing' ($dlm -match 'PULLS the signed baseline')
T '  ...so the GUI offers NO apply button at all' (-not ($html -match "class=`"dl-apply`""))
T '  ...and no client handler for one' (-not ($html -match "\.dl-apply"))
T 'MSP-3: the master never reaches into a managed store to WRITE' (-not ($dlm -match 'Invoke-PimDownlinkAdminApply|Invoke-PimDownlinkDefinitionApply|Invoke-PimDownlinkAssignmentApply'))
# Match the CALL, not the word: the file explains at length why it does not pass
# -SlaveGroupTags, and a bare word-match would be satisfied by that explanation.
T '  ...nor to READ (customer data never leaves their tenant)' (-not ($dlm -match "\`$planArgs\['SlaveGroupTags'\]" -or $dlm -match '-SlaveGroupTags '))
T '  ...and it no longer SELECTs a customer store coordinate' (-not ($dlm -match 'SELECT[^;]*StoreServer'))

# The projection policy is DELETE-then-INSERT, and "no rows" means ALLOW ALL -- so a
# half-applied write would silently WIDEN privilege. It must be one transaction.
T 'the policy write is transactional (a failure must not leave allow-all)' ($dlm -match 'BeginTransaction' -and $dlm -match 'Rollback')
T '  ...and validates BEFORE writing anything' ($dlm -match 'nothing was written')
T 'the baseline banner reports a REAL verification, not a hardcoded true' ($dlm -match 'Test-PimDownlinkBaseline -Doc \$bl\.doc')

# ===========================================================================
Write-Host "`n== 4. THE GUI RENDERS THE PLAN -- it must not form a second opinion ==" -ForegroundColor Cyan
# ===========================================================================
# The projection is decided server-side from the SIGNED bundle. If the browser
# re-derived it, the preview and the apply could disagree about who holds privilege.
T 'the view states the no-recompute rule' ($html -match 'NEVER RECOMPUTES')
# §37.4 -- these two are NEGATIVE assertions, the direction where a short window does not fail but
# simply STOPS TESTING: the forbidden construct sits past the bound, -notmatch is true, and the
# suite is green while the thing it forbids is present. The old bound was 6000 characters over an
# 11724-character function. 📌 That does NOT mean 5723 characters went unscanned: -match retries
# from EVERY occurrence of the anchor, and `renderDownlink` recurs inside its own body, so the
# covered region is the union of 6000-char windows after each mention -- unknowable without
# measuring, and it shifts whenever the name is added or removed. Demonstrated: with `Ring <=`
# planted at the very end the old assertion STILL caught it. The defect is not a proven hole; it is
# that coverage was an emergent property of where a string happens to repeat. Scoped to the body,
# it is the whole function by construction.
. (Join-Path $PSScriptRoot '_shared\PimSourceScope.ps1')
$jsRenderDownlink = Get-PimSourceJsFunctionBody -Text $html -Name 'renderDownlink'
T 'no client-side ring filtering' (-not ($jsRenderDownlink -match 'Ring\s*<='))
T 'no client-side allow/deny evaluation' (-not ($jsRenderDownlink -match "Mode === 'deny' \?\?"))
T 'excluded and unresolved are shown SEPARATELY (they mean different things)' ($html -match 'Held back' -and $html -match 'the role cannot be granted here')

# ===========================================================================
Write-Host "`n== 5. THE PURE HELPERS ==" -ForegroundColor Cyan
# ===========================================================================
T 'the downlink-manager library exists' (Test-Path -LiteralPath $lib)
$e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($lib, [ref]$null, [ref]$e)
T '  ...and parses clean under this PowerShell' (@($e).Count -eq 0)
. $lib
foreach ($fn in @('Get-PimManagerDownlinkTenants','Get-PimManagerDownlinkPolicy','Set-PimManagerDownlinkPolicy','Get-PimManagerBaselineDoc','Get-PimManagerDownlinkOverview','Invoke-PimManagerDownlinkRun')) {
    T "  ...defines $fn" ([bool](Get-Command $fn -ErrorAction SilentlyContinue))
}

# A missing baseline must be REPORTED, never silently treated as "nothing projects" --
# those two states look identical in the GUI and mean opposite things.
$blMissing = Get-PimManagerBaselineDoc -Path (Join-Path $env:TEMP ('no-such-baseline-' + [guid]::NewGuid().ToString('N') + '.json'))
T 'a MISSING baseline is reported, not treated as an empty projection' ($null -eq $blMissing.doc -and "$($blMissing.error)" -match 'not found')
$blBad = Join-Path $env:TEMP ('bad-baseline-' + [guid]::NewGuid().ToString('N') + '.json')
Set-Content -LiteralPath $blBad -Value 'not json at all' -Encoding ascii
try {
    $r = Get-PimManagerBaselineDoc -Path $blBad
    T 'a CORRUPT baseline is reported, not swallowed' ($null -eq $r.doc -and "$($r.error)" -match 'not valid JSON')
} finally { Remove-Item -LiteralPath $blBad -Force -ErrorAction SilentlyContinue }

# The preview is honest about being a preview -- it must not read as a completed sync.
T 'the preview says plainly that nothing was written' ($dlm -match 'nothing was written')
T '  ...and reports what would be OFFERED, not what was applied' ($dlm -match 'admins offered' -and $dlm -match 'roles offered')

# ===========================================================================
Write-Host "`n== MSP-4: REACH BY ROLE -- the operator's question, transposed ==" -ForegroundColor Cyan
# ===========================================================================
# The per-relationship table answers "what does THIS TENANT get". The operator's ask --
# "this role goes to only 5 of 28 tenants" -- is the INVERSE, and nobody can audit that by
# opening 28 tabs and remembering. Get-PimProjectionReach is that transpose.
. (Join-Path $root 'engine\_shared\PIM-Downlink.ps1')
. (Join-Path $root 'engine\_shared\PIM-DownlinkManager.ps1')
. (Join-Path $PSScriptRoot '_shared\PimSourceScope.ps1')
T 'MSP-4: Get-PimProjectionReach is defined' ($null -ne (Get-Command Get-PimProjectionReach -ErrorAction SilentlyContinue))

$m4rels = @(
    [ordered]@{ tenantId='t1'; name='Alpha'; ring=2
        projected = @([pscustomobject]@{ GroupTag='ROLE-GA' }, [pscustomobject]@{ GroupTag='ROLE-Help' })
        excluded = @(); unresolved = @() }
    [ordered]@{ tenantId='t2'; name='Beta'; ring=2
        projected = @([pscustomobject]@{ GroupTag='ROLE-Help' })
        excluded = @([pscustomobject]@{ GroupTag='ROLE-GA'; reason='denied by relationship policy' })
        unresolved = @() }
    [ordered]@{ tenantId='t3'; name='Gamma'; ring=2
        projected = @()
        excluded = @([pscustomobject]@{ GroupTag='ROLE-GA'; reason='tenant matches none of the target selectors' })
        unresolved = @([pscustomobject]@{ GroupTag='ROLE-Help'; reason='the slave has no group for this tag' }) }
)
$m4 = @(Get-PimProjectionReach -Relationships $m4rels)
$m4ga = @($m4 | Where-Object { $_.groupTag -eq 'ROLE-GA' })[0]
$m4hp = @($m4 | Where-Object { $_.groupTag -eq 'ROLE-Help' })[0]
T '  ...and reports the operator sentence directly ("N of M tenant(s)")' ("$($m4ga.summary)" -eq '1 of 3 tenant(s)')
T '  ...counting only tenants the role actually REACHES' ($m4ga.reachCount -eq 1 -and @($m4ga.reaches)[0].name -eq 'Alpha')
# The four narrowings stay distinguishable -- collapsing them is what makes "why did this
# role not arrive" unanswerable, and each has a different fix.
# 🪤 `(... | Where-Object ...).Count` IS NOT A ROW COUNT when the pipeline returns exactly ONE
# OrderedDictionary: .Count then reports the DICTIONARY'S KEY COUNT. These assertions first read
# `(@($x.withheld) | Where-Object {...}).Count -eq 1` and failed against CORRECT code, reporting 4
# -- the four keys of the single matching row. The @() must wrap the RESULT, not the source:
# `@($x.withheld | Where-Object {...}).Count`. Same family as the recorded "assign or materialise
# FIRST, then wrap" trap; a new place for it to bite.
T '  ...and each withheld tenant carries the PLAN''S OWN reason, not a generic "no"' (
    @($m4ga.withheld | Where-Object { $_.name -eq 'Beta'  -and $_.reason -match 'policy' }).Count -eq 1 -and
    @($m4ga.withheld | Where-Object { $_.name -eq 'Gamma' -and $_.reason -match 'target selectors' }).Count -eq 1)
T '  ...and an UNRESOLVED tag counts as withheld, not as reached (it never lands)' (
    $m4hp.reachCount -eq 2 -and @($m4hp.withheld | Where-Object { $_.name -eq 'Gamma' }).Count -eq 1)
# 🔒 "28 of 28" is not a narrowing. Flagging it is what makes the 5-of-28 rows findable.
T '  ...and flags NARROWED roles so a fully-reaching role does not hide them' (
    $m4ga.narrowed -eq $true)
$m4all = @(Get-PimProjectionReach -Relationships @(
    [ordered]@{ tenantId='t1'; name='Alpha'; ring=2; projected=@([pscustomobject]@{ GroupTag='ROLE-All' }); excluded=@(); unresolved=@() }))
T '  ...a role reaching EVERY tenant is not flagged as narrowed' (@($m4all)[0].narrowed -eq $false)
T '  ...and an empty fleet yields no rows rather than throwing' (@(Get-PimProjectionReach -Relationships @()).Count -eq 0)

# The wiring: an endpoint nobody can call, or a panel nothing fills, is not a surface.
T 'MSP-4: the Manager exposes GET /api/downlink/reach' ($srv -match "'/api/downlink/reach'")
T '  ...and builds it from the SAME overview (the two views cannot disagree)' (
    $srv -match '(?s)/api/downlink/reach.{0,400}?Get-PimManagerDownlinkOverview.{0,200}?Get-PimProjectionReach')
# 🔒 READ-ONLY. Authoring stays on the SuperAdmin-gated, audited policy path; a second write
# route into a customer's privilege is the last thing this surface needs.
T '  ...and is READ-ONLY (no PUT/POST on the reach route)' (-not ($srv -match "'/api/downlink/reach'\s+-and\s+\`$method\s+-eq\s+'(PUT|POST)'"))
T 'MSP-4: the tab has a reach panel and a renderer that fills it' (
    $html -match 'id="downlinkReachWrap"' -and $html -match 'function renderDownlinkReach')
# 🪤 STRIP COMMENTED-OUT LINES FIRST. The first version of this assert matched the raw HTML, so
# commenting the call out (`// renderDownlinkReach();`) still SATISFIED it -- the negative test
# reported green against a deliberately dead control. Same family as the recorded TAP trap: a
# source-scanning assertion must read CODE, or a comment can hold it up on its own.
$htmlCode = (($html -split "`r?`n") | Where-Object { $_ -notmatch '^\s*//' }) -join "`n"
T '  ...and the renderer is actually CALLED (a panel nothing fills is a dead control)' (
    $htmlCode -match 'renderDownlinkReach\(\);')
# 🪤 The reach view is an extra lens, not a prerequisite: if it fails it must degrade to a
# notice, never blank the table the operator came for.
T '  ...and a failing reach query degrades to a notice instead of blanking the tab' (
    $html -match 'Reach view unavailable')
# ===========================================================================
Write-Host "`n== MSP-4/read: THE COUNT IS PER TENANT, AND EVERY NARROWING IS VISIBLE ==" -ForegroundColor Cyan
# ===========================================================================
# 🔴 THE HEADLINE NUMBER WAS WRONG IN THE NORMAL CASE. `projected` carries one row per
# (admin, tag), and the first transpose counted ROWS -- so a tenant where two admins hold the
# same role was counted twice. Measured before the fix: one tenant, two admins, ROLE-GA read
# "2 of 2 tenant(s), not narrowed" when the truth was "1 of 2, NARROWED". With three admins it
# printed "3 of 2" -- an impossible number nobody re-reads, because the sentence looks ordinary.
# 🪤 It failed toward NOT NARROWED: it hid the exact thing this view exists to show.
$m4dup = @(Get-PimProjectionReach -Relationships @(
    [ordered]@{ tenantId='t1'; name='Alpha'; ring=2; projected=@(
        [pscustomobject]@{ UserName='a1'; GroupTag='ROLE-GA' }
        [pscustomobject]@{ UserName='a2'; GroupTag='ROLE-GA' }
        [pscustomobject]@{ UserName='a3'; GroupTag='ROLE-GA' }); excluded=@(); unresolved=@() }
    [ordered]@{ tenantId='t2'; name='Beta'; ring=2; projected=@(); excluded=@(); unresolved=@() }))
T 'MSP-4: three admins holding one role in one tenant is ONE tenant of reach' (
    "$($m4dup[0].summary)" -eq '1 of 2 tenant(s)' -and $m4dup[0].reachCount -eq 1)
T '  ...and the role is therefore reported as NARROWED (the pre-fix answer was "not")' (
    $m4dup[0].narrowed -eq $true)
T '  ...and reach can never exceed the tenant count' ($m4dup[0].reachCount -le $m4dup[0].tenantCount)
# 🪤 FOUND BY NEGATIVE VERIFICATION, NOT BY REVIEW. Dropping the early `return` on the reach
# branch left every projected row ALSO recording a withhold reason -- so a tenant with nothing
# held back came back `partial = $true`. The suite stayed 106/0: three admins still counted as
# one tenant, so the assertions above were all satisfied, and the only visible symptom would
# have been a "*" beside EVERY tenant in the GUI, which is the same as no marker at all.
T '  ...and a tenant with nothing held back is NOT flagged partial (or the flag means nothing)' (
    @($m4dup[0].reaches | Where-Object { $_.partial }).Count -eq 0)

# 🔴 A ROLE NARROWED BY ITS `Target` SELECTOR WAS IN NEITHER LIST. Targeting is applied UPSTREAM
# of the projection, so those rows land in the plan's `notTargeted` -- which the overview used to
# drop on the floor. The tenant then appeared in neither `reaches` nor `withheld`: the denominator
# quietly shrank and the row read as a normal answer. Two of the four narrowings this view
# PROMISES to keep apart could not be seen from it at all.
$m4ax = @(Get-PimProjectionReach -Relationships @(
    [ordered]@{ tenantId='t1'; name='Alpha'; ring=2; projected=@([pscustomobject]@{ UserName='a1'; GroupTag='R' }); excluded=@(); unresolved=@(); notTargeted=@(); classHeld=@() }
    [ordered]@{ tenantId='t2'; name='Beta';  ring=2; projected=@(); excluded=@(); unresolved=@(); classHeld=@()
        notTargeted=@([pscustomobject]@{ kind='role'; UserName='a1'; GroupTag='R'; reason='tenant matches none of the target selectors (tag:eu)' }) }
    [ordered]@{ tenantId='t3'; name='Gamma'; ring=2; projected=@(); excluded=@(); unresolved=@(); notTargeted=@()
        classHeld=@([pscustomobject]@{ kind='role'; UserName='a1'; GroupTag='R'; reason="the customer blocked 'roles' in their own manifest" }) }
    [ordered]@{ tenantId='t4'; name='Delta'; ring=2; projected=@(); unresolved=@(); notTargeted=@(); classHeld=@()
        excluded=@([pscustomobject]@{ UserName='a1'; GroupTag='R'; reason="admin 'a1' did not reach this tenant's ring -- their roles do not either" }) }))
$m4r = $m4ax[0]
T 'MSP-4: a TARGET-narrowed tenant is now WITHHELD, not absent' (
    @($m4r.withheld | Where-Object { $_.name -eq 'Beta' }).Count -eq 1)
T '  ...and carries axis=targeting as a FIELD, not only as prose' (
    @($m4r.withheld | Where-Object { $_.name -eq 'Beta' -and $_.axis -eq 'targeting' }).Count -eq 1)
T '  ...a capability the customer BLOCKED shows as axis=capability' (
    @($m4r.withheld | Where-Object { $_.name -eq 'Gamma' -and $_.axis -eq 'capability' }).Count -eq 1)
T '  ...and a ring exclusion as axis=ring' (
    @($m4r.withheld | Where-Object { $_.name -eq 'Delta' -and $_.axis -eq 'ring' }).Count -eq 1)
# 🔒 THE ACCOUNTING LINE: reaches + withheld against the tenant count. This is the assertion that
# would have caught the bug above on the day it shipped -- "absent" has no other symptom.
T '  ...and every tenant is ACCOUNTED FOR (the bug above had no other symptom)' (
    $m4r.accountedFor -eq 4 -and $m4r.unaccounted -eq 0)
$m4gap = @(Get-PimProjectionReach -Relationships @(
    [ordered]@{ tenantId='t1'; name='Alpha'; ring=2; projected=@([pscustomobject]@{ UserName='a1'; GroupTag='R' }); excluded=@(); unresolved=@() }
    [ordered]@{ tenantId='t2'; name='Beta';  ring=2; projected=@(); excluded=@(); unresolved=@() }))
T "  ...and a tenant the role's plan says NOTHING about is unaccounted, not dropped" (
    $m4gap[0].unaccounted -eq 1 -and @($m4gap[0].unaccountedTenants) -contains 'Beta')

# A tenant where one admin's copy projects and another's is denied DOES receive the role.
$m4part = @(Get-PimProjectionReach -Relationships @(
    [ordered]@{ tenantId='t1'; name='Alpha'; ring=2
        projected=@([pscustomobject]@{ UserName='a1'; GroupTag='R' })
        excluded=@([pscustomobject]@{ UserName='a2'; GroupTag='R'; reason='not in the relationship allow-list' })
        unresolved=@() }))
T 'MSP-4: a tenant that both projects and excludes the same tag REACHES (once)' (
    $m4part[0].reachCount -eq 1 -and @($m4part[0].withheld).Count -eq 0)
T '  ...and is flagged PARTIAL so the withheld admin is not silently lost' (
    @($m4part[0].reaches)[0].partial -eq $true)

# The classifier itself, including the fail-closed answer.
T 'MSP-4: the withhold AXIS is classified in one place' ($null -ne (Get-Command Get-PimProjectionWithholdAxis -ErrorAction SilentlyContinue))
T '  ...bucket beats prose (a notTargeted row is targeting whatever it says)' (
    (Get-PimProjectionWithholdAxis -Bucket 'notTargeted' -Reason 'anything at all') -eq 'targeting')
T '  ...a policy denial classifies as policy' (
    (Get-PimProjectionWithholdAxis -Bucket 'excluded' -Reason "denied by relationship policy (deny 'R')") -eq 'policy' -and
    (Get-PimProjectionWithholdAxis -Bucket 'excluded' -Reason 'not in the relationship allow-list') -eq 'policy')
# 🔒 FAIL CLOSED. An unrecognised reason must NOT fall through to 'policy', because 'policy' is
# the one axis the write half will act on -- and acting on a misread reason writes a rule that
# changes nothing and reports success.
T "  ...and an UNRECOGNISED reason is 'other', never 'policy'" (
    (Get-PimProjectionWithholdAxis -Bucket 'excluded' -Reason 'some future reason nobody wrote yet') -eq 'other')

# ---------------------------------------------------------------------------
# One axis must not wear another's name: both the ring gate and the Target gate drop an admin
# from -AdminUserNames, so from inside the projection they were indistinguishable -- and the
# message said "ring" for both. They have DIFFERENT FIXES (raise a ring vs rewrite a Target).
# ---------------------------------------------------------------------------
$ntA = @([pscustomobject]@{ UserName='u1'; GroupTag='R' })
$ntRing = Select-PimProjectedAssignments -Assignments $ntA -AdminUserNames @('other')
T 'MSP-4: an admin dropped by the RING still says ring' (@($ntRing.excluded)[0].reason -match 'ring')
$ntTgt = Select-PimProjectedAssignments -Assignments $ntA -AdminUserNames @('other') -NotTargetedAdminNames @('u1')
T '  ...but one dropped by TARGETING says targeting, not ring' (
    @($ntTgt.excluded)[0].reason -match 'not TARGETED' -and @($ntTgt.excluded)[0].reason -notmatch 'ring')
# 🔴 SESSION 32's ONE DEFECT SHAPE: a parameter DECLARED on the callee and never PASSED by the
# caller binds nothing, raises nothing, and leaves the gate looking wired. Assert the forward.
$dlSrc = Get-Content -LiteralPath (Join-Path $root 'engine\_shared\PIM-Downlink.ps1') -Raw
T '  ...and the plan actually FORWARDS it (declared-but-never-passed is the recurring defect)' (
    $dlSrc -match '(?s)\$selArgs = @\{.{0,1200}?NotTargetedAdminNames\s*=')

# ===========================================================================
Write-Host "`n== MSP-4/write: AUTHORING NARROWING ALONG THE TAG AXIS ==" -ForegroundColor Cyan
# ===========================================================================
# The read half was built first ON PURPOSE -- you cannot safely author a narrowing you cannot
# audit. This is the other half. It grants privilege in tenants the operator does not own, so
# the assertions below are mostly about what it REFUSES to do.
T 'MSP-4/write: the edit planner is defined and PURE' ($null -ne (Get-Command Get-PimProjectionReachEdit -ErrorAction SilentlyContinue))

$wRels = @(
    [ordered]@{ tenantId='t1'; name='Alpha'; ring=2; policy=@()
        projected=@([pscustomobject]@{ UserName='a1'; GroupTag='R' }); excluded=@(); unresolved=@(); notTargeted=@(); classHeld=@() }
    [ordered]@{ tenantId='t2'; name='Beta'; ring=2; policy=@([pscustomobject]@{ Mode='deny'; GroupTag='R' })
        projected=@(); unresolved=@(); notTargeted=@(); classHeld=@()
        excluded=@([pscustomobject]@{ UserName='a1'; GroupTag='R'; reason="denied by relationship policy (deny 'R')" }) }
    [ordered]@{ tenantId='t3'; name='Gamma'; ring=2; policy=@()
        projected=@(); excluded=@(); unresolved=@(); classHeld=@()
        notTargeted=@([pscustomobject]@{ kind='role'; UserName='a1'; GroupTag='R'; reason='tenant matches none of the target selectors (tag:eu)' }) }
    [ordered]@{ tenantId='t4'; name='Delta'; ring=2; policy=@([pscustomobject]@{ Mode='deny'; GroupTag='R*' })
        projected=@(); unresolved=@(); notTargeted=@(); classHeld=@()
        excluded=@([pscustomobject]@{ UserName='a1'; GroupTag='R'; reason="denied by relationship policy (deny 'R*')" }) }
    [ordered]@{ tenantId='t5'; name='Eps'; ring=2; policy=@([pscustomobject]@{ Mode='allow'; GroupTag='OTHER' })
        projected=@(); unresolved=@(); notTargeted=@(); classHeld=@()
        excluded=@([pscustomobject]@{ UserName='a1'; GroupTag='R'; reason='not in the relationship allow-list' }) }
)
$wEntry   = @(Get-PimProjectionReach -Relationships $wRels | Where-Object { $_.groupTag -eq 'R' })[0]
$wTenants = @($wRels | ForEach-Object { [ordered]@{ tenantId = $_.tenantId; name = $_.name } })
$wPol     = [ordered]@{}; foreach ($r in $wRels) { $wPol["$($r.tenantId)"] = @($r.policy) }
function New-ReachPlan([string[]]$want) {
    Get-PimProjectionReachEdit -GroupTag 'R' -DesiredTenantIds $want -ReachEntry $wEntry -Tenants $wTenants -CurrentPolicies $wPol
}
# 🪤 A FIXTURE THAT PROVES NOTHING IS THE TRAP THIS SUITE KEEPS PAYING FOR (session 32's empty
# desired set; session 31's premise-false test). So: assert the PREMISE before asserting on it --
# the fixture must really present all five narrowing states, or every refusal below is vacuous.
T 'MSP-4/write: the fixture really presents one tenant per narrowing state' (
    $wEntry.reachCount -eq 1 -and @($wEntry.withheld).Count -eq 4 -and
    @(@($wEntry.withheld) | ForEach-Object { $_.axis } | Sort-Object -Unique) -join ',' -eq 'policy,targeting')
# 🪤 AND THE PREMISE BEHIND THE PREMISE. The first version of this fixture denied `R-*`, which
# does NOT match tag `R` -- the match is a TRAILING-* PREFIX, not a glob -- so Delta had no
# matching deny at all and three assertions were exercising a case the fixture never built.
# The suite caught it only because those three went red; had they been worded loosely they would
# have passed on a fixture that proved nothing. Assert the fixture's own mechanism.
T '  ...and Delta really is blocked by a WILDCARD that matches the tag' (
    (Test-PimProjectionTagMatch -Tag 'R' -Pattern 'R*') -eq $true -and
    (Test-PimProjectionTagMatch -Tag 'R' -Pattern 'R-*') -eq $false)

# --- GRANTS: only the `policy` axis is deliverable from here -----------------
$pOk = New-ReachPlan @('t1','t2')
T 'MSP-4/write: a grant blocked ONLY by policy is planned, with the deny removed' (
    $pOk.ok -eq $true -and @($pOk.edits | Where-Object { $_.name -eq 'Beta' -and $_.action -eq 'grant' }).Count -eq 1 -and
    @(@($pOk.edits | Where-Object { $_.name -eq 'Beta' })[0].rules).Count -eq 0)
# 🔴 THE FAILURE THIS WHOLE FUNCTION EXISTS TO PREVENT: writing a rule that commits cleanly,
# changes nothing, and reports privilege as granted in someone else's tenant. Same family as
# BUG-70b's phantom applied work, pointed at a customer.
$pTgt = New-ReachPlan @('t1','t2','t3')
T '  ...but a grant held back by TARGETING is REFUSED, by name' (
    $pTgt.ok -eq $false -and @($pTgt.refusals | Where-Object { $_.name -eq 'Gamma' -and $_.axis -eq 'targeting' }).Count -eq 1)
T '  ...and the refusal says a rule here would change nothing and report success' (
    @($pTgt.refusals | Where-Object { $_.name -eq 'Gamma' })[0].reason -match 'change nothing and report success')
# 🪤 A WILDCARD DENY IS NOT MINE TO REMOVE: deleting `R*` to let one role in silently widens
# that tenant's projection to every role the pattern was holding back.
$pWild = New-ReachPlan @('t1','t4')
T '  ...a grant blocked by a WILDCARD deny is refused rather than widening the pattern away' (
    $pWild.ok -eq $false -and @($pWild.refusals | Where-Object { $_.name -eq 'Delta' })[0].reason -match 'WILDCARD')
# 🔒 ONE REFUSAL POISONS THE WHOLE EDIT. A partial narrowing is not a smaller narrowing -- it is
# an estate matching neither the old intent nor the new one, in tenants nobody here owns.
T '  ...and ANY refusal makes the whole plan not-ok (no partial narrowing)' ($pWild.ok -eq $false)
# An allow-LIST is still a list with every deny gone: the tag must be ON it.
$pAllow = New-ReachPlan @('t1','t5')
T '  ...and granting into an allow-LIST tenant ADDS the allow rule (deny-free is not enough)' (
    $pAllow.ok -eq $true -and
    @(@($pAllow.edits | Where-Object { $_.name -eq 'Eps' })[0].rules | Where-Object { $_.Mode -eq 'allow' -and $_.GroupTag -eq 'R' }).Count -eq 1)

# --- WITHHOLDS: always deliverable, and deliberately DURABLE -----------------
$pHold = New-ReachPlan @()
T 'MSP-4/write: unticking a reaching tenant writes an explicit deny' (
    @(@($pHold.edits | Where-Object { $_.name -eq 'Alpha' })[0].rules | Where-Object { $_.Mode -eq 'deny' -and $_.GroupTag -eq 'R' }).Count -eq 1)
# 🔒 THE ASYMMETRY IS THE DESIGN, and it always errs toward LESS privilege: a grant is refused
# unless policy is demonstrably the only blocker, but a withhold is written even when something
# else is already doing the work -- because a ring can be raised and a Target rewritten, and the
# operator's intent has to outlive both.
T '  ...even when another axis already withholds it, so the intent outlives a ring change' (
    @($pHold.edits | Where-Object { $_.name -eq 'Gamma' -and $_.alreadyWithheldBy -eq 'targeting' }).Count -eq 1)
T '  ...and unticking EVERYTHING never widens anything (no tenant is granted)' (
    @($pHold.edits | Where-Object { $_.action -eq 'grant' }).Count -eq 0 -and $pHold.ok -eq $true)
T '  ...while a tenant already covered by a matching deny is left alone' (
    @($pHold.unchanged | Where-Object { $_.name -eq 'Delta' }).Count -eq 1)

# --- the writer, the route, the measurement ---------------------------------
# 🔑 ONE WRITER, TWO ENTRY POINTS. Session 32 escalated exactly this shape as an operator
# decision ("duplicate it, or accept a weaker path?") when the third option -- share it --
# needed nobody's ruling.
T 'MSP-4/write: there is ONE writer, and the single-tenant path delegates to it' (
    $dlm -match 'function Set-PimManagerDownlinkPolicyMany' -and
    (Get-PimSourceFunctionBody -Text $dlm -Name 'Set-PimManagerDownlinkPolicy') -match 'Set-PimManagerDownlinkPolicyMany')
# 🔒 One operator action edits up to 28 relationships. A failure at tenant 12 must not leave the
# estate half-narrowed: DELETE-then-INSERT with no rows meaning ALLOW ALL is a widening.
T '  ...and all N relationships commit in ONE transaction' (
    (Get-PimSourceFunctionBody -Text $dlm -Name 'Set-PimManagerDownlinkPolicyMany') -match '(?s)BeginTransaction\(\).{0,600}?foreach \(\$e in \$clean\.ToArray\(\)\)')
T '  ...validating every edit BEFORE the first write' (
    (Get-PimSourceFunctionBody -Text $dlm -Name 'Set-PimManagerDownlinkPolicyMany') -match '(?s)nothing was written.{0,3000}?BeginTransaction')
# 🔴 "I wrote the rows I intended" and "the role now reaches the tenants you asked for" are
# DIFFERENT CLAIMS. Only the second is what the operator asked, so it is re-measured off a
# freshly composed plan and disagrees out loud when the rules did not deliver.
T 'MSP-4/write: the outcome is RE-MEASURED after the commit, not assumed' (
    (Get-PimSourceFunctionBody -Text $dlm -Name 'Set-PimProjectionReach') -match '(?s)Set-PimManagerDownlinkPolicyMany.{0,600}?Get-PimManagerDownlinkOverview.{0,400}?Get-PimProjectionReach')
T '  ...and a mismatch is reported as NOT ok even though the write succeeded' (
    $dlm -match 'THE RESULT IS NOT WHAT WAS ASKED FOR')
T '  ...and a plan carrying a refusal writes NOTHING' (
    $dlm -match '(?s)if \(-not \$plan\.ok\).{0,600}?wrote = \$false')

$hPolicy2 = Get-Handler $srv "'/api/downlink/policy' -and `$method -eq 'PUT'"
T 'MSP-4/write: the tag axis is served by the SAME policy route (not a second write path)' (
    $hPolicy2 -match 'groupTag' -and $hPolicy2 -match 'Set-PimProjectionReach')
T '  ...so it is behind the SAME SuperAdmin gate' (
    $hPolicy2 -match "(?s)Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin'.{0,2000}?groupTag")
T '  ...and is audited with the MEASURED reach, not the requested one' (
    $hPolicy2 -match 'downlink\.reach\.save' -and $hPolicy2 -match '(?s)downlink\.reach\.save.{0,400}?\$rr\.after')
T '  ...a refusal answers 409 and records that nothing was written' (
    $hPolicy2 -match 'downlink\.reach\.refused' -and $hPolicy2 -match 'return 409')
T '  ...and the reach ROUTE itself is still read-only' (
    -not ($srv -match "'/api/downlink/reach'\s+-and\s+\`$method\s+-eq\s+'(PUT|POST)'"))

T 'MSP-4/write: the panel offers the control and PUTs the tag axis' (
    $htmlCode -match 'reachEditBtn' -and $htmlCode -match "api\('PUT', '/api/downlink/policy', \{ groupTag")
T '  ...only when the server said this role may write' ($htmlCode -match 'canWrite \? .{0,120}reachEditBtn')
T '  ...and the 409 REFUSAL is rendered per tenant, not flattened to "error"' (
    $htmlCode -match 'refusals' -and $htmlCode -match 'Nothing was written')
# 🪤 The structured 409 body is the ANSWER for this endpoint; api() used to flatten every
# non-2xx to a message string, which would have thrown the per-tenant reasons away.
T '  ...which needs api() to keep the response BODY on a non-2xx' ($htmlCode -match 'err\.body = data')
Write-Host ""
Write-Host ("==== Downlink GUI test: {0} passed, {1} failed ====" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
