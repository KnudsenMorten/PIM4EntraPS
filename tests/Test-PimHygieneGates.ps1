#Requires -Version 5.1
<#
.SYNOPSIS
  THE CHECKS WHOSE ABSENCE LET EACH OF THESE SHIP. Three standing gates, one file.

.DESCRIPTION
  Every gate here exists because a defect was fixed BY HAND and nothing stopped the next one:

    1. BUG-89 -- user-visible GUI text named INTERNAL DOCS ("See DESIGN.md section 2") and the
       DECOMMISSIONED CSV store ("not defined in any PIM-Definitions-* CSV"). Six strings were
       corrected; nothing stopped a seventh. The operator's instruction was explicit: "do a
       complete audit of all pages and removes this crap. we have real people using the system".

    2. BUG-102 -- an `az` call with no explicit --subscription runs against the machine's
       ambient default, which on mgmt1 is routinely ANOTHER COMPANY'S tenant. Commit 623fc29a
       fixed "four tools, one defect"; the release gate was a FIFTH and was missed, so the
       deploy and the check of that deploy ran against different tenants. Grep-and-fix has now
       missed this same defect twice, which is the definition of something that needs a gate.

    3. SEC-14 -- a live test harness left 332 groups + 16 AUs holding 240 Entra directory-role
       assignments, including Global Administrator, in the PRODUCTION tenant for 77 days. The
       marker is a PREFIX, so the objects never matched the operator's own PIM-* filters: the
       invisibility that made the harness SAFE while it ran is what hid the debris afterwards.
       Any sweep for them must therefore look OUTSIDE the configured filters -- and the harness
       must refuse a tenant the registry flags as production.

  PURE + OFFLINE: source assertions only. No tenant, no network, no store.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

# ===========================================================================
Write-Host "`n== GATE 1 (BUG-89): no internal doc names or CSV-as-store in USER-VISIBLE text ==" -ForegroundColor Cyan
# ===========================================================================
# Scoped to text a user can actually READ. Comments are exempt: they are not user-visible, and
# rewriting them destroys accurate history (the validator's comments correctly describe how the
# reader works). A lint that fires on comments is a lint everyone learns to ignore.
$userVisible = @(
    (Join-Path $root 'tools\pim-manager\pim-manager.html'),
    (Join-Path $root 'tools\pim-manager\_validator.ps1')
)
$docNames = 'DESIGN\.md|REQUIREMENTS\.md|TESTS\.md|CLAUDE\.md'
$csvStore = 'PIM-Definitions-\*\s*CSV|PIM-Definitions-\*\s*CSVs|All CSVs'
$hits = New-Object System.Collections.Generic.List[string]
foreach ($f in $userVisible) {
    if (-not (Test-Path -LiteralPath $f)) { continue }
    $n = 0
    foreach ($line in [System.IO.File]::ReadAllLines($f)) {
        $n++
        $t = $line.TrimStart()
        # skip comment lines in both languages
        if ($t.StartsWith('//') -or $t.StartsWith('#') -or $t.StartsWith('*') -or $t.StartsWith('/*') -or $t.StartsWith('<!--')) { continue }
        if ($line -match $docNames -or $line -match $csvStore) {
            $hits.Add(("{0}:{1}: {2}" -f (Split-Path -Leaf $f), $n, $t.Substring(0, [Math]::Min(110, $t.Length))))
        }
    }
}
if ($hits.Count) { $hits | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow } }
T 'no internal doc name / CSV-as-store in user-visible strings' ($hits.Count -eq 0)

# ===========================================================================
Write-Host "`n== GATE 2 (BUG-102): every az call is scoped to an explicit subscription ==" -ForegroundColor Cyan
# ===========================================================================
# An unscoped `az` on mgmt1 targets whatever directory happens to be default -- frequently a
# different company. The convention in this codebase is an explicit --subscription or one of
# the splatted arg arrays (@subArgs / @smokeSub / @azSub).
$azScan = @()
foreach ($dir in @('tools', 'tests\live', 'sync')) {
    $p = Join-Path $root $dir
    if (Test-Path -LiteralPath $p) { $azScan += Get-ChildItem -Path $p -Recurse -Filter *.ps1 -ErrorAction SilentlyContinue }
}
$unscoped = New-Object System.Collections.Generic.List[string]
foreach ($f in $azScan) {
    $n = 0
    $inBlockComment = $false
    foreach ($line in [System.IO.File]::ReadAllLines($f.FullName)) {
        $n++
        $t = $line.TrimStart()
        # Track <# ... #> help blocks. Without this the scanner reported .SYNOPSIS/.DESCRIPTION
        # prose ("az acr build; deploy = roll the ACA revision...") as an unscoped invocation --
        # a false positive in the DEPLOY path, i.e. in exactly the assertion that must stay
        # trustworthy enough to block a release.
        if ($t -match '<#') { $inBlockComment = $true }
        if ($inBlockComment) { if ($t -match '#>') { $inBlockComment = $false }; continue }
        if ($t.StartsWith('#') -or $t.StartsWith('.')) { continue }
        # A real INVOCATION, not the letters "az" inside prose. The command must start the
        # line or follow a command separator / subexpression opener. Without this the gate
        # reported help text ("deploy = roll the ACA revision", "IMAGE needs -AcrName (az acr
        # build targets...)") as defects -- and a gate with false positives is a gate people
        # learn to skip, which is how the real ones survive.
        if ($t -notmatch '(^|[;&|]\s*|\$\(\s*|\(\s*)az\s+[a-z]') { continue }
        # inside a double-quoted message: `az` mentioned after an opening quote on the line
        $azAt = $t.IndexOf('az ')
        if ($azAt -gt 0) {
            $before = $t.Substring(0, $azAt)
            $dq = ([regex]::Matches($before, '"')).Count
            $sq = ([regex]::Matches($before, "'")).Count
            if (($dq % 2) -eq 1 -or ($sq % 2) -eq 1) { continue }   # we are inside a string literal
        }
        # Any splat whose name carries "sub" is this codebase's scoping convention
        # (@subArgs / @subArg / @smokeSub / @acrSubArgs / @azSub ...). Matching the CONVENTION
        # rather than a hard-coded list is what stops the gate reporting false positives the
        # moment someone adds a sixth splat name -- and a gate that cries wolf gets switched off.
        if ($t -match '--subscription' -or $t -match '@\w*[Ss]ub\w*') { continue }
        # `az login` / `az logout` / `az account set` establish or clear context: --subscription
        # is meaningless or wrong on them.
        # `az config set` belongs in the same category and was missing: it writes the CLI's OWN
        # client configuration (e.g. extension.use_dynamic_install), which has no subscription --
        # `az config set --subscription x` is not a scoped call, it is an invalid one. Without this
        # the gate reported the two lines that stop an unattended task hanging on "install the
        # containerapp extension? (Y/n)" as unscoped defects: a false positive of exactly the kind
        # the comments above say destroys a gate's credibility.
        if ($t -match '\baz\s+(login|logout)\b' -or $t -match '\baz\s+account\s+(set|clear|list|show)\b' -or $t -match '\baz\s+config\s+(set|unset|get)\b') { continue }
        $unscoped.Add(("{0}:{1}: {2}" -f $f.Name, $n, $t.Substring(0, [Math]::Min(120, $t.Length))))
    }
}

# 🔒 A RATCHET, NOT A WISH.
# The deploy + release-gate path -- the code that runs on EVERY deploy, and where BUG-102
# actually bit -- must be clean, and is asserted at zero below. The one-time provisioning
# scripts (New-PimHostingPrerequisites, _PimSetupShared, Setup-Pim*, Provision-PimLab ...) carry
# a large historical backlog. Asserting zero across all of them today would mean either a rushed
# sweep of ~15 infra files right after a release -- exactly how the deploy path got broken in the
# first place -- or a gate that is red forever and therefore ignored.
# So: the count may SHRINK but never GROW. A new unscoped call fails the build immediately; the
# backlog is visible, counted, and can only be paid down.
$deployPath = @(
    'Update-PimContainers.ps1', 'Build-PimManagerImage.ps1', 'Test-PimManagerHostedSmoke.ps1',
    'Test-PimDeployedVersionDrift.ps1', 'Invoke-PimDeployAll.ps1', 'Invoke-PimUpdate.ps1'
)
$deployHits = @($unscoped | Where-Object { $n = ($_ -split ':')[0]; $n -in $deployPath })
$otherHits  = @($unscoped | Where-Object { $n = ($_ -split ':')[0]; $n -notin $deployPath })
if ($deployHits.Count) { $deployHits | ForEach-Object { Write-Host "    DEPLOY-PATH  $_" -ForegroundColor Red } }
T 'DEPLOY + RELEASE-GATE path: every az call is subscription-scoped' ($deployHits.Count -eq 0)

# The ratchet. Lower this number when you fix some; NEVER raise it.
# 38 -> 37 on 2026-09-04. New-PimBaselineStorage.ps1 was added this session with five bare `az`
# calls and the ratchet caught them (44 vs 38). They now splat @subArgs, so that file asserts the
# context AND scopes every call. Lowered per this block's own instruction -- a ratchet that is only
# ever compared against and never tightened stops being a ratchet.
$KnownUnscopedBacklog = 37
if ($otherHits.Count -gt 0) {
    Write-Host ("    backlog: {0} unscoped az call(s) in one-time provisioning scripts (ratchet: {1})" -f $otherHits.Count, $KnownUnscopedBacklog) -ForegroundColor DarkYellow
    $otherHits | Select-Object -First 8 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
}
T ("no NEW unscoped az call (backlog {0} must not exceed the ratchet {1}; {2} file(s) scanned)" -f $otherHits.Count, $KnownUnscopedBacklog, $azScan.Count) ($otherHits.Count -le $KnownUnscopedBacklog)

# ===========================================================================
Write-Host "`n== GATE 3 (SEC-14): the live marker harness cannot run against production ==" -ForegroundColor Cyan
# ===========================================================================
$harnesses = @(
    'tests\live\Manage-PimCoreEngineTest.ps1',
    'tests\live\Seed-PimDummyData.ps1',
    'tests\live\Seed-PimBaselineDataset.ps1'
) | ForEach-Object { Join-Path $root $_ } | Where-Object { Test-Path -LiteralPath $_ }
T 'the marker harnesses are present to check' ($harnesses.Count -ge 1)
foreach ($h in $harnesses) {
    $src = [System.IO.File]::ReadAllText($h)
    $name = Split-Path -Leaf $h
    # It must consult the tenant registry / the shared guard before touching a tenant. The
    # registry is the ONLY thing that knows myfamilynetwork is production, and reading it after
    # the fact is what SEC-14 cost.
    T ("$name refuses a production tenant (calls the tenant guard)") ($src -match 'Assert-PimScenarioTenantAllowed|Assert-PimTenantIsNotProduction')
}
# -Revert must not be able to run before -Cleanup: reverting first erases the marker from SQL,
# which destroys the record of WHICH tenant objects still need deleting. That ordering is why
# 332 objects sat unnoticed for 77 days.
$mgr = Join-Path $root 'tests\live\Manage-PimCoreEngineTest.ps1'
if (Test-Path -LiteralPath $mgr) {
    $src = [System.IO.File]::ReadAllText($mgr)
    # 🪤 This assertion FIRST PASSED OFF THE FILE'S OWN HELP TEXT (".EXAMPLE -Cleanup # delete
    # ONLY marked tenant objects"). A source assertion satisfiable by documentation proves
    # nothing -- the exact trap the session-34 handoff recorded ("a source assertion was
    # satisfied or broken by a COMMENT four times"). It now matches the THROWN REFUSAL, which
    # only exists if the guard is really implemented.
    T '-Revert refuses while marked tenant objects still exist' ($src -match 'REFUSING -Revert')
}

# ===========================================================================
Write-Host "`n== GATE 4 (BUG-105): API lists are coerced with asList(), not guarded with || [] ==" -ForegroundColor Cyan
# ===========================================================================
# PowerShell ConvertTo-Json COLLAPSES a single-element array to a bare scalar. `|| []` guards
# NULL and does nothing about WRONG TYPE, so a row with exactly ONE changed column arrived as
# diffCols:"AssignmentType" -- truthy, `|| []` never fires, `.map` is not a function, and the
# whole Review & commit diff card died with
#     diff failed: (m.diffCols || []).map is not a function
# on the one screen an operator must reach to commit anything. asList() exists precisely for
# this and was simply not used here.
$mgrHtml = [System.IO.File]::ReadAllText((Join-Path $root 'tools\pim-manager\pim-manager.html'))
T 'asList() helper still exists'                ($mgrHtml -match 'function asList\(')
# 🪤 Scanned line-by-line with COMMENTS EXCLUDED. Whole-file matching failed here on the
# comment that quotes the original error text ("diff failed: (m.diffCols || []).map is not a
# function") -- a source assertion BROKEN by a comment, the same trap that earlier made one
# SATISFIED by help text. Comments are documentation, not behaviour; a check that reads them
# as behaviour is measuring the wrong thing in both directions.
$diffColsFallback = @()
$ln = 0
foreach ($line in ($mgrHtml -split "`r?`n")) {
    $ln++
    $tl = $line.TrimStart()
    if ($tl.StartsWith('//') -or $tl.StartsWith('*') -or $tl.StartsWith('/*') -or $tl.StartsWith('<!--')) { continue }
    if ($line -match 'diffCols\s*\|\|\s*\[\]') { $diffColsFallback += "line ${ln}: $($tl.Substring(0, [Math]::Min(90, $tl.Length)))" }
}
if ($diffColsFallback.Count) { $diffColsFallback | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow } }
T 'no "|| []" fallback left on a diffCols read (code, not comments)' ($diffColsFallback.Count -eq 0)
T 'every diffCols read goes through asList()'   ((([regex]::Matches($mgrHtml, 'asList\([A-Za-z_$][\w$]*\.diffCols\)')).Count) -ge 2)

# ===========================================================================
Write-Host "`n== GATE 5 (BUG-107): a two-person control must be OPT-IN ==" -ForegroundColor Cyan
# ===========================================================================
# The maker/checker gate shipped unconditionally, so a single-administrator deployment could
# not commit any privileged change: the 409 demands a SECOND administrator, self-approval is
# refused by design, and in that tenant there is no second administrator. "i have not enabled
# this feature ... that should not be standard".
# 🪤 The flag must live in PIM-FeatureCatalog.ps1 -- the catalog Test-PimFeatureAvailable
# actually resolves against -- NOT in PIM-FeatureFlags.ps1, which only drives GUI TAB
# visibility. Putting it in the tab list made the gate return $false as an "unknown feature
# key": the right ANSWER (policy off) for entirely the wrong REASON, and the operator could
# then never switch it ON. That mistake passed a naive source check, which is why these
# assertions name the catalog, the tier and the default separately.
$flagSrc = [System.IO.File]::ReadAllText((Join-Path $root 'engine\_shared\PIM-FeatureCatalog.ps1'))
$sensSrc = [System.IO.File]::ReadAllText((Join-Path $root 'engine\_shared\PIM-SensitiveAuthoring.ps1'))
T "'makerchecker' is in the RUNTIME feature catalog" ($flagSrc -match "key='makerchecker'")
T "'makerchecker' ships DEFAULT OFF"                ($flagSrc -match "key='makerchecker'[^\r\n]*defaultEnabled=\`$false")
# tier='core' short-circuits Test-PimFeatureAvailable to $true and is unswitchable, which would
# silently restore the always-on behaviour this whole fix exists to remove.
T "'makerchecker' is 'advanced', so it can be switched" ($flagSrc -match "key='makerchecker'[^\r\n]*tier='advanced'")
# Enforced in the LIBRARY so no future call site can reintroduce the unconditional behaviour.
T 'the gate itself honours the flag'            ($sensSrc -match "Test-PimFeatureAvailable -Key 'makerchecker'")
T 'the refusal tells the reader how to proceed' ($sensSrc -match 'Second-approver on sensitive changes')

Write-Host ""
if ($fail) { Write-Host " RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
Write-Host " RESULT: $pass pass, 0 fail" -ForegroundColor Green
exit 0
