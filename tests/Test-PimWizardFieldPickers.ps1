#Requires -Version 5.1
<#
.SYNOPSIS
    §37 DURABILITY GATE -- a wizard field that names a role, a scope or an owner must offer a
    picker. Fails when a NEW free-text `wuxField` is added for a value the tenant already knows.

.DESCRIPTION
    §37 audited every `wuxField` in every wizard and fixed what it found. Its own closing line
    says why that is not enough: *"the audit above is a snapshot, not a gate."* A snapshot cannot
    stop the next field from being added as free text, and this suite is the gate it asked for.

    🔑 The defect §37 found was worse than plain free text: TWO CONTROLS FOR ONE VALUE. Three
    fields rendered a `(pick from tenant cache...)` <select> directly above a required free-text
    box, and BOTH wrote the same state variable -- so the picker was advisory, the text box was
    authoritative, and every typo still went through. A user who carefully picked from the list
    could still have the value overwritten by whatever was typed. That shape is pinned dead here.

    HOW IT WORKS. The file is split on `wuxField(` so each chunk is exactly one field plus the
    lines that immediately follow it -- which is where a picker is attached (`pimAttachCombo`,
    `pimAttachPeopleCombo`, `pimAttachChips`). A field is CLASSIFIED from its id + label; a
    classified field must then be a `type:'select'`, or carry an attach call, or appear in one of
    the two lists below.

    TWO LISTS, AND THEY MEAN DIFFERENT THINGS.
      * $EXEMPT     -- free text ON PURPOSE, with the §37.1 rule that says so. Aliases and short
                       codes are names the operator INVENTS: a picker there would be theatre.
      * $KNOWN_OPEN -- free text that SHOULD have a picker and does not. Each is a recorded
                       finding. It is here so the suite stays green while the debt stays VISIBLE
                       and cannot grow; it is not an excuse.

    Both lists are asserted EXACTLY, in both directions. A new offender fails. Fixing an offender
    ALSO fails, telling you to delete the row -- otherwise a list like this quietly becomes a
    graveyard of things that were repaired years ago, and stops describing anything real.

    Static only: no browser, no tenant, no live SQL. Run standalone (exit 0 green / 1 red) or via
    Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$mgrDir   = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\pim-manager'
$htmlPath = Join-Path $mgrDir 'pim-manager.html'
T 'pim-manager.html present' (Test-Path -LiteralPath $htmlPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
$html = [System.IO.File]::ReadAllText($htmlPath)

# --- the two lists ------------------------------------------------------------
# Free text ON PURPOSE. The reason is the §37.1 rule, not "we did not get to it".
$EXEMPT = [ordered]@{
    'wa-rA'     = 'alias the operator INVENTS -- there is nothing to pick from (§37.1)'
    'wa-scA'    = 'alias the operator INVENTS -- there is nothing to pick from (§37.1)'
    'wr-scname' = 'display name the operator INVENTS (§37.1)'
    'wr-wlsc'   = 'shape differs per connector and no catalog exists (§37.0)'
    'wr-roles'  = 'the FALLBACK path only -- a picklist renders whenever the cache has roles (§37.0)'
}
# Free text that SHOULD offer a picker. Each row is a recorded finding, not a decision.
$KNOWN_OPEN = [ordered]@{
    'wr-au@role-group-wizard' = 'BUG-116 -- Administrative Unit as free text in the role-group wizard, while the SAME id in the delegation wizard is a combo over the cached AU list'
}

# --- parse every wizard field -------------------------------------------------
$idx = @([regex]::Matches($html, 'wuxField\(') | ForEach-Object { $_.Index })
$fields = New-Object System.Collections.ArrayList
for ($i = 0; $i -lt $idx.Count; $i++) {
    $start = $idx[$i]
    $end   = if ($i + 1 -lt $idx.Count) { $idx[$i + 1] } else { $html.Length }
    $chunk = $html.Substring($start, $end - $start)
    # `f.appendChild(wuxField(wrapped))` has no literal options object -- nothing to classify.
    if ($chunk -notmatch 'id:''([a-zA-Z0-9\-]+)''') { continue }
    $id = $Matches[1]
    $lb = if ($chunk -match 'label:''([^'']*)''') { $Matches[1] } else { '' }
    [void]$fields.Add([pscustomobject]@{
        Id     = $id
        Label  = $lb
        Line   = ($html.Substring(0, $start) -split "`n").Count
        Select = [bool]($chunk -match 'type:''select''')
        Picker = [bool]($chunk -match 'pimAttach(Combo|PeopleCombo|Chips)\s*\(')
    })
}

Write-Host "`n-- the scan itself found something (a scan that finds nothing passes everything) --" -ForegroundColor Cyan
# 🔒 The whole gate rests on this parse. If the helper is renamed or the option style changes,
# every assertion below would go green over an EMPTY set -- the vacuous-guard failure this repo
# has now hit twice. Assert the shape of the scan before trusting anything it says.
T 'wizard fields were found'            ($fields.Count -ge 40)
T '   ...with ids and labels parsed'    (@($fields | Where-Object { $_.Label }).Count -ge 40)
T '   ...and some already carry pickers' (@($fields | Where-Object { $_.Picker -or $_.Select }).Count -ge 10)

# --- §37.1 rule 1: ONE CONTROL PER VALUE -------------------------------------
Write-Host "`n-- the twin-control defect stays dead --" -ForegroundColor Cyan
# The original finding: a picker and a text box writing the SAME state variable. The picker looked
# safe and the text box decided. These three twins were deleted; assert they do not come back, and
# assert the SHAPE generally, so a fourth twin under a new name is caught too.
foreach ($twin in 'wa-rPick', 'wa-scPick', 'wr-scpick') {
    T "the deleted twin control '$twin' has not returned" ($html -notmatch [regex]::Escape($twin))
}
$twins = @([regex]::Matches($html, "id:'([a-zA-Z0-9\-]+[Pp]ick)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
T 'no field id is a *Pick twin of another field' ($twins.Count -eq 0)
if ($twins.Count) { foreach ($t in $twins) { Write-Host "    TWIN: $t" -ForegroundColor Red } }

# --- classify + gate ----------------------------------------------------------
Write-Host "`n-- every role / scope / owner field offers a picker --" -ForegroundColor Cyan
function Get-PimWizardFieldConcept {
    # Classify from id AND label together. The label is what the USER reads, and it is the label
    # that tells you a box is asking for a role; the id alone is too terse to judge ('wa-r').
    param([string]$Id, [string]$Label)
    $t = "$Id $Label".ToLowerInvariant()
    if ($t -match '\bowner')                                   { return 'owner' }
    if ($t -match '\brole')                                    { return 'role'  }
    if ($t -match '\bscope|administrative unit|\bau\b')         { return 'scope' }
    return ''
}
$classified = New-Object System.Collections.ArrayList
$offenders  = New-Object System.Collections.ArrayList
foreach ($f in $fields) {
    $concept = Get-PimWizardFieldConcept -Id $f.Id -Label $f.Label
    if (-not $concept) { continue }
    [void]$classified.Add($f.Id)
    if ($f.Select -or $f.Picker) { continue }
    if ($EXEMPT.Contains($f.Id)) { continue }
    [void]$offenders.Add([pscustomobject]@{ Id = $f.Id; Label = $f.Label; Line = $f.Line; Concept = $concept })
}
T 'the classifier matched role/scope/owner fields' ($classified.Count -ge 10)

# 🪤 The SAME id appears in more than one wizard (wr-au is a combo in one and free text in
# another), so an offender cannot be keyed by id alone -- that is precisely how §37's audit
# recorded wr-au as done while one of the two was still free text. Key by id + which wizard.
function Get-PimWizardName {
    # Nearest preceding wizard step label gives a stable, human name for the offending screen.
    param([int]$Line)
    if ($Line -gt 13000) { return 'role-group-wizard' }
    if ($Line -gt 12600) { return 'azure-scope-wizard' }
    if ($Line -gt 12200) { return 'entitlement-wizard' }
    return 'delegation-wizard'
}
$seen = @($offenders | ForEach-Object { '{0}@{1}' -f $_.Id, (Get-PimWizardName -Line $_.Line) } | Sort-Object)
$want = @($KNOWN_OPEN.Keys | Sort-Object)

foreach ($o in $offenders) {
    $key = '{0}@{1}' -f $o.Id, (Get-PimWizardName -Line $o.Line)
    $known = $KNOWN_OPEN.Contains($key)
    $colour = if ($known) { 'Yellow' } else { 'Red' }
    Write-Host ("    {0} FREE TEXT: {1,-10} [{2}] line {3} -- {4}" -f $(if ($known) { 'known-open' } else { 'NEW' }), $o.Id, $o.Concept, $o.Line, $o.Label) -ForegroundColor $colour
}
# Both directions. A new offender fails; a FIXED offender fails too, so the list cannot rot into
# a record of problems that no longer exist.
T 'no UNDOCUMENTED free-text role/scope/owner field' (@($seen | Where-Object { $want -notcontains $_ }).Count -eq 0)
T 'every KNOWN_OPEN row still reproduces (else delete it)' (@($want | Where-Object { $seen -notcontains $_ }).Count -eq 0)

Write-Host "`n-- the two lists stay honest --" -ForegroundColor Cyan
# A stale exemption is worse than no exemption: it silently pre-approves whatever a future field
# with that id happens to be.
foreach ($k in $EXEMPT.Keys) {
    T "exempt field '$k' still exists" (@($fields | Where-Object { $_.Id -eq $k }).Count -ge 1)
}
foreach ($k in $EXEMPT.Keys) {
    T "   ...and '$k' records WHY" ("$($EXEMPT[$k])".Trim().Length -gt 20)
}
foreach ($k in $KNOWN_OPEN.Keys) {
    T "known-open '$k' cites a finding id" ("$($KNOWN_OPEN[$k])" -match '\b(BUG|IMP|SEC|TEST|DOC)-\d+')
}

# --- negative verification ----------------------------------------------------
Write-Host "`n-- the gate would actually catch a new offender (not a tautology) --" -ForegroundColor Cyan
# 🔒 Every assertion above passes on a tree where nothing is wrong. That is exactly the state in
# which a broken guard is indistinguishable from a working one, so drive the classifier directly.
T 'a free-text "Azure RBAC role name" classifies as role'  ((Get-PimWizardFieldConcept -Id 'wx-new' -Label 'Azure RBAC role name') -eq 'role')
T 'a free-text "Owner email(s)" classifies as owner'       ((Get-PimWizardFieldConcept -Id 'wx-new' -Label 'Owner email(s)') -eq 'owner')
T 'a free-text "Azure scope (ARM path)" classifies as scope' ((Get-PimWizardFieldConcept -Id 'wx-new' -Label 'Azure scope (ARM path)') -eq 'scope')
T 'an Administrative Unit field classifies as scope'       ((Get-PimWizardFieldConcept -Id 'wx-au' -Label 'Administrative Unit') -eq 'scope')
# ...and the other direction: it must NOT classify things that are legitimately free text, or the
# gate becomes noise and the next person raises the bar by adding exemptions.
T 'a short-code field is NOT classified'                   ((Get-PimWizardFieldConcept -Id 'wf-ini' -Label 'Initials (short code)') -eq '')
T 'a description field is NOT classified'                  ((Get-PimWizardFieldConcept -Id 'wr-desc' -Label 'Description') -eq '')
T 'a lifetime field is NOT classified'                     ((Get-PimWizardFieldConcept -Id 'wf-life' -Label 'Lifetime (days)') -eq '')

# And prove the PICKER detection is real, by checking a field known to carry one.
$war = @($fields | Where-Object { $_.Id -eq 'wa-r' })[0]
T 'the RBAC role field is detected as picker-backed' ($war -and $war.Picker)
$wown = @($fields | Where-Object { $_.Id -eq 'we-own' })[0]
T 'the owner field is detected as chips-backed'      ($wown -and $wown.Picker)

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
