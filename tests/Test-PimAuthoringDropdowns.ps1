#Requires -Version 5.1
<#
.SYNOPSIS
    HEADLESS verification of the PIM Manager Authoring tab dropdowns (no browser).

    Two layers:
      1. Static markup assertions (here) -- the Authoring controls are dropdowns/
         comboboxes wired to real data sources, with no raw free-text path left for
         group / role / tag / admin selection.
      2. A Node executor (tests/gui/authoring-dropdowns.test.js) that extracts the
         PURE data-source helpers from pim-manager.html and runs them against a
         SEEDED catalog, asserting the produced option lists. Node IS available on
         mgmt1/CI; if it is genuinely absent this layer SELF-SKIPS (not a failure),
         mirroring the Live-test doctrine -- the static layer still gates.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
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

# --- Pure data-source helpers exist (the no-dead-views contract) --------------
T 'helper extraction markers present' (($html -match '__PIM_AUTHORING_HELPERS_START__') -and ($html -match '__PIM_AUTHORING_HELPERS_END__'))
foreach ($fn in 'collectAuthoringEntraRoles','collectKnownAdmins','collectAdminAssignedTags') {
    T "data-source helper defined: $fn" ($html -match ("function $fn\("))
}
# Roles come from the live tenant-list cache, NOT hand-typed.
T 'entra-role helper reads the entraRoles cache' ($html -match "getCachedList[\s\S]{0,40}'entraRoles'|get\('entraRoles'\)")
# Admins/from-tags come from the real assignment CSV.
T 'admin helper reads PIM-Assignments-Admins' ($html -match "PIM-Assignments-Admins")

# --- Bulk-attach card: dropdowns from real data, no raw strings ---------------
T 'bulk-attach GroupTag is a pick-or-type combobox' (($html -match 'id="aBaGroup"[^>]*list="aBaGroupList"') -and ($html -match '<datalist id="aBaGroupList">'))
T 'bulk-attach Entra roles is a multi-select'        ($html -match '<select id="aBaRoles" multiple')
T 'bulk-attach reads roles from selectedOptions'     ($html -match "getElementById\('aBaRoles'\)\.selectedOptions")
T 'bulk-attach has NO free-text roles input'         (-not ($html -match 'id="aBaRoles" type="text"'))
T 'bulk-attach has NO free-text grouptag-only input' (-not ($html -match 'id="aBaGroup" type="text">'))  # must carry list=
T 'bulk-attach fills roles from real catalog'        ($html -match 'collectAuthoringEntraRoles\(\)')
T 'bulk-attach fills tags from known catalog'        ($html -match 'collectKnownGroupTags\(\)[\s\S]{0,160}aBaGroupList')

# --- Move-admin card: dropdowns from real data, no raw strings ----------------
T 'move-admin Admin is a <select>'         ($html -match "fieldRow\('Admin', '<select id=`"aMvUser`">")
T 'move-admin From-tag is a <select>'      ($html -match "fieldRow\('From tag \(current\)', '<select id=`"aMvFrom`">")
T 'move-admin To-tag is a combobox'        (($html -match 'id="aMvTo"[^>]*list="aMvToList"') -and ($html -match '<datalist id="aMvToList">'))
T 'move-admin has NO free-text user input' (-not ($html -match 'id="aMvUser" type="text"'))
T 'move-admin has NO free-text from input' (-not ($html -match 'id="aMvFrom" type="text"'))
T 'move-admin fills admins from catalog'   ($html -match 'collectKnownAdmins\(\)')
T 'move-admin from-tags follow the admin'  ($html -match "aMvUser[\s\S]{0,200}onchange = fillMoveFromTags|function fillMoveFromTags")
T 'move-admin submit validates picks'      ($html -match "if \(!username\) throw")

# --- Preload so nothing renders empty (no dead view) --------------------------
T 'authoring preloads the role tenant list' ($html -match "ensureTenantLists\(\['entraRoles'\]\)")
T 'authoring preloads definition + admin CSVs' (($html -match "loadCsv\('PIM-Assignments-Admins'\)") -and ($html -match "loadCsv\('Account-Definitions-Admins'\)"))

# --- Genuinely-free fields stay free (allowed): new-tag + CSV paste -----------
T 'clone new-tags stays free text (new values)'      ($html -match 'id="aClTags" type="text"')
T 'import-admins stays a free paste box (external CSV)' ($html -match 'id="aImpText"')

Write-Host ("`n -- static layer: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })

# --- Node executor layer (seeded catalog -> assert option lists) --------------
$node = Get-Command node -ErrorAction SilentlyContinue
$nodeTest = Join-Path $PSScriptRoot 'gui\authoring-dropdowns.test.js'
if (-not $node) {
    Write-Host "  SKIP (node executor): Node.js not found on PATH -- static layer still gated." -ForegroundColor Yellow
} elseif (-not (Test-Path -LiteralPath $nodeTest)) {
    T 'node executor present' $false
} else {
    Write-Host "`n -- node executor: tests/gui/authoring-dropdowns.test.js --" -ForegroundColor Cyan
    & node $nodeTest
    if ($LASTEXITCODE -ne 0) { $fail++; Write-Host "  node executor FAILED" -ForegroundColor Red }
    else { Write-Host "  node executor green" -ForegroundColor Green }
}

Write-Host ("`n RESULT: {0} static pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
