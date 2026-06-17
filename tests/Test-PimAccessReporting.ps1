#Requires -Version 5.1
<#
.SYNOPSIS
    Visibility & reporting (REQUIREMENTS.md §26a) -- static GUI/server wiring asserts
    PLUS in-proc data-correlation tests proving the "who can do what" report (forward
    + reverse) and the global search reflect REAL seeded delegation-model data (no
    dead/island views, no hardcoded results).

.DESCRIPTION
    Two layers, all offline (no live tenant, no server boot):

      1. STATIC GUI/SERVER WIRING -- the Reports tab + global-search box are declared
         and routed, renderReports calls the who-can/who-has endpoints, the server
         defines /api/access-report/who-can, /api/access-report/who-has and /api/search,
         and the export bars are wired into the operational views.

      2. DATA CORRELATION (in-proc) -- extract Get-PimReachableTargets / Get-PimRoleReachers
         / Get-PimGlobalSearch / Get-PimAccessGraphModel / Get-PimNodeLabel from
         Open-PimManager.ps1, stub Build-PimGraphData with a SEEDED node/edge model
         (admin -> role group -> nested permission group -> Entra-role / Azure target),
         then assert: forward report finds every reachable target WITH the path; the
         reverse report finds every person who can activate a role; search returns the
         right typed hits across people/groups/roles/scopes/tags.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root     = Split-Path -Parent $PSScriptRoot          # ...\PIM4EntraPS
$mgrDir   = Join-Path $root 'tools\pim-manager'
$htmlPath = Join-Path $mgrDir 'pim-manager.html'
$srvPath  = Join-Path $mgrDir 'Open-PimManager.ps1'
T 'pim-manager.html present'    (Test-Path -LiteralPath $htmlPath)
T 'Open-PimManager.ps1 present' (Test-Path -LiteralPath $srvPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
$html = [System.IO.File]::ReadAllText($htmlPath)
$srv  = [System.IO.File]::ReadAllText($srvPath)

# ===========================================================================
# Layer 1 -- STATIC GUI / SERVER WIRING (no dead views)
# ===========================================================================
Write-Host "`n-- Layer 1: Reports + search + export wiring (static) --" -ForegroundColor Cyan
T 'Reports tab declared'                    ($html -match 'data-tab="reports"')
T 'Reports panel container present'         ($html -match 'id="reportsTab"')
T 'switchTab routes reports -> renderReports' ($html -match "name === 'reports'\s*\)\s*renderReports")
T 'renderReports defined'                   ($html -match 'async function renderReports\(')
T 'reports calls who-can endpoint'          ($html -match '/api/access-report/who-can\?person=')
T 'reports calls who-has endpoint'          ($html -match '/api/access-report/who-has\?role=')
T 'global search box present'               ($html -match 'id="globalSearch"')
T 'initGlobalSearch defined + booted'       ($html -match 'function initGlobalSearch\(' -and $html -match 'initGlobalSearch\(\);')
T 'global search calls /api/search'         ($html -match '/api/search\?q=')
T 'shared CSV export helper defined'        ($html -match 'function downloadCsv\(')
T 'shared print helper defined'             ($html -match 'function printTable\(')
# [L5]/[H5] -- Role Lookup (all 4 modes) + Maintenance active-assignments now export.
T 'role-lookup permissions view exports'    ($html -match "wireExportBar\('rpPerm'")
T 'role-lookup by-action view exports'       ($html -match "wireExportBar\('baMatch'")
T 'role-lookup reverse view exports'         ($html -match "wireExportBar\('rvReach'")
T 'role-lookup compare view exports'         ($html -match "wireExportBar\('cmpCmp'")
T 'active-assignments view exports'          ($html -match 'id="revExportBar"' -and $html -match 'revExpCsv')

# Server handlers exist (the three §26a read endpoints).
T 'server handles GET /api/access-report/who-can'  ($srv -match "\`$path -eq '/api/access-report/who-can' -and \`$method -eq 'GET'")
T 'server handles GET /api/access-report/who-has'  ($srv -match "\`$path -eq '/api/access-report/who-has' -and \`$method -eq 'GET'")
T 'server handles GET /api/search'                 ($srv -match "\`$path -eq '/api/search' -and \`$method -eq 'GET'")
T 'Get-PimReachableTargets defined'         ($srv -match 'function Get-PimReachableTargets')
T 'Get-PimRoleReachers defined'             ($srv -match 'function Get-PimRoleReachers')
T 'Get-PimGlobalSearch defined'             ($srv -match 'function Get-PimGlobalSearch')
T 'Get-PimAccessGraphModel defined'         ($srv -match 'function Get-PimAccessGraphModel')

# ===========================================================================
# Layer 2 -- DATA CORRELATION (in-proc, seeded fixtures)
# ===========================================================================
Write-Host "`n-- Layer 2: report engine reflects seeded delegation model (in-proc) --" -ForegroundColor Cyan

function Get-FnBody([string]$source, [string]$name) {
    $pat = 'function ' + [regex]::Escape($name) + '\b[\s\S]*?\n\}\r?\n'
    $m = [regex]::Match($source, $pat)
    if (-not $m.Success) { return $null }
    return $m.Value
}
$labelFn = Get-FnBody $srv 'Get-PimNodeLabel'
$fieldFn = Get-FnBody $srv 'Get-PimNodeField'
$modelFn = Get-FnBody $srv 'Get-PimAccessGraphModel'
$reachFn = Get-FnBody $srv 'Get-PimReachableTargets'
$revFn   = Get-FnBody $srv 'Get-PimRoleReachers'
$searchFn = Get-FnBody $srv 'Get-PimGlobalSearch'
T 'Get-PimNodeLabel extracted'        ([bool]$labelFn)
T 'Get-PimNodeField extracted'        ([bool]$fieldFn)
T 'Get-PimAccessGraphModel extracted' ([bool]$modelFn)
T 'Get-PimReachableTargets extracted' ([bool]$reachFn)
T 'Get-PimRoleReachers extracted'     ([bool]$revFn)
T 'Get-PimGlobalSearch extracted'     ([bool]$searchFn)

if ($labelFn -and $fieldFn -and $modelFn -and $reachFn -and $revFn -and $searchFn) {
    Set-StrictMode -Off
    Invoke-Expression $labelFn
    Invoke-Expression $fieldFn
    Invoke-Expression $modelFn
    Invoke-Expression $reachFn
    Invoke-Expression $revFn
    Invoke-Expression $searchFn

    # --- SEED a realistic delegation model (generic descriptors only). --------
    # admin1 -> ROLE-Id (role group) -> entra-role:Global Administrator (direct)
    #                                 -> SVC-Bkp (nested perm group) -> az-res target
    # admin2 -> ROLE-Help (role group) -> au-role target (Helpdesk @ AU:Sales)
    # admin3 -> reaches nothing (gap admin, no edges)
    $script:__nodes = @(
        [ordered]@{ id='admin1@example.test'; kind='admin'; label='Admin One';  purpose='HighPriv' }
        [ordered]@{ id='admin2@example.test'; kind='admin'; label='Admin Two';  purpose='Day2Day' }
        [ordered]@{ id='admin3@example.test'; kind='admin'; label='Admin Three';purpose='Day2Day' }
        [ordered]@{ id='group:ROLE-Id';   kind='role-group';       label='PIM-ROLE-Id-L0-T0';   level='L0'; groupTag='ROLE-Id' }
        [ordered]@{ id='group:ROLE-Help'; kind='role-group';       label='PIM-ROLE-Help-L2-T0'; level='L2'; groupTag='ROLE-Help' }
        [ordered]@{ id='group:SVC-Bkp';   kind='permission-group'; label='PIM-SVC-Bkp-L1-T1';   level='L1'; groupTag='SVC-Bkp' }
        [ordered]@{ id='au:Sales';        kind='au';               label='Sales';               auTag='Sales' }
        [ordered]@{ id='entra-role:Global Administrator'; kind='entra-role'; label='Global Administrator'; roleName='Global Administrator' }
        [ordered]@{ id='au-role:Sales:Helpdesk Administrator'; kind='au-role'; label='Helpdesk Administrator @ AU:Sales'; roleName='Helpdesk Administrator'; auTag='Sales' }
        [ordered]@{ id='az-res:/subscriptions/abc:Backup Operator'; kind='az-resource'; label='Backup Operator @ abc'; roleName='Backup Operator'; scopePath='/subscriptions/abc'; scopeType='Subscription'; scopeShort='abc' }
    )
    $script:__edges = @(
        [ordered]@{ source='admin1@example.test'; target='group:ROLE-Id';   type='Eligible'; kind='admin-to-group'; source_csv='PIM-Assignments-Admins' }
        [ordered]@{ source='group:ROLE-Id'; target='entra-role:Global Administrator'; type='Eligible'; kind='group-to-entra-role'; source_csv='PIM-Assignments-Roles-Groups' }
        # nesting: SVC-Bkp is a member of ROLE-Id -> reach flows ROLE-Id -> SVC-Bkp (engine emits SourceGroupTag=SVC-Bkp target=ROLE-Id)
        [ordered]@{ source='group:ROLE-Id'; target='group:SVC-Bkp'; type='Active'; kind='group-to-group'; source_csv='PIM-Assignments-Groups' }
        [ordered]@{ source='group:SVC-Bkp'; target='az-res:/subscriptions/abc:Backup Operator'; type='Eligible'; kind='group-to-az-resource'; source_csv='PIM-Assignments-Azure-Resources' }
        [ordered]@{ source='admin2@example.test'; target='group:ROLE-Help'; type='Eligible'; kind='admin-to-group'; source_csv='PIM-Assignments-Admins' }
        [ordered]@{ source='group:ROLE-Help'; target='au-role:Sales:Helpdesk Administrator'; type='Eligible'; kind='group-to-au-role'; source_csv='PIM-Assignments-Roles-AUs' }
        # cosmetic au->au-role edge (must NOT be a reach path)
        [ordered]@{ source='au:Sales'; target='au-role:Sales:Helpdesk Administrator'; type=''; kind='au-to-au-role'; source_csv='PIM-Assignments-Roles-AUs'; cosmetic=$true }
    )
    function Build-PimGraphData { [ordered]@{ generatedUtc='2026-06-16T00:00:00Z'; nodes=$script:__nodes; edges=$script:__edges; tenantId='00000000-0000-0000-0000-000000000000'; tenantName='Example' } }

    $model = Get-PimAccessGraphModel
    T 'model builds outgoing/incoming maps'  ([bool]$model -and [bool]$model.outgoing -and [bool]$model.incoming)
    T 'cosmetic au->au-role edge excluded from outgoing' (-not $model.outgoing.ContainsKey('au:Sales'))

    # --- FORWARD: "who can do what" ------------------------------------------
    $r1 = Get-PimReachableTargets -Person 'admin1@example.test' -Model $model
    T 'forward: admin1 resolves as a real person'  ([bool]$r1.found)
    T 'forward: admin1 reaches 2 targets'          ([int]$r1.count -eq 2)
    $tids = @($r1.targets | ForEach-Object { $_.targetId })
    T 'forward: reaches Global Administrator (direct group grant)' ($tids -contains 'entra-role:Global Administrator')
    T 'forward: reaches Azure target THROUGH the nested group'     ($tids -contains 'az-res:/subscriptions/abc:Backup Operator')
    $gaRow = @($r1.targets | Where-Object { $_.targetId -eq 'entra-role:Global Administrator' })[0]
    T 'forward: GA row carries the role name'       ($gaRow.roleName -eq 'Global Administrator')
    T 'forward: GA path starts at the role group'   ($gaRow.pathText -match 'PIM-ROLE-Id')
    $azRow = @($r1.targets | Where-Object { $_.targetId -like 'az-res:*' })[0]
    T 'forward: Azure row carries scope path'       ($azRow.scopePath -eq '/subscriptions/abc')
    T 'forward: Azure path shows the nested group'  ($azRow.pathText -match 'PIM-SVC-Bkp')

    $rGap = Get-PimReachableTargets -Person 'admin3@example.test' -Model $model
    T 'forward: gap admin found but reaches nothing' ([bool]$rGap.found -and [int]$rGap.count -eq 0)
    $rMiss = Get-PimReachableTargets -Person 'nobody@example.test' -Model $model
    T 'forward: unknown person -> found=$false, 0 targets' ((-not $rMiss.found) -and [int]$rMiss.count -eq 0)

    # --- REVERSE: who can activate a role ------------------------------------
    $rev1 = Get-PimRoleReachers -Role 'Global Administrator' -Model $model
    T 'reverse: GA resolves to a target'          ([int]$rev1.resolved -ge 1)
    T 'reverse: exactly 1 person can activate GA'  ([int]$rev1.count -eq 1)
    T 'reverse: that person is admin1'             (@($rev1.reachers | ForEach-Object { $_.person }) -contains 'admin1@example.test')
    T 'reverse: reacher carries the path'          ($rev1.reachers[0].pathText -match 'PIM-ROLE-Id')
    T 'reverse: reacher carries purpose'           ($rev1.reachers[0].purpose -eq 'HighPriv')

    $revBkp = Get-PimRoleReachers -Role 'Backup Operator' -Model $model
    T 'reverse: nested Azure target reachable by admin1' (@($revBkp.reachers | ForEach-Object { $_.person }) -contains 'admin1@example.test')

    $revHelp = Get-PimRoleReachers -Role 'Helpdesk Administrator' -Model $model
    T 'reverse: AU-scoped role reachable by admin2 only' ([int]$revHelp.count -eq 1 -and (@($revHelp.reachers | ForEach-Object { $_.person }) -contains 'admin2@example.test'))

    $revNone = Get-PimRoleReachers -Role 'No Such Role' -Model $model
    T 'reverse: unknown role -> resolved=0, 0 reachers' ([int]$revNone.resolved -eq 0 -and [int]$revNone.count -eq 0)

    # --- GLOBAL SEARCH -------------------------------------------------------
    $sAdmin = Get-PimGlobalSearch -Query 'Admin One' -Model $model
    T 'search: finds a person by display name' (@($sAdmin.hits | Where-Object { $_.type -eq 'person' -and $_.id -eq 'admin1@example.test' }).Count -eq 1)

    $sRole = Get-PimGlobalSearch -Query 'Global Admin' -Model $model
    T 'search: finds a role by name' (@($sRole.hits | Where-Object { $_.type -eq 'role' }).Count -ge 1)

    $sScope = Get-PimGlobalSearch -Query 'subscriptions/abc' -Model $model
    T 'search: finds an Azure scope by path' (@($sScope.hits | Where-Object { $_.type -eq 'scope' }).Count -ge 1)

    $sGroup = Get-PimGlobalSearch -Query 'ROLE-Id' -Model $model
    T 'search: finds a group' (@($sGroup.hits | Where-Object { $_.type -eq 'group' }).Count -ge 1)
    T 'search: surfaces the matching TAG facet' (@($sGroup.hits | Where-Object { $_.type -eq 'tag' -and $_.label -eq 'ROLE-Id' }).Count -eq 1)

    $sNone = Get-PimGlobalSearch -Query 'zzz-no-such-thing' -Model $model
    T 'search: no match -> 0 hits' ([int]$sNone.count -eq 0)

    $sEmpty = Get-PimGlobalSearch -Query '' -Model $model
    T 'search: empty query -> 0 hits (no scan)' ([int]$sEmpty.count -eq 0)

    # hits sort person before role before scope before tag.
    $allHits = (Get-PimGlobalSearch -Query 'a' -Model $model).hits
    if (@($allHits).Count -ge 2) {
        $rank = @{ person=0; group=1; role=2; scope=3; tag=4; other=5 }
        $ordered = $true
        for ($i=1; $i -lt @($allHits).Count; $i++) {
            if ([int]$rank["$($allHits[$i-1].type)"] -gt [int]$rank["$($allHits[$i].type)"]) { $ordered = $false; break }
        }
        T 'search: hits are type-ordered (person->group->role->scope->tag)' $ordered
    }
}

# ===========================================================================
# Layer 3 -- Node executor (export-helper injection safety + per-view wiring)
# Runs the companion tests/gui/access-reporting.test.js; self-skips if Node is
# absent (the PS layers above still gate).
# ===========================================================================
$node = Get-Command node -ErrorAction SilentlyContinue
$nodeTest = Join-Path $PSScriptRoot 'gui\access-reporting.test.js'
if (-not $node) {
    Write-Host "`n  SKIP (node executor): Node.js not found on PATH -- PS layers still gated." -ForegroundColor Yellow
} elseif (-not (Test-Path -LiteralPath $nodeTest)) {
    T 'node executor present' $false
} else {
    Write-Host "`n -- node executor: tests/gui/access-reporting.test.js --" -ForegroundColor Cyan
    & node $nodeTest
    if ($LASTEXITCODE -ne 0) { $fail++; Write-Host "  node executor FAILED" -ForegroundColor Red }
    else { Write-Host "  node executor green" -ForegroundColor Green }
}

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
