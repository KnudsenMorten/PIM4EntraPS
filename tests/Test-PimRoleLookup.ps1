#Requires -Version 5.1
<#
.SYNOPSIS
    Role Lookup upgrade (REQUIREMENTS.md §28 [H9]) -- OFFLINE, in-proc data tests
    over the PURE matching/compare functions PLUS static GUI/server wiring asserts.

.DESCRIPTION
    Two layers, all offline (no live tenant, no server boot):

      1. PURE LOGIC (in-proc) -- dot-source engine/_shared/PIM-Authoring.ps1 and
         exercise the unit-testable functions behind the upgraded Role Lookup tab:
           Get-PimStringSimilarity   -- ranking primitive
           Resolve-PimRoleQuery      -- typo tolerance: exact resolves; a TYPO
                                        returns ranked "did you mean..." candidates
                                        and NEVER throws / NEVER 503s; empty query
                                        -> empty list; unknown -> empty list.
           Compare-PimReachSets      -- role compare overlap + each-only sets.
         The reverse-lookup (who can activate) reuses Get-PimRoleReachers (extracted
         from Open-PimManager.ps1 over a SEEDED delegation model -- the same fixture
         shape Test-PimAccessReporting.ps1 uses) so we prove the right principals +
         paths come back and that a typo flows into ranked candidates.

      2. STATIC GUI / SERVER WIRING -- the Role Lookup tab declares the three
         sub-modes (perms / reverse / compare), the GUI calls the three endpoints,
         the server defines them, and the near-miss path is 200-with-candidates
         (NOT a 503) for /api/role-permissions.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root    = Split-Path -Parent $PSScriptRoot                 # ...\PIM4EntraPS
$mgrDir  = Join-Path $root 'tools\pim-manager'
$htmlPath = Join-Path $mgrDir 'pim-manager.html'
$srvPath  = Join-Path $mgrDir 'Open-PimManager.ps1'
$authPath = Join-Path $root 'engine\_shared\PIM-Authoring.ps1'
T 'pim-manager.html present'    (Test-Path -LiteralPath $htmlPath)
T 'Open-PimManager.ps1 present' (Test-Path -LiteralPath $srvPath)
T 'PIM-Authoring.ps1 present'   (Test-Path -LiteralPath $authPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
$html = [System.IO.File]::ReadAllText($htmlPath)
$srv  = [System.IO.File]::ReadAllText($srvPath)

# ===========================================================================
# Layer 1 -- PURE LOGIC (in-proc)
# ===========================================================================
Write-Host "`n-- Layer 1: pure matching / compare logic (in-proc) --" -ForegroundColor Cyan
Set-StrictMode -Off
. $authPath
T 'Get-PimStringSimilarity loaded' ([bool](Get-Command Get-PimStringSimilarity -ErrorAction SilentlyContinue))
T 'Resolve-PimRoleQuery loaded'    ([bool](Get-Command Resolve-PimRoleQuery -ErrorAction SilentlyContinue))
T 'Compare-PimReachSets loaded'    ([bool](Get-Command Compare-PimReachSets -ErrorAction SilentlyContinue))

# --- Get-PimStringSimilarity -------------------------------------------------
T 'similarity: identical = 1'           ((Get-PimStringSimilarity -A 'Global Administrator' -B 'Global Administrator') -eq 1.0)
T 'similarity: case-insensitive = 1'    ((Get-PimStringSimilarity -A 'global admin' -B 'Global Admin') -eq 1.0)
T 'similarity: one-letter typo is high' ((Get-PimStringSimilarity -A 'Globel Administrator' -B 'Global Administrator') -ge 0.9)
T 'similarity: unrelated is low'        ((Get-PimStringSimilarity -A 'Backup Operator' -B 'Global Administrator') -lt 0.55)
T 'similarity: empty vs nonempty = 0'   ((Get-PimStringSimilarity -A '' -B 'x') -eq 0.0)

# --- Resolve-PimRoleQuery: the typo-tolerance core ---------------------------
$catalog = @('Global Administrator','Global Reader','Privileged Role Administrator','Helpdesk Administrator','Backup Operator','User Administrator')

# Exact match (case-insensitive) resolves outright -- matched=$true, no candidates.
$rExact = Resolve-PimRoleQuery -Query 'global administrator' -RoleNames $catalog
T 'resolve: exact (case-insensitive) -> matched=$true'        ([bool]$rExact.matched)
T 'resolve: exact returns the canonical role name'            ($rExact.role -eq 'Global Administrator')
T 'resolve: exact has no candidates'                          (@($rExact.candidates).Count -eq 0)

# A TYPO must NOT throw and must NOT be matched -- it returns ranked candidates.
$rTypo = $null; $threw = $false
try { $rTypo = Resolve-PimRoleQuery -Query 'Globel AdministraTOR' -RoleNames $catalog } catch { $threw = $true }
T 'resolve: a typo does NOT throw (no 503-shaped failure)'    (-not $threw)
T 'resolve: a typo is matched=$false'                         (-not $rTypo.matched)
T 'resolve: a typo yields >=1 ranked candidate'               (@($rTypo.candidates).Count -ge 1)
T 'resolve: top candidate is the intended role'               ($rTypo.candidates[0].role -eq 'Global Administrator')
T 'resolve: candidates carry a score + reason'                (($rTypo.candidates[0].score -gt 0) -and "$($rTypo.candidates[0].reason)".Trim())
# ranking is descending by score.
$desc = $true
for ($i=1; $i -lt @($rTypo.candidates).Count; $i++) { if ([double]$rTypo.candidates[$i-1].score -lt [double]$rTypo.candidates[$i].score) { $desc = $false; break } }
T 'resolve: candidates are ranked best-first'                 $desc

# Substring query -> substring candidates (e.g. "admin" finds all the Administrators).
$rSub = Resolve-PimRoleQuery -Query 'administrator' -RoleNames $catalog
T 'resolve: substring query is matched=$false (not exact)'    (-not $rSub.matched)
T 'resolve: substring query surfaces every Administrator'     (@($rSub.candidates | Where-Object { $_.role -like '*Administrator*' }).Count -ge 4)

# Empty query -> empty list (NOT an error, NOT a scan).
$rEmpty = Resolve-PimRoleQuery -Query '' -RoleNames $catalog
T 'resolve: empty query -> matched=$false, empty candidates'  ((-not $rEmpty.matched) -and @($rEmpty.candidates).Count -eq 0)

# Unknown-and-not-close -> empty list (graceful, never an error).
$rNone = Resolve-PimRoleQuery -Query 'zzqqxx-not-a-role' -RoleNames $catalog
T 'resolve: genuine miss -> empty candidate list (no throw)'  (@($rNone.candidates).Count -eq 0 -and -not $rNone.matched)

# Empty catalog -> still no throw, empty list.
$rNoCat = Resolve-PimRoleQuery -Query 'Global Administrator' -RoleNames @()
T 'resolve: empty catalog -> empty list, no throw'            (-not $rNoCat.matched -and @($rNoCat.candidates).Count -eq 0)

# Max cap honoured.
$big = 1..50 | ForEach-Object { "Administrator $_" }
$rCap = Resolve-PimRoleQuery -Query 'Administrator' -RoleNames $big -Max 5
T 'resolve: candidate list honours -Max cap'                  (@($rCap.candidates).Count -le 5)

# ===========================================================================
# Reverse lookup (reuse Get-PimRoleReachers) over a SEEDED delegation model.
# ===========================================================================
Write-Host "`n-- Layer 1b: reverse lookup + compare over a seeded model --" -ForegroundColor Cyan
function Get-FnBody([string]$source, [string]$name) {
    $pat = 'function ' + [regex]::Escape($name) + '\b[\s\S]*?\n\}\r?\n'
    $m = [regex]::Match($source, $pat)
    if (-not $m.Success) { return $null }
    return $m.Value
}
$labelFn  = Get-FnBody $srv 'Get-PimNodeLabel'
$fieldFn  = Get-FnBody $srv 'Get-PimNodeField'
$modelFn  = Get-FnBody $srv 'Get-PimAccessGraphModel'
$revFn    = Get-FnBody $srv 'Get-PimRoleReachers'
T 'Get-PimNodeLabel extracted'        ([bool]$labelFn)
T 'Get-PimNodeField extracted'        ([bool]$fieldFn)
T 'Get-PimAccessGraphModel extracted' ([bool]$modelFn)
T 'Get-PimRoleReachers extracted'     ([bool]$revFn)

if ($labelFn -and $fieldFn -and $modelFn -and $revFn) {
    Invoke-Expression $labelFn
    Invoke-Expression $fieldFn
    Invoke-Expression $modelFn
    Invoke-Expression $revFn

    # Seeded model: admin1 reaches GA + (nested) Backup Operator; admin2 reaches GA
    # + Helpdesk @ AU:Sales. So GA is reachable by BOTH; Backup Operator only by
    # admin1; Helpdesk only by admin2 -- the exact compare overlap fixture.
    $script:__nodes = @(
        [ordered]@{ id='admin1@example.test'; kind='admin'; label='Admin One'; purpose='HighPriv' }
        [ordered]@{ id='admin2@example.test'; kind='admin'; label='Admin Two'; purpose='Day2Day' }
        [ordered]@{ id='group:ROLE-Id';   kind='role-group';       label='PIM-ROLE-Id-L0-T0';   level='L0'; groupTag='ROLE-Id' }
        [ordered]@{ id='group:ROLE-Help'; kind='role-group';       label='PIM-ROLE-Help-L2-T0'; level='L2'; groupTag='ROLE-Help' }
        [ordered]@{ id='group:SVC-Bkp';   kind='permission-group'; label='PIM-SVC-Bkp-L1-T1';   level='L1'; groupTag='SVC-Bkp' }
        [ordered]@{ id='au:Sales';        kind='au';               label='Sales';               auTag='Sales' }
        [ordered]@{ id='entra-role:Global Administrator'; kind='entra-role'; label='Global Administrator'; roleName='Global Administrator' }
        [ordered]@{ id='au-role:Sales:Helpdesk Administrator'; kind='au-role'; label='Helpdesk Administrator @ AU:Sales'; roleName='Helpdesk Administrator'; auTag='Sales' }
        [ordered]@{ id='az-res:/subscriptions/abc:Backup Operator'; kind='az-resource'; label='Backup Operator @ abc'; roleName='Backup Operator'; scopePath='/subscriptions/abc'; scopeType='Subscription'; scopeShort='abc' }
    )
    $script:__edges = @(
        [ordered]@{ source='admin1@example.test'; target='group:ROLE-Id';   type='Eligible'; kind='admin-to-group' }
        [ordered]@{ source='group:ROLE-Id'; target='entra-role:Global Administrator'; type='Eligible'; kind='group-to-entra-role' }
        [ordered]@{ source='group:ROLE-Id'; target='group:SVC-Bkp'; type='Active'; kind='group-to-group' }
        [ordered]@{ source='group:SVC-Bkp'; target='az-res:/subscriptions/abc:Backup Operator'; type='Eligible'; kind='group-to-az-resource' }
        [ordered]@{ source='admin2@example.test'; target='group:ROLE-Help'; type='Eligible'; kind='admin-to-group' }
        [ordered]@{ source='group:ROLE-Help'; target='entra-role:Global Administrator'; type='Eligible'; kind='group-to-entra-role' }
        [ordered]@{ source='group:ROLE-Help'; target='au-role:Sales:Helpdesk Administrator'; type='Eligible'; kind='group-to-au-role' }
    )
    function Build-PimGraphData { [ordered]@{ generatedUtc='2026-06-16T00:00:00Z'; nodes=$script:__nodes; edges=$script:__edges; tenantId='00000000-0000-0000-0000-000000000000'; tenantName='Example' } }
    $model = Get-PimAccessGraphModel

    # --- reverse lookup lists the right principals + paths --------------------
    $revGA = Get-PimRoleReachers -Role 'Global Administrator' -Model $model
    T 'reverse: GA resolves to a target'                ([int]$revGA.resolved -ge 1)
    $gaPeople = @($revGA.reachers | ForEach-Object { $_.person })
    T 'reverse: BOTH admins can activate GA'            ($gaPeople -contains 'admin1@example.test' -and $gaPeople -contains 'admin2@example.test')
    T 'reverse: each GA reacher carries a path'         (@($revGA.reachers | Where-Object { "$($_.pathText)".Trim() }).Count -eq @($revGA.reachers).Count)
    $bkp = Get-PimRoleReachers -Role 'Backup Operator' -Model $model
    T 'reverse: nested Azure role reachable by admin1 only' ([int]$bkp.count -eq 1 -and (@($bkp.reachers | ForEach-Object { $_.person }) -contains 'admin1@example.test'))
    $revMiss = Get-PimRoleReachers -Role 'No Such Role' -Model $model
    T 'reverse: unknown role -> resolved=0, count=0 (empty, not error)' ([int]$revMiss.resolved -eq 0 -and [int]$revMiss.count -eq 0)

    # --- a typo on the reverse path flows into ranked candidates --------------
    # (mirrors the endpoint: when resolved=0, Resolve over the model's role names)
    $modelCatalog = @($model.nodes | Where-Object { ('entra-role','au-role','az-resource') -contains (Get-PimNodeField -Node $_ -Name 'kind') } | ForEach-Object { Get-PimNodeField -Node $_ -Name 'roleName' })
    $rTypoRev = Resolve-PimRoleQuery -Query 'Globel Administrator' -RoleNames $modelCatalog
    T 'reverse-typo: resolves to GA candidate (no 503 path)' ((-not $rTypoRev.matched) -and $rTypoRev.candidates[0].role -eq 'Global Administrator')

    # --- Compare-PimReachSets: overlap + each-only ---------------------------
    $cmp = Compare-PimReachSets -ReachersA @($revGA.reachers) -ReachersB @($bkp.reachers) -LabelA 'Global Administrator' -LabelB 'Backup Operator'
    $bothP  = @($cmp.both  | ForEach-Object { $_.person })
    $onlyAP = @($cmp.onlyA | ForEach-Object { $_.person })
    T 'compare: admin1 is in BOTH (reaches GA and Backup Operator)'   ($bothP -contains 'admin1@example.test')
    T 'compare: admin2 is ONLY-A (GA but not Backup Operator)'        ($onlyAP -contains 'admin2@example.test')
    T 'compare: onlyB is empty (no Backup-only reacher)'              (@($cmp.onlyB).Count -eq 0)
    T 'compare: counts are consistent'                               ([int]$cmp.countBoth -eq @($cmp.both).Count -and [int]$cmp.countA -eq @($cmp.onlyA).Count -and [int]$cmp.countB -eq @($cmp.onlyB).Count)
    # Two roles reachable by the SAME set -> all overlap, no each-only.
    $help = Get-PimRoleReachers -Role 'Helpdesk Administrator' -Model $model
    $cmpSame = Compare-PimReachSets -ReachersA @($revGA.reachers) -ReachersB @($revGA.reachers)
    T 'compare: identical sets -> all overlap, no each-only'          (@($cmpSame.onlyA).Count -eq 0 -and @($cmpSame.onlyB).Count -eq 0 -and [int]$cmpSame.countBoth -eq @($revGA.reachers).Count)
    # Disjoint sets -> no overlap.
    $cmpDisjoint = Compare-PimReachSets -ReachersA @($bkp.reachers) -ReachersB @($help.reachers)
    T 'compare: disjoint sets -> no overlap'                          (@($cmpDisjoint.both).Count -eq 0)
    # Empty inputs -> all empty (no throw).
    $cmpEmpty = Compare-PimReachSets -ReachersA @() -ReachersB @()
    T 'compare: empty inputs -> all empty (no throw)'                 (@($cmpEmpty.both).Count -eq 0 -and @($cmpEmpty.onlyA).Count -eq 0 -and @($cmpEmpty.onlyB).Count -eq 0)
}

# ===========================================================================
# Layer 2 -- STATIC GUI / SERVER WIRING
# ===========================================================================
Write-Host "`n-- Layer 2: Role Lookup tab + endpoint wiring (static) --" -ForegroundColor Cyan
T 'Role Lookup tab declared'                ($html -match 'data-tab="roleperms"')
T 'roleperms routes -> renderRolePerms'     ($html -match "name === 'roleperms'\s*\)\s*renderRolePerms")
T 'tab has three sub-modes (perms/reverse/compare)' ($html -match 'id="rlModePerms"' -and $html -match 'id="rlModeReverse"' -and $html -match 'id="rlModeCompare"')
T 'GUI renders did-you-mean candidates'     ($html -match 'function didYouMean\(')
T 'GUI handles matched===false (no error)'  ($html -match 'data\.matched === false')
T 'GUI calls /api/role-permissions'         ($html -match '/api/role-permissions\?role=')
T 'GUI calls /api/role-lookup/reverse'      ($html -match '/api/role-lookup/reverse\?role=')
T 'GUI calls /api/role-lookup/compare'      ($html -match '/api/role-lookup/compare\?roleA=')

# Server endpoints.
T 'server handles GET /api/role-permissions'      ($srv -match "\`$path -eq '/api/role-permissions' -and \`$method -eq 'GET'")
T 'server handles GET /api/role-lookup/reverse'   ($srv -match "\`$path -eq '/api/role-lookup/reverse' -and \`$method -eq 'GET'")
T 'server handles GET /api/role-lookup/compare'   ($srv -match "\`$path -eq '/api/role-lookup/compare' -and \`$method -eq 'GET'")
T 'role-permissions near-miss is 200 w/ candidates (NOT 503)' ($srv -match 'Resolve-PimRoleQuery' -and $srv -match "matched = \`$false; role = \`$roleName")
T 'reverse endpoint reuses Get-PimRoleReachers'   ($srv -match 'Get-PimRoleReachers -Role \$roleName')
T 'compare endpoint reuses Compare-PimReachSets'  ($srv -match 'Compare-PimReachSets')
T 'Get-PimRoleCatalogNames helper defined'        ($srv -match 'function Get-PimRoleCatalogNames')
# Guard: the OLD 503-on-near-miss path must be gone from role-permissions.
$rpBlock = ''
$mRp = [regex]::Match($srv, "if \(\`$path -eq '/api/role-permissions'[\s\S]*?\n        \}")
if ($mRp.Success) { $rpBlock = $mRp.Value }
T 'role-permissions block no longer emits a 503' ($rpBlock -and ($rpBlock -notmatch 'Status 503'))

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
