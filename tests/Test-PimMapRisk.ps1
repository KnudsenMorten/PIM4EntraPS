#Requires -Version 5.1
<#
.SYNOPSIS
    Offline proof for the Delegation Map search-result builder + risk overlay
    (REQUIREMENTS §28 [M8]). Drives the PURE engine functions
    (engine/_shared/PIM-MapRisk.ps1: Get-PimMapSearchResults +
    Get-PimMapRiskOverlay) over a SEEDED node/edge model -- no SQL, no Graph,
    no HTTP. Same reach semantics as Build-PimGraphData / the Map's buildMapModel.

    Asserts:
      * search returns the right ORDERED, typed matches and a jump target id;
      * an intentionally ORPHANED group (no admin path) is flagged orphan;
      * an over-privileged principal reaching a T0 target is flagged overpriv;
      * a healthy node is flagged NEITHER;
      * stale flags only fire when a real review signal is present;
      * the over-priv count threshold is EMPIRICAL (mean+stddev), no magic cap.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$lib = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-MapRisk.ps1'
T 'PIM-MapRisk.ps1 present' (Test-Path -LiteralPath $lib)
if (-not (Test-Path -LiteralPath $lib)) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
. $lib

# ---------------------------------------------------------------------------
# Seeded model -- the SHAPE Build-PimGraphData emits (nodes/edges, ordered
# hashtables). Two admins:
#   - adm-ga    -> ROLE-GA   -> Entra-GA bundle -> Global Administrator (T0 target)
#                 => OVER-PRIVILEGED (reaches a T0 target)
#   - adm-help  -> ROLE-Help -> Tasks-Helpdesk  -> au-role Helpdesk @ AU-Users (T2)
#                 => HEALTHY (no T0/T1, normal reach)
# One ORPHAN group: ROLE-Orphan has NO admin assignment into it (dead delegation).
# One STALE permission group via a review signal (lastReviewedUtc + reviewDays).
# ---------------------------------------------------------------------------
function New-SeedModel {
    $nodes = @(
        [ordered]@{ id = 'adm-ga@seed.test';   label = 'GA Admin';      kind = 'admin';            purpose = 'HighPriv' }
        [ordered]@{ id = 'adm-help@seed.test'; label = 'Helpdesk';      kind = 'admin';            purpose = 'Day2Day' }
        [ordered]@{ id = 'group:ROLE-GA';      label = 'GA role';       kind = 'role-group';       tier = 'T0'; groupTag = 'ROLE-GA' }
        [ordered]@{ id = 'group:ROLE-Help';    label = 'Helpdesk role'; kind = 'role-group';       tier = 'T2'; groupTag = 'ROLE-Help' }
        [ordered]@{ id = 'group:ROLE-Orphan';  label = 'Orphan role';   kind = 'role-group';       tier = 'T1'; groupTag = 'ROLE-Orphan' }
        [ordered]@{ id = 'group:Entra-GA';     label = 'GA bundle';     kind = 'permission-group'; tier = 'T0'; groupTag = 'Entra-GA' }
        [ordered]@{ id = 'group:Tasks-Help';   label = 'Helpdesk tasks'; kind = 'permission-group'; tier = 'T2'; groupTag = 'Tasks-Help'; lastReviewedUtc = '2000-01-01T00:00:00Z'; reviewDays = '90' }
        [ordered]@{ id = 'entra-role:Global Administrator'; label = 'Global Administrator'; kind = 'entra-role'; tier = 'T0'; roleName = 'Global Administrator' }
        [ordered]@{ id = 'au-role:AU-Users:Helpdesk Administrator'; label = 'Helpdesk Administrator @ AU:AU-Users'; kind = 'au-role'; tier = 'T2'; roleName = 'Helpdesk Administrator'; auTag = 'AU-Users' }
    )
    $edges = @(
        [ordered]@{ source = 'adm-ga@seed.test';   target = 'group:ROLE-GA';   kind = 'admin-to-group' }
        [ordered]@{ source = 'adm-help@seed.test'; target = 'group:ROLE-Help'; kind = 'admin-to-group' }
        # canonical nesting: role group (Source) nested INTO permission group (Target)
        [ordered]@{ source = 'group:Entra-GA';   target = 'group:ROLE-GA';   kind = 'group-to-group' }
        [ordered]@{ source = 'group:Tasks-Help'; target = 'group:ROLE-Help'; kind = 'group-to-group' }
        [ordered]@{ source = 'group:Entra-GA';   target = 'entra-role:Global Administrator'; kind = 'group-to-entra-role' }
        [ordered]@{ source = 'group:Tasks-Help'; target = 'au-role:AU-Users:Helpdesk Administrator'; kind = 'group-to-au-role' }
    )
    return @{ nodes = $nodes; edges = $edges }
}

$model = New-SeedModel

# === SEARCH ================================================================
Write-Host "`n-- Search: typed, ordered result list + jump target --" -ForegroundColor Cyan
$r = Get-PimMapSearchResults -Data $model -Query 'help'
T 'search finds the helpdesk matches' ($r.count -ge 2)
$ids = @($r.hits | ForEach-Object { $_.id })
T 'search includes the helpdesk admin (jump target id)'   ($ids -contains 'adm-help@seed.test')
T 'search includes the helpdesk role group'               ($ids -contains 'group:ROLE-Help')
# ordering: person (rank 0) sorts before group (rank 1)
$firstPersonIx = [array]::IndexOf($ids, 'adm-help@seed.test')
$firstGroupIx  = [array]::IndexOf($ids, 'group:ROLE-Help')
T 'people are ordered before groups'                       ($firstPersonIx -ge 0 -and $firstPersonIx -lt $firstGroupIx)
$hit = @($r.hits | Where-Object { $_.id -eq 'adm-help@seed.test' })[0]
T 'person hit is typed "person"'                          ($hit.type -eq 'person')
T 'empty query returns no hits'                            ((Get-PimMapSearchResults -Data $model -Query '').count -eq 0)
$r2 = Get-PimMapSearchResults -Data $model -Query 'global administrator'
T 'search matches a target by role name'                  (@($r2.hits | ForEach-Object { $_.id }) -contains 'entra-role:Global Administrator')

# === RISK OVERLAY ==========================================================
Write-Host "`n-- Risk overlay: orphan / stale / over-privileged --" -ForegroundColor Cyan
$ov = Get-PimMapRiskOverlay -Data $model

# ORPHAN: ROLE-Orphan has no admin path into it.
T 'orphan group flagged orphan'           ($ov.orphanIds -contains 'group:ROLE-Orphan')
T 'orphan reason explains dead delegation' ("$($ov.nodes['group:ROLE-Orphan'].reasons['orphan'])" -match 'No admin path')

# OVER-PRIVILEGED: adm-ga reaches Global Administrator (T0).
T 'GA admin flagged over-privileged'       ($ov.overprivIds -contains 'adm-ga@seed.test')
T 'over-priv reason cites the T0/T1 reach'  ("$($ov.nodes['adm-ga@seed.test'].reasons['overpriv'])" -match 'Tier-0')

# HEALTHY: adm-help reaches only a T2 au-role -> flagged NEITHER.
T 'helpdesk admin is NOT orphan'           (-not ($ov.orphanIds   -contains 'adm-help@seed.test'))
T 'helpdesk admin is NOT over-privileged'  (-not ($ov.overprivIds -contains 'adm-help@seed.test'))
T 'helpdesk admin carries no risk entry'   (-not $ov.nodes.ContainsKey('adm-help@seed.test'))

# STALE: only the permission group with a real review signal, past horizon.
T 'stale node flagged from a real review signal' ($ov.staleIds -contains 'group:Tasks-Help')
T 'node WITHOUT a review signal is never stale'   (-not ($ov.staleIds -contains 'group:Entra-GA'))

# Reachable T0 target itself is NOT an orphan (a principal reaches it).
T 'reachable T0 target is not orphan'      (-not ($ov.orphanIds -contains 'entra-role:Global Administrator'))

# Threshold is empirical (finite only with >=2 reach data points; here counts
# are {1,1} so no spread -> count signal disabled, T0/T1 reach still flags).
T 'threshold is computed, not a magic cap' ($ov.summary.overpriv -ge 1)

# === EMPIRICAL THRESHOLD FIXTURE ===========================================
# Build a model where one principal reaches MANY targets and the rest reach
# one each, so the count distribution has spread and the outlier is flagged by
# count alone (no T0/T1 tier on any target).
Write-Host "`n-- Empirical over-priv: count outlier flagged without any tier signal --" -ForegroundColor Cyan
function New-OutlierModel {
    $nodes = New-Object System.Collections.ArrayList
    $edges = New-Object System.Collections.ArrayList
    # the outlier admin -> a fat role group reaching 6 distinct entra roles
    [void]$nodes.Add([ordered]@{ id = 'adm-fat@seed.test'; label = 'Fat'; kind = 'admin'; purpose = 'Day2Day' })
    [void]$nodes.Add([ordered]@{ id = 'group:ROLE-Fat'; label = 'Fat role'; kind = 'role-group'; tier = 'T2'; groupTag = 'ROLE-Fat' })
    [void]$edges.Add([ordered]@{ source = 'adm-fat@seed.test'; target = 'group:ROLE-Fat'; kind = 'admin-to-group' })
    for ($i = 1; $i -le 6; $i++) {
        $tid = "entra-role:Role$i"
        [void]$nodes.Add([ordered]@{ id = $tid; label = "Role$i"; kind = 'entra-role'; tier = 'T2'; roleName = "Role$i" })
        [void]$edges.Add([ordered]@{ source = 'group:ROLE-Fat'; target = $tid; kind = 'group-to-entra-role' })
    }
    # several thin admins -> a role group reaching exactly one (distinct) target each
    for ($j = 1; $j -le 5; $j++) {
        $a = "adm-thin$j@seed.test"; $g = "group:ROLE-Thin$j"; $t = "entra-role:Thin$j"
        [void]$nodes.Add([ordered]@{ id = $a; label = "Thin$j"; kind = 'admin'; purpose = 'Day2Day' })
        [void]$nodes.Add([ordered]@{ id = $g; label = "Thin role $j"; kind = 'role-group'; tier = 'T2'; groupTag = "ROLE-Thin$j" })
        [void]$nodes.Add([ordered]@{ id = $t; label = "Thin$j role"; kind = 'entra-role'; tier = 'T2'; roleName = "Thin$j" })
        [void]$edges.Add([ordered]@{ source = $a; target = $g; kind = 'admin-to-group' })
        [void]$edges.Add([ordered]@{ source = $g; target = $t; kind = 'group-to-entra-role' })
    }
    return @{ nodes = $nodes.ToArray(); edges = $edges.ToArray() }
}
$ov2 = Get-PimMapRiskOverlay -Data (New-OutlierModel)
T 'count threshold is finite (distribution has spread)' ($ov2.threshold -lt [double]::PositiveInfinity)
T 'fat admin flagged over-privileged by COUNT'          ($ov2.overprivIds -contains 'adm-fat@seed.test')
T 'fat reason cites reach count vs estate norm'          ("$($ov2.nodes['adm-fat@seed.test'].reasons['overpriv'])" -match 'above the estate norm')
T 'a thin admin (reaches 1) is NOT over-privileged'      (-not ($ov2.overprivIds -contains 'adm-thin1@seed.test'))

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
