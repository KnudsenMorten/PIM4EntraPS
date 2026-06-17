#Requires -Version 5.1
<#
.SYNOPSIS
    Tier-impact report (REQUIREMENTS.md §23, ROADMAP #24) -- PURE offline tests of
    engine/_shared/PIM-TierImpact.ps1 over a SEEDED delegation model, PLUS static
    GUI/server wiring asserts (no dead view; the report is engine-backed).

.DESCRIPTION
    Two layers, all offline (no live tenant, no server boot):

      1. DATA CORRELATION (in-proc) -- dot-source the pure lib, seed a realistic
         node/edge model (admins -> role groups -> nested permission group(s) ->
         Entra-role / AU-role / Azure targets), and assert that Get-PimTierImpactReport
         finds every admin with a path to a Tier-0/Tier-1 target -- INCLUDING the
         indirect path through a nested group -- with the right highest tier, count,
         worst-target path, and the viaNested flag the flat-role-list view misses.

      2. STATIC GUI/SERVER WIRING -- the Reports tab has a Tier-impact mode, it calls
         GET /api/tier-impact, the server defines that route, dot-sources the lib, and
         the wrapper Get-PimTierImpactReportLive is defined.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root   = Split-Path -Parent $PSScriptRoot          # ...\PIM4EntraPS
$libPath = Join-Path $root 'engine\_shared\PIM-TierImpact.ps1'
$mgrDir  = Join-Path $root 'tools\pim-manager'
$htmlPath = Join-Path $mgrDir 'pim-manager.html'
$srvPath  = Join-Path $mgrDir 'Open-PimManager.ps1'
T 'PIM-TierImpact.ps1 present' (Test-Path -LiteralPath $libPath)
T 'pim-manager.html present'   (Test-Path -LiteralPath $htmlPath)
T 'Open-PimManager.ps1 present' (Test-Path -LiteralPath $srvPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

# ===========================================================================
# Layer 1 -- DATA CORRELATION (in-proc, seeded fixtures)
# ===========================================================================
Write-Host "`n-- Layer 1: tier-impact engine reflects seeded delegation model (in-proc) --" -ForegroundColor Cyan
Set-StrictMode -Off
. $libPath

# SEED a realistic delegation model (generic descriptors only).
#  admin1 (HighPriv): -> ROLE-Id (L0 role group) -> entra-role:Global Administrator  [DIRECT, T0]
#                                                 -> SVC-Bkp (L1 nested perm group) -> az target [NESTED, T1]
#  admin2 (Day2Day):  -> ROLE-Help (L2 role group) -> au-role target  [T2 -- NOT high tier]
#  admin3 (Day2Day):  -> SVC-T1 (L1 perm group, attached straight to admin) -> entra-role:Security Reader [T1]
#  admin4 (Day2Day):  reaches nothing (gap admin, no edges)
$nodes = @(
    [ordered]@{ id='admin1@example.test'; kind='admin'; label='Admin One';   purpose='HighPriv' }
    [ordered]@{ id='admin2@example.test'; kind='admin'; label='Admin Two';   purpose='Day2Day' }
    [ordered]@{ id='admin3@example.test'; kind='admin'; label='Admin Three'; purpose='Day2Day' }
    [ordered]@{ id='admin4@example.test'; kind='admin'; label='Admin Four';  purpose='Day2Day' }
    [ordered]@{ id='group:ROLE-Id';   kind='role-group';       label='PIM-ROLE-Id-L0-T0';     level='L0'; groupTag='ROLE-Id' }
    [ordered]@{ id='group:ROLE-Help'; kind='role-group';       label='PIM-ROLE-Help-L2-T2';   level='L2'; groupTag='ROLE-Help' }
    [ordered]@{ id='group:SVC-Bkp';   kind='permission-group'; label='PIM-SVC-Bkp-L1-T1';     level='L1'; groupTag='SVC-Bkp' }
    [ordered]@{ id='group:SVC-T1';    kind='permission-group'; label='PIM-SVC-T1-L1-T1';      level='L1'; groupTag='SVC-T1' }
    [ordered]@{ id='entra-role:Global Administrator'; kind='entra-role'; label='Global Administrator'; roleName='Global Administrator' }
    [ordered]@{ id='entra-role:Security Reader';      kind='entra-role'; label='Security Reader';      roleName='Security Reader' }
    [ordered]@{ id='au-role:Sales:Helpdesk Administrator'; kind='au-role'; label='Helpdesk Administrator @ AU:Sales'; roleName='Helpdesk Administrator'; auTag='Sales' }
    [ordered]@{ id='az-res:/subscriptions/abc:Backup Operator'; kind='az-resource'; label='Backup Operator @ abc'; roleName='Backup Operator'; scopePath='/subscriptions/abc' }
    [ordered]@{ id='au:Sales'; kind='au'; label='Sales'; auTag='Sales' }
)
$edges = @(
    [ordered]@{ source='admin1@example.test'; target='group:ROLE-Id'; type='Eligible'; kind='admin-to-group' }
    [ordered]@{ source='group:ROLE-Id'; target='entra-role:Global Administrator'; type='Eligible'; kind='group-to-entra-role' }
    # nesting: SVC-Bkp is a member of ROLE-Id -> reach flows ROLE-Id -> SVC-Bkp
    [ordered]@{ source='group:ROLE-Id'; target='group:SVC-Bkp'; type='Active'; kind='group-to-group' }
    [ordered]@{ source='group:SVC-Bkp'; target='az-res:/subscriptions/abc:Backup Operator'; type='Eligible'; kind='group-to-az-resource' }
    [ordered]@{ source='admin2@example.test'; target='group:ROLE-Help'; type='Eligible'; kind='admin-to-group' }
    [ordered]@{ source='group:ROLE-Help'; target='au-role:Sales:Helpdesk Administrator'; type='Eligible'; kind='group-to-au-role' }
    [ordered]@{ source='admin3@example.test'; target='group:SVC-T1'; type='Eligible'; kind='admin-to-group' }
    [ordered]@{ source='group:SVC-T1'; target='entra-role:Security Reader'; type='Eligible'; kind='group-to-entra-role' }
    # cosmetic au->au-role edge (must NOT be a reach path)
    [ordered]@{ source='au:Sales'; target='au-role:Sales:Helpdesk Administrator'; type=''; kind='au-to-au-role'; cosmetic=$true }
)
$data = [ordered]@{ generatedUtc='2026-06-17T00:00:00Z'; nodes=$nodes; edges=$edges; tenantId='00000000-0000-0000-0000-000000000000'; tenantName='Example' }

$rpt = Get-PimTierImpactReport -Data $data
T 'report builds'                       ([bool]$rpt)
T 'scanned all 4 admins'                ([int]$rpt.scannedAdmins -eq 4)
# admin1 (T0), admin3 (T1) reach high tier; admin2 (T2) does not; admin4 reaches nothing.
T 'impacted = 2 admins (admin1 + admin3)' ([int]$rpt.impactedCount -eq 2)
T 'tier0Count = 1'                      ([int]$rpt.tier0Count -eq 1)
T 'tier1Count = 1'                      ([int]$rpt.tier1Count -eq 1)

$byPerson = @{}
foreach ($r in $rpt.rows) { $byPerson["$($r.person)"] = $r }
T 'admin1 present in report'            ($byPerson.ContainsKey('admin1@example.test'))
T 'admin3 present in report'            ($byPerson.ContainsKey('admin3@example.test'))
T 'admin2 (T2 only) NOT in report'     (-not $byPerson.ContainsKey('admin2@example.test'))
T 'admin4 (gap) NOT in report'         (-not $byPerson.ContainsKey('admin4@example.test'))

$a1 = $byPerson['admin1@example.test']
T 'admin1 highest tier = T0'           ($a1.highestTier -eq 'T0' -and [int]$a1.highestTierLevel -eq 0)
T 'admin1 carries purpose HighPriv'    ($a1.purpose -eq 'HighPriv')
# admin1 reaches GA (direct) AND the Azure target (nested) -- BOTH effectively T0
# because they are reached through the L0 role group (the running min level
# propagates L0 down the nested edge). So 2 high-tier targets, both at level 0.
T 'admin1 reaches 2 high-tier targets' ([int]$a1.highTargetCount -eq 2)
# The worst (most privileged) target tie-breaks to the NESTED path -- the hidden
# indirect reach a flat per-admin role list misses -- so the headline surfaces it.
T 'admin1 worst target reached through a nested group' ([bool]$a1.viaNested)
T 'admin1 worst path names BOTH the role group and the nested perm group' ($a1.pathText -match 'PIM-ROLE-Id' -and $a1.pathText -match 'PIM-SVC-Bkp')

$a3 = $byPerson['admin3@example.test']
T 'admin3 highest tier = T1'           ($a3.highestTier -eq 'T1' -and [int]$a3.highestTierLevel -eq 1)
T 'admin3 reaches exactly 1 high-tier target' ([int]$a3.highTargetCount -eq 1)
T 'admin3 worst target is Security Reader' ($a3.worstTarget -eq 'entra-role:Security Reader')

# INDIRECT (nested) reach is the headline value: admin1 reaches the Azure target
# ONLY through the nested permission group SVC-Bkp -- prove the engine surfaces
# a NESTED path (the thing a flat per-admin role list cannot see).
$a1b = @($rpt.rows | Where-Object { $_.person -eq 'admin1@example.test' })[0]
T 'admin1 still 2 high-tier targets at HighTierMax=1 (default)' ([int]$a1b.highTargetCount -eq 2)

# Narrow to Tier-0 ONLY: only admin1 qualifies (admin3 is T1).
$rptT0 = Get-PimTierImpactReport -Data $data -HighTierMax 0
$t0rows = @($rptT0.rows)
T 'HighTierMax=0 -> only Tier-0 admins (admin1)' ([int]$rptT0.impactedCount -eq 1 -and ($t0rows[0].person -eq 'admin1@example.test'))

# A model with NO high-tier reach -> honest empty (no fabricated rows).
$lowData = [ordered]@{ nodes=@(
    [ordered]@{ id='u@example.test'; kind='admin'; label='U'; purpose='Day2Day' }
    [ordered]@{ id='group:ROLE-Low'; kind='role-group'; label='PIM-ROLE-Low-L4-T4'; level='L4'; groupTag='ROLE-Low' }
    [ordered]@{ id='entra-role:Reports Reader'; kind='entra-role'; label='Reports Reader'; roleName='Reports Reader' }
); edges=@(
    [ordered]@{ source='u@example.test'; target='group:ROLE-Low'; type='Eligible'; kind='admin-to-group' }
    [ordered]@{ source='group:ROLE-Low'; target='entra-role:Reports Reader'; type='Eligible'; kind='group-to-entra-role' }
) }
$rptLow = Get-PimTierImpactReport -Data $lowData
T 'no high-tier reach -> 0 impacted (honest empty)' ([int]$rptLow.impactedCount -eq 0 -and [int]$rptLow.scannedAdmins -eq 1)

# Empty model -> safe (0 scanned, 0 impacted), never throws.
$empty = Get-PimTierImpactReport -Data ([ordered]@{ nodes=@(); edges=@() })
T 'empty model -> 0/0, no throw' ([int]$empty.scannedAdmins -eq 0 -and [int]$empty.impactedCount -eq 0)

# rows are ordered most-privileged first (T0 before T1).
if (@($rpt.rows).Count -ge 2) {
    $ordered = $true
    for ($i=1; $i -lt @($rpt.rows).Count; $i++) {
        if ([int]$rpt.rows[$i-1].highestTierLevel -gt [int]$rpt.rows[$i].highestTierLevel) { $ordered = $false; break }
    }
    T 'rows ordered most-privileged-first (T0 before T1)' $ordered
}

# tenant context carried through.
T 'report carries tenant id'   ($rpt.tenantId -eq '00000000-0000-0000-0000-000000000000')
T 'report carries tenant name' ($rpt.tenantName -eq 'Example')

# ===========================================================================
# Layer 2 -- STATIC GUI / SERVER WIRING (no dead view)
# ===========================================================================
Write-Host "`n-- Layer 2: tier-impact GUI + server wiring (static) --" -ForegroundColor Cyan
$html = [System.IO.File]::ReadAllText($htmlPath)
$srv  = [System.IO.File]::ReadAllText($srvPath)

T 'Reports tab has a tier-impact mode button' ($html -match 'rptModeTierImpact')
T 'renderReports handles tier-impact mode'    ($html -match "tier-impact")
T 'GUI calls GET /api/tier-impact'            ($html -match '/api/tier-impact')
T 'server handles GET /api/tier-impact'       ($srv -match "\`$path -eq '/api/tier-impact' -and \`$method -eq 'GET'")
T 'server dot-sources PIM-TierImpact.ps1'     ($srv -match 'PIM-TierImpact\.ps1')
T 'wrapper Get-PimTierImpactReportLive defined' ($srv -match 'function Get-PimTierImpactReportLive')

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
