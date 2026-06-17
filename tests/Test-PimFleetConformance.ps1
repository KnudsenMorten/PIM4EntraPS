<#
  Offline tests for the FLEET conformance matrix + ring-wide rollout plan
  (engine/_shared/PIM-Conformance.ps1 -- REQUIREMENTS.md s28 [H8]).

  Background: the single-tenant conformance cores answer "how far behind is THIS
  tenant?". An MSP runs MANY tenants against ONE central set of approved templates
  and needs the cross-fleet view -- tenants x templates, behind-by-N, in one place,
  plus a ring-wide rollout plan. This proves:

    * Get-PimFleetConformance builds a tenants x templates matrix where each cell
      carries status (UpToDate/Behind/NeverApplied/Ahead) + behind-by-N;
    * only APPROVED templates form columns (a draft is never a column);
    * a tenant with no applied versions is a valid row (every cell NeverApplied);
    * tenant-level rollups (current / behind / never) + a fleet total are correct;
    * tenants sort worst-behind first; per-template rollup counts are correct;
    * Get-PimRingRolloutPlan groups tenants into exclusive ring bands with per-band
      behind/never counts for one template;
    * Get-PimFleetStateForInstance reads applied versions + an optional ring stamp
      from a real state file and tolerates a missing/garbage file.

  PURE -- no network, no Graph, no SQL. In-memory template + tenant objects; the
  one I/O test writes a temp state file.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-Conformance.ps1"

$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

Write-Host "=== PIM-FleetConformance tests ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Templates: two approved (v3, v2) + one DRAFT (must never be a column).
# ---------------------------------------------------------------------------
function New-Tpl([string]$id, [string]$wl, [int]$ver, [string]$status) {
    [pscustomobject]@{ templateId = $id; workload = $wl; templateVersion = $ver; status = $status
        entries = @([pscustomobject]@{ key = "role:$id"; sinceVersion = 1; ring = 0; roleName = 'R'; groupTag = 'G' }) }
}
$templates = @(
    (New-Tpl 'defender-xdr-roles' 'defenderxdr' 3 'approved')
    (New-Tpl 'intune-roles'       'intune'      2 'approved')
    (New-Tpl 'draft-roles'        'sentinel'    5 'draft')      # draft -> excluded
)

# ---------------------------------------------------------------------------
# Tenants:
#   t-up    ring 0 : defender v3 (UpToDate), intune v2 (UpToDate)  -> Current
#   t-behind ring 1: defender v1 (Behind 2), intune v2 (UpToDate)  -> behind
#   t-never ring 2 : no applied versions                            -> all NeverApplied
#   t-ahead ring 0 : defender v5 (Ahead),  intune v2 (UpToDate)    -> ahead
# ---------------------------------------------------------------------------
$tenants = @(
    @{ tenantId = 't-up';     ring = 0; appliedVersions = @{ 'defender-xdr-roles' = 3; 'intune-roles' = 2 } }
    @{ tenantId = 't-behind'; ring = 1; appliedVersions = @{ 'defender-xdr-roles' = 1; 'intune-roles' = 2 } }
    @{ tenantId = 't-never';  ring = 2; appliedVersions = @{} }
    @{ tenantId = 't-ahead';  ring = 0; appliedVersions = @{ 'defender-xdr-roles' = 5; 'intune-roles' = 2 } }
)

$fleet = Get-PimFleetConformance -Templates $templates -Tenants $tenants

# --- columns: only approved templates ---------------------------------------
Assert "2 columns (drafts excluded)"            ($fleet.Templates.Count -eq 2)
Assert "draft template is not a column"          (-not ($fleet.Templates | Where-Object { $_.TemplateId -eq 'draft-roles' }))
Assert "columns sorted by templateId"            ($fleet.Templates[0].TemplateId -eq 'defender-xdr-roles' -and $fleet.Templates[1].TemplateId -eq 'intune-roles')

# --- totals ------------------------------------------------------------------
Assert "4 tenants total"                         ($fleet.TotalTenants -eq 4)
Assert "1 tenant fully current"                  ($fleet.CurrentTenants -eq 1)
Assert "3 tenants behind/not-current"            ($fleet.BehindTenants -eq 3)

# --- per-tenant cell statuses + behind-by-N ----------------------------------
$byTen = @{}; foreach ($r in $fleet.Tenants) { $byTen[$r.TenantId] = $r }
function Cell($row, $tpl) { @($row.Cells | Where-Object { $_.TemplateId -eq $tpl })[0] }

Assert "t-up defender UpToDate"                  ((Cell $byTen['t-up'] 'defender-xdr-roles').Status -eq 'UpToDate')
Assert "t-up is Current"                         ($byTen['t-up'].Current -eq $true)
Assert "t-behind defender Behind"                ((Cell $byTen['t-behind'] 'defender-xdr-roles').Status -eq 'Behind')
Assert "t-behind defender behind-by-2"           ((Cell $byTen['t-behind'] 'defender-xdr-roles').Behind -eq 2)
Assert "t-behind intune UpToDate"                ((Cell $byTen['t-behind'] 'intune-roles').Status -eq 'UpToDate')
Assert "t-behind not Current"                    ($byTen['t-behind'].Current -eq $false)
Assert "t-behind MaxBehind = 2"                  ($byTen['t-behind'].MaxBehind -eq 2)
Assert "t-never defender NeverApplied"           ((Cell $byTen['t-never'] 'defender-xdr-roles').Status -eq 'NeverApplied')
Assert "t-never NeverCount = 2"                  ($byTen['t-never'].NeverCount -eq 2)
Assert "t-never behind-cell = templateVersion"   ((Cell $byTen['t-never'] 'defender-xdr-roles').Behind -eq 3)
Assert "t-ahead defender Ahead"                  ((Cell $byTen['t-ahead'] 'defender-xdr-roles').Status -eq 'Ahead')
Assert "t-ahead not Current (ahead counts)"      ($byTen['t-ahead'].Current -eq $false)

# --- worst-first sort: t-never (max behind 3) first -------------------------
Assert "worst-behind tenant sorts first"         ($fleet.Tenants[0].TenantId -eq 't-never')

# --- per-template rollup -----------------------------------------------------
$pt = @{}; foreach ($p in $fleet.PerTemplate) { $pt[$p.TemplateId] = $p }
Assert "defender rollup: 1 up-to-date (only t-up)" ($pt['defender-xdr-roles'].UpToDate -eq 1)
Assert "defender rollup: 1 behind"               ($pt['defender-xdr-roles'].BehindCount -eq 1)
Assert "defender rollup: 1 never"                ($pt['defender-xdr-roles'].NeverCount -eq 1)
Assert "defender rollup: 1 ahead"                ($pt['defender-xdr-roles'].AheadCount -eq 1)
Assert "defender rollup: needs rollout"          ($pt['defender-xdr-roles'].NeedsRollout -eq $true)
Assert "intune rollup: 3 up-to-date"             ($pt['intune-roles'].UpToDate -eq 3)
Assert "intune rollup: 1 never"                  ($pt['intune-roles'].NeverCount -eq 1)
Assert "intune rollup: needs rollout (the never)" ($pt['intune-roles'].NeedsRollout -eq $true)

# --- empty fleet -------------------------------------------------------------
$empty = Get-PimFleetConformance -Templates $templates -Tenants @()
Assert "empty fleet: 0 tenants"                  ($empty.TotalTenants -eq 0)
Assert "empty fleet: still has columns"          ($empty.Templates.Count -eq 2)
$noTpl = Get-PimFleetConformance -Templates @() -Tenants $tenants
Assert "no approved templates: 0 columns"        ($noTpl.Templates.Count -eq 0)
Assert "no columns: every tenant trivially current" ($noTpl.CurrentTenants -eq 4)

# --- appliedVersions as PSCustomObject (JSON-parsed shape) -------------------
$tenObj = @(@{ tenantId = 't-json'; ring = 0; appliedVersions = ([pscustomobject]@{ 'defender-xdr-roles' = 2 }) })
$jf = Get-PimFleetConformance -Templates $templates -Tenants $tenObj
$jt = $jf.Tenants[0]
Assert "PSCustomObject appliedVersions parsed"   ((Cell $jt 'defender-xdr-roles').AppliedVersion -eq 2)
Assert "PSCustomObject behind computed"          ((Cell $jt 'defender-xdr-roles').Behind -eq 1)

# ---------------------------------------------------------------------------
# Ring-wide rollout plan for ONE template (defender, approved v3).
#   bands: ring0 = {t-up up, t-ahead ahead}, ring1 = {t-behind behind}, ring2 = {t-never never}
# ---------------------------------------------------------------------------
$tpl3 = $templates[0]
$plan = Get-PimRingRolloutPlan -Template $tpl3 -Tenants $tenants
Assert "plan: templateVersion 3"                 ($plan.TemplateVersion -eq 3)
Assert "plan: approved"                          ($plan.Approved -eq $true)
Assert "plan: 4 tenants"                         ($plan.TotalTenants -eq 4)
Assert "plan: 2 need rollout (behind + never)"   ($plan.NeedsRolloutCount -eq 2)
Assert "plan: 3 ring bands"                      ($plan.Bands.Count -eq 3)
$band = @{}; foreach ($b in $plan.Bands) { $band[$b.Ring] = $b }
Assert "band ring0: 2 tenants"                   ($band[0].TenantCount -eq 2)
Assert "band ring0: 0 behind (up + ahead)"       ($band[0].BehindCount -eq 0)
Assert "band ring0: not needs-rollout"           ($band[0].NeedsRollout -eq $false)
Assert "band ring1: 1 behind"                    ($band[1].BehindCount -eq 1)
Assert "band ring1: needs-rollout"               ($band[1].NeedsRollout -eq $true)
Assert "band ring2: 1 never"                     ($band[2].NeverCount -eq 1)
Assert "bands sorted ascending by ring"          ($plan.Bands[0].Ring -lt $plan.Bands[1].Ring -and $plan.Bands[1].Ring -lt $plan.Bands[2].Ring)
$b1member = @($band[1].Tenants)[0]
Assert "band ring1 member is t-behind"           ($b1member.TenantId -eq 't-behind')
Assert "band ring1 member behind-by-2"           ($b1member.Behind -eq 2)

# A draft template still produces a plan but flags Approved=$false.
$draftPlan = Get-PimRingRolloutPlan -Template $templates[2] -Tenants $tenants
Assert "draft plan: Approved false"              ($draftPlan.Approved -eq $false)

# ---------------------------------------------------------------------------
# Get-PimFleetStateForInstance: read applied versions + ring from a state file.
# ---------------------------------------------------------------------------
$tmpDir = Join-Path $env:TEMP ("pim-fleet-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
$stateFile = Join-Path $tmpDir 'template-state.json'
$stateObj = [ordered]@{
    'cust-a|defender-xdr-roles' = @{ LastAppliedVersion = 2; AppliedUtc = '2026-06-10T00:00:00Z'; AppliedBy = 'ops' }
    'cust-a|intune-roles'       = @{ LastAppliedVersion = 1; AppliedUtc = '2026-06-09T00:00:00Z'; AppliedBy = 'ops' }
    'cust-b|defender-xdr-roles' = @{ LastAppliedVersion = 3; AppliedUtc = '2026-06-11T00:00:00Z'; AppliedBy = 'ops' }  # other tenant
    'scopeVersions'             = @{ 'cust-a|Groups' = @{ LastAppliedVersion = 9 } }                                    # different feature -> ignored
    'fleetRingByTenant'         = @{ 'cust-a' = 1; 'cust-b' = 0 }
}
$stateObj | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $stateFile -Encoding UTF8

$rd = Get-PimFleetStateForInstance -StateFile $stateFile -TenantId 'cust-a'
Assert "state read: 2 applied templates for cust-a"  ($rd.appliedVersions.Keys.Count -eq 2)
Assert "state read: defender v2"                     ($rd.appliedVersions['defender-xdr-roles'] -eq 2)
Assert "state read: intune v1"                       ($rd.appliedVersions['intune-roles'] -eq 1)
Assert "state read: other tenant rows ignored"       (-not $rd.appliedVersions.ContainsKey('cust-b|defender-xdr-roles'))
Assert "state read: scopeVersions ignored"           (-not $rd.appliedVersions.ContainsKey('Groups'))
Assert "state read: ring stamp = 1"                  ($rd.ring -eq 1)

$rdMissing = Get-PimFleetStateForInstance -StateFile (Join-Path $tmpDir 'nope.json') -TenantId 'cust-a'
Assert "missing file: empty applied map"             ($rdMissing.appliedVersions.Keys.Count -eq 0)
Assert "missing file: null ring"                     ($null -eq $rdMissing.ring)

Set-Content -LiteralPath $stateFile -Value 'not json {{{' -Encoding UTF8
$rdBad = Get-PimFleetStateForInstance -StateFile $stateFile -TenantId 'cust-a'
Assert "garbage file: empty applied map (no throw)"  ($rdBad.appliedVersions.Keys.Count -eq 0)

# End-to-end: feed the read state into the matrix for a never-stamped tenant.
$e2e = Get-PimFleetConformance -Templates $templates -Tenants @(
    @{ tenantId = 'cust-a'; ring = 1; appliedVersions = (Get-PimFleetStateForInstance -StateFile (Join-Path $tmpDir 'nope.json') -TenantId 'cust-a').appliedVersions }
)
Assert "e2e never-stamped tenant: all NeverApplied"  (@($e2e.Tenants[0].Cells | Where-Object { $_.Status -eq 'NeverApplied' }).Count -eq 2)

Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host ("RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 } else { exit 0 }
