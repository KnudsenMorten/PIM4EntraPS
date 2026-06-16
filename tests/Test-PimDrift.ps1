<#
  Offline tests for the Governance DRIFT view + gated remediation
  (engine/_shared/PIM-Governance.ps1 §5 -- REQUIREMENTS §28 [M5] / §26c).

  Proves:
    * the drift report reuses the ENGINE delta (Compare-PimDesiredVsLive) and
      classifies missing / changed / extra correctly from seeded desired/live;
    * the remediation plan targets ONLY the selected drift;
    * NO destructive removal of an 'extra' without explicit opt-in (-AllowRemove);
    * the whole round-trip drives the EXISTING engine create/update path
      (Invoke-PimEngine -Changes <plan>) -- a real in-memory provider applies
      exactly the selected drift and nothing else, and plan/WhatIf never writes.

  PURE -- no network, no clock (time injected), in-memory engine provider.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-ChangeQueue.ps1"
. "$here\..\engine\_shared\PIM-EngineCore.ps1"
. "$here\..\engine\_shared\PIM-Lifecycle.ps1"
. "$here\..\engine\_shared\PIM-Governance.ps1"

$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }
$now = ([datetime]'2026-06-16T12:00:00Z').ToUniversalTime()

Write-Host "=== PIM-Drift tests ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Seed a tiny estate: desired (the store) vs live (the tenant), one scope.
#   alpha  -> desired + live, IDENTICAL          -> nochange (no drift)
#   bravo  -> desired + live, DIFFERENT value    -> changed
#   delta  -> desired only                       -> missing
#   ghost  -> live only                          -> extra
# ---------------------------------------------------------------------------
$desired = @(
    [pscustomobject]@{ name = 'alpha'; val = '1' }
    [pscustomobject]@{ name = 'bravo'; val = '2' }
    [pscustomobject]@{ name = 'delta'; val = '4' }
)
$live = @(
    [pscustomobject]@{ name = 'alpha'; val = '1' }
    [pscustomobject]@{ name = 'bravo'; val = '99' }   # drifted value
    [pscustomobject]@{ name = 'ghost'; val = '9' }    # not desired
)
$keyOf = { param($r) "$($r.name)" }
$equal = { param($d, $l) "$($d.val)" -eq "$($l.val)" }

# Reuse the ENGINE delta core -- with prune ON so 'extra' (ghost) is computed too.
$diff = Compare-PimDesiredVsLive -Desired $desired -Live $live -KeyOf $keyOf -Equal $equal -Prune

Write-Host "-- drift classification (reuses Compare-PimDesiredVsLive) --" -ForegroundColor DarkCyan
$report = Get-PimDriftReport -ScopeDiffs @([pscustomobject]@{ scope = 'Groups'; entity = 'PIM-Groups'; create = $diff.create; update = $diff.update; remove = $diff.remove }) -NowUtc $now

Assert "total drift = 3 (missing+changed+extra; nochange excluded)" ($report.total -eq 3)
Assert "1 missing (delta)"  ($report.counts.missing -eq 1 -and (@($report.items | Where-Object { $_.type -eq 'missing' }).key -eq 'delta'))
Assert "1 changed (bravo)"  ($report.counts.changed -eq 1 -and (@($report.items | Where-Object { $_.type -eq 'changed' }).key -eq 'bravo'))
Assert "1 extra (ghost)"    ($report.counts.extra   -eq 1 -and (@($report.items | Where-Object { $_.type -eq 'extra' }).key   -eq 'ghost'))
Assert "alpha (nochange) is NOT in drift" (-not (@($report.items).key -contains 'alpha'))
Assert "every item carries entity"        (@($report.items | Where-Object { $_.entity -eq 'PIM-Groups' }).Count -eq 3)
Assert "per-scope summary populated"       ($report.scopes['Groups'].missing -eq 1 -and $report.scopes['Groups'].changed -eq 1 -and $report.scopes['Groups'].extra -eq 1)

# Without prune the engine never even computes removals -> no 'extra' surfaced.
$diffNoPrune = Compare-PimDesiredVsLive -Desired $desired -Live $live -KeyOf $keyOf -Equal $equal
$reportNoPrune = Get-PimDriftReport -ScopeDiffs @([pscustomobject]@{ scope = 'Groups'; entity = 'PIM-Groups'; create = $diffNoPrune.create; update = $diffNoPrune.update; remove = $diffNoPrune.remove })
Assert "no-prune diff surfaces no 'extra'" ($reportNoPrune.counts.extra -eq 0 -and $reportNoPrune.total -eq 2)

# ---------------------------------------------------------------------------
# Remediation plan: targets ONLY selected drift; 'extra' gated behind opt-in.
# ---------------------------------------------------------------------------
Write-Host "-- remediation plan (selection + opt-in removal gate) --" -ForegroundColor DarkCyan

# select ONLY the missing 'delta'
$plan = Get-PimDriftRemediationPlan -DriftReport $report -SelectKeys @('Groups|delta')
Assert "plan targets only the selected key"        (@($plan.changes).Count -eq 1 -and "$($plan.changes[0].Key)" -eq 'delta' -and "$($plan.changes[0].Entity)" -eq 'PIM-Groups')
Assert "selecting a 'missing' needs no prune"      (-not $plan.requiresPrune)
Assert "nothing refused for a missing selection"   (@($plan.refused).Count -eq 0)

# select missing + changed by bare key
$plan2 = Get-PimDriftRemediationPlan -DriftReport $report -SelectKeys @('delta', 'bravo')
Assert "two non-extra selected -> 2 changes"       (@($plan2.changes).Count -eq 2 -and -not $plan2.requiresPrune)

# explicitly select the 'extra' WITHOUT opt-in -> refused, never in the plan
$planX = Get-PimDriftRemediationPlan -DriftReport $report -SelectKeys @('Groups|ghost')
Assert "extra without -AllowRemove -> 0 changes"   (@($planX.changes).Count -eq 0)
Assert "extra without -AllowRemove -> refused"     (@($planX.refused).Count -eq 1 -and "$($planX.refused[0].key)" -eq 'ghost')
Assert "extra without -AllowRemove -> no prune"    (-not $planX.requiresPrune)

# select the 'extra' WITH opt-in -> included, requires prune
$planXok = Get-PimDriftRemediationPlan -DriftReport $report -SelectKeys @('Groups|ghost') -AllowRemove
Assert "extra WITH -AllowRemove -> in the plan"    (@($planXok.changes).Count -eq 1 -and "$($planXok.changes[0].Key)" -eq 'ghost')
Assert "extra WITH -AllowRemove -> requiresPrune"  ($planXok.requiresPrune -and @($planXok.refused).Count -eq 0)

# -All selects every NON-extra; extras silently skipped (non-destructive default)
$planAll = Get-PimDriftRemediationPlan -DriftReport $report -All
Assert "-All -> missing+changed only (no extra, no prune)" (@($planAll.changes).Count -eq 2 -and -not $planAll.requiresPrune -and @($planAll.refused).Count -eq 0)
Assert "-All keys = bravo+delta (ghost excluded)"  ((@($planAll.changes.Key | Sort-Object) -join ',') -eq 'bravo,delta')

# -All -AllowRemove -> everything including the extra (-> prune)
$planAllRm = Get-PimDriftRemediationPlan -DriftReport $report -All -AllowRemove
Assert "-All -AllowRemove -> all 3, requiresPrune" (@($planAllRm.changes).Count -eq 3 -and $planAllRm.requiresPrune)

# empty selection -> empty plan (engine does nothing)
$planEmpty = Get-PimDriftRemediationPlan -DriftReport $report -SelectKeys @()
Assert "empty selection -> empty plan"             (@($planEmpty.changes).Count -eq 0)

# ---------------------------------------------------------------------------
# End-to-end: the plan drives the EXISTING engine create/update path, applying
# ONLY the selected drift. Register an in-memory provider whose Apply* record
# what they touched; run Invoke-PimEngine -Changes <plan> (commit) + WhatIf.
# ---------------------------------------------------------------------------
Write-Host "-- engine round-trip: remediate applies ONLY selected drift --" -ForegroundColor DarkCyan

$script:Created = New-Object System.Collections.Generic.List[string]
$script:Updated = New-Object System.Collections.Generic.List[string]
$script:Removed = New-Object System.Collections.Generic.List[string]
$global:PIM_DesiredRows = @{ 'PIM-Groups' = $desired }

Register-PimEngineProvider -Provider @{
    scope  = 'Groups'; entity = 'PIM-Groups'; order = 50
    GetDesired = { param($ctx) $desired }
    GetLive    = { param($ctx) $live }
    KeyOf      = $keyOf
    Equal      = $equal
    ApplyCreate = { param($i, $ctx) $script:Created.Add("$($i.key)") }
    ApplyUpdate = { param($i, $ctx) $script:Updated.Add("$($i.key)") }
    ApplyRemove = { param($i, $ctx) $script:Removed.Add("$($i.key)") }
}

# WhatIf plan only -- proves NO writes happen on a preview.
$null = Invoke-PimEngine -Scope 'Groups' -Mode 'Delta' -WhatIf -Changes @($plan2.changes)
Assert "WhatIf plan writes nothing" ($script:Created.Count -eq 0 -and $script:Updated.Count -eq 0 -and $script:Removed.Count -eq 0)

# Commit the selected (missing delta + changed bravo) -> exactly those, no extra removed.
$res = Invoke-PimEngine -Scope 'Groups' -Mode 'Delta' -Changes @($plan2.changes)
Assert "commit created exactly 'delta'"  ((@($script:Created) -join ',') -eq 'delta')
Assert "commit updated exactly 'bravo'"  ((@($script:Updated) -join ',') -eq 'bravo')
Assert "commit removed NOTHING (delta mode, ghost untouched)" ($script:Removed.Count -eq 0)
Assert "engine reported ok"              ($res.ok -and $res.errors -eq 0)

# Now opt-in remove the extra: Full + Prune + the extra-only change list.
$script:Created.Clear(); $script:Updated.Clear(); $script:Removed.Clear()
$res2 = Invoke-PimEngine -Scope 'Groups' -Mode 'Full' -Prune -Changes @($planXok.changes)
Assert "Full+Prune removed exactly the opted-in 'ghost'" ((@($script:Removed) -join ',') -eq 'ghost')
Assert "Full+Prune created/updated nothing else"        ($script:Created.Count -eq 0 -and $script:Updated.Count -eq 0)
Assert "Full+Prune engine reported ok"                  ($res2.ok -and $res2.errors -eq 0)

Remove-Variable -Name PIM_DesiredRows -Scope Global -ErrorAction SilentlyContinue

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor ($(if ($fail) { 'Red' } else { 'Green' }))
if ($fail) { exit 1 }
