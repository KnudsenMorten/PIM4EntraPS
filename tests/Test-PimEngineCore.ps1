<#
  Offline tests for the NEW REST+SQL engine core (PIM-EngineCore.ps1). Pure diff +
  orchestrator with an in-memory provider (no network). Covers create/update/remove/
  nochange detection, Delta vs Full (prune), and WhatIf(plan) vs commit(apply).
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-ChangeQueue.ps1"
. "$here\..\engine\_shared\PIM-EngineCore.ps1"

$pass=0; $fail=0
function Assert($n,$c){ if($c){ $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

Write-Host "=== PIM-EngineCore tests ===" -ForegroundColor Cyan

# ---- pure diff ----
$keyOf = { param($r) "$($r.id)" }
$equal = { param($d,$l) "$($d.val)" -eq "$($l.val)" }
$desired = @(
    [pscustomobject]@{ id='a'; val='1' }   # unchanged
    [pscustomobject]@{ id='b'; val='2' }   # changed (update)
    [pscustomobject]@{ id='c'; val='9' }   # new (create)
)
$live = @(
    [pscustomobject]@{ id='a'; val='1' }
    [pscustomobject]@{ id='b'; val='OLD' }
    [pscustomobject]@{ id='z'; val='x' }   # not desired (remove on Full)
)
$d1 = Compare-PimDesiredVsLive -Desired $desired -Live $live -KeyOf $keyOf -Equal $equal
Assert "create detects new (c)"        ($d1.create.Count -eq 1 -and $d1.create[0].key -eq 'c')
Assert "update detects changed (b)"    ($d1.update.Count -eq 1 -and $d1.update[0].key -eq 'b')
Assert "nochange detects same (a)"     ($d1.nochange.Count -eq 1 -and $d1.nochange[0].key -eq 'a')
Assert "no remove without -Prune"      ($d1.remove.Count -eq 0)
$d2 = Compare-PimDesiredVsLive -Desired $desired -Live $live -KeyOf $keyOf -Equal $equal -Prune
Assert "remove detects orphan (z) on Prune" ($d2.remove.Count -eq 1 -and $d2.remove[0].key -eq 'z')
Assert "case-insensitive key match"    ((Compare-PimDesiredVsLive -Desired @([pscustomobject]@{id='A';val='1'}) -Live @([pscustomobject]@{id='a';val='1'}) -KeyOf $keyOf -Equal $equal).nochange.Count -eq 1)
Assert "null rows ignored"             ((Compare-PimDesiredVsLive -Desired @($null,[pscustomobject]@{id='a';val='1'}) -Live @($null) -KeyOf $keyOf -Equal $equal).create.Count -eq 1)

# ---- provider + orchestrator (in-memory, no network) ----
$script:created=0; $script:updated=0; $script:removed=0
Register-PimEngineProvider -Provider @{
    scope='UnitTest'; entity='UT-Entity'
    GetDesired = { param($ctx) $desired }
    GetLive    = { param($ctx) $live }
    KeyOf = $keyOf; Equal = $equal
    ApplyCreate = { param($i,$ctx) $script:created++ }
    ApplyUpdate = { param($i,$ctx) $script:updated++ }
    ApplyRemove = { param($i,$ctx) $script:removed++ }
}
Assert "provider registered + discoverable" ((Get-PimEngineScopes) -contains 'UnitTest')

# Delta + WhatIf -> plan only, NO apply
$r = Invoke-PimEngineScope -Scope 'UnitTest' -Mode Delta -WhatIf
Assert "delta plan: 1 create + 1 update, 0 remove" ($r.create -eq 1 -and $r.update -eq 1 -and $r.remove -eq 0)
Assert "WhatIf applied nothing"          ($r.applied -eq 0 -and $script:created -eq 0 -and $script:updated -eq 0)
Assert "plan carries change records"     ($r.plan.Count -eq 2)

# Full + commit -> applies create+update+remove
$script:created=0; $script:updated=0; $script:removed=0
$r2 = Invoke-PimEngineScope -Scope 'UnitTest' -Mode Full
Assert "full commit applied 3 (create+update+remove)" ($r2.applied -eq 3 -and $script:created -eq 1 -and $script:updated -eq 1 -and $script:removed -eq 1)
Assert "full commit ok, no errors"       ($r2.ok -and $r2.errors -eq 0)

# unknown scope -> graceful
$r3 = Invoke-PimEngineScope -Scope 'DoesNotExist'
Assert "unknown scope -> ok=false, no crash" (-not $r3.ok -and "$($r3.detail)" -match 'no provider')

# Invoke-PimEngine All runs registered providers
$rAll = @(Invoke-PimEngine -Scope All -Mode Delta -WhatIf)
Assert "Scope All runs registered providers" ($rAll.Count -ge 1 -and ($rAll.scope -contains 'UnitTest'))

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass,$fail) -ForegroundColor ($(if($fail){'Red'}else{'Green'}))
if ($fail) { exit 1 }
