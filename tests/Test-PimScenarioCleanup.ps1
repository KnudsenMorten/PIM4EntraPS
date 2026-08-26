#Requires -Version 5.1
<#
.SYNOPSIS
    TEST-12 -- the scenario NAMING + CLEANUP contract (REQUIREMENTS §33.7.e-2).

    Operator directive, given for BOTH live suites: "it must be easy to delete the tests
    (naming)." That makes this a locked contract, and a contract that is only exercised by
    a live sweep is not verified -- the sweep only ever runs against tenants that already
    contain marked objects, so the branch that MATTERS (refusing an unmarked one) never
    executes. These assertions run it offline, where it can be pointed at hostile input.

    The two properties that carry the whole guarantee:
      1. an unmarked name can never be deleted -- the guard THROWS
      2. a marked name is recognised in EVERY shape the harness creates, including the two
         shapes that are constrained by engine filters rather than by taste

    The naming traps are asserted by name because they are non-obvious and were paid for
    once already in TEST-11: a group may not LEAD with the marker (the engine's lean
    context fetches `startswith(displayName,'PIM')` and the PimGroup filter is `PIM-*`, so
    `PIMSCEN-...` is invisible to half the engine and the test silently exercises nothing),
    and an admin UPN must start with a configured admin prefix and carry `-ID` or the
    Admins scope's naming filter will not see it either.

    Offline. No tenant, no network -- this file dot-sources only the side-effect-free
    marker contract.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$liveDir = Join-Path $solRoot 'tests\live'
. (Join-Path $liveDir '_PimScenarioMarker.ps1')

Write-Host "=== TEST-12: the scenario naming + cleanup contract ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
Write-Host "`n[the ownership predicate]" -ForegroundColor Cyan
Assert "default marker is PIMSCEN"                    ((Get-PimScenarioMarker) -eq 'PIMSCEN')
Assert "a marked AU name is owned"                    (Test-PimScenarioOwnedName -Name 'PIMSCEN-AU-Helpdesk')
Assert "a marked GROUP name is owned (marker NOT first)" (Test-PimScenarioOwnedName -Name 'PIM-PIMSCEN-Entra-ID-UserAdmin-L1')
Assert "a marked ADMIN upn is owned"                  (Test-PimScenarioOwnedName -Name 'Admin-PIMSCEN-OPS-ID@contoso.example')
Assert "case does not matter"                         (Test-PimScenarioOwnedName -Name 'pim-pimscen-lowercase')
Assert "a marked file name is owned"                  (Test-PimScenarioOwnedName -Name 'PIMSCEN-admins.sync.json')

# The assertions that actually protect the tenant:
Assert "a REAL group is NOT owned"                    (-not (Test-PimScenarioOwnedName -Name 'PIM-Entra-ID-GlobalAdministrator-L0-T0-CP-ID'))
Assert "a REAL admin is NOT owned"                    (-not (Test-PimScenarioOwnedName -Name 'Admin-AAA-L0-T0-ID@contoso.example'))
Assert "a REAL AU is NOT owned"                       (-not (Test-PimScenarioOwnedName -Name 'AU-HighPrivGlobalRoles'))
Assert "the OTHER harness's marker is NOT owned"      (-not (Test-PimScenarioOwnedName -Name 'PIM-PIMTEST-ROLE-Operator'))
Assert "an empty name is NOT owned"                   (-not (Test-PimScenarioOwnedName -Name ''))
Assert "whitespace is NOT owned"                      (-not (Test-PimScenarioOwnedName -Name '   '))
Assert "`$null is NOT owned"                          (-not (Test-PimScenarioOwnedName -Name $null))

# ---------------------------------------------------------------------------
Write-Host "`n[the guard -- the branch a live sweep never reaches]" -ForegroundColor Cyan
$threw = $false; $msg = ''
try { [void](Assert-PimScenarioOwnedName -Name 'PIM-Entra-ID-GlobalAdministrator-L0-T0-CP-ID' -What 'group abc') } catch { $threw = $true; $msg = "$($_.Exception.Message)" }
Assert "an unmarked name THROWS"                      $threw
Assert "  ...and the message names the object"        ($msg -match 'GlobalAdministrator')
Assert "  ...and names the marker"                    ($msg -match 'PIMSCEN')
$threw = $false
try { [void](Assert-PimScenarioOwnedName -Name '' -What 'group with no displayName') } catch { $threw = $true }
Assert "a BLANK name THROWS (no name is not a licence)" $threw
Assert "a marked name passes the guard"               (Assert-PimScenarioOwnedName -Name 'PIM-PIMSCEN-Whatever')

# A blank marker would make every name 'owned' -- the one input that silently disables the
# guard entirely. It must be refused, not accepted.
$threw = $false
try { Set-PimScenarioMarker -Marker '  ' } catch { $threw = $true }
Assert "a BLANK marker is refused"                    $threw
Assert "  ...and the marker is unchanged"             ((Get-PimScenarioMarker) -eq 'PIMSCEN')

# ---------------------------------------------------------------------------
Write-Host "`n[name shapes -- the engine-filter traps, asserted by name]" -ForegroundColor Cyan
$g = New-PimScenarioName -Kind group -Suffix 'Entra-ID-UserAdmin-L1'
Assert "group name STARTS with 'PIM-' (lean-context filter)" ($g -like 'PIM-*')
Assert "  ...and is NOT 'PIMSCEN-...' (the TEST-11 trap)"    (-not ($g -like 'PIMSCEN*'))
Assert "  ...and still carries the marker"                   (Test-PimScenarioOwnedName -Name $g)
Assert "  ...and matches the PimGroup filter 'PIM-*'"        ($g -like 'PIM-*')

$a = New-PimScenarioName -Kind admin -Suffix 'OPS'
Assert "admin name starts with an admin prefix"       ($a -like 'Admin-*')
Assert "  ...carries '-ID' (AdminCandidate filter)"   ($a -like '*-ID*')
Assert "  ...and carries the marker"                  (Test-PimScenarioOwnedName -Name $a)

$au = New-PimScenarioName -Kind au -Suffix 'Helpdesk'
Assert "AU name is marked"                            ((Test-PimScenarioOwnedName -Name $au) -and $au -like 'PIMSCEN-AU-*')
$p = New-PimScenarioName -Kind plain -Suffix 'admins.sync.json'
Assert "plain name is marked"                         (Test-PimScenarioOwnedName -Name $p)

# ---------------------------------------------------------------------------
Write-Host "`n[structural: the sweep uses the shared contract and orders deletes correctly]" -ForegroundColor Cyan
$sweep = Get-Content -LiteralPath (Join-Path $liveDir 'Clear-PimScenarioEstate.ps1') -Raw
Assert "the sweep dot-sources the shared marker file"  ($sweep -match '_PimScenarioMarker\.ps1')
Assert "its delete path calls the THROWING guard"      ($sweep -match 'Assert-PimScenarioOwnedName')
Assert "it re-asserts the marker outside the catch"    ($sweep -match "lost its marker -- refusing")
# Order is the TEST-11 lesson: a schedule outlives its principal and becomes unattributable
# (and unremovable if its scope is gone too). Schedules MUST be removed first.
$iSched = $sweep.IndexOf('SCHEDULES FIRST')
$iGroups = $sweep.IndexOf('groups, then users, then AUs')
Assert "schedules are removed BEFORE principals"       ($iSched -gt 0 -and $iGroups -gt $iSched)
Assert "ARM schedules are swept too"                   ($sweep -match 'roleEligibilityScheduleInstances')
Assert "PIM-for-Groups schedules are swept too"        ($sweep -match 'privilegedAccess/group/')
Assert "sync files on disk are swept"                  ($sweep -match 'SyncRoot')
Assert "the scratch store's marked rows are swept"     ($sweep -match 'pim\.Rows')
Assert "it REFUSES to sweep the real platform store"   ($sweep -match "-ne 'PimPlatform'")
Assert "it retries in a second pass"                   ($sweep -match '\$Passes')
Assert "it reports what it could NOT remove"           ($sweep -match 'NOT REMOVED')
Assert "it has a WhatIf-only mode"                     ($sweep -match '\$WhatIfOnly')

# ---------------------------------------------------------------------------
# TEST-14 -- the master REGISTRY tables. These are the rows this suite never looked
# at, and that is exactly where the sweep was broken: it matched platform.Tenants /
# platform.TenantApps on a [Name] column NEITHER table has, so every DELETE threw
# "Invalid column name 'Name'" into a catch written for "the table may not exist" --
# and -WhatIfOnly never queried those tables at all, so the dry run always said 0.
# A marked tenant row therefore survived every sweep while the summary read clean.
# These assertions are deliberately about the QUERY TEXT: they are what makes the
# three independent parts of that bug un-reintroducible.
# ---------------------------------------------------------------------------
Write-Host "`n[the registry sweep -- TEST-14]" -ForegroundColor Cyan
$regBlock = [regex]::Match($sweep, '\$registrySweeps\s*=\s*@\(.*?\n\s*\)', 'Singleline').Value
Assert "there IS an explicit per-table registry sweep"   ($regBlock)
# Scan CODE only: the block above documents the old broken predicate verbatim, and a
# comment that explains a bug must not be able to fail the test that prevents it.
$sweepCode = ($sweep -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
Assert "it no longer guesses the column with -match 'Admins'" (-not ($sweepCode -match "\`$tbl -match 'Admins'"))
Assert "no [Name] column is referenced in code"          (-not ($sweepCode -match '\[Name\]'))
Assert "platform.Tenants matches on [DisplayName]"       ($regBlock -match "platform\.Tenants'.*DisplayName")
Assert "pim.CentralAdmins matches on [UserName]"         ($regBlock -match "pim\.CentralAdmins'.*UserName")
Assert "pim.LocalAdmins is swept too (31.4)"             ($regBlock -match "pim\.LocalAdmins")
Assert "TenantApps is swept by its marked TenantId"      ($regBlock -match "platform\.TenantApps'.*TenantId.*IN \(SELECT")
# children before parents: deleting the Tenants row first would orphan TenantApps,
# whose only claim to being marked is the tenant row it points at.
$iApps = $regBlock.IndexOf('platform.TenantApps'); $iTen = $regBlock.LastIndexOf("Table = 'platform.Tenants'")
Assert "TenantApps is swept BEFORE platform.Tenants"     ($iApps -ge 0 -and $iTen -ge 0 -and $iApps -lt $iTen)
# the WhatIf and the delete branch must ask the SAME question -- a dry run that
# cannot see a row is worse than no dry run, because it is believed.
$regLoop = [regex]::Match($sweep, 'foreach \(\$sweep in \$registrySweeps\).*?\n\s{12}\}', 'Singleline').Value
Assert "WhatIf COUNTs the registry tables (it never did)" ($regLoop -match 'WhatIfOnly.*\n.*SELECT COUNT\(\*\) FROM \$tbl WHERE \$\(\$sweep\.Where\)')
Assert "delete uses the SAME predicate as the count"      ($regLoop -match 'DELETE FROM \$tbl WHERE \$\(\$sweep\.Where\)')
# a failed sweep must never read as a clean one
Assert "'table absent' is distinguished from 'query failed'" ($regLoop -match 'Invalid object name')
Assert "a failed registry sweep lands in Leftovers"       ($regLoop -match 'Leftovers\.Add\("\$tbl \(sweep failed')

# ---------------------------------------------------------------------------
# BUG-26 -- the -TenantJson parse, and the two ways it went wrong.
#
# This block MUST be able to run under Windows PowerShell 5.1, because the defect it
# guards EXISTS ONLY THERE: `@(Get-Content ... | ConvertFrom-Json)` yields 2 entries
# under pwsh 7 and 1 under 5.1, so a PS 7-only test would have passed throughout the
# entire life of the bug. Assert the shell too, so a green run states which shell it
# was green in rather than leaving that to be assumed.
# ---------------------------------------------------------------------------
Write-Host "`n[the -TenantJson parse -- BUG-26]" -ForegroundColor Cyan
. (Join-Path $liveDir '_PimScenarioTenants.ps1')
Write-Host ("  (running under PowerShell {0} -- the collapse only reproduces on 5.1)" -f $PSVersionTable.PSVersion) -ForegroundColor DarkGray

$twoTenants = @'
[
  { "name": "master-t0", "tenantId": "11111111-2222-3333-4444-555555555551", "clientId": "11111111-1111-1111-1111-111111111111", "certThumbprint": "AAAA" },
  { "name": "slave-t1",  "tenantId": "11111111-2222-3333-4444-555555555552", "clientId": "22222222-2222-2222-2222-222222222222", "certThumbprint": "BBBB" }
]
'@
# THE assertion the bug turned on. Under 5.1 the old inline form gave 1.
$parsedTenants = @(ConvertFrom-PimScenarioTenantJson -Json $twoTenants -Source 'test')
Assert "a 2-entry TenantJson yields exactly 2 tenants"  (@($parsedTenants).Count -eq 2)
Assert "  ...and each tenantId is a single GUID"        (@($parsedTenants | Where-Object { "$($_.tenantId)" -match '^[0-9a-fA-F-]{36}$' }).Count -eq 2)
Assert "  ...and the two are DIFFERENT tenants"         ($parsedTenants[0].tenantId -ne $parsedTenants[1].tenantId)
Assert "  ...and names survive"                         ($parsedTenants[0].name -eq 'master-t0' -and $parsedTenants[1].name -eq 'slave-t1')
Assert "  ...and clientId/thumbprint survive"           ($parsedTenants[1].clientId -eq '22222222-2222-2222-2222-222222222222' -and $parsedTenants[1].certThumbprint -eq 'BBBB')

# Demonstrate the ACTUAL defect in this shell, so the test documents the mechanism rather
# than just the fix. On 5.1 $bad is 1; on 7 it is 2. Either way the shared parse gives 2.
$bad = @($twoTenants | ConvertFrom-Json).Count
Write-Host ("  (the old inline form yields {0} here; the shared parse yields {1})" -f $bad, @($parsedTenants).Count) -ForegroundColor DarkGray
Assert "the shared parse is shell-INDEPENDENT"          (@($parsedTenants).Count -eq 2)

# A 1-entry file must stay an ARRAY -- the mirror-image collapse.
$oneTenant = @'
[ { "name": "solo", "tenantId": "f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e" } ]
'@
$solo = @(ConvertFrom-PimScenarioTenantJson -Json $oneTenant -Source 'test')
Assert "a 1-entry TenantJson yields exactly 1 tenant"   (@($solo).Count -eq 1)
Assert "  ...and it is still an array, not a scalar"    ($solo -is [array])

# BOTH supported call styles, pinned. Writing the parse as `return ,$out` -- the usual
# "guarantee an array" idiom -- makes the FIRST of these yield 1 on 5.1 AND 7, which is
# the same collapse this whole finding is about, just one layer up. It was written that
# way first and this assertion is what caught it.
$styleWrap = @(ConvertFrom-PimScenarioTenantJson -Json $twoTenants -Source 'test')
$tmpAssign = ConvertFrom-PimScenarioTenantJson -Json $twoTenants -Source 'test'
$styleAssign = @($tmpAssign)
Assert "call style @(F) yields 2"                       (@($styleWrap).Count -eq 2)
Assert "call style assign-then-@() yields 2"            (@($styleAssign).Count -eq 2)
Assert "the parse does NOT comma-wrap its return"       (-not ((Get-Content -LiteralPath (Join-Path $liveDir '_PimScenarioTenants.ps1') -Raw) -match '(?m)^\s*return\s*,'))

# The validation that makes a future recurrence LOUD instead of silent.
$threw = $false; $msg = ''
try { [void](ConvertFrom-PimScenarioTenantJson -Json '[ { "name": "collapsed", "tenantId": "11111111-2222-3333-4444-555555555551 11111111-2222-3333-4444-555555555552" } ]' -Source 'test') } catch { $threw = $true; $msg = "$($_.Exception.Message)" }
Assert "two ids joined by a space THROW"                $threw
Assert "  ...and the message names BUG-26"              ($msg -match 'BUG-26')
$threw = $false
try { [void](ConvertFrom-PimScenarioTenantJson -Json '[ { "name": "no-id" } ]' -Source 'test') } catch { $threw = $true }
Assert "a tenant with no tenantId THROWS"               $threw
$threw = $false
try { [void](ConvertFrom-PimScenarioTenantJson -Json '[]' -Source 'test') } catch { $threw = $true }
Assert "an EMPTY tenant list THROWS (never sweeps 0)"   $threw
$threw = $false
try { [void](ConvertFrom-PimScenarioTenantJson -Json '' -Source 'test') } catch { $threw = $true }
Assert "an empty file THROWS"                           $threw

# ---------------------------------------------------------------------------
# BUG-26's second half: the sweep FAILED OPEN. A tenant it could not authenticate to
# was WARNed and skipped, and the run still printed "0 object(s)/row(s) would be
# removed" and exited 0 -- indistinguishable from a clean estate (the D4.a shape).
# These are structural assertions on the sweep source, like the TEST-14 block above.
# ---------------------------------------------------------------------------
Write-Host "`n[the sweep may not report clean for a tenant it never inspected -- BUG-26]" -ForegroundColor Cyan
Assert "the sweep uses the shared TenantJson parse"      ($sweep -match 'Import-PimScenarioTenantJson')
Assert "  ...and NOT the inline collapsing form"         (-not ($sweepCode -match '@\(Get-Content -LiteralPath \$TenantJson -Raw \| ConvertFrom-Json\)'))
Assert "an unauthenticated tenant is tracked"            ($sweepCode -match 'Unverified')
Assert "  ...separately from Leftovers"                  ($sweepCode -match 'Unverified\s*=\s*New-Object' -and $sweepCode -match 'Leftovers\s*=\s*New-Object')
Assert "  ...and is recorded on the auth failure path"   ($sweepCode -match 'cannot authenticate to.*\n.*Unverified\.Add|Unverified\.Add\("\$\(\$T\.name\)')
Assert "the SUMMARY reports it as UNVERIFIED"            ($sweepCode -match 'UNVERIFIED')
Assert "the summary states inspected-of-total"           ($sweepCode -match 'inspected \{0\} of \{1\} tenant')
Assert "an uninspected tenant is FATAL to the exit code" ($sweepCode -match 'if \(\$script:Unverified\.Count\)[\s\S]{0,400}?exit 3')
# The exact sentence the old behaviour made a lie. It must no longer be reachable alone.
$iUnver = $sweepCode.IndexOf('$script:Unverified.Count')
$iExit0 = $sweepCode.LastIndexOf('exit 0')
Assert "the Unverified gate precedes the success exit"   ($iUnver -gt 0 -and $iExit0 -gt $iUnver)

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
