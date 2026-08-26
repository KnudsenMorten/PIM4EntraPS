#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-12 -- the Admins scope may only ever consider ADMIN ACCOUNTS.

    Root cause of the 2026-06-15 incident, and it survived the incident: the Admins
    provider's GetLive was `/users` with NO filter -- the whole tenant population --
    diffed against the ADMIN definitions, so every ordinary user was a removal
    candidate. Measured live 2026-08-06: 79 users returned, 13 admin accounts, 66
    ordinary users (59 enabled), 8 desired -> 71 classed as removals.

    The guards could never fix this. They are blast-radius limiters: a tenant with 50
    users of which 47 are defined admins yields 3 removals -- under EVERY threshold --
    and disables 3 real people with no trip and no alert. Small tenants get the least
    protection. The fix has to make an ordinary user impossible to classify, not merely
    unlikely to be reached.

    The assertions that matter most here are the FAIL-CLOSED ones. An unfiltered
    fallback is the defect; a test suite that only checks the happy path would let it
    come straight back.

    Offline. No tenant, no network.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$shared  = Join-Path $solRoot 'engine\_shared'
. (Join-Path $shared 'PIM-Swallow.ps1')
. (Join-Path $shared 'PIM-DateSafe.ps1')
. (Join-Path $shared 'PIM-DisableGuard.ps1')

Write-Host "=== BUG-12: the Admins scope sees ONLY admin accounts ===" -ForegroundColor Cyan

# --- prefix resolution, from the config the solution already owns ---------------
$nc = @{ AdminAccountPatterns = @('Admin-', 'x-Admin', 'g-Admin') }
$p = Get-PimAdminAccountPrefixes -NamingConventions $nc
Assert "resolves a string[] of prefixes"        (@($p).Count -eq 3 -and $p -contains 'admin-')
Assert "  ...lower-cased for comparison"        ($p -contains 'x-admin')

# a TEMPLATE must reduce to its literal head -- 'Admin-{Initial}' can only be
# startswith-filtered on 'Admin-'
$p = Get-PimAdminAccountPrefixes -NamingConventions @{ AdminAccountPattern = 'Admin-{Initial}{Platform}' }
# NOTE @($p)[0], not $p[0]: a single-element array returned from a function unwraps to a
# STRING, and $p[0] then indexes its first CHARACTER ('a'). Wrap the whole thing.
Assert "a template reduces to its literal head" (@($p).Count -eq 1 -and @($p)[0] -eq 'admin-')

# a pattern that STARTS with a token has no usable literal head -> contributes nothing
$p = Get-PimAdminAccountPrefixes -NamingConventions @{ AdminAccountPatterns = @('{AdminTypePrefix}Admin-') }
Assert "a leading-token pattern yields NO prefix (cannot be a filter)" (@($p).Count -eq 0)

$p = Get-PimAdminAccountPrefixes -NamingConventions @{ AdminAccountPatterns = @{ Internal='adm_'; External='ext_' } }
Assert "a hashtable form resolves"              (@($p).Count -eq 2 -and $p -contains 'adm_')
$p = Get-PimAdminAccountPrefixes -NamingConventions @{ AdminAccountPatterns = 'Admin-' }
Assert "a single-string form resolves"          (@($p).Count -eq 1)
$p = Get-PimAdminAccountPrefixes -NamingConventions @{ AdminAccountPatterns = @('Admin-','admin-',' Admin- ') }
Assert "duplicates/whitespace collapse"         (@($p).Count -eq 1)

# --- FAIL CLOSED: nothing configured must NEVER mean "match everything" ---------
$p = Get-PimAdminAccountPrefixes -NamingConventions @{}
Assert "no config -> EMPTY prefix list (not a wildcard)" (@($p).Count -eq 0)
Assert "an empty prefix list matches NOTHING"           (-not (Test-PimIsAdminAccountName -Name 'anyone@x' -Prefixes @()))
Assert "  ...not even an admin-looking name"            (-not (Test-PimIsAdminAccountName -Name 'Admin-XY@x' -Prefixes @()))

# --- classification ------------------------------------------------------------
$P = @('admin-','x-admin')
Assert "an admin account matches"               (Test-PimIsAdminAccountName -Name 'Admin-XY-ID@contoso.com' -Prefixes $P)
Assert "  ...case-insensitively"                (Test-PimIsAdminAccountName -Name 'ADMIN-XY@contoso.com' -Prefixes $P)
Assert "an x- admin matches"                    (Test-PimIsAdminAccountName -Name 'x-admin-abc@contoso.com' -Prefixes $P)
Assert "an ORDINARY user does NOT match"        (-not (Test-PimIsAdminAccountName -Name 'jane.doe@contoso.com' -Prefixes $P))
Assert "  ...nor one merely CONTAINING 'admin'" (-not (Test-PimIsAdminAccountName -Name 'jane.admin@contoso.com' -Prefixes $P))
Assert "empty/null does not match"              ((-not (Test-PimIsAdminAccountName -Name '' -Prefixes $P)) -and (-not (Test-PimIsAdminAccountName -Name $null -Prefixes $P)))

# --- the structural assertion: both sides must be the same population -----------
function U($upn) { [pscustomobject]@{ userPrincipalName = $upn } }

$r = Assert-PimAdminPopulationComparable -Live @(U 'Admin-A@x'; U 'x-Admin-B@x') -Prefixes $P
Assert "an all-admin live set is comparable"    ($r.ok)

# THE incident shape: ordinary users in the live set.
$r = Assert-PimAdminPopulationComparable -Live @(U 'Admin-A@x'; U 'jane@x'; U 'bob@x') -Prefixes $P
Assert "ordinary users in the live set is a HARD STOP" (-not $r.ok)
Assert "  ...and they are counted"                     (@($r.offenders).Count -eq 2)
Assert "  ...and named in the reason"                  ("$($r.reason)" -match 'jane@x')
Assert "  ...and the reason cites the incident shape"  ("$($r.reason)" -match '2026-06-15')

# no prefixes at all -> not comparable, whatever the live set looks like
$r = Assert-PimAdminPopulationComparable -Live @(U 'Admin-A@x') -Prefixes @()
Assert "no configured prefix -> NOT comparable (fail closed)" (-not $r.ok)
Assert "  ...and says what to configure"                      ("$($r.reason)" -match 'AdminAccountPatterns')

$r = Assert-PimAdminPopulationComparable -Live @() -Prefixes $P
Assert "an empty live set is trivially comparable" ($r.ok)

# --- the WIRING: the provider must actually use it ------------------------------
$prov = [System.IO.File]::ReadAllText((Join-Path $shared 'PIM-EngineProviders.ps1'))
Assert "the Admins provider resolves the prefixes"       ($prov -match 'Get-PimAdminAccountPrefixes')
Assert "  ...and THROWS when none are configured"        ($prov -match "REFUSING to scan the whole user population")
Assert "  ...filters server-side with startswith"        ($prov -match "startswith\(userPrincipalName")
Assert "  ...and asserts the population is comparable"   ($prov -match 'Assert-PimAdminPopulationComparable')
# The regression that must never come back.
Assert "the UNFILTERED /users read is GONE from Admins"  ($prov -notmatch '/users\?\$select=id,userPrincipalName,displayName,accountEnabled"\s*-All')

Write-Host ""
Write-Host ("BUG-12 admin population: {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
