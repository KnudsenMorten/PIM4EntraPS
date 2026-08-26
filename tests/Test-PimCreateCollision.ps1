#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-18 -- the create path must re-check by NAME immediately before writing, so a run
    inside the directory's replication window cannot silently make a DUPLICATE.

    What happened: the engine decides create-vs-nochange from ONE bulk live LIST read,
    and Graph reads are not replica-pinned. A -WhatIf plan reported a scope fully
    converged and a real run FOUR SECONDS later created the object again:

        12:01:58  AdministrativeUnits Delta PLAN   desired=2 live=2  create=0 nochange=2
        12:02:02  AdministrativeUnits Delta APPLY  desired=2 live=1  create=1  applied=1

    Entra does not enforce unique displayName on AUs or groups, so the duplicate was
    accepted silently -- no conflict, no error, errors=0. Observed three times in one
    session. It matters because the engine KEYS ON DISPLAY NAME: once two objects share a
    name, every later run resolves it to whichever copy a replica returns first, so
    assignments can land on one while the Manager shows the other.

    The fix is a CHECK, not a wait. A sleep or retry delay would be guesswork about a
    window nobody can measure (and the no-caps rule forbids exactly that); one extra
    filtered read immediately before the POST is cheap and deterministic. It cannot close
    a window narrower than a single round-trip -- nothing can, short of a uniqueness
    constraint the directory does not offer -- and this file says so rather than implying
    the race is gone.

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
. (Join-Path $shared 'PIM-EngineCore.ps1')
. (Join-Path $shared 'PIM-EngineProviders.ps1')

Write-Host "=== BUG-18: no duplicate objects from a stale live read ===" -ForegroundColor Cyan

$script:LiveGroups = @()      # what the DIRECT probe sees
$script:LiveAus    = @()
$script:Posts      = @()
$script:Probes     = @()

function Ensure-PimContextLoaded { }
function Add-PimContextObject { param($Kind, $Object) }
function Get-PimTagToAuName { @{} }
function Resolve-PimGroupOwnerIds { param($Row, $Ctx) @('owner-1') }
function Get-PimMailNickname { param($n) "$n" -replace '[^A-Za-z0-9]', '' }
function Invoke-PimGraph {
    param([string]$Method='GET', [string]$Path, [object]$Body, [hashtable]$Headers, [switch]$All)
    if ($Method -eq 'POST') { $script:Posts += "$Path"; return [pscustomobject]@{ id = 'new-id'; displayName = "$($Body.displayName)" } }
    # Greedy to the LAST quote, then UNESCAPE '' -> ' the way an OData parser does. A
    # naive [^']+ stops at the doubled quote inside an escaped name and the stub reports a
    # miss the real service would not -- a defect in the test, not in the code under test.
    if ($Path -match "^/groups\?.*displayName eq '(.*)'") {
        $name = $Matches[1] -replace "''", "'"
        $script:Probes += "group:$name"
        return @($script:LiveGroups | Where-Object { $_ -eq $name } | ForEach-Object { [pscustomobject]@{ id = "gid-$_"; displayName = $_ } })
    }
    if ($Path -match "administrativeUnits\?.*displayName eq '(.*)'") {
        $name = $Matches[1] -replace "''", "'"
        $script:Probes += "au:$name"
        return @($script:LiveAus | Where-Object { $_ -eq $name } | ForEach-Object { [pscustomobject]@{ id = "aid-$_"; displayName = $_ } })
    }
    return @()
}

# ---------------------------------------------------------------------------
Write-Host "`n[the probe itself]" -ForegroundColor Cyan
$script:LiveAus = @('AU-ALPHA')
Assert "finds an AU that exists"                      ((Test-PimNameAlreadyLive -Kind administrativeUnit -DisplayName 'AU-ALPHA') -eq 'aid-AU-ALPHA')
Assert "does not invent one that does not"            ($null -eq (Test-PimNameAlreadyLive -Kind administrativeUnit -DisplayName 'AU-NOPE'))
$script:LiveGroups = @('PIM-ALPHA')
Assert "finds a group that exists"                    ((Test-PimNameAlreadyLive -Kind group -DisplayName 'PIM-ALPHA') -eq 'gid-PIM-ALPHA')
Assert "an empty name is never a match"               ($null -eq (Test-PimNameAlreadyLive -Kind group -DisplayName '  '))
# a partial/case-different name must NOT count as a hit -- the engine keys on the exact name
$script:LiveGroups = @('PIM-ALPHA-EXTRA')
Assert "a DIFFERENT name is not a false hit"          ($null -eq (Test-PimNameAlreadyLive -Kind group -DisplayName 'PIM-ALPHA'))
# a quote in the name must not break the OData filter
$script:LiveGroups = @("PIM-O'Brien")
Assert "a name containing a quote is handled"         ((Test-PimNameAlreadyLive -Kind group -DisplayName "PIM-O'Brien") -eq "gid-PIM-O'Brien")

# ---------------------------------------------------------------------------
Write-Host "`n[AU create -- the exact case that duplicated]" -ForegroundColor Cyan
$au = New-PimAdministrativeUnitsProvider
# The diff said CREATE (its bulk read missed the object) but the object is really there:
$script:LiveAus = @('AU-ALPHA'); $script:Posts = @(); $script:Probes = @()
$r = & $au.ApplyCreate ([pscustomobject]@{ key = 'AU-ALPHA'; desired = [pscustomobject]@{ AUDisplayName = 'AU-ALPHA' } }) @{}
Assert "a stale 'create' does NOT POST a duplicate"   ($script:Posts.Count -eq 0)
Assert "  ...it probed by name first"                 ($script:Probes -contains 'au:AU-ALPHA')
Assert "  ...and returns the EXISTING object's id"    ("$($r.id)" -eq 'aid-AU-ALPHA')
# and a genuine create still happens
$script:LiveAus = @(); $script:Posts = @()
[void](& $au.ApplyCreate ([pscustomobject]@{ key = 'AU-NEW'; desired = [pscustomobject]@{ AUDisplayName = 'AU-NEW' } }) @{})
Assert "a genuine create still POSTs"                 ($script:Posts.Count -eq 1 -and $script:Posts[0] -match 'administrativeUnits')

# ---------------------------------------------------------------------------
Write-Host "`n[Group create -- same guard]" -ForegroundColor Cyan
$gp = New-PimGroupsProvider
$script:LiveGroups = @('PIM-BETA'); $script:Posts = @(); $script:Probes = @()
$r = & $gp.ApplyCreate ([pscustomobject]@{ key = 'PIM-BETA'; desired = [pscustomobject]@{ GroupName = 'PIM-BETA'; Owners = 'o@x.test' } }) @{ tagToAuName = @{} }
Assert "a stale 'create' does NOT POST a duplicate"   (@($script:Posts | Where-Object { $_ -eq '/groups' }).Count -eq 0)
Assert "  ...it probed by name first"                 ($script:Probes -contains 'group:PIM-BETA')
Assert "  ...and returns the EXISTING group's id"     ("$($r.id)" -eq 'gid-PIM-BETA')
$script:LiveGroups = @(); $script:Posts = @()
[void](& $gp.ApplyCreate ([pscustomobject]@{ key = 'PIM-NEW'; desired = [pscustomobject]@{ GroupName = 'PIM-NEW'; Owners = 'o@x.test' } }) @{ tagToAuName = @{} })
Assert "a genuine create still POSTs"                 (@($script:Posts | Where-Object { $_ -eq '/groups' }).Count -eq 1)

# ---------------------------------------------------------------------------
Write-Host "`n[the probe must be DIRECT -- never the context cache]" -ForegroundColor Cyan
# A cache-backed check would be worthless: the cache is exactly what was stale.
$src = Get-Content -LiteralPath (Join-Path $shared 'PIM-EngineProviders.ps1') -Raw
$i = $src.IndexOf('function Test-PimNameAlreadyLive')
$body = $src.Substring($i, [Math]::Min(2500, $src.Length - $i))
Assert "it queries Graph with a displayName filter"   ($body -match 'displayName eq')
Assert "it does NOT consult `$Global:Groups_All_ID"   ($body -notmatch 'Groups_All_ID')
Assert "it does NOT consult `$Global:AU_All_ID"       ($body -notmatch 'AU_All_ID')
Assert "group probe asks for eventual consistency"    ($body -match 'ConsistencyLevel')
# and the guard is on BOTH create paths
foreach ($fn in 'New-PimAdministrativeUnitsProvider','New-PimGroupsProvider') {
    $j = $src.IndexOf("function $fn")
    $b = $src.Substring($j, [Math]::Min(5000, $src.Length - $j))
    Assert "$fn calls the probe before creating"      ($b -match 'Test-PimNameAlreadyLive')
}
# no sleep/retry crept in as a "fix"
Assert "no Start-Sleep was added to the create paths" ($src -notmatch '(?s)function New-PimAdministrativeUnitsProvider.{0,4000}Start-Sleep')

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
