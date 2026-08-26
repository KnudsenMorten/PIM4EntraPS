#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-16 -- a group's Administrative-Unit membership must be RECONCILED, not attached
    once at create time and then forgotten.

    What happened: the attach lived only in Groups.ApplyCreate, read the possibly-stale
    context cache, and swallowed every failure to Write-Verbose. When the AU had been
    created moments earlier by the AdministrativeUnits scope and had not yet replicated
    to the replica that process read, the lookup missed, the attach was skipped in
    silence, and nothing ever repaired it -- the Groups provider's Equal is
    existence-based, so on every later run the group is `nochange`. The run reported
    `applied=4 skipped=0 errors=0` either way.

    Observed in 1 of 3 identical live runs, which is what makes it dangerous: it is a
    TIMING-dependent silent failure, not a deterministic one, so it will not show up in
    a single happy-path test.

    Why it is not cosmetic: AU membership is the SCOPE BOUNDARY for AU-scoped
    delegation -- an L2 helpdesk role is granted AT the AU -- so a group that never
    joined its AU silently has a different reach than the delegation model says. A model
    that quietly disagrees with the directory is the thing this product exists to prevent.

    The assertion that keeps it fixed: after a MISSED attach, the next run plans the
    repair. Plus the containment rules -- only solution-owned groups, only defined AUs.

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

Write-Host "=== BUG-16: AU membership is reconciled, not create-time-only ===" -ForegroundColor Cyan

$GID_AUGRP  = 'aaaaaaaa-1111-1111-1111-111111111111'   # PIM-TEST-Helpdesk-L2   (AU-scoped, tag PERM-HD)
$GID_PLAIN  = 'bbbbbbbb-2222-2222-2222-222222222222'   # PIM-TEST-UserAdmin     (no AU)
$AUID_LIVE  = 'cccccccc-3333-3333-3333-333333333333'   # AU-TEST
$FOREIGN    = 'dddddddd-4444-4444-4444-444444444444'   # a group the solution does NOT own

$script:Desired = @{}
$script:AuMembers = @{}      # auId -> @(member ids)
$script:Posted = @()

function Get-PimDesiredRows { param([string]$Entity) if ($script:Desired.ContainsKey($Entity)) { return @($script:Desired[$Entity]) } return @() }
function Ensure-PimContextLoaded { }
function Resolve-PimLiveGroupIdByName {
    param([string]$Name)
    switch ("$Name") { 'PIM-TEST-Helpdesk-L2' { return $GID_AUGRP } 'PIM-TEST-UserAdmin' { return $GID_PLAIN } }
    return $null
}
function Invoke-PimGraph {
    param([string]$Method='GET', [string]$Path, [object]$Body, [hashtable]$Headers, [switch]$All)
    if ($Method -eq 'POST') { $script:Posted += "$Path :: $($Body['@odata.id'])"; return @{} }
    if ($Path -match '/directory/administrativeUnits/([^/]+)/members') {
        $au = $Matches[1]
        if ($script:AuMembers.ContainsKey($au)) { return @($script:AuMembers[$au] | ForEach-Object { [pscustomobject]@{ id = $_ } }) }
        return @()
    }
    return @()
}

function Reset-Estate {
    $script:PimSolutionGroupsAt = $null
    $script:Posted = @()
    $script:Desired = @{
        'PIM-Definitions-AU'       = @([pscustomobject]@{ AdministrativeUnitTag='AU-T'; AUDisplayName='AU-TEST' })
        'PIM-Definitions-Services' = @(
            [pscustomobject]@{ GroupName='PIM-TEST-Helpdesk-L2'; GroupTag='PERM-HD'; AdministrativeUnitTag='AU-T' }
            [pscustomobject]@{ GroupName='PIM-TEST-UserAdmin';   GroupTag='PERM-UA' })          # no AU tag
    }
    $Global:AU_All_ID = @([pscustomobject]@{ Id=$AUID_LIVE; DisplayName='AU-TEST' })
    $script:AuMembers = @{}
}

$p = New-PimAuMembersProvider
Assert "the provider registers under its own scope"   ("$($p.scope)" -eq 'AdministrativeUnitMembers')
Assert "it runs AFTER Groups (20) and before owners (25)" ([int]$p.order -eq 22)

# ---------------------------------------------------------------------------
Write-Host "`n[the missed attach is REPAIRED on the next run -- the whole point]" -ForegroundColor Cyan
Reset-Estate
$script:AuMembers[$AUID_LIVE] = @()          # the create-time attach was silently skipped
$ctx = @{}
$des = @(& $p.GetDesired $ctx); $liv = @(& $p.GetLive $ctx)
Assert "desired has exactly the AU-scoped group"      ($des.Count -eq 1 -and "$($des[0].groupId)" -eq $GID_AUGRP)
Assert "a group with NO AU tag is not in desired"     (@($des | Where-Object { "$($_.groupId)" -eq $GID_PLAIN }).Count -eq 0)
Assert "live shows the membership is missing"         ($liv.Count -eq 0)
$diff = Compare-PimDesiredVsLive -Desired $des -Live $liv -KeyOf $p.KeyOf -Equal $p.Equal -Prune
Assert "the repair is PLANNED (create=1)"             ($diff.create.Count -eq 1)
& $p.ApplyCreate $diff.create[0] $ctx | Out-Null
Assert "  ...and it POSTs the group into the AU"      ($script:Posted.Count -eq 1 -and $script:Posted[0] -match "administrativeUnits/$AUID_LIVE/members" -and $script:Posted[0] -match $GID_AUGRP)

# ---------------------------------------------------------------------------
Write-Host "`n[once attached it is a no-op -- reconcile, not re-attach every run]" -ForegroundColor Cyan
Reset-Estate
$script:AuMembers[$AUID_LIVE] = @($GID_AUGRP)
$ctx = @{}
$des = @(& $p.GetDesired $ctx); $liv = @(& $p.GetLive $ctx)
Assert "keys agree across desired and live"           ((& $p.KeyOf $des[0]) -eq (& $p.KeyOf $liv[0]))
$diff = Compare-PimDesiredVsLive -Desired $des -Live $liv -KeyOf $p.KeyOf -Equal $p.Equal -Prune
Assert "second run: nothing to create"                ($diff.create.Count -eq 0 -and $diff.nochange.Count -eq 1)
Assert "second run: nothing to remove"                ($diff.remove.Count -eq 0)

# ---------------------------------------------------------------------------
Write-Host "`n[containment -- it can only ever see what the solution owns]" -ForegroundColor Cyan
Reset-Estate
$script:AuMembers[$AUID_LIVE] = @($GID_AUGRP, $FOREIGN)   # something else lives in this AU too
$ctx = @{}
$liv = @(& $p.GetLive $ctx)
Assert "a group the solution does NOT own is ignored"  ($liv.Count -eq 1 -and @($liv | Where-Object { "$($_.groupId)" -eq $FOREIGN }).Count -eq 0)
$des = @(& $p.GetDesired $ctx)
$diff = Compare-PimDesiredVsLive -Desired $des -Live $liv -KeyOf $p.KeyOf -Equal $p.Equal -Prune
Assert "  ...so a -Prune can never plan against it"    ($diff.remove.Count -eq 0)
# an AU the solution does not define is out of scope entirely
Reset-Estate
$Global:AU_All_ID = @([pscustomobject]@{ Id=$AUID_LIVE; DisplayName='AU-TEST' }, [pscustomobject]@{ Id='eeee'; DisplayName='SomeoneElsesAU' })
$script:AuMembers['eeee'] = @($GID_AUGRP)
$ctx = @{}
Assert "an AU the solution does not define is skipped" (@(& $p.GetLive $ctx).Count -eq 0)

# ---------------------------------------------------------------------------
Write-Host "`n[not-yet-live objects are simply deferred, never guessed]" -ForegroundColor Cyan
Reset-Estate
$Global:AU_All_ID = @()                       # the AU has not replicated yet
$ctx = @{}
Assert "no live AU -> nothing desired this pass"      (@(& $p.GetDesired $ctx).Count -eq 0)
Reset-Estate
$script:Desired['PIM-Definitions-Services'] = @([pscustomobject]@{ GroupName='PIM-TEST-NotCreatedYet'; GroupTag='X'; AdministrativeUnitTag='AU-T' })
$ctx = @{}
Assert "no live GROUP -> nothing desired this pass"   (@(& $p.GetDesired $ctx).Count -eq 0)

# ---------------------------------------------------------------------------
Write-Host "`n[structural: the create-time attach must no longer fail in silence]" -ForegroundColor Cyan
$src = Get-Content -LiteralPath (Join-Path $shared 'PIM-EngineProviders.ps1') -Raw
# 🪤 THIS BOUNDED THE SEARCH AT A MAGIC 6000 CHARACTERS AND WENT RED WHEN THE PROVIDER GREW.
# `New-PimGroupsProvider` starts at ~line 739 and the AU-attach warning sits at ~line 820, which
# passed the 6000-char cut only while the intervening lines stayed short. The CODE was correct
# throughout -- `Write-Warning "  [engine] Groups: AU attach at create time failed ... The
# AdministrativeUnitMembers scope will reconcile it."` -- and this test still reported it as
# "the AU attach WARNS instead of Write-Verbose: FAIL", i.e. it accused the code of the exact
# silent-failure defect it exists to prevent. A structural assertion must be bounded by
# STRUCTURE, so the body now ends at the next top-level `function` instead of at a byte count.
$i = $src.IndexOf('function New-PimGroupsProvider')
if ($i -lt 0) { throw 'New-PimGroupsProvider not found in PIM-EngineProviders.ps1 -- this assertion can no longer see what it claims to check.' }
$nextFn = $src.IndexOf("`nfunction ", $i + 1)
$groupsEnd = if ($nextFn -ge 0) { $nextFn } else { $src.Length }
$groupsBody = $src.Substring($i, $groupsEnd - $i)
# Narrow to the STATEMENT, not a character slice around it: the lines of the provider body that
# actually mention the AU attach. That is both stricter than a ±400-character window (a
# Write-Warning elsewhere in the provider cannot satisfy it) and immune to the code moving.
$window = (($groupsBody -split "`r?`n" | Where-Object { $_ -match 'AU attach' }) -join "`n")
Assert "the AU attach WARNS instead of Write-Verbose" ($window -match 'Write-Warning')
Assert "  ...and it names the scope that repairs it"  ($window -match 'AdministrativeUnitMembers')
Assert "the scope is registered by default"           ($src -match 'Register-PimEngineProvider -Provider \(New-PimAuMembersProvider\)')
Assert "it has NO ApplyRemove (create-only by design)" (-not ($p.ContainsKey('ApplyRemove')))

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
