<#
  Offline tests for the engine's APPLIED ACCOUNTING -- BUG-70's residue.

  The invariant under test: `applied` in a run summary must count only items the engine
  ACTUALLY CHANGED. It is the one number an operator reads, and every incident in this
  family looked like a perfect green over work that never happened:
    * BUG-35a -- AdminOffboarding Report mode summarised `remove=1 applied=1`.
    * BUG-66/70 -- AdminTap's mail refusal returned $null; six dead accounts, `applied=6 ok=True`.

  These are BEHAVIOURAL, not source-scanning: each real handler scriptblock is run through the
  REAL core (Invoke-PimEngineScope) with stubbed Graph, and the core's own verdict is asserted.
  A source regex would pass against a core that had stopped honouring the convention.

  🔒 BOTH DIRECTIONS ARE PINNED ON PURPOSE. The handlers that ACT but return nothing must stay
  APPLIED. The obvious-looking repair for BUG-70 -- "treat a bare $null as not-applied" -- would
  turn those into false negatives, which is the same defect pointing the other way. If a future
  change makes that flip, the second block below goes red. See PIM-EngineCore.ps1 for the survey.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-ChangeQueue.ps1"
. "$here\..\engine\_shared\PIM-EngineCore.ps1"
. "$here\..\engine\_shared\PIM-EngineProviders.ps1"

$pass = 0; $fail = 0
function Assert($n, $c, $d = '') {
    if ($c) { $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $n $d" -ForegroundColor Red }
}

Write-Host "=== PIM applied-accounting tests (BUG-70 residue) ===" -ForegroundColor Cyan

# ---- stubs: no network. A Graph 204 returns the EMPTY STRING, not $null -- measured on
# ---- pwsh 7.6.3 AND Windows PowerShell 5.1, both hosts agree. Reproducing that exactly is
# ---- the whole point: it is what makes the PATCH/DELETE handlers non-null.
$script:writes = 0
function Invoke-PimGraph {
    param($Method = 'GET', $Path, $Body, [switch]$All, [switch]$Beta, $Headers)
    $script:writes++
    if ($Method -in 'PATCH', 'DELETE' -or $Path -match '\$ref$') { return '' }   # 204 No Content
    if ($All) { return @() }
    return [pscustomobject]@{ id = 'obj-1' }
}
function Get-PimRowProp { param($Row, $Names) foreach ($n in $Names) { if ($Row.PSObject.Properties[$n]) { return "$($Row.$n)" } } '' }
function Resolve-PimLiveGroupIdByName { param($n) 'gid-1' }
function Get-PimGroupMemberPolicyId { param($GroupId) 'pol-1' }
function Invoke-PimPolicyRulePatch { param($PolicyId, $Body, [ref]$Recovered) $script:writes++; return }
function ConvertTo-PimEnablementRuleBodies { param($Enablement, $LegacyEndUserAssignment) @(@{ id = 'Enablement_Admin_Assignment' }) }
function ConvertTo-PimExpirationRuleBodies { param($Expiration) @(@{ id = 'Expiration_Admin_Assignment' }) }
function Test-PimAccountDisableEnabled { $false }        # guard: account-disable OFF
function Get-PimBreakGlassIdentifiers { @() }
function Test-PimAutoOffboardingEnabled { $false }        # guard: auto-offboarding OFF
function Export-PimHybridAdWorkPackage { param($Plan, $Path) return }

# Run ONE item through the REAL core and report its verdict + how many writes it made.
#
# 🪤 The fixture shape matters. The first version of this harness drove REMOVE with an EMPTY
# desired set, and all three remove probes came back applied=0 skipped=0 -- which reads exactly
# like the fix working. It was not: the core refuses to prune ANYTHING when desired is empty
# ("not authoritative", the 2026-06-15 mass-disable guard), so the handler was never called and
# the assertions were passing/failing on a diff that contained no remove at all. A remove fixture
# therefore needs a non-empty desired set: one FILLER row that matches live (-> nochange) plus the
# target row present only in live (-> remove).
function Invoke-Probe {
    param([string]$Scope, [string]$Handler, [scriptblock]$Body, $Target, $Live, [switch]$Differs)
    $script:writes = 0
    $filler = [pscustomobject]@{ k = 'filler' }
    switch ($Handler) {
        'ApplyCreate' { $desired = @($Target); $liveSet = @() }
        'ApplyUpdate' { $desired = @($Target); $liveSet = @($Live) }
        default       { $desired = @($filler); $liveSet = @($filler, $Live) }   # ApplyRemove
    }
    $prov = @{
        scope = "UT-$Scope"; entity = "UT-$Scope"; order = 1
        KeyOf = { param($r) "$($r.k)" }
        # $true -> a same-key pair is NOCHANGE, so only the intended op reaches a handler.
        # An update probe passes -Differs to force the pair into the update bucket instead.
        Equal = { param($d, $l) -not $Differs }.GetNewClosure()
        GetDesired = { param($ctx) $desired }.GetNewClosure()
        GetLive    = { param($ctx) $liveSet }.GetNewClosure()
        $Handler   = $Body
    }
    Register-PimEngineProvider -Provider $prov
    $r = Invoke-PimEngineScope -Scope "UT-$Scope" -Mode Full -Prune 6>$null
    # Guard the harness itself, and THROW rather than return a flag: if the diff produced no item
    # of the intended kind then the handler never ran, and `applied=0` -- the thing half these
    # assertions are looking for -- would be true for the most boring possible reason. That is how
    # the empty-desired version of this fixture looked green-adjacent while testing nothing. A
    # returned flag only helps if every call site remembers to assert on it; a throw cannot be
    # forgotten.
    $planned = switch ($Handler) { 'ApplyCreate' { $r.create } 'ApplyUpdate' { $r.update } default { $r.remove } }
    if ($planned -ne 1) {
        throw ("probe '$Scope/$Handler' planned $planned item(s), expected exactly 1 -- the fixture is wrong, " +
               "so the handler was never invoked and this probe proves nothing. (create=$($r.create) update=$($r.update) remove=$($r.remove))")
    }
    [pscustomobject]@{ Applied = $r.applied; Skipped = $r.skipped; Errors = $r.errors; Writes = $script:writes; Planned = $planned }
}

$admins = New-PimAdminsProvider
$hybrid = New-PimHybridAdProvider
$offb   = New-PimOffboardingProvider
$owners = New-PimGroupOwnersProvider
$gpol   = New-PimGroupsPoliciesProvider
$aumem  = New-PimAuMembersProvider

$adminRow = [pscustomobject]@{ k = 'a@x.io'; id = 'u1'; UserPrincipalName = 'a@x.io' }

# ---------------------------------------------------------------------------
# 1. HANDLERS THAT DO NOT ACT must NOT be counted as applied.
#    Each of these prints a refusal and changes nothing; before the BUG-70-residue fix they
#    returned a bare $null and the core scored them as a real change.
# ---------------------------------------------------------------------------
Write-Host "`n-- a guard that changes nothing is NOT an apply --" -ForegroundColor Cyan

$r = Invoke-Probe -Scope 'AdminsDisableOff' -Handler 'ApplyRemove' -Body $admins.ApplyRemove -Live $adminRow
Assert 'Admins.ApplyRemove: account-disable OFF -> NOT applied' ($r.Applied -eq 0 -and $r.Skipped -eq 1) "applied=$($r.Applied) skipped=$($r.Skipped)"
Assert '...and it really disabled nothing'                      ($r.Writes -eq 0) "writes=$($r.Writes)"

function Get-PimBreakGlassIdentifiers { @('a@x.io') }
function Test-PimAccountDisableEnabled { $true }               # disable ON, so only break-glass can stop it
function Test-PimRowIsBreakGlass { param($Row, $Identifiers) $true }
$r = Invoke-Probe -Scope 'AdminsBreakGlass' -Handler 'ApplyRemove' -Body $admins.ApplyRemove -Live $adminRow
Assert 'Admins.ApplyRemove: BREAK-GLASS -> NOT applied' ($r.Applied -eq 0 -and $r.Skipped -eq 1) "applied=$($r.Applied) skipped=$($r.Skipped)"
# The worst instance of the family: the summary would otherwise claim the engine disabled the
# one account the entire guard exists to protect.
Assert '...and the break-glass account was never touched' ($r.Writes -eq 0) "writes=$($r.Writes)"

$r = Invoke-Probe -Scope 'HybridPlan' -Handler 'ApplyCreate' -Body $hybrid.ApplyCreate `
        -Target ([pscustomobject]@{ k = 's1'; samAccountName = 's1'; accountKind = 'user'; targetOu = '' })
Assert 'HybridAd.ApplyCreate: plans only -> NOT applied' ($r.Applied -eq 0 -and $r.Skipped -eq 1) "applied=$($r.Applied) skipped=$($r.Skipped)"
Assert '...and the cloud engine provisioned nothing on-prem' ($r.Writes -eq 0) "writes=$($r.Writes)"

$r = Invoke-Probe -Scope 'Offboard' -Handler 'ApplyRemove' -Body $offb.ApplyRemove -Live ([pscustomobject]@{ k = 'a@x.io'; UserPrincipalName = 'a@x.io' })
Assert 'AdminOffboarding.ApplyRemove: offboarding OFF -> NOT applied (BUG-35a, still holds)' ($r.Applied -eq 0 -and $r.Skipped -eq 1) "applied=$($r.Applied) skipped=$($r.Skipped)"

# ---------------------------------------------------------------------------
# 2. HANDLERS THAT DO ACT must STAY applied -- including the two that return NOTHING.
#    This half is the guard rail on the fix. "A handler that returns nothing did nothing" is
#    false for these two, so the tempting $null-means-not-applied flip must never be made.
# ---------------------------------------------------------------------------
Write-Host "`n-- a handler that acts stays APPLIED, even when it returns nothing --" -ForegroundColor Cyan

$r = Invoke-Probe -Scope 'GroupOwners' -Handler 'ApplyCreate' -Body $owners.ApplyCreate `
        -Target ([pscustomobject]@{ k = 'G1|o1'; GroupName = 'G1'; OwnerId = 'o1' })
Assert 'GroupOwners.ApplyCreate: returns NOTHING but DID add the owner -> applied' ($r.Applied -eq 1 -and $r.Skipped -eq 0) "applied=$($r.Applied) skipped=$($r.Skipped)"
Assert '...and it really wrote'                                                    ($r.Writes -ge 1) "writes=$($r.Writes)"

$r = Invoke-Probe -Scope 'GroupsPolicies' -Handler 'ApplyUpdate' -Body $gpol.ApplyUpdate `
        -Target ([pscustomobject]@{ k = 'G1'; GroupName = 'G1'; Enablement = $null; Expiration = $null; Notification = $null; Approval = $null }) `
        -Live ([pscustomobject]@{ k = 'G1'; Rules = @() }) -Differs
Assert 'GroupsPolicies.ApplyUpdate: returns NOTHING but DID patch the rules -> applied' ($r.Applied -eq 1 -and $r.Skipped -eq 0) "applied=$($r.Applied) skipped=$($r.Skipped)"
Assert '...and it really patched'                                                       ($r.Writes -ge 1) "writes=$($r.Writes)"

# A Graph 204 is the EMPTY STRING, not $null -- so every PATCH/DELETE/$ref handler is non-null
# and is unaffected by the convention either way. Pinned because assuming otherwise is what
# made BUG-70's residue look far larger than it is.
$r = Invoke-Probe -Scope 'AuMembers' -Handler 'ApplyCreate' -Body $aumem.ApplyCreate `
        -Target ([pscustomobject]@{ k = 'au1|g1'; auId = 'au1'; groupId = 'g1' })
Assert 'AuMembers.ApplyCreate: a 204 ($ref POST) still counts as applied' ($r.Applied -eq 1 -and $r.Skipped -eq 0) "applied=$($r.Applied) skipped=$($r.Skipped)"

$r = Invoke-Probe -Scope 'AdminsEnable' -Handler 'ApplyUpdate' -Body $admins.ApplyUpdate -Target $adminRow -Live $adminRow -Differs
Assert 'Admins.ApplyUpdate: a 204 (PATCH enable) still counts as applied' ($r.Applied -eq 1 -and $r.Skipped -eq 0) "applied=$($r.Applied) skipped=$($r.Skipped)"

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
