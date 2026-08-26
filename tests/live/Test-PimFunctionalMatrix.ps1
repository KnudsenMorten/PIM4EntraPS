#Requires -Version 5.1
<#
.SYNOPSIS
  TEST-11 -- the STRUCTURED LIVE FUNCTIONAL MATRIX. Every engine scope, every
  operation, against a REAL test tenant, with the destructive paths (prune /
  disable / delete) run TWICE: gated OFF (must refuse) and deliberately ON
  (must do exactly the right thing, and NOTHING more).

.DESCRIPTION
  Design: REQUIREMENTS.md s33.6. This is the harness that closes TEST-11.

  WHY IT EXISTS
  Everything proven before this was offline, or a plan, or a single apply. The
  destructive paths -- the ones that disabled 53 production accounts on
  2026-06-15 -- had only ever been verified in the "refuses" direction. A guard
  proven only to STOP is half-proven: we know it stops, we do not know that the
  thing it gates does the right thing when it is allowed to run.

  WHAT MAKES IT DIFFERENT FROM THE OTHER LIVE HARNESSES
  Every case asserts the BLAST RADIUS, not just the outcome. A full tenant
  inventory (users + their accountEnabled, groups, AUs, AU members, group
  members/eligibilities, directory-role assignments + eligibilities) is captured
  before and after every mutating case, and the delta must consist of EXACTLY the
  marked objects the case was supposed to touch. "It disabled the right account"
  is not enough -- the incident was about what else went with it.

  THE MARKER  (operator's naming request, s33.6)
  Every object the harness creates carries the marker 'PIMTEST' in its name, so a
  single filter finds all of it:
      AUs            PIMTEST-AU-<case>
      groups         PIM-PIMTEST-<...>          (see NOTE below)
      admin accounts Admin-PIMTEST-<case>-ID@<domain>
  NOTE on groups: the leading segment cannot be the marker. The engine's LEAN
  context fetches groups server-side with startswith(displayName,'PIM') and the
  PimGroup filter is `PIM-*`, so a group called 'PIMTEST-...' is invisible to
  half the engine and the matrix would test nothing. The marker therefore sits in
  the SECOND segment for groups. Ownership is decided by Test-PimMatrixOwnedName
  (name CONTAINS the marker), which is one filter for every object type.

  THE CLEANUP CANNOT REACH A REAL OBJECT
  Remove-PimMatrixObject refuses -- throws -- on any name that does not carry the
  marker, so -Cleanup pointed at the wrong tenant deletes nothing. The preflight
  refuses to run at all unless the connected tenant classifies as 'test'
  (Resolve-PimEnvironmentClass, i.e. its id is in PIM_TestTenantIds) and unless
  the desired store contains ONLY harness-owned rows -- a store polluted with
  real desired rows could otherwise make the engine plan removals of real things.

  IDENTITY
  SPN + certificate only (client id / thumbprint / tenant id supplied by the
  caller or the PIM_* env vars; real values live in internal/ENGINE-IDENTITY.md).
  Never interactive, never a secret, never device-code.

  SKIP != PASS
  Every case records {ok; skipped; required}. A self-skip (no subscription, a
  capability not present) is NEVER counted as a pass. Exit code is non-zero on
  any required failure, and also on a required skip when -FailOnSkip.

.PARAMETER TenantId / ClientId / CertThumbprint
  The TEST tenant's engine SPN. Defaults to $env:PIM_TenantId / PIM_ClientId /
  PIM_CertThumbprint.

.PARAMETER SqlServer / SqlDatabase
  The DESIRED store the matrix seeds and the engine reads. Defaults to
  .\SQLEXPRESS / PimMatrixTest -- a SCRATCH database, deliberately NOT the
  platform store. The harness refuses a store holding rows it does not own.

.PARAMETER UpnDomain
  Domain for the marked admin accounts. Defaults to the tenant's default
  verified domain (resolved live).

.PARAMETER AzSubscriptionId
  Enables the AzRes cases. Omitted => those cases self-skip (recorded, not passed).

.PARAMETER Case
  Run one case (or one family: 'lifecycle', 'destructive') instead of all.

.PARAMETER IncludeDestructive
  Run the "deliberately ON" half of the destructive matrix (the half that really
  disables / deletes marked objects). Without it only the gated-OFF half runs and
  the ON half is recorded as SKIPPED -- which is not a pass.

.PARAMETER Cleanup
  Remove every marked object + every harness-owned desired row, then exit.

.PARAMETER FailOnSkip
  Treat a skipped REQUIRED case as a hard failure.

.PARAMETER KeepStore
  Do not clear harness desired rows at the end (for debugging a run).

.EXAMPLE
  # full matrix incl. the destructive-ON half, against the test tenant
  $env:PIM_TestTenantIds = '<test-tenant-guid>'
  .\Test-PimFunctionalMatrix.ps1 -TenantId <guid> -ClientId <guid> -CertThumbprint <thumb> `
      -SqlDatabase PimMatrixTest -IncludeDestructive -FailOnSkip
.EXAMPLE
  .\Test-PimFunctionalMatrix.ps1 -TenantId <guid> -ClientId <guid> -CertThumbprint <thumb> -Cleanup
#>
[CmdletBinding()]
param(
    [string]$TenantId       = $env:PIM_TenantId,
    [string]$ClientId       = $env:PIM_ClientId,
    [string]$CertThumbprint = $env:PIM_CertThumbprint,
    [string]$SqlServer      = $(if ($env:PIM_MatrixSqlServer) { $env:PIM_MatrixSqlServer } else { '.\SQLEXPRESS' }),
    [string]$SqlDatabase    = $(if ($env:PIM_MatrixSqlDatabase) { $env:PIM_MatrixSqlDatabase } else { 'PimMatrixTest' }),
    [string]$UpnDomain,
    [string]$AzSubscriptionId,
    [string]$Case = 'All',
    [switch]$IncludeDestructive,
    [switch]$Cleanup,
    [switch]$FailOnSkip,
    [switch]$KeepStore
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = (Get-Location).Path }
$solution   = (Resolve-Path (Join-Path $here '..\..')).Path
$shared     = Join-Path $solution 'engine\_shared'
$configDir  = Join-Path $solution 'config'
$enginePath = Join-Path $solution 'tools\pim-engine\Invoke-PimEngineCore.ps1'

# The single ownership marker. EVERYTHING the harness creates carries it; nothing
# without it can ever be deleted, disabled or pruned by this file.
$script:Marker = 'PIMTEST'

# ============================================================================
# region  logging / result model
# ============================================================================
$script:RunStamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$script:LogRoot  = Join-Path $here ("logs\matrix-$($script:RunStamp)")
New-Item -ItemType Directory -Path $script:LogRoot -Force | Out-Null
$script:LogFile  = Join-Path $script:LogRoot 'matrix.log'
$script:Results  = New-Object System.Collections.Generic.List[object]

function Write-MxLog {
    param([ValidateSet('INFO','STEP','PASS','FAIL','SKIP','WARN','DATA')][string]$Level, [string]$Message)
    $line = "{0} [{1,-4}] {2}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $script:LogFile -Value $line
    $color = switch ($Level) {
        'PASS' { 'Green' } 'FAIL' { 'Red' } 'SKIP' { 'DarkYellow' }
        'WARN' { 'Yellow' } 'STEP' { 'Cyan' } 'DATA' { 'DarkGray' } default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
}

function New-MxResult {
    # One row of the matrix. `required` drives the exit code; `skipped` is NEVER a pass.
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$Name,
        [bool]$Ok = $false,
        [bool]$Skipped = $false,
        [bool]$Required = $true,
        [string]$Detail = '',
        [string]$Family = 'lifecycle'
    )
    $r = [pscustomobject]@{ id=$Id; scope=$Scope; name=$Name; family=$Family; ok=$Ok; skipped=$Skipped; required=$Required; detail=$Detail }
    $script:Results.Add($r)
    if     ($Skipped) { Write-MxLog SKIP ("{0} [{1}] {2} -- {3}" -f $Id, $Scope, $Name, $Detail) }
    elseif ($Ok)      { Write-MxLog PASS ("{0} [{1}] {2}{3}" -f $Id, $Scope, $Name, $(if ($Detail) { " -- $Detail" } else { '' })) }
    else              { Write-MxLog FAIL ("{0} [{1}] {2} -- {3}" -f $Id, $Scope, $Name, $Detail) }
    $r
}

function Assert-Mx {
    # Assert with an id. Returns the result row so a caller can branch on .ok.
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Condition,
        [string]$Detail = '',
        [bool]$Required = $true,
        [string]$Family = 'lifecycle'
    )
    New-MxResult -Id $Id -Scope $Scope -Name $Name -Ok $Condition -Required $Required -Detail $Detail -Family $Family
}

# ============================================================================
# region  engine stack (REST-only, no modules)
# ============================================================================
$global:PIM_UseGraphSdk = $false
. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-ChangeQueue.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')
. (Join-Path $shared 'PIM-DisableGuard.ps1')
. (Join-Path $configDir 'PIM4EntraPS.NamingConventions.locked.ps1')

if (-not $TenantId)       { throw "TenantId is required (-TenantId or `$env:PIM_TenantId)." }
if (-not $ClientId)       { throw "ClientId is required (-ClientId or `$env:PIM_ClientId)." }
if (-not $CertThumbprint) { throw "CertThumbprint is required (-CertThumbprint or `$env:PIM_CertThumbprint)." }

$global:PIM_TenantId       = $TenantId
$global:PIM_ClientId       = $ClientId
$global:PIM_CertThumbprint = $CertThumbprint
$global:PIM_SqlServer      = $SqlServer
$global:PIM_SqlDatabase    = $SqlDatabase

# ============================================================================
# region  ownership + safe removal
# ============================================================================
function Test-PimMatrixOwnedName {
    # THE ownership test. One filter for every object type the harness creates.
    param([string]$Name)
    return ("$Name".ToUpperInvariant().Contains($script:Marker))
}

function Remove-PimMatrixObject {
    <#
      The ONLY delete path in this harness. It refuses -- throws -- on any name
      that does not carry the marker, so a cleanup pointed at the wrong tenant
      cannot reach a real object even if the id is real.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('user','group','administrativeUnit')][string]$Kind,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name
    )
    if (-not (Test-PimMatrixOwnedName -Name $Name)) {
        throw "REFUSING to delete '$Name' ($Kind $Id): it does not carry the '$($script:Marker)' marker. The matrix harness may only ever remove objects it created."
    }
    $path = switch ($Kind) {
        'user'               { "/users/$Id" }
        'group'              { "/groups/$Id" }
        'administrativeUnit' { "/directory/administrativeUnits/$Id" }
    }
    Invoke-PimGraph -Method DELETE -Path $path | Out-Null
    Write-MxLog INFO "    removed $Kind '$Name'"
}

# ============================================================================
# region  live inventory + blast radius
# ============================================================================
function Get-MxGraph {
    <#
      A 404-tolerant Graph read for the INVENTORY only.
      Entra is eventually consistent: an object can be listed by one call and answer
      404 on the next while replication catches up (observed on a just-created AU).
      That is a property of the directory, not a test failure -- so an inventory read
      returns @() for a vanished object instead of aborting the whole matrix. Every
      ASSERTION still works off the resulting snapshot, so a genuinely missing object
      still fails its case.
    #>
    param([Parameter(Mandatory)][string]$Path, [hashtable]$Headers)
    try {
        if ($Headers) { return @(Invoke-PimGraph -Path $Path -Headers $Headers -All) }
        return @(Invoke-PimGraph -Path $Path -All)
    } catch {
        $m = "$($_.Exception.Message)"
        if ($m -match 'HTTP 404|Request_ResourceNotFound') { return @() }
        throw
    }
}

function Get-PimMatrixInventory {
    <#
      A full picture of everything the engine can mutate in this tenant, as flat
      key->value maps so two snapshots can be diffed exactly. Cheap here: a test
      tenant is small by definition, and the preflight refuses a tenant that is not
      classified as test.
    #>
    [CmdletBinding()] param()
    $inv = [ordered]@{
        users            = @{}   # upn(lower)     -> "<enabled>|<displayName>"
        groups           = @{}   # displayName    -> id
        aus              = @{}   # displayName    -> id
        auMembers        = @{}   # "<auName>|<memberId>"        -> $true
        groupMembers     = @{}   # "<groupName>|<memberId>"     -> $true
        groupOwners      = @{}   # "<groupName>|<ownerId>"      -> $true
        roleAssignments  = @{}   # "<roleName>|<principalId>|<scope>" -> $true
        roleEligibility  = @{}   # "<roleName>|<principalId>|<scope>" -> $true
        pimGroupSchedules= @{}   # "<groupName>|<principalId>|<accessId>|<kind>" -> $true
    }
    foreach ($u in (Get-MxGraph -Path "/users?`$select=id,userPrincipalName,displayName,accountEnabled&`$top=999")) {
        if (-not $u) { continue }
        $inv.users["$($u.userPrincipalName)".ToLowerInvariant()] = "{0}|{1}|{2}" -f [bool]$u.accountEnabled, $u.displayName, $u.id
    }
    $groupById = @{}
    foreach ($g in (Get-MxGraph -Path "/groups?`$select=id,displayName&`$top=999")) {
        if (-not $g) { continue }
        $inv.groups["$($g.displayName)"] = "$($g.id)"
        $groupById["$($g.id)"] = "$($g.displayName)"
    }
    foreach ($a in (Get-MxGraph -Path "/directory/administrativeUnits?`$select=id,displayName")) {
        if (-not $a) { continue }
        $inv.aus["$($a.displayName)"] = "$($a.id)"
        foreach ($m in (Get-MxGraph -Path "/directory/administrativeUnits/$($a.id)/members?`$select=id")) {
            if ($m -and $m.id) { $inv.auMembers["$($a.displayName)|$($m.id)"] = $true }
        }
    }
    foreach ($gid in @($groupById.Keys)) {
        $gn = $groupById[$gid]
        foreach ($m in (Get-MxGraph -Path "/groups/$gid/members?`$select=id"))  { if ($m -and $m.id) { $inv.groupMembers["$gn|$($m.id)"] = $true } }
        foreach ($o in (Get-MxGraph -Path "/groups/$gid/owners?`$select=id"))   { if ($o -and $o.id) { $inv.groupOwners["$gn|$($o.id)"]  = $true } }
    }
    # Directory-role assignments + eligibilities (PIM).
    #
    # KEYS MUST CARRY THE OWNER'S NAME. The blast-radius check decides ownership from
    # the KEY TEXT, so a key built only from GUIDs ("User Administrator|<guid>|/")
    # would look unowned and every marked assignment would be reported as collateral.
    # We therefore resolve the principal id and the AU scope back to their display
    # names -- which is also what makes a failure message readable.
    $principalName = @{}
    foreach ($k in @($inv.users.Keys))  { $principalName[(("$($inv.users[$k])" -split '\|')[2])] = $k }
    foreach ($k in @($inv.groups.Keys)) { $principalName["$($inv.groups[$k])"] = $k }
    # Service principals hold real directory roles in any tenant (sync engines, the PIM
    # engine SPN itself). Without them those assignments key as bare GUIDs, which the
    # blast-radius check cannot attribute to anyone.
    foreach ($sp in (Get-MxGraph -Path "/servicePrincipals?`$select=id,displayName&`$top=999")) {
        if ($sp -and $sp.id) { $principalName["$($sp.id)"] = "spn:$($sp.displayName)" }
    }
    $auName = @{}
    foreach ($k in @($inv.aus.Keys)) { $auName["$($inv.aus[$k])"] = $k }
    $roleName = @{}
    foreach ($rd in (Get-MxGraph -Path "/roleManagement/directory/roleDefinitions?`$select=id,displayName")) {
        if ($rd) { $roleName["$($rd.id)"] = "$($rd.displayName)" }
    }
    $resolveScope = {
        param($scopeId)
        $s = "$scopeId"
        if ($s -match '^/administrativeUnits/(.+)$') {
            $n = $auName[$Matches[1]]
            if ($n) { return "/administrativeUnits/$n" }
        }
        return $s
    }
    foreach ($pair in @(
        @{ path = '/roleManagement/directory/roleAssignmentSchedules';  bucket = 'roleAssignments' },
        @{ path = '/roleManagement/directory/roleEligibilitySchedules'; bucket = 'roleEligibility' })) {
        try {
            foreach ($s in (Get-MxGraph -Path "$($pair.path)?`$select=roleDefinitionId,principalId,directoryScopeId")) {
                if (-not $s) { continue }
                $rn = $roleName["$($s.roleDefinitionId)"]; if (-not $rn) { $rn = "$($s.roleDefinitionId)" }
                $pn = $principalName["$($s.principalId)"]
                # DANGLING principal: the schedule outlived the object it points at.
                # Entra keeps the schedule when a principal is deleted, and if the scope
                # was an AU that is also gone it cannot even be removed any more (the
                # adminRemove request 404s). Such a row is inert debris from an earlier
                # run -- and because these lists are themselves eventually consistent it
                # FLICKERS in and out of a snapshot, which showed up once as phantom
                # "collateral damage" in a case that had touched nothing of the sort.
                # It cannot be attributed to anyone, and by construction it is never
                # something the CURRENT run created (a live principal always resolves),
                # so it is excluded. Real deletions are still caught: the users/groups
                # buckets assert those directly.
                if (-not $pn) { continue }
                $inv[$pair.bucket]["$rn|$pn|$(& $resolveScope $s.directoryScopeId)"] = $true
            }
        } catch { Write-MxLog WARN "inventory: $($pair.bucket) read failed: $($_.Exception.Message)" }
    }
    # PIM-for-Groups schedules (the AdminMembers / GroupMembers surface).
    foreach ($pair in @(
        @{ path = '/identityGovernance/privilegedAccess/group/assignmentSchedules';  kind = 'active' },
        @{ path = '/identityGovernance/privilegedAccess/group/eligibilitySchedules'; kind = 'eligible' })) {
        foreach ($gid in @($groupById.Keys)) {
            try {
                foreach ($s in (Get-MxGraph -Path "$($pair.path)?`$filter=groupId eq '$gid'&`$select=principalId,accessId")) {
                    if (-not $s) { continue }
                    $pn = $principalName["$($s.principalId)"]; if (-not $pn) { $pn = "$($s.principalId)" }
                    $inv.pimGroupSchedules["$($groupById[$gid])|$pn|$($s.accessId)|$($pair.kind)"] = $true
                }
            } catch { }   # a non-role-assignable / non-PIM group answers 400; not an inventory failure
        }
    }
    return $inv
}

function Wait-PimMatrixInventory {
    <#
      Entra is EVENTUALLY consistent. An engine apply that returned 2xx is not
      necessarily visible on the next read -- the first run of this harness saw
      exactly that (2 AUs created, applied=2, then invisible; the following run
      re-created one because the engine's own live read had not caught up either).

      So: after every apply, poll the inventory until the case's own verification
      predicate holds, bounded by -TimeoutSec. This is NOT a blanket sleep to make
      a flaky test pass -- if the predicate never becomes true the case still FAILS,
      and the returned snapshot is the last one read. It removes replication lag as
      a source of false results without hiding a real one.
    #>
    param([scriptblock]$Verify, [int]$TimeoutSec = 150, [int]$IntervalSec = 6)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $inv = Get-PimMatrixInventory
    if (-not $Verify) { return $inv }
    $waited = 0
    while ($true) {
        $ok = $false
        try { $ok = [bool](& $Verify $inv) } catch { $ok = $false }
        if ($ok) {
            if ($waited -gt 0) { Write-MxLog DATA "    (directory settled after ${waited}s)" }
            return $inv
        }
        if ((Get-Date) -ge $deadline) {
            Write-MxLog WARN "    directory did not settle within ${TimeoutSec}s -- asserting against the last snapshot"
            return $inv
        }
        Start-Sleep -Seconds $IntervalSec
        $waited += $IntervalSec
        $inv = Get-PimMatrixInventory
    }
}

function Compare-PimMatrixInventory {
    # Exact delta between two snapshots, per bucket.
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After)
    $delta = [ordered]@{}
    foreach ($bucket in @($Before.Keys)) {
        $b = $Before[$bucket]; $a = $After[$bucket]
        $added   = @($a.Keys | Where-Object { -not $b.ContainsKey($_) })
        $removed = @($b.Keys | Where-Object { -not $a.ContainsKey($_) })
        $changed = @($a.Keys | Where-Object { $b.ContainsKey($_) -and "$($b[$_])" -ne "$($a[$_])" })
        if ($added.Count -or $removed.Count -or $changed.Count) {
            $delta[$bucket] = [pscustomobject]@{ added=$added; removed=$removed; changed=$changed }
        }
    }
    return $delta
}

function Test-PimMatrixUnchanged {
    # $delta is an ORDERED DICTIONARY. `@($delta).Count` is 1 whether it is empty or not
    # (a dictionary wraps as ONE object), which silently turned "nothing changed" into a
    # failed assertion. Count the KEYS.
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After)
    $d = Compare-PimMatrixInventory -Before $Before -After $After
    return (@($d.Keys).Count -eq 0)
}

function Assert-PimMatrixBlastRadius {
    <#
      THE assertion that makes this harness worth writing. Every key that changed
      between the two snapshots must carry the marker (i.e. belong to an object the
      harness created). Anything else is collateral damage -- the incident shape --
      and fails the case.

      -ExpectAdded / -ExpectRemoved / -ExpectChanged are OPTIONAL exact-count
      expectations per bucket, e.g. @{ users = 1 }.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)]$After,
        [string]$Family = 'lifecycle',
        [hashtable]$ExpectAdded   = @{},
        [hashtable]$ExpectRemoved = @{},
        [hashtable]$ExpectChanged = @{}
    )
    $delta = Compare-PimMatrixInventory -Before $Before -After $After
    $collateral = New-Object System.Collections.Generic.List[string]
    foreach ($bucket in @($delta.Keys)) {
        foreach ($op in 'added','removed','changed') {
            foreach ($k in @($delta[$bucket].$op)) {
                if (-not (Test-PimMatrixOwnedName -Name $k)) { [void]$collateral.Add("$bucket/${op}: $k") }
            }
        }
    }
    $summary = (@($delta.Keys | ForEach-Object {
        "{0}(+{1}/-{2}/~{3})" -f $_, @($delta[$_].added).Count, @($delta[$_].removed).Count, @($delta[$_].changed).Count
    }) -join ' ')
    if (-not $summary) { $summary = 'no change' }

    $ok = ($collateral.Count -eq 0)
    $detail = "delta: $summary"
    if ($collateral.Count) { $detail = "COLLATERAL DAMAGE ($($collateral.Count)): " + (($collateral | Select-Object -First 6) -join ' ; ') }

    # exact-count expectations
    foreach ($spec in @(
        @{ map = $ExpectAdded;   op = 'added' },
        @{ map = $ExpectRemoved; op = 'removed' },
        @{ map = $ExpectChanged; op = 'changed' })) {
        foreach ($bucket in @($spec.map.Keys)) {
            $want = [int]$spec.map[$bucket]
            $got  = 0
            if ($delta.Contains($bucket)) { $got = @($delta[$bucket].$($spec.op)).Count }
            if ($got -ne $want) {
                $ok = $false
                $detail += " ; expected $bucket $($spec.op)=$want but got $got"
            }
        }
    }
    Assert-Mx -Id $Id -Scope $Scope -Name 'blast radius: only marked objects changed' -Condition $ok -Detail $detail -Family $Family | Out-Null
    return $delta
}

# ============================================================================
# region  desired store
# ============================================================================
function Initialize-PimMatrixStore {
    Initialize-PimSqlDatabase -Server $SqlServer -Database $SqlDatabase
    $script:Cs = Get-PimSqlConnectionString
    Initialize-PimSqlStore -ConnectionString $script:Cs
    Write-MxLog INFO "desired store: $SqlServer / $SqlDatabase"
}

# Entities the matrix owns end-to-end. A -Cleanup clears exactly these.
$script:MatrixEntities = @(
    'PIM-Definitions-AU','PIM-Definitions-Roles','PIM-Definitions-Services',
    'PIM-Definitions-Departments','Account-Definitions-Admins','PIM-Assignments-Admins',
    'PIM-Assignments-Groups','PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs',
    'PIM-Assignments-Azure-Resources'
)

function Set-PimMatrixRow {
    param([Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][hashtable]$Row, [string]$KeyBase)
    $obj = [pscustomobject]$Row
    $base = if ($KeyBase) { $KeyBase } else { $Entity }
    $key  = Get-PimStoreRowKey -Base $base -Row $obj
    if (-not $key) { throw "no key derived for a $Entity row" }
    Set-PimSqlRow -ConnectionString $script:Cs -Entity $Entity -Key $key -Data $obj
    return $key
}
function Remove-PimMatrixRow {
    param([Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][string]$Key)
    Invoke-PimSqlNonQuery -ConnectionString $script:Cs -Sql "DELETE FROM pim.Rows WHERE Entity=@e AND [Key]=@k" -Parameters @{ e=$Entity; k=$Key } | Out-Null
}
function Clear-PimMatrixStore {
    $n = 0
    foreach ($e in $script:MatrixEntities) {
        $n += [int](Invoke-PimSqlNonQuery -ConnectionString $script:Cs -Sql "DELETE FROM pim.Rows WHERE Entity=@e" -Parameters @{ e=$e })
    }
    Write-MxLog INFO "cleared $n desired rows from the matrix store"
}

# ============================================================================
# region  engine runner (child process = clean globals per case)
# ============================================================================
function Invoke-PimMatrixEngine {
    <#
      Run the REAL engine entrypoint in a child pwsh so every case starts from
      clean global state (feature flags, context cache, naming config). Returns
      @{ summary; text; exitCode } where summary is the parsed pim-engine-summary
      and text is everything the engine printed (asserted against for the guard
      messages: 'prune SKIPPED', 'BREAK-GLASS', 'REMOVAL BUDGET', ...).
    #>
    param(
        [Parameter(Mandatory)][string]$Scope,
        [ValidateSet('Full','Delta')][string]$Mode = 'Delta',
        [switch]$WhatIf,
        [switch]$Prune,
        [hashtable]$Env = @{},
        [hashtable]$Globals = @{},
        [string]$Label = ''
    )
    $tag     = if ($Label) { $Label } else { "$Scope-$Mode" }
    $caseDir = Join-Path $script:LogRoot ("engine-" + ($tag -replace '[^A-Za-z0-9\-_]', '_'))
    New-Item -ItemType Directory -Path $caseDir -Force | Out-Null
    $jsonOut = Join-Path $caseDir 'summary.json'

    $argStr = "-Scope '$Scope' -Mode $Mode -LogDir '$caseDir'"
    if ($WhatIf) { $argStr += ' -WhatIf' }
    if ($Prune)  { $argStr += ' -Prune' }
    # -Globals sets $global:* in the CHILD before the engine runs.
    #
    # This is not a shortcut -- it is the only channel that exists. The destructive
    # safety knobs (PIM_AccountDisableEnabled, PIM_DisableMaxCount/Percent,
    # PIM_RemoveUnmanagedAdmins) are read ONLY from $global:*: the engine entrypoint
    # hydrates five unrelated names from the environment, loads no custom config, and
    # pim.Settings lands in $global:PIM_NamingConventions instead. Two knobs in the very
    # same guard file (PIM_TestTenantIds, PIM_BREAKGLASS_ACCOUNTS) DO read the
    # environment -- which is what makes the omission an inconsistency rather than a
    # design. Recorded as SEC-07; case D8 asserts the env channel and stays RED until
    # it works. Meanwhile the ON/OFF halves have to be driven this way to be driven at all.
    $prelude = ''
    foreach ($g in @($Globals.Keys)) {
        $v = $Globals[$g]
        $lit = if ($v -is [bool]) { if ($v) { '$true' } else { '$false' } }
               elseif ($v -is [int] -or $v -is [double]) { "$v" }
               else { "'" + ("$v" -replace "'", "''") + "'" }
        $prelude += "`$global:$g = $lit; "
    }
    $cmd = "$prelude& '$enginePath' $argStr | Where-Object { `$_.kind -eq 'pim-engine-summary' } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath '$jsonOut' -Encoding UTF8"

    # Per-case environment on top of the harness baseline. Saved + restored so one
    # case's opt-in can never leak into the next.
    $baseEnv = @{
        PIM_TenantId       = $TenantId
        PIM_ClientId       = $ClientId
        PIM_CertThumbprint = $CertThumbprint
        PIM_SqlServer      = $SqlServer
        PIM_SqlDatabase    = $SqlDatabase
        PIM_TestTenantIds  = $TenantId
    }
    $all   = @{}
    foreach ($k in $baseEnv.Keys) { $all[$k] = $baseEnv[$k] }
    foreach ($k in $Env.Keys)     { $all[$k] = $Env[$k] }
    $saved = @{}
    foreach ($k in $all.Keys) {
        $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
        [Environment]::SetEnvironmentVariable($k, "$($all[$k])", 'Process')
    }
    try {
        $pwshExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
        $text = & $pwshExe -NoProfile -Command $cmd 2>&1 | ForEach-Object { "$_" }
        $exit = $LASTEXITCODE
    }
    finally {
        foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
    }
    $joined = ($text -join [Environment]::NewLine)
    Set-Content -LiteralPath (Join-Path $caseDir 'console.txt') -Value $joined -Encoding UTF8
    $summary = $null
    if (Test-Path -LiteralPath $jsonOut) {
        try { $summary = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json } catch { }
    }
    return [pscustomobject]@{ summary = $summary; text = $joined; exitCode = $exit; dir = $caseDir }
}

function Get-MxScopeResult {
    # The per-scope row out of an engine summary (the matrix always runs one scope).
    param($Run, [string]$Scope)
    if (-not $Run -or -not $Run.summary) { return $null }
    return @($Run.summary.perScope | Where-Object { "$($_.scope)" -eq $Scope }) | Select-Object -First 1
}

# ============================================================================
# region  the marked desired set
# ============================================================================
function Get-PimMatrixNames {
    param([string]$Domain)
    $m = $script:Marker
    [pscustomobject]@{
        AuScoped        = "$m-AU-Helpdesk"
        AuPrune         = "$m-AU-Retired"
        RoleGroup       = "PIM-$m-ROLE-Operator"
        RoleGroupTag    = "$m-ROLE-Operator"
        PermGroup       = "PIM-$m-Entra-ID-UserAdministrator-L1-T0-CP-ID"
        PermGroupTag    = "$m-Entra-ID-UserAdministrator-L1"
        AuGroup         = "PIM-$m-Entra-ID-Helpdesk-L2-T2-CP-ID"
        AuGroupTag      = "$m-Entra-ID-Helpdesk-L2"
        PruneGroup      = "PIM-$m-Entra-ID-Reader-L3-T2-CP-ID"
        PruneGroupTag   = "$m-Entra-ID-Reader-L3"
        AzGroup         = "PIM-$m-AzRes-Subscription-Reader-L5-T1-MP-RES"
        AzGroupTag      = "$m-AzRes-Subscription-Reader-L5"
        AdminUpn        = "Admin-$m-OPS-ID@$Domain"
        AdminDisplay    = "$m Admin Operations (matrix)"
        AdminPruneUpn   = "Admin-$m-TEMP-ID@$Domain"
        AdminPruneDisp  = "$m Admin Temp (matrix, removable)"
        AdminBgUpn      = "Admin-$m-BREAKGLASS-ID@$Domain"
        AdminBgDisplay  = "$m Admin Break-Glass (matrix)"
        # 🔴 POPULATION IS PART OF THE TEST, not padding. D4 disables exactly ONE admin, and the
        # mass-disable circuit breaker judges that as a PERCENTAGE of the accounts it scanned.
        # With three admins in the tenant one disable is 33.3%, which is over the IMP-01 HARD
        # CEILING of 25% -- so on a small tenant there is NO legal setting that permits a single
        # legitimate retirement, and D4 could never pass. Measured on 2026-08-25 (tenant xx391):
        #   "would disable 1 of 3 scanned accounts (33,3% > cap 20%). Disabled NOTHING this run."
        # The engine was RIGHT; the harness had assumed ~8 admins ("one disable is 12.5%") and
        # the tenant scans 3. Two filler admins take the population to five, so one disable is
        # exactly 20% -- inside the cap, and the guard is exercised at a REAL operator setting
        # rather than neutered. 🪤 Never "fix" this by raising the percentage: that tests nothing.
        AdminFill1Upn   = "Admin-$m-FILL1-ID@$Domain"
        AdminFill1Disp  = "$m Admin Filler 1 (matrix, population)"
        AdminFill2Upn   = "Admin-$m-FILL2-ID@$Domain"
        AdminFill2Disp  = "$m Admin Filler 2 (matrix, population)"
    }
}

function Get-PimMatrixLiveAdminPreserveRows {
    <#
      The Admins scope's desired set is AUTHORITATIVE: an admin account NOT in it is
      supposed to be deprovisioned (the MSP model -- see s33.0). The test tenant
      legitimately holds admin accounts that are not part of this matrix, so we read
      them LIVE and put them in the desired set as preserve rows. Two reasons:
        1. they must never be collateral of a matrix prune, and
        2. hardcoding real UPNs into a published tree is exactly what SEC-02 removed.
    #>
    param([string]$Domain)
    $prefixes = @(Get-PimAdminAccountPrefixes)
    $rows = New-Object System.Collections.Generic.List[hashtable]
    $seen = @{}
    foreach ($p in $prefixes) {
        $esc = "$p".Replace("'", "''")
        foreach ($u in @(Invoke-PimGraph -Path "/users?`$select=id,userPrincipalName,displayName&`$filter=startswith(userPrincipalName,'$esc')" -All)) {
            if (-not $u) { continue }
            $upn = "$($u.userPrincipalName)"
            if (Test-PimMatrixOwnedName -Name $upn) { continue }      # matrix-owned rows are seeded explicitly
            $local = ($upn -split '@')[0]
            if ($seen.ContainsKey($local.ToLowerInvariant())) { continue }
            $seen[$local.ToLowerInvariant()] = $true
            [void]$rows.Add(@{
                UserName = $local; DisplayName = "$($u.displayName)"; UserPrincipalName = $upn
                UserType = 'Member'; AccountStatus = 'Enabled'; CreateTAP = 'FALSE'; Purpose = 'Preserved (live, not matrix-owned)'
            })
        }
    }
    return $rows.ToArray()
}

function Set-PimMatrixDesiredSet {
    <#
      Seed the whole marked desired set. Every group/AU/account name carries the
      marker. Returns the map of {entity -> {logical name -> row key}} so the
      destructive cases can delete ONE row precisely.
    #>
    param([Parameter(Mandatory)][string]$Domain, [string]$OwnerUpn, [string]$SubscriptionId)
    $n = Get-PimMatrixNames -Domain $Domain
    $keys = @{}
    function Put([string]$Entity, [hashtable]$Row, [string]$Logical, [string]$Base) {
        $k = Set-PimMatrixRow -Entity $Entity -Row $Row -KeyBase $Base
        if (-not $keys.ContainsKey($Entity)) { $keys[$Entity] = @{} }
        $keys[$Entity][$Logical] = $k
    }

    # --- AUs (scope containers) -------------------------------------------------
    Put 'PIM-Definitions-AU' @{ AdministrativeUnitTag="$($script:Marker)-AU-L2"; AUDisplayName=$n.AuScoped; AUDescription='matrix: AU-scoped helpdesk'; Workload='PIM'; Level='L2'; Visibility='Public' } 'auScoped' 'PIM-Definitions-AU'
    Put 'PIM-Definitions-AU' @{ AdministrativeUnitTag="$($script:Marker)-AU-RET"; AUDisplayName=$n.AuPrune;  AUDescription='matrix: removable AU (prune case)'; Workload='PIM'; Level='L2'; Visibility='Public' } 'auPrune' 'PIM-Definitions-AU'

    # --- departments (owner source) --------------------------------------------
    Set-PimSqlRow -ConnectionString $script:Cs -Entity 'PIM-Definitions-Departments' -Key "$($script:Marker)-IT" -Data ([pscustomobject]@{ Department="$($script:Marker)-IT"; Owners=$OwnerUpn; Mode='Serial' })

    # --- role group (tier 2) ----------------------------------------------------
    Put 'PIM-Definitions-Roles' @{ GroupName=$n.RoleGroup; GroupTag=$n.RoleGroupTag; GroupDescription='matrix: operator role group'; IsRoleAssignable='TRUE'; Department="$($script:Marker)-IT"; SponsorUpn=$OwnerUpn; PolicyTemplate='' } 'roleGroup' 'PIM-Definitions-Roles'

    # --- permission groups (tier 3) --------------------------------------------
    Put 'PIM-Definitions-Services' @{ GroupName=$n.PermGroup; GroupTag=$n.PermGroupTag; GroupDescription='matrix: User Administrator'; IsRoleAssignable='TRUE'; Workload='Entra-ID'; Level='L1'; Plane='CP'; CPPlatform='ID'; Department="$($script:Marker)-IT"; Owners=$OwnerUpn; PolicyTemplate='' } 'permGroup' 'PIM-Definitions-Services'
    Put 'PIM-Definitions-Services' @{ GroupName=$n.AuGroup;   GroupTag=$n.AuGroupTag;   GroupDescription='matrix: Helpdesk Administrator (AU-scoped)'; IsRoleAssignable='TRUE'; Workload='Entra-ID'; Level='L2'; Plane='CP'; CPPlatform='ID'; AdministrativeUnitTag="$($script:Marker)-AU-L2"; Department="$($script:Marker)-IT"; Owners=$OwnerUpn; PolicyTemplate='' } 'auGroup' 'PIM-Definitions-Services'
    Put 'PIM-Definitions-Services' @{ GroupName=$n.PruneGroup; GroupTag=$n.PruneGroupTag; GroupDescription='matrix: removable permission group (prune case)'; IsRoleAssignable='TRUE'; Workload='Entra-ID'; Level='L3'; Plane='CP'; CPPlatform='ID'; Department="$($script:Marker)-IT"; Owners=$OwnerUpn; PolicyTemplate='' } 'pruneGroup' 'PIM-Definitions-Services'
    if ($SubscriptionId) {
        Put 'PIM-Definitions-Services' @{ GroupName=$n.AzGroup; GroupTag=$n.AzGroupTag; GroupDescription='matrix: Azure Reader at subscription'; IsRoleAssignable='FALSE'; Workload='Azure'; Level='L5'; Plane='MP'; CPPlatform='RES'; Department="$($script:Marker)-IT"; Owners=$OwnerUpn; PolicyTemplate='' } 'azGroup' 'PIM-Definitions-Services'
        Put 'PIM-Assignments-Azure-Resources' @{ GroupTag=$n.AzGroupTag; AzScope="/subscriptions/$SubscriptionId"; AzScopePermission='Reader'; AssignmentType='Eligible'; Action='Assign'; Permanent='FALSE'; NumOfDaysWhenExpire='365' } 'azAssign' 'PIM-Assignments-Azure-Resources'
    }

    # --- admin accounts ---------------------------------------------------------
    # 1. the preserved live admins (authoritative desired set, read live -- never hardcoded)
    foreach ($r in @(Get-PimMatrixLiveAdminPreserveRows -Domain $Domain)) {
        Set-PimMatrixRow -Entity 'Account-Definitions-Admins' -Row $r -KeyBase 'Account-Definitions-Admins' | Out-Null
    }
    # 2. the marked matrix admins
    Put 'Account-Definitions-Admins' @{ UserName="Admin-$($script:Marker)-OPS-ID"; DisplayName=$n.AdminDisplay; UserPrincipalName=$n.AdminUpn; UserType='Member'; AccountStatus='Enabled'; CreateTAP='FALSE'; Purpose='matrix: stable admin' } 'adminStable' 'Account-Definitions-Admins'
    Put 'Account-Definitions-Admins' @{ UserName="Admin-$($script:Marker)-TEMP-ID"; DisplayName=$n.AdminPruneDisp; UserPrincipalName=$n.AdminPruneUpn; UserType='Member'; AccountStatus='Enabled'; CreateTAP='FALSE'; Purpose='matrix: removable admin (disable case)' } 'adminPrune' 'Account-Definitions-Admins'
    Put 'Account-Definitions-Admins' @{ UserName="Admin-$($script:Marker)-BREAKGLASS-ID"; DisplayName=$n.AdminBgDisplay; UserPrincipalName=$n.AdminBgUpn; UserType='Member'; AccountStatus='Enabled'; CreateTAP='FALSE'; Purpose='matrix: break-glass exclusion case' } 'adminBg' 'Account-Definitions-Admins'
    # The two population fillers -- see Get-PimMatrixNames. They exist so that ONE disable in D4 is
    # 20% of the scanned set rather than 33%, i.e. so the circuit breaker can be exercised at a
    # legal operator setting instead of being impossible to satisfy.
    Put 'Account-Definitions-Admins' @{ UserName="Admin-$($script:Marker)-FILL1-ID"; DisplayName=$n.AdminFill1Disp; UserPrincipalName=$n.AdminFill1Upn; UserType='Member'; AccountStatus='Enabled'; CreateTAP='FALSE'; Purpose='matrix: population filler (breaker percentage)' } 'adminFill1' 'Account-Definitions-Admins'
    Put 'Account-Definitions-Admins' @{ UserName="Admin-$($script:Marker)-FILL2-ID"; DisplayName=$n.AdminFill2Disp; UserPrincipalName=$n.AdminFill2Upn; UserType='Member'; AccountStatus='Enabled'; CreateTAP='FALSE'; Purpose='matrix: population filler (breaker percentage)' } 'adminFill2' 'Account-Definitions-Admins'

    # --- admin -> role group delegation ----------------------------------------
    Put 'PIM-Assignments-Admins' @{ Username=$n.AdminUpn; GroupTag=$n.RoleGroupTag; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE' } 'adminMember' 'PIM-Assignments-Admins'

    # --- group nesting (role group -> permission group) ------------------------
    # 🔴 DIRECTION -- Target and Source were SEEDED THE WRONG WAY ROUND, and the first live run of
    # this matrix (2026-08-25, tenant xx391) is what exposed it. The engine's convention, stated at
    # PIM-EngineProviders.ps1 and verified there against a real tenant, is:
    #     SourceGroupTag = where the permission comes FROM  -> the SERVICE group, the CONTAINER
    #     TargetGroupTag = the group that RECEIVES it       -> the ROLE group, the MEMBER
    # This row had Target=PermGroup / Source=RoleGroup, which asks the engine to nest the SERVICE
    # group inside the ROLE group -- the inverse of the delegation model -- and the engine did
    # exactly that, correctly. The verify then asserted the OPPOSITE nesting and failed.
    # 🪤 The engine converged and a second run applied nothing, so every counter said "healthy":
    # an engine that consistently writes what you asked will always converge on the wrong thing.
    # Only the LIVE read-back caught it. That is the whole reason this harness reads the directory
    # instead of trusting the summary -- and here it caught a defect in the TEST, not the product.
    Put 'PIM-Assignments-Groups' @{ TargetGroupTag=$n.RoleGroupTag; SourceGroupTag=$n.PermGroupTag; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE' } 'groupNest' 'PIM-Assignments-Groups'

    # --- Entra role -> permission group ----------------------------------------
    Put 'PIM-Assignments-Roles-Groups' @{ GroupTag=$n.PermGroupTag;  RoleDefinitionName='User Administrator'; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE'; Plane='CP'; PermissionScope='Global' } 'roleUserAdmin' 'PIM-Assignments-Roles-Groups'
    Put 'PIM-Assignments-Roles-Groups' @{ GroupTag=$n.PruneGroupTag; RoleDefinitionName='Global Reader';      AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE'; Plane='CP'; PermissionScope='Global' } 'roleGlobalReader' 'PIM-Assignments-Roles-Groups'

    # --- AU-scoped Entra role --------------------------------------------------
    Put 'PIM-Assignments-Roles-AUs' @{ GroupTag=$n.AuGroupTag; AdministrativeUnitTag="$($script:Marker)-AU-L2"; RoleDefinitionName='Helpdesk Administrator'; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='90'; Permanent='FALSE' } 'roleAu' 'PIM-Assignments-Roles-AUs'

    return @{ names = $n; keys = $keys }
}

# ============================================================================
# region  cleanup
# ============================================================================
function Invoke-PimMatrixCleanup {
    <#
      Two passes, and neither one may abort the other.

      An account that is still an eligible member of a role-assignable group answers 403
      "Insufficient privileges" on DELETE -- deleting a role-assignable principal needs
      more than User.ReadWrite.All. Removing the GROUP clears that, but not instantly, so
      pass 1 deletes what it can, we let the directory catch up, and pass 2 sweeps the
      rest. A single failure must never leave the remaining objects behind, so per-object
      errors are collected and reported, never thrown.

      The marker guard inside Remove-PimMatrixObject is NOT softened by any of this: it
      still throws, and that throw is deliberately not caught below.
    #>
    param([int]$Passes = 2, [int]$SettleSec = 30)
    Write-MxLog STEP "=== CLEANUP: removing every '$($script:Marker)' object + desired row ==="
    $totalRemoved = 0
    $leftovers = @()
    # STEP 0 -- assignments BEFORE principals. A directory-role schedule outlives the
    # group it points at: delete the group first and the schedule is orphaned with a
    # principalId that no longer resolves to a marked name, so nothing can ever attribute
    # it again. It then shows up in the NEXT run's blast radius as unowned collateral
    # (which is how this was found). BUG-17 means the engine will not clean it up either.
    $markedGroupIds = @{}
    foreach ($g in (Get-MxGraph -Path "/groups?`$select=id,displayName&`$top=999")) {
        if ($g -and (Test-PimMatrixOwnedName -Name "$($g.displayName)")) { $markedGroupIds["$($g.id)"] = "$($g.displayName)" }
    }
    if ($markedGroupIds.Count) {
        $sched = 0
        foreach ($pair in @(
            @{ read = '/roleManagement/directory/roleEligibilitySchedules'; write = '/roleManagement/directory/roleEligibilityScheduleRequests' },
            @{ read = '/roleManagement/directory/roleAssignmentSchedules';  write = '/roleManagement/directory/roleAssignmentScheduleRequests' })) {
            foreach ($s in (Get-MxGraph -Path "$($pair.read)?`$select=roleDefinitionId,principalId,directoryScopeId")) {
                if (-not $s -or -not $markedGroupIds.ContainsKey("$($s.principalId)")) { continue }
                try {
                    Invoke-PimGraph -Method POST -Path $pair.write -Body @{
                        action='adminRemove'; justification='PIMTEST matrix cleanup'
                        roleDefinitionId="$($s.roleDefinitionId)"; principalId="$($s.principalId)"; directoryScopeId="$($s.directoryScopeId)"
                    } | Out-Null
                    $sched++
                } catch { Write-MxLog WARN "    could not remove a role schedule for '$($markedGroupIds["$($s.principalId)"])': $($_.Exception.Message -replace '\s+',' ' -replace '(.{120}).*','$1...')" }
            }
        }
        if ($sched) { Write-MxLog INFO "    removed $sched directory-role schedule(s) held by marked groups" }

        # ARM (AzRes) schedules too, when the run used a subscription. Same reason as the
        # directory-role step: an Azure RBAC eligibility outlives the group it points at, and
        # once the group is deleted its principalId resolves to nothing, so it can never be
        # attributed -- or removed -- again. This was missing while -AzSubscriptionId was
        # unused; the moment L9 started really creating ARM assignments it had to exist.
        if ($AzSubscriptionId) {
            $armScope = "/subscriptions/$AzSubscriptionId"
            $armN = 0
            foreach ($pair in @(
                @{ read = 'roleEligibilityScheduleInstances'; write = 'roleEligibilityScheduleRequests'; type = 'AdminRemove' },
                @{ read = 'roleAssignmentScheduleInstances';  write = 'roleAssignmentScheduleRequests';  type = 'AdminRemove' })) {
                try {
                    foreach ($s in @(Invoke-PimArm -Path "$armScope/providers/Microsoft.Authorization/$($pair.read)" -ApiVersion '2020-10-01-preview' -All)) {
                        if (-not $s -or -not $markedGroupIds.ContainsKey("$($s.properties.principalId)")) { continue }
                        $guid = [guid]::NewGuid().ToString()
                        Invoke-PimArm -Method PUT -Path "$armScope/providers/Microsoft.Authorization/$($pair.write)/$guid" -ApiVersion '2020-10-01-preview' -Body @{
                            properties = @{ principalId = "$($s.properties.principalId)"; roleDefinitionId = "$($s.properties.roleDefinitionId)"
                                            requestType = $pair.type; justification = 'PIMTEST matrix cleanup' }
                        } | Out-Null
                        $armN++
                    }
                } catch { Write-MxLog WARN "    ARM $($pair.read) cleanup: $($_.Exception.Message -replace '\s+',' ' -replace '(.{120}).*','$1...')" }
            }
            if ($armN) { Write-MxLog INFO "    removed $armN Azure RBAC schedule(s) held by marked groups" }
        }
    }

    for ($pass = 1; $pass -le $Passes; $pass++) {
        $removed = 0
        $leftovers = @()
        # order matters: group membership is what blocks a user delete, so groups first
        $targets = @()
        foreach ($g in (Get-MxGraph -Path "/groups?`$select=id,displayName&`$top=999")) {
            if ($g -and (Test-PimMatrixOwnedName -Name "$($g.displayName)")) { $targets += @{ kind='group'; id="$($g.id)"; name="$($g.displayName)" } }
        }
        foreach ($u in (Get-MxGraph -Path "/users?`$select=id,userPrincipalName&`$top=999")) {
            if ($u -and (Test-PimMatrixOwnedName -Name "$($u.userPrincipalName)")) { $targets += @{ kind='user'; id="$($u.id)"; name="$($u.userPrincipalName)" } }
        }
        foreach ($a in (Get-MxGraph -Path "/directory/administrativeUnits?`$select=id,displayName")) {
            if ($a -and (Test-PimMatrixOwnedName -Name "$($a.displayName)")) { $targets += @{ kind='administrativeUnit'; id="$($a.id)"; name="$($a.displayName)" } }
        }
        if (-not $targets.Count) { break }
        foreach ($t in $targets) {
            # The marker check runs INSIDE Remove-PimMatrixObject and throws; re-assert it
            # here so that throw can never be swallowed by the try below.
            if (-not (Test-PimMatrixOwnedName -Name $t.name)) { throw "cleanup target '$($t.name)' lost its marker -- refusing" }
            try { Remove-PimMatrixObject -Kind $t.kind -Id $t.id -Name $t.name; $removed++ }
            catch {
                $m = "$($_.Exception.Message)"
                if ($m -match 'HTTP 404|Request_ResourceNotFound') { continue }   # already gone
                $leftovers += "$($t.kind) '$($t.name)': $($m -replace '\s+', ' ' -replace '(.{140}).*', '$1...')"
            }
        }
        $totalRemoved += $removed
        Write-MxLog INFO "pass ${pass}: removed $removed object(s)$(if ($leftovers.Count) { ", $($leftovers.Count) could not be removed yet" })"
        if (-not $leftovers.Count) { break }
        if ($pass -lt $Passes) {
            Write-MxLog INFO "    waiting ${SettleSec}s for the directory to release them, then retrying"
            Start-Sleep -Seconds $SettleSec
        }
    }
    Write-MxLog INFO "removed $totalRemoved marked tenant object(s)"
    foreach ($l in $leftovers) { Write-MxLog WARN "NOT REMOVED -- $l" }
    if ($leftovers.Count) { Write-MxLog WARN "re-run -Cleanup to finish; nothing unmarked was touched." }
    try { Clear-PimMatrixStore } catch { Write-MxLog WARN "store clear skipped: $($_.Exception.Message)" }
}

# ============================================================================
# region  MAIN
# ============================================================================
Write-MxLog STEP "=== PIM4EntraPS LIVE FUNCTIONAL MATRIX (TEST-11) ==="
Write-MxLog INFO "log dir: $($script:LogRoot)"

# ---- preflight: this must be a TEST tenant -----------------------------------
$envClass = Resolve-PimEnvironmentClass -TenantId $TenantId
if ($envClass -ne 'test') {
    throw ("REFUSING to run: tenant $TenantId classifies as '$envClass', not 'test'. " +
           "The matrix creates, disables and deletes objects. Add the tenant id to `$env:PIM_TestTenantIds " +
           "(real values: internal/REAL-IDENTIFIERS.md) and re-run. This refusal is the point -- it is what " +
           "keeps the destructive half off a production tenant.")
}
Write-MxLog PASS "preflight: tenant $TenantId classifies as 'test'"

$org = Invoke-PimGraph -Path "/organization?`$select=displayName,verifiedDomains"
$orgObj = if ($org.value) { $org.value[0] } else { $org }
if (-not $UpnDomain) {
    $def = @($orgObj.verifiedDomains | Where-Object { $_.isDefault }) | Select-Object -First 1
    if (-not $def) { throw "could not resolve the tenant's default verified domain -- pass -UpnDomain." }
    $UpnDomain = "$($def.name)"
}
Write-MxLog INFO "tenant: $($orgObj.displayName) / domain $UpnDomain"

Initialize-PimMatrixStore

if ($Cleanup) {
    Invoke-PimMatrixCleanup
    Write-MxLog STEP "cleanup complete."
    return
}

# ---- preflight: the desired store must hold ONLY rows we own -----------------
# Prune treats desired as authoritative. A store carrying real rows could make the
# engine plan removals of real things, so a shared/populated store is refused.
$foreign = New-Object System.Collections.Generic.List[string]
foreach ($e in $script:MatrixEntities) {
    foreach ($r in @(Get-PimSqlRows -ConnectionString $script:Cs -Entity $e)) {
        $blob = ($r | ConvertTo-Json -Depth 6 -Compress)
        if (-not (Test-PimMatrixOwnedName -Name $blob)) { [void]$foreign.Add("$e") }
    }
}
if ($foreign.Count -gt 0) {
    # Preserved live-admin rows are seeded by this harness and are legitimately unmarked;
    # anything else means the store is shared with something real.
    $unexpected = @($foreign | Where-Object { $_ -ne 'Account-Definitions-Admins' })
    if ($unexpected.Count -gt 0) {
        throw ("REFUSING to run: the desired store $SqlServer/$SqlDatabase holds $($unexpected.Count) row(s) the matrix does not own " +
               "(entities: $(($unexpected | Select-Object -Unique) -join ', ')). Point -SqlDatabase at a scratch store " +
               "(default PimMatrixTest) -- the matrix prunes against this set and must never be authoritative over real rows.")
    }
}
Write-MxLog PASS "preflight: desired store holds no foreign rows"

# ---- owner for the marked groups (a group is never created ownerless) --------
# Use a REAL, resolvable account in the tenant: the marked stable admin once it
# exists, else any live admin account. Resolved live, never hardcoded.
$ownerUpn = $null
foreach ($u in @(Invoke-PimGraph -Path "/users?`$select=userPrincipalName&`$filter=startswith(userPrincipalName,'admin')" -All)) {
    if ($u -and -not (Test-PimMatrixOwnedName -Name "$($u.userPrincipalName)")) { $ownerUpn = "$($u.userPrincipalName)"; break }
}
if (-not $ownerUpn) { throw "no resolvable owner account found in the tenant (need one existing admin-* user to own the marked groups)." }
Write-MxLog INFO "group owner (live, unmarked): $ownerUpn"

$seed  = Set-PimMatrixDesiredSet -Domain $UpnDomain -OwnerUpn $ownerUpn -SubscriptionId $AzSubscriptionId
$names = $seed.names
$keys  = $seed.keys
Write-MxLog PASS "desired set seeded (marker '$($script:Marker)')"

$script:Baseline = Get-PimMatrixInventory
Write-MxLog DATA ("baseline: users={0} groups={1} aus={2} roleElig={3} pimSched={4}" -f `
    $script:Baseline.users.Count, $script:Baseline.groups.Count, $script:Baseline.aus.Count, `
    $script:Baseline.roleEligibility.Count, $script:Baseline.pimGroupSchedules.Count)

$runLifecycle  = ($Case -eq 'All' -or $Case -eq 'lifecycle')
$runDestructive= ($Case -eq 'All' -or $Case -eq 'destructive')

# ============================================================================
# region  LIFECYCLE MATRIX -- create / idempotency / no-op, per scope
# ============================================================================
function Invoke-MxLifecycleScope {
    <#
      One scope, both directions:
        1. APPLY   -- the operation happens, exactly as planned, with no collateral
        2. RE-APPLY-- a second run is a no-op (idempotency): create=0, update=0
      -Verify is a scriptblock returning $true when the live tenant really shows
      the result (never trust the engine's own counters alone).
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Scope,
        [int]$ExpectCreate = -1,
        [scriptblock]$Verify,
        [string]$VerifyName = 'live tenant shows the created object(s)',
        [hashtable]$Env = @{},
        [bool]$Required = $true
    )
    Write-MxLog STEP "--- $Id  scope=$Scope  (create -> verify -> idempotency)"
    $before = Get-PimMatrixInventory
    $run = Invoke-PimMatrixEngine -Scope $Scope -Mode Delta -Env $Env -Label "$Id-apply"
    $sr  = Get-MxScopeResult -Run $run -Scope $Scope

    if (-not $sr) {
        New-MxResult -Id "$Id.a" -Scope $Scope -Name 'engine produced a scope result' -Ok $false -Required $Required -Detail "no summary (exit $($run.exitCode)); see $($run.dir)" | Out-Null
        return
    }
    Assert-Mx -Id "$Id.a" -Scope $Scope -Name 'apply run has no errors' -Condition ([int]$sr.errors -eq 0) -Detail ("create=$($sr.create) update=$($sr.update) applied=$($sr.applied) skipped=$($sr.skipped) errors=$($sr.errors)") -Required $Required | Out-Null
    if ($ExpectCreate -ge 0) {
        Assert-Mx -Id "$Id.b" -Scope $Scope -Name "apply creates exactly $ExpectCreate item(s)" -Condition ([int]$sr.create -eq $ExpectCreate) -Detail "create=$($sr.create)" -Required $Required | Out-Null
    }
    # Wait for the directory to reflect what the engine just applied before asserting
    # (and before the idempotency run -- otherwise the engine's own live read lags and
    # re-creates what it already made).
    $after = Wait-PimMatrixInventory -Verify $Verify
    Assert-PimMatrixBlastRadius -Id "$Id.c" -Scope $Scope -Before $before -After $after | Out-Null

    if ($Verify) {
        $vOk = $false; $vDetail = ''
        try { $vOk = [bool](& $Verify $after) } catch { $vDetail = $_.Exception.Message }
        Assert-Mx -Id "$Id.d" -Scope $Scope -Name $VerifyName -Condition $vOk -Detail $vDetail -Required $Required | Out-Null
    }

    # ---- IDEMPOTENCY -------------------------------------------------------
    # Measured with -WhatIf PLANS, not with a second apply, and that choice matters.
    #
    # A second APPLY conflates two different things. Entra's directory is eventually
    # consistent and Graph reads are not replica-pinned: the harness saw its own
    # freshly-created AUs while the engine's list call, seconds later, still returned
    # zero -- so a second apply CREATED THEM AGAIN, leaving duplicates in the tenant
    # and a "non-idempotent" verdict that was really replication lag.
    #
    # A -WhatIf plan writes nothing, so it can be repeated until the engine's OWN view
    # has caught up. That separates the two cases cleanly:
    #   * replication lag  -> a later plan reaches create=0; we record how long it took
    #   * a real defect    -> create stays > 0 for every plan in the window and the case
    #                         FAILS (this is what BUG-11 does on RolesAUs/GroupMembers:
    #                         desired and live key differently, so no plan can converge)
    # Only once the plan is clean do we spend a real apply, asserting it changed nothing.
    # TWO CONSECUTIVE clean plans are required, not one. Graph reads are not replica-
    # pinned: a plan can come back clean and the very next call, seconds later, hit a
    # replica that has not caught up. That happened here -- a converged plan followed by
    # a real run that created a DUPLICATE AU four seconds later (recorded as BUG-18).
    # Two in a row makes a one-replica fluke unlikely without weakening the assertion,
    # since a genuine key mismatch never produces even one.
    $idemDeadline = (Get-Date).AddSeconds(180)
    $attempts = 0; $clean = 0; $planOk = $false; $lastDetail = 'no plan'
    while ($true) {
        $attempts++
        $plan = Invoke-PimMatrixEngine -Scope $Scope -Mode Delta -WhatIf -Env $Env -Label "$Id-plan$attempts"
        $ps   = Get-MxScopeResult -Run $plan -Scope $Scope
        if ($ps) {
            $lastDetail = "create=$($ps.create) update=$($ps.update) nochange=$($ps.nochange)"
            if (([int]$ps.create -eq 0) -and ([int]$ps.update -eq 0)) {
                $clean++
                if ($clean -ge 2) { $planOk = $true; break }
            } else { $clean = 0 }
        } else { $lastDetail = "no summary (exit $($plan.exitCode))"; $clean = 0 }
        if ((Get-Date) -ge $idemDeadline) { break }
        Start-Sleep -Seconds 10
    }
    Assert-Mx -Id "$Id.e" -Scope $Scope -Name 'converges: two consecutive re-plans find nothing to do' `
        -Condition $planOk -Detail "$lastDetail (plan attempts=$attempts, consecutive clean=$clean)" -Required $Required | Out-Null

    $run2 = Invoke-PimMatrixEngine -Scope $Scope -Mode Delta -Env $Env -Label "$Id-idem"
    $sr2  = Get-MxScopeResult -Run $run2 -Scope $Scope
    if ($sr2) {
        # A real second run must apply NOTHING. If it applies something after two clean
        # plans, the engine created a duplicate off a stale live read -- BUG-18, and a red
        # here is the right answer, not a flaky test.
        Assert-Mx -Id "$Id.f" -Scope $Scope -Name 'a real second run applies nothing' `
            -Condition (([int]$sr2.applied -eq 0) -and ([int]$sr2.errors -eq 0)) `
            -Detail ("create=$($sr2.create) update=$($sr2.update) applied=$($sr2.applied) nochange=$($sr2.nochange) errors=$($sr2.errors)" +
                     $(if ([int]$sr2.applied -gt 0) {
                         if ($planOk) { " -- BUG-18: applied after TWO CLEAN PLANS, i.e. a duplicate created off a stale live read" }
                         else         { " -- the plan never converged (see the previous case), so this re-applies what BUG-11 keeps re-planning" }
                       } else { '' })) -Required $Required | Out-Null
    } else {
        New-MxResult -Id "$Id.f" -Scope $Scope -Name 'a real second run applies nothing' -Ok $false -Required $Required -Detail 'no summary from the second run' | Out-Null
    }
    $after2 = Get-PimMatrixInventory
    Assert-PimMatrixBlastRadius -Id "$Id.g" -Scope $Scope -Before $after -After $after2 | Out-Null
}

if ($runLifecycle) {
    Write-MxLog STEP "=========== LIFECYCLE MATRIX ==========="

    Invoke-MxLifecycleScope -Id 'L1' -Scope 'AdministrativeUnits' -ExpectCreate 2 `
        -VerifyName 'both marked AUs exist live' `
        -Verify { param($inv) $inv.aus.ContainsKey($names.AuScoped) -and $inv.aus.ContainsKey($names.AuPrune) }

    Invoke-MxLifecycleScope -Id 'L2' -Scope 'Groups' -ExpectCreate $(if ($AzSubscriptionId) { 5 } else { 4 }) `
        -VerifyName 'all marked groups exist live' `
        -Verify {
            param($inv)
            $inv.groups.ContainsKey($names.RoleGroup) -and $inv.groups.ContainsKey($names.PermGroup) -and
            $inv.groups.ContainsKey($names.AuGroup)   -and $inv.groups.ContainsKey($names.PruneGroup)
        }

    # BUG-16. AU membership used to be asserted as part of L2, because the attach happened
    # inside Groups.ApplyCreate -- once, from a possibly-stale cache, failure swallowed. It
    # is now its own reconciling scope, so it gets its own case: the attach must hold, and
    # (via the shared lifecycle shape) a re-plan must find nothing to do. ExpectCreate is
    # unpinned: if Groups already attached it at create time there is nothing left to do,
    # and if it did not, this scope repairs it -- both are correct, and the VERIFY below is
    # what actually decides.
    Invoke-MxLifecycleScope -Id 'L2b' -Scope 'AdministrativeUnitMembers' `
        -VerifyName 'the AU-scoped group really IS a member of its AU' `
        -Verify { param($inv) $inv.auMembers.ContainsKey("$($names.AuScoped)|$($inv.groups[$names.AuGroup])") }

    Invoke-MxLifecycleScope -Id 'L3' -Scope 'GroupOwners' `
        -VerifyName 'every marked group has at least one owner' `
        -Verify {
            param($inv)
            $need = @($names.RoleGroup, $names.PermGroup, $names.AuGroup, $names.PruneGroup)
            $missing = @($need | Where-Object { $gn = $_; -not @($inv.groupOwners.Keys | Where-Object { $_ -like "$gn|*" }).Count })
            $missing.Count -eq 0
        }

    Invoke-MxLifecycleScope -Id 'L4' -Scope 'Admins' -ExpectCreate 5 `
        -VerifyName 'all five marked admin accounts exist and are ENABLED' `
        -Verify {
            param($inv)
            $all = $true
            foreach ($upn in @($names.AdminUpn, $names.AdminPruneUpn, $names.AdminBgUpn, $names.AdminFill1Upn, $names.AdminFill2Upn)) {
                $v = $inv.users[$upn.ToLowerInvariant()]
                if (-not $v -or -not "$v".StartsWith('True')) { $all = $false }
            }
            $all
        }

    Invoke-MxLifecycleScope -Id 'L5' -Scope 'AdminMembers' -ExpectCreate 1 `
        -VerifyName 'the marked admin is an ELIGIBLE member of the marked role group' `
        -Verify {
            param($inv)
            $inv.pimGroupSchedules.ContainsKey("$($names.RoleGroup)|$($names.AdminUpn.ToLowerInvariant())|member|eligible")
        }

    Invoke-MxLifecycleScope -Id 'L6' -Scope 'GroupMembers' -ExpectCreate 1 `
        -VerifyName 'the marked role group is an ELIGIBLE member of the marked permission group' `
        -Verify {
            param($inv)
            $inv.pimGroupSchedules.ContainsKey("$($names.PermGroup)|$($names.RoleGroup)|member|eligible")
        }

    Invoke-MxLifecycleScope -Id 'L7' -Scope 'EntraRoles' -ExpectCreate 2 `
        -VerifyName 'both Entra roles are ELIGIBLE to their marked groups at tenant scope' `
        -Verify {
            param($inv)
            $inv.roleEligibility.ContainsKey("User Administrator|$($names.PermGroup)|/") -and
            $inv.roleEligibility.ContainsKey("Global Reader|$($names.PruneGroup)|/")
        }

    Invoke-MxLifecycleScope -Id 'L8' -Scope 'RolesAUs' -ExpectCreate 1 `
        -VerifyName 'Helpdesk Administrator is ELIGIBLE to the marked group scoped to the marked AU' `
        -Verify {
            param($inv)
            $inv.roleEligibility.ContainsKey("Helpdesk Administrator|$($names.AuGroup)|/administrativeUnits/$($names.AuScoped)")
        }

    if ($AzSubscriptionId) {
        Invoke-MxLifecycleScope -Id 'L9' -Scope 'AzRes' -ExpectCreate 1 `
            -VerifyName 'Azure Reader is eligible to the marked group at the subscription scope' `
            -Verify { param($inv) $true }   # asserted by the engine result + blast radius; ARM state is read by the provider
    } else {
        New-MxResult -Id 'L9' -Scope 'AzRes' -Name 'Azure RBAC delegation lifecycle' -Skipped $true -Required $true -Detail 'no -AzSubscriptionId supplied' | Out-Null
    }
}

# ============================================================================
# region  DESTRUCTIVE MATRIX -- each case run TWICE (gated OFF / deliberately ON)
# ============================================================================
if ($runDestructive) {
    Write-MxLog STEP "=========== DESTRUCTIVE MATRIX ==========="

    # ---- D1  empty desired never prunes (G1, always on) ---------------------
    # A scope whose desired set is empty must refuse to remove its live items --
    # "0 desired" is 'the store was not seeded', never 'delete everything'.
    Write-MxLog STEP "--- D1  empty-desired guard (always on, both directions)"
    $auKeys = $keys['PIM-Definitions-AU']
    $savedAuRows = @(Get-PimSqlRows -ConnectionString $script:Cs -Entity 'PIM-Definitions-AU')
    foreach ($k in $auKeys.Values) { Remove-PimMatrixRow -Entity 'PIM-Definitions-AU' -Key $k }
    $beforeD1 = Get-PimMatrixInventory
    $d1 = Invoke-PimMatrixEngine -Scope 'AdministrativeUnits' -Mode Full -Prune -Label 'D1-empty-desired'
    $d1s = Get-MxScopeResult -Run $d1 -Scope 'AdministrativeUnits'
    Assert-Mx -Id 'D1.a' -Scope 'AdministrativeUnits' -Family 'destructive' `
        -Name 'empty desired set: engine REFUSES to prune' `
        -Condition ($d1.text -match 'prune SKIPPED -- desired set is empty') `
        -Detail $(if ($d1.text -match 'prune SKIPPED[^\r\n]*') { $Matches[0] } else { 'guard message not found' }) | Out-Null
    Assert-Mx -Id 'D1.b' -Scope 'AdministrativeUnits' -Family 'destructive' `
        -Name 'empty desired set: remove=0' -Condition ($d1s -and [int]$d1s.remove -eq 0) -Detail "remove=$(if ($d1s) { $d1s.remove } else { 'n/a' })" | Out-Null
    $afterD1 = Get-PimMatrixInventory
    Assert-PimMatrixBlastRadius -Id 'D1.c' -Scope 'AdministrativeUnits' -Family 'destructive' -Before $beforeD1 -After $afterD1 `
        -ExpectRemoved @{ aus = 0 } | Out-Null
    # restore
    foreach ($r in $savedAuRows) { Set-PimSqlRow -ConnectionString $script:Cs -Entity 'PIM-Definitions-AU' -Key (Get-PimStoreRowKey -Base 'PIM-Definitions-AU' -Row $r) -Data $r }

    # ---- D2  prune with a removed desired row -------------------------------
    # OFF: Delta never removes.  ON: Full -Prune removes exactly the one marked row.
    Write-MxLog STEP "--- D2  prune of ONE removed desired row (EntraRoles -- a scope that really removes)"
    $beforeD2 = Get-PimMatrixInventory
    $d2off = Invoke-PimMatrixEngine -Scope 'EntraRoles' -Mode Delta -Label 'D2-prune-off'
    $d2offS = Get-MxScopeResult -Run $d2off -Scope 'EntraRoles'
    Assert-Mx -Id 'D2.a' -Scope 'EntraRoles' -Family 'destructive' `
        -Name 'gated OFF (Delta): remove=0' -Condition ($d2offS -and [int]$d2offS.remove -eq 0) -Detail "remove=$(if ($d2offS) { $d2offS.remove } else { 'n/a' })" | Out-Null

    if ($IncludeDestructive) {
        # remove exactly ONE desired row -> exactly ONE live row must go
        Remove-PimMatrixRow -Entity 'PIM-Assignments-Roles-Groups' -Key $keys['PIM-Assignments-Roles-Groups']['roleGlobalReader']
        $mid = Get-PimMatrixInventory
        $d2on = Invoke-PimMatrixEngine -Scope 'EntraRoles' -Mode Full -Prune -Label 'D2-prune-on'
        $d2onS = Get-MxScopeResult -Run $d2on -Scope 'EntraRoles'
        Assert-Mx -Id 'D2.b' -Scope 'EntraRoles' -Family 'destructive' `
            -Name 'deliberately ON: removes exactly 1' -Condition ($d2onS -and [int]$d2onS.remove -eq 1) -Detail "remove=$(if ($d2onS) { $d2onS.remove } else { 'n/a' }) applied=$(if ($d2onS) { $d2onS.applied } else { 'n/a' })" | Out-Null
        $afterD2 = Wait-PimMatrixInventory -Verify { param($i) -not $i.roleEligibility.ContainsKey("Global Reader|$($names.PruneGroup)|/") }
        Assert-Mx -Id 'D2.c' -Scope 'EntraRoles' -Family 'destructive' `
            -Name 'the pruned eligibility is GONE from the live tenant' `
            -Condition (-not $afterD2.roleEligibility.ContainsKey("Global Reader|$($names.PruneGroup)|/")) -Detail "key: Global Reader|$($names.PruneGroup)|/" | Out-Null
        Assert-Mx -Id 'D2.d' -Scope 'EntraRoles' -Family 'destructive' `
            -Name 'the OTHER marked eligibility SURVIVED (removal was surgical)' `
            -Condition ($afterD2.roleEligibility.ContainsKey("User Administrator|$($names.PermGroup)|/")) | Out-Null
        Assert-PimMatrixBlastRadius -Id 'D2.e' -Scope 'EntraRoles' -Family 'destructive' -Before $mid -After $afterD2 | Out-Null
        # restore the desired row so later cases see a complete set
        Set-PimMatrixRow -Entity 'PIM-Assignments-Roles-Groups' -Row @{ GroupTag=$names.PruneGroupTag; RoleDefinitionName='Global Reader'; AssignmentType='Eligible'; Action='Assign'; AutoExtend='TRUE'; NumOfDaysWhenExpire='365'; Permanent='FALSE'; Plane='CP'; PermissionScope='Global' } -KeyBase 'PIM-Assignments-Roles-Groups' | Out-Null
    } else {
        New-MxResult -Id 'D2.b' -Scope 'EntraRoles' -Name 'deliberately ON: removes exactly the one marked row' -Skipped $true -Detail 'needs -IncludeDestructive' -Family 'destructive' | Out-Null
    }

    # ---- D3  BUG-11: prune on the tag-keyed scopes --------------------------
    # RolesAUs / GroupMembers / AzRes key live rows by resolved GUID and desired rows
    # by tag, so NO live key can ever match a desired key -> under -Prune every live
    # row is classed as a removal. This is the case that proves or disproves it.
    Write-MxLog STEP "--- D3  BUG-11 probe: -Prune on the tag-keyed scopes (plan only, nothing removed from desired)"
    foreach ($sc in @('RolesAUs','GroupMembers')) {
        $bd = Get-PimMatrixInventory
        $d3 = Invoke-PimMatrixEngine -Scope $sc -Mode Full -Prune -Label "D3-$sc"
        $d3s = Get-MxScopeResult -Run $d3 -Scope $sc
        $liveCount = 0
        if ($d3.text -match "\[engine\] $sc\s+Full \w+\s+desired=(\d+) live=(\d+)") { $liveCount = [int]$Matches[2] }
        $removed = if ($d3s) { [int]$d3s.remove } else { -1 }
        # The desired set is COMPLETE here -- every live row has a matching desired row --
        # so a correct engine removes NOTHING. Any removal is the BUG-11 key mismatch.
        Assert-Mx -Id "D3.$sc" -Scope $sc -Family 'destructive' `
            -Name 'prune with a COMPLETE desired set removes nothing (BUG-11)' `
            -Condition ($removed -eq 0) `
            -Detail "live=$liveCount remove=$removed$(if ($d3.text -match 'REMOVAL BUDGET') { ' (G4 remove-budget TRIPPED -- the removals were dropped, but they should never have been planned)' } else { '' })" | Out-Null
        Assert-Mx -Id "D3.$sc.g4" -Scope $sc -Family 'destructive' `
            -Name 'G4 removal budget caps this scope' -Required $false `
            -Condition ($removed -le 5) -Detail "remove=$removed budget=5" | Out-Null
        $ad = Get-PimMatrixInventory
        Assert-PimMatrixBlastRadius -Id "D3.$sc.blast" -Scope $sc -Family 'destructive' -Before $bd -After $ad | Out-Null
    }

    # ---- D4  account disable, both directions -------------------------------
    Write-MxLog STEP "--- D4  account disable (Admins remove path), gated OFF then deliberately ON"
    $savedAdminKey = $keys['Account-Definitions-Admins']['adminPrune']
    $savedAdminRow = Get-PimSqlRow -ConnectionString $script:Cs -Entity 'Account-Definitions-Admins' -Key $savedAdminKey
    Remove-PimMatrixRow -Entity 'Account-Definitions-Admins' -Key $savedAdminKey

    $beforeD4 = Get-PimMatrixInventory
    $d4off = Invoke-PimMatrixEngine -Scope 'Admins' -Mode Full -Prune -Label 'D4-disable-off' `
        -Globals @{ PIM_AccountDisableEnabled = $false }
    $d4offS = Get-MxScopeResult -Run $d4off -Scope 'Admins'
    # It must abort, and it must abort for the RIGHT reason. Asserting only "remove=0"
    # would have passed on the first run of this harness while the opt-out was in fact
    # being ignored and a different guard (the % breaker) happened to catch it. Which
    # guard fired is the assertion.
    Assert-Mx -Id 'D4.a' -Scope 'Admins' -Family 'destructive' `
        -Name 'gated OFF: the disable pass is refused, and specifically as feature-off' `
        -Condition ($d4offS -and [int]$d4offS.remove -eq 0 -and "$($d4offS.disableAborted)" -eq 'feature-off') `
        -Detail "remove=$(if ($d4offS) { $d4offS.remove } else { 'n/a' }) disableAborted=$(if ($d4offS) { $d4offS.disableAborted } else { 'n/a' })" | Out-Null
    $afterD4off = Get-PimMatrixInventory
    Assert-Mx -Id 'D4.b' -Scope 'Admins' -Family 'destructive' `
        -Name 'gated OFF: NO account was disabled' `
        -Condition (Test-PimMatrixUnchanged -Before $beforeD4 -After $afterD4off) `
        -Detail 'inventory unchanged' | Out-Null

    if ($IncludeDestructive) {
        # MaxPercent 20 is a REAL operator setting, not a neutered guard: it is inside the
        # hard ceiling of 25 (IMP-01). One disable out of the FIVE marked admins this harness
        # seeds is exactly 20% -- at the cap, not over it -- so the breaker is exercised rather
        # than bypassed. The absolute cap (5) and the G4 budget (5) are untouched.
        # 🪤 THE COUNT IS LOAD-BEARING, and this comment used to guess it. It claimed "~8 admin
        # accounts ... 12.5%"; the tenant actually scanned THREE, one disable was 33.3%, and the
        # breaker refused every time -- correctly. D4 was unpassable for a reason that had
        # nothing to do with the product. See Get-PimMatrixNames for why two fillers exist.
        $d4on = Invoke-PimMatrixEngine -Scope 'Admins' -Mode Full -Prune -Label 'D4-disable-on' `
            -Globals @{ PIM_AccountDisableEnabled = $true; PIM_DisableMaxPercent = 20 }
        $d4onS = Get-MxScopeResult -Run $d4on -Scope 'Admins'
        $afterD4on = Wait-PimMatrixInventory -Verify { param($i) "$($i.users[$names.AdminPruneUpn.ToLowerInvariant()])".StartsWith('False') }
        Assert-Mx -Id 'D4.c' -Scope 'Admins' -Family 'destructive' `
            -Name 'deliberately ON: exactly 1 account classed for removal' `
            -Condition ($d4onS -and [int]$d4onS.remove -eq 1) -Detail "remove=$(if ($d4onS) { $d4onS.remove } else { 'n/a' }) applied=$(if ($d4onS) { $d4onS.applied } else { 'n/a' })" | Out-Null
        $v = "$($afterD4on.users[$names.AdminPruneUpn.ToLowerInvariant()])"
        Assert-Mx -Id 'D4.d' -Scope 'Admins' -Family 'destructive' `
            -Name 'deliberately ON: the marked temp admin is DISABLED' `
            -Condition ($v -and $v.StartsWith('False')) -Detail "accountEnabled state = $v" | Out-Null
        Assert-Mx -Id 'D4.e' -Scope 'Admins' -Family 'destructive' `
            -Name 'deliberately ON: the marked STABLE admin is still enabled' `
            -Condition ("$($afterD4on.users[$names.AdminUpn.ToLowerInvariant()])".StartsWith('True')) | Out-Null
        # THE incident assertion: no unmarked account changed state.
        Assert-PimMatrixBlastRadius -Id 'D4.f' -Scope 'Admins' -Family 'destructive' -Before $afterD4off -After $afterD4on `
            -ExpectChanged @{ users = 1 } | Out-Null

        # re-enable + restore desired so the rest of the matrix is unaffected
        if ($savedAdminRow) { Set-PimSqlRow -ConnectionString $script:Cs -Entity 'Account-Definitions-Admins' -Key $savedAdminKey -Data $savedAdminRow }
        $reRun = Invoke-PimMatrixEngine -Scope 'Admins' -Mode Delta -Label 'D4-reenable'
        $reS = Get-MxScopeResult -Run $reRun -Scope 'Admins'
        Assert-Mx -Id 'D4.g' -Scope 'Admins' -Family 'destructive' `
            -Name 'restoring the desired row RE-ENABLES the account (update path)' `
            -Condition ($reS -and [int]$reS.update -ge 1) -Detail "update=$(if ($reS) { $reS.update } else { 'n/a' })" | Out-Null
        $afterRe = Wait-PimMatrixInventory -Verify { param($i) "$($i.users[$names.AdminPruneUpn.ToLowerInvariant()])".StartsWith('True') }
        Assert-Mx -Id 'D4.h' -Scope 'Admins' -Family 'destructive' `
            -Name 'the temp admin is enabled again' `
            -Condition ("$($afterRe.users[$names.AdminPruneUpn.ToLowerInvariant()])".StartsWith('True')) | Out-Null
    } else {
        if ($savedAdminRow) { Set-PimSqlRow -ConnectionString $script:Cs -Entity 'Account-Definitions-Admins' -Key $savedAdminKey -Data $savedAdminRow }
        New-MxResult -Id 'D4.c' -Scope 'Admins' -Name 'deliberately ON: only the marked account is disabled' -Skipped $true -Detail 'needs -IncludeDestructive' -Family 'destructive' | Out-Null
    }

    # ---- D5  break-glass is NEVER disabled ---------------------------------
    # Same shape as D4-ON, but the account is declared break-glass. It must be
    # excluded BEFORE the breaker -- with no override, in a test tenant, with the
    # feature explicitly ON.
    Write-MxLog STEP "--- D5  break-glass exclusion on the engine disable path (BUG-14)"
    $bgKey = $keys['Account-Definitions-Admins']['adminBg']
    $bgRow = Get-PimSqlRow -ConnectionString $script:Cs -Entity 'Account-Definitions-Admins' -Key $bgKey
    Remove-PimMatrixRow -Entity 'Account-Definitions-Admins' -Key $bgKey
    $beforeD5 = Get-PimMatrixInventory
    # Feature explicitly ON and the caps wide enough that the pass WOULD go through --
    # so if the exclusion were missing, the account really would be disabled. That is
    # what makes this a proof rather than a coincidence.
    $d5 = Invoke-PimMatrixEngine -Scope 'Admins' -Mode Full -Prune -Label 'D5-breakglass' `
        -Globals @{ PIM_AccountDisableEnabled = $true; PIM_DisableMaxPercent = 20 } `
        -Env @{ PIM_BREAKGLASS_ACCOUNTS = $names.AdminBgUpn }
    $d5s = Get-MxScopeResult -Run $d5 -Scope 'Admins'
    Assert-Mx -Id 'D5.a' -Scope 'Admins' -Family 'destructive' `
        -Name 'break-glass account is EXCLUDED from the disable set' `
        -Condition ($d5.text -match '(?i)BREAK-GLASS account\(s\) excluded') `
        -Detail $(if ($d5.text -match '(?i)[^\r\n]*BREAK-GLASS[^\r\n]*') { $Matches[0].Trim() } else { 'exclusion message not found' }) | Out-Null
    Assert-Mx -Id 'D5.b' -Scope 'Admins' -Family 'destructive' `
        -Name 'break-glass: remove=0 (nothing was even planned)' `
        -Condition ($d5s -and [int]$d5s.remove -eq 0) -Detail "remove=$(if ($d5s) { $d5s.remove } else { 'n/a' })" | Out-Null
    $afterD5 = Get-PimMatrixInventory
    Assert-Mx -Id 'D5.c' -Scope 'Admins' -Family 'destructive' `
        -Name 'break-glass account is still ENABLED' `
        -Condition ("$($afterD5.users[$names.AdminBgUpn.ToLowerInvariant()])".StartsWith('True')) | Out-Null
    Assert-PimMatrixBlastRadius -Id 'D5.d' -Scope 'Admins' -Family 'destructive' -Before $beforeD5 -After $afterD5 | Out-Null
    if ($bgRow) { Set-PimSqlRow -ConnectionString $script:Cs -Entity 'Account-Definitions-Admins' -Key $bgKey -Data $bgRow }

    # ---- D6  mass-disable breaker + G4 budget are NOT raisable --------------
    # Drop EVERY admin desired row: the whole live admin population becomes a
    # removal set. Both G2 (% of scanned) and G4 (budget 5) must trip, and the
    # published overrides must be CLAMPED, not honoured.
    Write-MxLog STEP "--- D6  mass-disable breaker + G4 budget (over the cap, with overrides attempted)"
    $allAdminRows = @(Get-PimSqlRows -ConnectionString $script:Cs -Entity 'Account-Definitions-Admins')
    $adminKeyList = @($allAdminRows | ForEach-Object { Get-PimStoreRowKey -Base 'Account-Definitions-Admins' -Row $_ })
    # keep ONE row so the desired set is not empty (that would trip G1 instead and
    # prove nothing about G2/G4 -- we want the mass-disable path specifically)
    $keepKey = $adminKeyList | Select-Object -First 1
    foreach ($k in $adminKeyList) { if ($k -ne $keepKey) { Remove-PimMatrixRow -Entity 'Account-Definitions-Admins' -Key $k } }
    $beforeD6 = Get-PimMatrixInventory
    $d6 = Invoke-PimMatrixEngine -Scope 'Admins' -Mode Full -Prune -Label 'D6-mass-disable' `
        -Globals @{ PIM_AccountDisableEnabled = $true; PIM_DisableMaxCount = 100000; PIM_DisableMaxPercent = 100 }
    $d6s = Get-MxScopeResult -Run $d6 -Scope 'Admins'
    Assert-Mx -Id 'D6.a' -Scope 'Admins' -Family 'destructive' `
        -Name 'over-cap disable pass is ABORTED (breaker or budget)' `
        -Condition ($d6s -and [int]$d6s.remove -eq 0 -and "$($d6s.disableAborted)".Trim() -ne '') `
        -Detail "remove=$(if ($d6s) { $d6s.remove } else { 'n/a' }) tripped=$(if ($d6s) { $d6s.disableAborted } else { 'n/a' })" | Out-Null
    Assert-Mx -Id 'D6.b' -Scope 'Admins' -Family 'destructive' `
        -Name 'the raised overrides are CLAMPED, not honoured (IMP-01)' `
        -Condition ($d6.text -match '(?i)CLAMPED') `
        -Detail $(if ($d6.text -match '(?i)[^\r\n]*CLAMPED[^\r\n]*') { $Matches[0].Trim() } else { 'no clamp warning seen' }) | Out-Null
    $afterD6 = Get-PimMatrixInventory
    Assert-Mx -Id 'D6.c' -Scope 'Admins' -Family 'destructive' `
        -Name 'over-cap run disabled NOTHING (never a partial mass-disable)' `
        -Condition (Test-PimMatrixUnchanged -Before $beforeD6 -After $afterD6) | Out-Null
    # restore every admin desired row
    foreach ($r in $allAdminRows) { Set-PimSqlRow -ConnectionString $script:Cs -Entity 'Account-Definitions-Admins' -Key (Get-PimStoreRowKey -Base 'Account-Definitions-Admins' -Row $r) -Data $r }

    # ---- D7  offboarding / delete path --------------------------------------
    Write-MxLog STEP "--- D7  AdminOffboarding delete path (gated OFF; ON only with -IncludeDestructive)"
    $beforeD7 = Get-PimMatrixInventory
    $d7off = Invoke-PimMatrixEngine -Scope 'AdminOffboarding' -Mode Full -Prune -Label 'D7-offboard-off' `
        -Env @{ PIM_OffboardingEnabled = 'false' }
    $d7offS = Get-MxScopeResult -Run $d7off -Scope 'AdminOffboarding'
    Assert-Mx -Id 'D7.a' -Scope 'AdminOffboarding' -Family 'destructive' `
        -Name 'gated OFF: no offboarding removal is applied' `
        -Condition ($d7offS -and [int]$d7offS.applied -eq 0) `
        -Detail "remove=$(if ($d7offS) { $d7offS.remove } else { 'n/a' }) applied=$(if ($d7offS) { $d7offS.applied } else { 'n/a' }) feature=$(if ($d7offS) { $d7offS.skippedFeature } else { '' })" | Out-Null
    $afterD7 = Get-PimMatrixInventory
    Assert-Mx -Id 'D7.b' -Scope 'AdminOffboarding' -Family 'destructive' `
        -Name 'gated OFF: no user was deleted' `
        -Condition ($afterD7.users.Count -eq $beforeD7.users.Count) -Detail "users before=$($beforeD7.users.Count) after=$($afterD7.users.Count)" | Out-Null

    # ---- D8  the safety switches must be settable the way the product is deployed ----
    # SEC-07. The hosted engine is configured ENTIRELY by container environment variables
    # (Setup-PimContainers.ps1 sets PIM_HOSTED / PIM_StorageBackend / PIM_SqlServer /
    # PIM_SqlDatabase / PIM_TenantId that way). PIM_TestTenantIds and
    # PIM_BREAKGLASS_ACCOUNTS honour the environment. The account-disable OPT-OUT and the
    # blast-radius CAPS do not -- they read $global: only -- so an operator who sets them
    # on the container app changes nothing and is never told.
    #
    # This case runs the SAME scenario as D4-off but through the ENVIRONMENT channel. It
    # is REQUIRED and it will stay RED until the flags read the environment like their
    # siblings. A red here is the product being wrong, not the test.
    Write-MxLog STEP "--- D8  SEC-07: an explicit opt-OUT set the way the product is deployed (env var)"
    $d8Key = $keys['Account-Definitions-Admins']['adminPrune']
    $d8Row = Get-PimSqlRow -ConnectionString $script:Cs -Entity 'Account-Definitions-Admins' -Key $d8Key
    Remove-PimMatrixRow -Entity 'Account-Definitions-Admins' -Key $d8Key
    $d8 = Invoke-PimMatrixEngine -Scope 'Admins' -Mode Full -Prune -Label 'D8-envflag' `
        -Env @{ PIM_AccountDisableEnabled = 'false'; PIM_DisableMaxPercent = '20' }
    $d8s = Get-MxScopeResult -Run $d8 -Scope 'Admins'
    Assert-Mx -Id 'D8.a' -Scope 'Admins' -Family 'destructive' `
        -Name 'SEC-07: PIM_AccountDisableEnabled=false as an ENV VAR is honoured' `
        -Condition ($d8s -and "$($d8s.disableAborted)" -eq 'feature-off') `
        -Detail ("tripped=$(if ($d8s) { $d8s.disableAborted } else { 'n/a' }) -- expected 'feature-off'. " +
                 "Anything else means the explicit opt-out was IGNORED and some other guard happened to catch it.") | Out-Null
    $afterD8 = Get-PimMatrixInventory
    Assert-Mx -Id 'D8.b' -Scope 'Admins' -Family 'destructive' `
        -Name 'SEC-07: nothing was disabled regardless (a second guard still held)' `
        -Condition (Test-PimMatrixUnchanged -Before $afterD7 -After $afterD8) | Out-Null
    if ($d8Row) { Set-PimSqlRow -ConnectionString $script:Cs -Entity 'Account-Definitions-Admins' -Key $d8Key -Data $d8Row }
}

# ============================================================================
# region  final blast radius vs the run baseline + summary
# ============================================================================
$final = Get-PimMatrixInventory
Assert-PimMatrixBlastRadius -Id 'Z1' -Scope 'ALL' -Family 'summary' -Before $script:Baseline -After $final | Out-Null

$pass    = @($script:Results | Where-Object { $_.ok -and -not $_.skipped }).Count
$fail    = @($script:Results | Where-Object { -not $_.ok -and -not $_.skipped }).Count
$skipped = @($script:Results | Where-Object { $_.skipped }).Count
$reqFail = @($script:Results | Where-Object { -not $_.ok -and -not $_.skipped -and $_.required }).Count
$reqSkip = @($script:Results | Where-Object { $_.skipped -and $_.required }).Count

Write-MxLog STEP "=========== MATRIX SUMMARY ==========="
$script:Results | ForEach-Object {
    $state = if ($_.skipped) { 'SKIP' } elseif ($_.ok) { 'PASS' } else { 'FAIL' }
    "{0,-4}  {1,-10} {2,-22} {3}" -f $state, $_.id, $_.scope, $_.name
} | ForEach-Object { Write-MxLog DATA $_ }
Write-MxLog STEP ("TOTAL  pass={0} fail={1} skipped={2}  (required failures={3}, required skips={4})" -f $pass, $fail, $skipped, $reqFail, $reqSkip)
Write-MxLog INFO "logs: $($script:LogRoot)"
if (-not $IncludeDestructive) { Write-MxLog WARN "the destructive-ON half did NOT run (-IncludeDestructive). A skip is not a pass." }
Write-MxLog INFO "marked objects were LEFT in the tenant for inspection -- run with -Cleanup to remove them."

# emit the structured result for a caller
$script:Results

if ($reqFail -gt 0) { exit 1 }
if ($FailOnSkip -and $reqSkip -gt 0) { exit 2 }
exit 0
