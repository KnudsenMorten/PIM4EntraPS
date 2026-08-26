#Requires -Version 5.1
<#
.SYNOPSIS
  TEST-12 -- the ONE command that deletes everything the scenario matrix creates, across
  every tenant, and that provably cannot touch anything else.

.DESCRIPTION
  Operator directive, stated for both live test suites: **"it must be easy to delete the
  tests (naming)."** REQUIREMENTS §33.7.e-2 makes that a locked contract. This is it.

  ONE MARKER. Every object the scenario matrix creates carries `PIMSCEN` in its name, so a
  single predicate finds all of it in any tenant. Ownership is "the name CONTAINS the
  marker" -- one rule for users, groups, AUs, schedules, blobs, files and SQL rows alike.

  IT CANNOT REACH A REAL OBJECT. Remove-ScenarioObject THROWS on any name without the
  marker. A run pointed at the wrong tenant deletes nothing. That guard is deliberately
  NOT wrapped in the error handling that makes the rest of the sweep resilient.

  ORDER MATTERS, and it is the lesson TEST-11 paid for:
    1. ARM (Azure RBAC) + directory-role + PIM-for-Groups SCHEDULES come off FIRST, while
       their principal still exists. A schedule outlives the group it points at; once the
       group is gone its principalId resolves to nothing, so the schedule is
       unattributable -- and if its scope was an AU that is also gone, Entra 404s the
       removal request and it is stuck forever. Two such orphans are still in a test
       tenant from TEST-11's early runs. Do not reorder this.
    2. Then groups (membership is what blocks a user delete).
    3. Then users, then AUs.
  TWO PASSES with a wait: a user that is still an eligible member of a role-assignable
  group answers 403 until that membership clears. Per-object failures are collected and
  reported, never thrown, so one stubborn object cannot strand the rest.

  It also clears the non-directory estate the scenario matrix creates and TEST-11 never
  had: staged sync files on disk, the signed baseline blobs, and the marked rows in both
  the master registry store and each slave's local store.

.PARAMETER Tenant
  One or more tenants to sweep, each @{ name; tenantId; clientId; certThumbprint;
  subscriptionId (optional) }. Supply via -TenantJson or the -Master/-Slave shorthands.

.PARAMETER TenantJson
  Path to a JSON array of the above. Keeps real tenant ids out of the command line.

.PARAMETER SyncRoot
  One or more staging roots to sweep for per-tenant sync folders (PIM_SyncRootCentral /
  PIM_SyncRootLocal). Only marked folders/files are removed.

.PARAMETER SqlServer / SqlDatabase
  The SCRATCH desired/registry store the matrix seeded. Marked rows are deleted from the
  scenario entities. Defaults to .\SQLEXPRESS / PimScenarioTest -- deliberately NOT
  PimPlatform, which is the real platform store.

.PARAMETER WhatIfOnly
  Report what WOULD be removed and remove nothing. Use this first, always.

.EXAMPLE
  # see what is there (safe)
  .\Clear-PimScenarioEstate.ps1 -TenantJson .\scenario-tenants.json -WhatIfOnly
.EXAMPLE
  # sweep every tenant + the staging roots + the scratch store
  .\Clear-PimScenarioEstate.ps1 -TenantJson .\scenario-tenants.json `
      -SyncRoot $env:PIM_SyncRootCentral, $env:PIM_SyncRootLocal
#>
[CmdletBinding()]
param(
    [object[]]$Tenant,
    [string]$TenantJson,
    [string[]]$SyncRoot,
    [string]$SqlServer   = $(if ($env:PIM_ScenarioSqlServer)   { $env:PIM_ScenarioSqlServer }   else { '.\SQLEXPRESS' }),
    [string]$SqlDatabase = $(if ($env:PIM_ScenarioSqlDatabase) { $env:PIM_ScenarioSqlDatabase } else { 'PimScenarioTest' }),
    [string]$Marker      = 'PIMSCEN',
    [int]$Passes         = 2,
    [int]$SettleSec      = 30,
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = (Get-Location).Path }
$shared = (Resolve-Path (Join-Path $here '..\..\engine\_shared')).Path

$global:PIM_UseGraphSdk = $false
. (Join-Path $shared 'PIM-Rest.ps1')
# The marker contract lives in ONE dot-sourceable, side-effect-free file so it can be
# unit-tested offline (tests/Test-PimScenarioCleanup.ps1) instead of only in a live sweep.
. (Join-Path $here '_PimScenarioMarker.ps1')
# BUG-26: the -TenantJson parse contract, likewise isolated so it is offline-testable under
# BOTH 5.1 and 7 -- the shell difference IS the defect.
. (Join-Path $here '_PimScenarioTenants.ps1')
Set-PimScenarioMarker -Marker $Marker

$script:Marker     = Get-PimScenarioMarker
$script:Removed    = 0
$script:Would      = 0
$script:Leftovers  = New-Object System.Collections.Generic.List[string]
# BUG-26: a tenant this sweep could not authenticate to has been INSPECTED BY NOBODY. It may
# never contribute to a "0 to remove" result, so it is tracked separately from $Leftovers
# (which means "seen, and could not be deleted") and it changes the exit code.
$script:Unverified = New-Object System.Collections.Generic.List[string]

function Write-ScLog {
    param([ValidateSet('INFO','STEP','OK','WARN','SKIP')][string]$Level, [string]$Message)
    $c = switch ($Level) { 'OK' {'Green'} 'WARN' {'Yellow'} 'STEP' {'Cyan'} 'SKIP' {'DarkYellow'} default {'Gray'} }
    Write-Host ("{0,-5} {1}" -f $Level, $Message) -ForegroundColor $c
}

function Test-ScenarioOwnedName {
    # Thin alias onto the shared contract (_PimScenarioMarker.ps1) so this script and the
    # offline test can never drift apart on what "owned" means.
    param([string]$Name)
    return (Test-PimScenarioOwnedName -Name $Name)
}

function Remove-ScenarioObject {
    <#
      The ONLY delete path. Throws on an unmarked name -- so a sweep pointed at the wrong
      tenant removes nothing even if the id is real. This throw must NOT be caught by the
      resilience wrapper in Invoke-ScenarioTenantSweep; that wrapper re-asserts the marker
      before calling, precisely so a guard failure surfaces instead of being swallowed.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('user','group','administrativeUnit')][string]$Kind,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Name
    )
    [void](Assert-PimScenarioOwnedName -Name $Name -What "$Kind $Id")
    if ($WhatIfOnly) { Write-ScLog INFO "    WOULD remove $Kind '$Name'"; $script:Would++; return }
    $path = switch ($Kind) {
        'user'               { "/users/$Id" }
        'group'              { "/groups/$Id" }
        'administrativeUnit' { "/directory/administrativeUnits/$Id" }
    }
    Invoke-PimGraph -Method DELETE -Path $path | Out-Null
    Write-ScLog OK "    removed $Kind '$Name'"
    $script:Removed++
}

function Get-ScGraph {
    # 404-tolerant read: Entra is eventually consistent, and an object listed by one call
    # can 404 on the next while replication catches up. That is the directory, not a fault.
    param([Parameter(Mandatory)][string]$Path, [hashtable]$Headers)
    try {
        if ($Headers) { return @(Invoke-PimGraph -Path $Path -Headers $Headers -All) }
        return @(Invoke-PimGraph -Path $Path -All)
    } catch {
        if ("$($_.Exception.Message)" -match 'HTTP 404|Request_ResourceNotFound') { return @() }
        throw
    }
}

function Invoke-ScenarioTenantSweep {
    param([Parameter(Mandatory)][hashtable]$T)

    Write-ScLog STEP "=== tenant $($T.name)  [$($T.tenantId)] ==="
    $global:PIM_TenantId       = "$($T.tenantId)"
    $global:PIM_ClientId       = "$($T.clientId)"
    $global:PIM_CertThumbprint = "$($T.certThumbprint)"
    $script:PimTokenCache      = @{}          # per-tenant token, never a cached other-tenant one

    # BUG-26: this used to WARN and `return`, which let the run continue to a SUMMARY that
    # said "0 object(s)/row(s) would be removed" for an estate no call had ever looked at --
    # the D4.a failure shape (an assertion that passes while checking nothing). An
    # unauthenticated tenant is now UNVERIFIED: recorded, reported by name in the summary,
    # and fatal to the exit code.
    try { [void](Get-PimRestToken -Resource graph -TenantId $T.tenantId -ClientId $T.clientId -CertThumbprint $T.certThumbprint -Force) }
    catch {
        $m = "$($_.Exception.Message)" -replace '\s+',' '
        Write-ScLog WARN "  cannot authenticate to $($T.name) [$($T.tenantId)] -- this tenant was NOT swept: $m"
        [void]$script:Unverified.Add("$($T.name) [$($T.tenantId)]: $m")
        return
    }

    # --- which groups here are ours? needed BEFORE anything is deleted ---------------
    $markedGroups = @{}
    foreach ($g in (Get-ScGraph -Path "/groups?`$select=id,displayName&`$top=999")) {
        if ($g -and (Test-ScenarioOwnedName -Name "$($g.displayName)")) { $markedGroups["$($g.id)"] = "$($g.displayName)" }
    }
    $markedUsers = @{}
    foreach ($u in (Get-ScGraph -Path "/users?`$select=id,userPrincipalName&`$top=999")) {
        if ($u -and (Test-ScenarioOwnedName -Name "$($u.userPrincipalName)")) { $markedUsers["$($u.id)"] = "$($u.userPrincipalName)" }
    }
    $principals = @{}
    foreach ($k in @($markedGroups.Keys)) { $principals[$k] = $markedGroups[$k] }
    foreach ($k in @($markedUsers.Keys))  { $principals[$k] = $markedUsers[$k] }
    Write-ScLog INFO ("  marked: {0} group(s), {1} user(s)" -f $markedGroups.Count, $markedUsers.Count)

    # --- 1. SCHEDULES FIRST, while their principal still resolves --------------------
    if ($principals.Count) {
        $n = 0
        foreach ($p in @(
            @{ read='/roleManagement/directory/roleEligibilitySchedules'; write='/roleManagement/directory/roleEligibilityScheduleRequests' },
            @{ read='/roleManagement/directory/roleAssignmentSchedules';  write='/roleManagement/directory/roleAssignmentScheduleRequests' })) {
            foreach ($s in (Get-ScGraph -Path "$($p.read)?`$select=roleDefinitionId,principalId,directoryScopeId")) {
                if (-not $s -or -not $principals.ContainsKey("$($s.principalId)")) { continue }
                if ($WhatIfOnly) { Write-ScLog INFO "    WOULD remove directory-role schedule for '$($principals["$($s.principalId)"])'"; $script:Would++; continue }
                try {
                    Invoke-PimGraph -Method POST -Path $p.write -Body @{
                        action='adminRemove'; justification='PIMSCEN scenario cleanup'
                        roleDefinitionId="$($s.roleDefinitionId)"; principalId="$($s.principalId)"; directoryScopeId="$($s.directoryScopeId)"
                    } | Out-Null
                    $n++
                } catch { Write-ScLog WARN "    directory-role schedule for '$($principals["$($s.principalId)"])': $($_.Exception.Message -replace '\s+',' ' -replace '(.{110}).*','$1...')" }
            }
        }
        if ($n) { Write-ScLog OK "    removed $n directory-role schedule(s)" }

        # PIM-for-Groups schedules on marked groups (membership held BY anyone).
        $m = 0
        foreach ($gid in @($markedGroups.Keys)) {
            foreach ($p in @(
                @{ read='eligibilitySchedules'; write='eligibilityScheduleRequests' },
                @{ read='assignmentSchedules';  write='assignmentScheduleRequests' })) {
                try {
                    foreach ($s in (Get-ScGraph -Path "/identityGovernance/privilegedAccess/group/$($p.read)?`$filter=groupId eq '$gid'&`$select=principalId,accessId")) {
                        if (-not $s) { continue }
                        if ($WhatIfOnly) { $script:Would++; continue }
                        try {
                            Invoke-PimGraph -Method POST -Path "/identityGovernance/privilegedAccess/group/$($p.write)" -Body @{
                                action='adminRemove'; justification='PIMSCEN scenario cleanup'
                                groupId=$gid; principalId="$($s.principalId)"; accessId="$($s.accessId)"
                            } | Out-Null
                            $m++
                        } catch { }
                    }
                } catch { }
            }
        }
        if ($m) { Write-ScLog OK "    removed $m PIM-for-Groups schedule(s)" }

        # ARM / Azure-RBAC schedules at the tenant's test subscription.
        if ("$($T.subscriptionId)".Trim()) {
            $armScope = "/subscriptions/$($T.subscriptionId)"
            $a = 0
            foreach ($p in @(
                @{ read='roleEligibilityScheduleInstances'; write='roleEligibilityScheduleRequests' },
                @{ read='roleAssignmentScheduleInstances';  write='roleAssignmentScheduleRequests' })) {
                try {
                    foreach ($s in @(Invoke-PimArm -Path "$armScope/providers/Microsoft.Authorization/$($p.read)" -ApiVersion '2020-10-01-preview' -All)) {
                        if (-not $s -or -not $principals.ContainsKey("$($s.properties.principalId)")) { continue }
                        if ($WhatIfOnly) { Write-ScLog INFO "    WOULD remove ARM schedule for '$($principals["$($s.properties.principalId)"])'"; $script:Would++; continue }
                        try {
                            Invoke-PimArm -Method PUT -Path "$armScope/providers/Microsoft.Authorization/$($p.write)/$([guid]::NewGuid())" -ApiVersion '2020-10-01-preview' -Body @{
                                properties = @{ principalId = "$($s.properties.principalId)"; roleDefinitionId = "$($s.properties.roleDefinitionId)"
                                                requestType = 'AdminRemove'; justification = 'PIMSCEN scenario cleanup' } } | Out-Null
                            $a++
                        } catch { Write-ScLog WARN "    ARM schedule: $($_.Exception.Message -replace '\s+',' ' -replace '(.{110}).*','$1...')" }
                    }
                } catch { Write-ScLog WARN "    ARM $($p.read): $($_.Exception.Message -replace '\s+',' ' -replace '(.{110}).*','$1...')" }
            }
            if ($a) { Write-ScLog OK "    removed $a Azure RBAC schedule(s)" }
        }
    }

    # --- 2/3/4. groups, then users, then AUs -- two passes ---------------------------
    for ($pass = 1; $pass -le $Passes; $pass++) {
        $targets = @()
        foreach ($g in (Get-ScGraph -Path "/groups?`$select=id,displayName&`$top=999")) {
            if ($g -and (Test-ScenarioOwnedName -Name "$($g.displayName)")) { $targets += @{ kind='group'; id="$($g.id)"; name="$($g.displayName)" } }
        }
        foreach ($u in (Get-ScGraph -Path "/users?`$select=id,userPrincipalName&`$top=999")) {
            if ($u -and (Test-ScenarioOwnedName -Name "$($u.userPrincipalName)")) { $targets += @{ kind='user'; id="$($u.id)"; name="$($u.userPrincipalName)" } }
        }
        foreach ($a in (Get-ScGraph -Path "/directory/administrativeUnits?`$select=id,displayName")) {
            if ($a -and (Test-ScenarioOwnedName -Name "$($a.displayName)")) { $targets += @{ kind='administrativeUnit'; id="$($a.id)"; name="$($a.displayName)" } }
        }
        if (-not $targets.Count) { break }

        $failed = @()
        foreach ($t in $targets) {
            # Re-assert the marker HERE so Remove-ScenarioObject's throw can never be
            # swallowed by the catch below (which exists for transient 403/404 only).
            if (-not (Test-ScenarioOwnedName -Name $t.name)) { throw "sweep target '$($t.name)' lost its marker -- refusing" }
            try { Remove-ScenarioObject -Kind $t.kind -Id $t.id -Name $t.name }
            catch {
                $m = "$($_.Exception.Message)"
                if ($m -match 'HTTP 404|Request_ResourceNotFound') { continue }
                $failed += "$($T.name)/$($t.kind) '$($t.name)': $($m -replace '\s+',' ' -replace '(.{130}).*','$1...')"
            }
        }
        if ($WhatIfOnly) { break }
        if (-not $failed.Count) { break }
        if ($pass -lt $Passes) {
            Write-ScLog INFO "  pass ${pass}: $($failed.Count) not removable yet (role-assignable membership still clearing) -- waiting ${SettleSec}s"
            Start-Sleep -Seconds $SettleSec
        } else {
            foreach ($f in $failed) { [void]$script:Leftovers.Add($f) }
        }
    }
}

# ---------------------------------------------------------------------------
# Resolve the tenant list
# ---------------------------------------------------------------------------
$tenants = @()
if ($TenantJson) {
    # BUG-26: the parse lives in _PimScenarioTenants.ps1 and is shell-agnostic + validated.
    # It must NOT be inlined back as `@(Get-Content ... | ConvertFrom-Json)`: under 5.1 that
    # collapses every tenant into one, and this script's failure mode for a tenant it cannot
    # reach used to be silent.
    foreach ($t in @(Import-PimScenarioTenantJson -Path $TenantJson)) {
        $tenants += $t
    }
}
foreach ($t in @($Tenant)) {
    if (-not $t) { continue }
    $tenants += @{ name="$($t.name)"; tenantId="$($t.tenantId)"; clientId="$($t.clientId)"; certThumbprint="$($t.certThumbprint)"; subscriptionId="$($t.subscriptionId)" }
}
if (-not $tenants.Count) { throw "No tenants supplied. Use -TenantJson <file> or -Tenant @{name=..;tenantId=..;clientId=..;certThumbprint=..}." }

Write-ScLog STEP "=== PIMSCEN scenario-estate cleanup ($($tenants.Count) tenant(s))$(if ($WhatIfOnly) { ' -- WHAT-IF, nothing will be removed' }) ==="

foreach ($t in $tenants) { Invoke-ScenarioTenantSweep -T $t }

# ---------------------------------------------------------------------------
# Non-directory estate: staged sync files
# ---------------------------------------------------------------------------
foreach ($root in @($SyncRoot | Where-Object { "$_".Trim() })) {
    if (-not (Test-Path -LiteralPath $root)) { Write-ScLog SKIP "sync root not present: $root"; continue }
    Write-ScLog STEP "=== sync files under $root ==="
    foreach ($item in @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction SilentlyContinue)) {
        if (-not (Test-ScenarioOwnedName -Name $item.Name)) { continue }
        if ($WhatIfOnly) { Write-ScLog INFO "    WOULD remove $($item.FullName)"; $script:Would++; continue }
        try { Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop; Write-ScLog OK "    removed $($item.FullName)"; $script:Removed++ }
        catch { [void]$script:Leftovers.Add("file '$($item.FullName)': $($_.Exception.Message)") }
    }
}

# ---------------------------------------------------------------------------
# Non-directory estate: the SCRATCH store's marked rows
# ---------------------------------------------------------------------------
# This list MUST stay in step with the seeder's $desiredEntities. PIM-Offboarding and
# PIM-Discovery were missing here: they were harmless while TEST-13 meant the seeder
# planted zero of them, and became a real leak the moment that was fixed -- the sweep
# reported "clean" while two marked rows sat in the store. Found by
# Test-PimScenarioCleanupComplete.ps1 on its first run, which is exactly the pair of
# claims (complete AND contained) it exists to make.
$scenarioEntities = @(
    'PIM-Definitions-AU','PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization',
    'PIM-Definitions-Tasks','PIM-Definitions-Departments','PIM-Definitions-Resources',
    'Account-Definitions-Admins','PIM-Assignments-Admins','PIM-Assignments-Groups',
    'PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs','PIM-Assignments-Azure-Resources',
    'PIM-Offboarding','PIM-Discovery'
)
if ("$SqlDatabase".Trim() -and "$SqlDatabase" -ne 'PimPlatform') {
    Write-ScLog STEP "=== scratch store $SqlServer / $SqlDatabase ==="
    try {
        . (Join-Path $shared 'PIM-ChangeQueue.ps1'); . (Join-Path $shared 'PIM-SqlStore.ps1')
        $global:PIM_SqlServer = $SqlServer; $global:PIM_SqlDatabase = $SqlDatabase
        $cs = Get-PimSqlConnectionString
        if (Test-PimSqlConnectivity -ConnectionString $cs) {
            $rows = 0
            foreach ($e in $scenarioEntities) {
                if ($WhatIfOnly) {
                    try { $rows += [int](Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT COUNT(*) FROM pim.Rows WHERE Entity=@e AND (UPPER([Key]) LIKE @m OR UPPER(DataJson) LIKE @m)" -Parameters @{ e=$e; m="%$($script:Marker)%" }) } catch { }
                } else {
                    try { $rows += [int](Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "DELETE FROM pim.Rows WHERE Entity=@e AND (UPPER([Key]) LIKE @m OR UPPER(DataJson) LIKE @m)" -Parameters @{ e=$e; m="%$($script:Marker)%" }) } catch { }
                }
            }
            # TEST-14: the master registry tables. This block used to guess the name column
            # with `if ($tbl -match 'Admins') {'[UserName]'} else {'[Name]'}`. NEITHER
            # platform.Tenants nor platform.TenantApps has a [Name] column, so the DELETE
            # threw "Invalid column name 'Name'" into the empty catch below -- which was
            # written for "the table may not exist in this store" and could not tell the two
            # apart. Result: a marked tenant row survived EVERY sweep while the summary said
            # clean, so §33.7.e-2 rule 5 (cleanup alone restores the baseline) was false.
            #
            # Now: an explicit per-table predicate, children BEFORE parents (TenantApps has
            # no name of its own -- it is owned by the marked Tenants row it points at, the
            # same schedules-before-principals ordering rule this sweep already obeys), the
            # SAME predicate in the WhatIf and the delete branch, and a SQL failure that is
            # not "table absent" is REPORTED instead of swallowed.
            $registrySweeps = @(
                @{ Table = 'pim.CentralAdmins'; Where = "UPPER(CONCAT('',[UserName])) LIKE @m" }
                @{ Table = 'pim.LocalAdmins';   Where = "UPPER(CONCAT('',[UserName])) LIKE @m" }
                @{ Table = 'platform.TenantApps'; Where = "[TenantId] IN (SELECT [TenantId] FROM platform.Tenants WHERE UPPER(CONCAT('',[DisplayName])) LIKE @m)" }
                @{ Table = 'platform.Tenants';  Where = "UPPER(CONCAT('',[DisplayName])) LIKE @m" }
            )
            foreach ($sweep in $registrySweeps) {
                $tbl = $sweep.Table
                try {
                    if ($WhatIfOnly) {
                        $rows += [int](Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT COUNT(*) FROM $tbl WHERE $($sweep.Where)" -Parameters @{ m = "%$($script:Marker)%" })
                    } else {
                        $rows += [int](Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "DELETE FROM $tbl WHERE $($sweep.Where)" -Parameters @{ m = "%$($script:Marker)%" })
                    }
                } catch {
                    $msg = "$($_.Exception.Message)"
                    # "Invalid object name" = the table genuinely is not in this store (not
                    # every store is a master). Anything else is a sweep that FAILED, and a
                    # failed sweep must never read as a clean one.
                    if ($msg -match 'Invalid object name') {
                        Write-ScLog INFO "    $tbl not in this store -- skipped"
                    } else {
                        Write-ScLog WARN "    $tbl sweep FAILED: $msg"
                        [void]$script:Leftovers.Add("$tbl (sweep failed: $msg)")
                    }
                }
            }
            if ($WhatIfOnly) { Write-ScLog INFO "    WOULD remove ~$rows marked row(s)"; $script:Would += $rows }
            else             { Write-ScLog OK  "    removed $rows marked row(s)" }
        } else { Write-ScLog SKIP "    store not reachable" }
    } catch { Write-ScLog WARN "    store sweep skipped: $($_.Exception.Message)" }
} else {
    Write-ScLog SKIP "store sweep skipped -- SqlDatabase is 'PimPlatform' (the real platform store). Pass a scratch -SqlDatabase."
}

# ---------------------------------------------------------------------------
Write-ScLog STEP "=== SUMMARY ==="
# BUG-26: the count is only meaningful for the tenants actually inspected. State the
# denominator, so "0 to remove" can never again be read as "the estate is clean" when the
# real reason is that nothing was looked at.
$swept = $tenants.Count - $script:Unverified.Count
Write-ScLog INFO ("inspected {0} of {1} tenant(s)" -f $swept, $tenants.Count)
if ($WhatIfOnly) { Write-ScLog INFO "WHAT-IF: $($script:Would) object(s)/row(s) would be removed. Nothing was changed." }
else             { Write-ScLog OK   "removed $($script:Removed) object(s)/file(s) + the marked store rows" }
foreach ($l in $script:Leftovers) { Write-ScLog WARN "NOT REMOVED -- $l" }
foreach ($u in $script:Unverified) { Write-ScLog WARN "UNVERIFIED -- not swept, could not authenticate: $u" }
if ($script:Unverified.Count) {
    Write-ScLog WARN ("{0} of {1} tenant(s) were NOT inspected. This result does NOT mean the estate is clean -- " -f $script:Unverified.Count, $tenants.Count)
    Write-ScLog WARN "fix the credentials for the tenant(s) above and re-run. Nothing unmarked was touched."
    exit 3
}
if ($script:Leftovers.Count) {
    Write-ScLog WARN "re-run to finish. Nothing unmarked was touched."
    exit 2
}
exit 0
