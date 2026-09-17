<#
  PIM4EntraPS -- NEW engine core (REST + SQL, no modules). Replaces the legacy
  PIM-Baseline-Management-CSV chain.

  Model: each SCOPE is a PROVIDER that knows how to read DESIRED (from SQL), read LIVE
  (from the tenant via PIM-Rest), key + compare rows, and apply Create/Update/Remove
  (via PIM-Rest). The core is a PURE diff (Compare-PimDesiredVsLive, fully testable) +
  an orchestrator (Invoke-PimEngineScope) that turns the diff into change-queue records
  and either previews (WhatIf / dry-run) or applies them.

    desired (SQL)  ─┐
                     ├─►  Compare-PimDesiredVsLive  ─►  {create, update, remove, nochange}
    live (REST)    ─┘                                     │
                                                          ├─ WhatIf -> change-queue PLAN (no writes)
                                                          └─ commit -> provider.Apply* via REST

  Mode: Delta = create/update only (fast, no removals); Full = also prune live items not
  in desired (whole-scope reconcile). Providers register via Register-PimEngineProvider.
#>

Set-StrictMode -Off

$script:PimEngineProviders = @{}   # scope(lower) -> provider hashtable

# ---- pure diff core (testable, no I/O) ------------------------------------
function Compare-PimDesiredVsLive {
    param(
        [object[]]$Desired = @(),
        [object[]]$Live    = @(),
        [Parameter(Mandatory)][scriptblock]$KeyOf,   # row -> natural key string
        [Parameter(Mandatory)][scriptblock]$Equal,   # (desired,live) -> bool
        [switch]$Prune,                              # remove live not in desired (Full)
        # v1 parity (REQUIREMENTS 68.6 rows 24-25). Both are OPTIONAL and additive: a caller that
        # passes neither gets exactly the old diff.
        #   -RemoveRows : rows explicitly marked Action=Remove. Each one removes EXACTLY the live
        #                 item whose key it produces -- a TARGETED removal, not a prune -- in every
        #                 mode, because the row itself names what to remove (v1 did the same).
        #   -TypeKeyOf  : row -> key WITHOUT the assignment type. When given, a live item of the
        #                 OTHER type for a principal/target/role the desired set names with a
        #                 different type is superseded: a create becomes a TYPE CHANGE (update
        #                 item with typeChange=$true, removal-first in the orchestrator).
        #   -RemoveTypeLeftovers : ALSO remove a live item of the other type when the desired type is
        #                 already present (both types live, one desired). OFF by default: no row asks
        #                 for that removal and v1 kept both, so it waits for the operator (68.6 row 25).
        [object[]]$RemoveRows = @(),
        [scriptblock]$TypeKeyOf,
        [switch]$RemoveTypeLeftovers
    )
    $liveMap = @{}
    foreach ($l in @($Live)) { if ($null -eq $l) { continue }; $k = "$(& $KeyOf $l)".Trim().ToLowerInvariant(); if ($k) { $liveMap[$k] = $l } }
    $create = New-Object System.Collections.Generic.List[object]
    $update = New-Object System.Collections.Generic.List[object]
    $nochange = New-Object System.Collections.Generic.List[object]
    $desKeys = @{}
    foreach ($d in @($Desired)) {
        if ($null -eq $d) { continue }
        $k = "$(& $KeyOf $d)".Trim(); $lk = $k.ToLowerInvariant(); if (-not $lk) { continue }
        $desKeys[$lk] = $true
        if (-not $liveMap.ContainsKey($lk)) { $create.Add([pscustomobject]@{ key=$k; desired=$d }) }
        else {
            $l = $liveMap[$lk]
            if (& $Equal $d $l) { $nochange.Add([pscustomobject]@{ key=$k; desired=$d; live=$l }) }
            else                { $update.Add([pscustomobject]@{ key=$k; desired=$d; live=$l }) }
        }
    }
    $remove = New-Object System.Collections.Generic.List[object]
    $claimed = @{}   # live keys already consumed by a type change or a targeted removal

    # ---- TYPE CHANGE (68.6 row 25) ------------------------------------------------------
    # Without this, switching a row Eligible -> Active planned a CREATE of Active and left the
    # Eligible assignment in place: MORE privilege than the row asks for. The live item of the
    # other type is paired with the desired row so it is removed, and never also pruned.
    if ($TypeKeyOf) {
        $liveByTk = @{}
        foreach ($l in @($Live)) {
            if ($null -eq $l) { continue }
            $k = "$(& $KeyOf $l)".Trim(); $lk = $k.ToLowerInvariant()
            if (-not $lk -or $desKeys.ContainsKey($lk)) { continue }
            $tk = "$(& $TypeKeyOf $l)".Trim().ToLowerInvariant(); if (-not $tk) { continue }
            if (-not $liveByTk.ContainsKey($tk)) { $liveByTk[$tk] = New-Object System.Collections.Generic.List[object] }
            $liveByTk[$tk].Add([pscustomobject]@{ key=$k; lk=$lk; live=$l })
        }
        if ($liveByTk.Count) {
            $keptCreate = New-Object System.Collections.Generic.List[object]
            foreach ($c in $create.ToArray()) {
                $tk = "$(& $TypeKeyOf $c.desired)".Trim().ToLowerInvariant()
                $cands = if ($tk -and $liveByTk.ContainsKey($tk)) { @($liveByTk[$tk] | Where-Object { -not $claimed.ContainsKey($_.lk) }) } else { @() }
                if ($cands.Count -eq 0) { $keptCreate.Add($c); continue }
                $first = $cands[0]; $claimed[$first.lk] = $true
                $update.Add([pscustomobject]@{ key=$c.key; desired=$c.desired; live=$first.live; typeChange=$true; replacesKey=$first.key })
                foreach ($x in @($cands | Select-Object -Skip 1)) {
                    $claimed[$x.lk] = $true
                    $remove.Add([pscustomobject]@{ key=$x.key; live=$x.live; typeChange=$true; supersededBy=$c.key })
                }
            }
            $create = $keptCreate
            # Leftovers next to an already-correct assignment. Measured on the first 2.4.338 tick
            # (2026-09-13): this removed 3 active org memberships and wanted 81 eligible Entra role
            # assignments gone, none of them named by any row. Opt-in only.
            $present = if ($RemoveTypeLeftovers) { @($update.ToArray() | Where-Object { -not $_.typeChange }) + @($nochange.ToArray()) } else { @() }
            foreach ($e in $present) {
                $tk = "$(& $TypeKeyOf $e.desired)".Trim().ToLowerInvariant()
                if (-not $tk -or -not $liveByTk.ContainsKey($tk)) { continue }
                foreach ($x in @($liveByTk[$tk] | Where-Object { -not $claimed.ContainsKey($_.lk) })) {
                    $claimed[$x.lk] = $true
                    $remove.Add([pscustomobject]@{ key=$x.key; live=$x.live; typeChange=$true; supersededBy=$e.key })
                }
            }
        }
    }

    # ---- TARGETED REMOVALS (68.6 row 24) ------------------------------------------------
    $absent = New-Object System.Collections.Generic.List[object]
    $conflicts = New-Object System.Collections.Generic.List[object]
    # Operator 2026-09-13: a Remove row REVOKES the delegation, like the Manager's revoke -- BOTH types.
    # For an assignment scope (TypeKeyOf given; every key ends in "|<type>") the row matches the live
    # eligible AND active item for the same principal/target/role, whatever AssignmentType it carries.
    $neutral = { param($key) ("$key".Trim().ToLowerInvariant() -replace '\|[^|]*$', '') }
    $liveByNeutral = @{}
    $desNeutral = @{}
    if ($TypeKeyOf) {
        foreach ($lk0 in @($liveMap.Keys)) { $nk0 = & $neutral $lk0; if (-not $liveByNeutral.ContainsKey($nk0)) { $liveByNeutral[$nk0] = New-Object System.Collections.Generic.List[string] }; $liveByNeutral[$nk0].Add($lk0) }
        foreach ($dk0 in @($desKeys.Keys)) { $desNeutral[(& $neutral $dk0)] = $true }
    }
    foreach ($r in @($RemoveRows)) {
        if ($null -eq $r) { continue }
        $k = "$(& $KeyOf $r)".Trim(); $lk = $k.ToLowerInvariant(); if (-not $lk) { continue }
        if ($TypeKeyOf) {
            $nk = & $neutral $lk
            # Another row ASSIGNS the same delegation (either type): removing it would flap against the
            # create every run, so neither wins silently -- report it, remove nothing, keep the row.
            if ($desNeutral.ContainsKey($nk)) { $conflicts.Add([pscustomobject]@{ key=$k; row=$r }); continue }
            $hits = if ($liveByNeutral.ContainsKey($nk)) { @($liveByNeutral[$nk] | Where-Object { -not $claimed.ContainsKey($_) }) } else { @() }
            if ($hits.Count) {
                foreach ($h in $hits) {
                    $claimed[$h] = $true
                    $remove.Add([pscustomobject]@{ key=$h; live=$liveMap[$h]; targeted=$true; row=$r; rowKey=$lk })
                }
            } elseif (-not @(@($liveByNeutral[$nk]) | Where-Object { $_ }).Count) {
                $absent.Add([pscustomobject]@{ key=$k; row=$r })        # nothing of either type live = done
            }
            continue
        }
        # Non-assignment scope: exact key, as before.
        if ($desKeys.ContainsKey($lk)) { $conflicts.Add([pscustomobject]@{ key=$k; row=$r }); continue }
        if ($claimed.ContainsKey($lk)) { continue }                    # already being removed
        if ($liveMap.ContainsKey($lk)) {
            $claimed[$lk] = $true
            $remove.Add([pscustomobject]@{ key=$k; live=$liveMap[$lk]; targeted=$true; row=$r; rowKey=$lk })
        } else {
            $absent.Add([pscustomobject]@{ key=$k; row=$r })            # already gone = success
        }
    }

    if ($Prune) {
        foreach ($l in @($Live)) {
            if ($null -eq $l) { continue }
            $k = "$(& $KeyOf $l)".Trim(); $lk = $k.ToLowerInvariant()
            if ($lk -and -not $desKeys.ContainsKey($lk) -and -not $claimed.ContainsKey($lk)) { $remove.Add([pscustomobject]@{ key=$k; live=$l }) }
        }
    }
    return [pscustomobject]@{ create=$create.ToArray(); update=$update.ToArray(); remove=$remove.ToArray(); nochange=$nochange.ToArray()
                              absent=$absent.ToArray(); conflicts=$conflicts.ToArray() }
}

# ---- provider registry ----------------------------------------------------
function Register-PimEngineProvider {
    # Provider = @{ scope; entity?; GetDesired(ctx); GetLive(ctx); KeyOf(row); Equal(d,l);
    #               ApplyCreate(item,ctx); ApplyUpdate(item,ctx); ApplyRemove(item,ctx) }
    param([Parameter(Mandatory)][hashtable]$Provider)
    if (-not $Provider.scope) { throw "provider needs a 'scope'" }
    $script:PimEngineProviders["$($Provider.scope)".ToLowerInvariant()] = $Provider
}
function Get-PimEngineProvider { param([string]$Scope) $script:PimEngineProviders["$Scope".ToLowerInvariant()] }
function Get-PimEngineScopes {
    # Ordered by provider.order (default 100) so an 'All' run honours dependencies:
    # AdministrativeUnits -> Groups -> (role/resource/membership) assignments. Ties
    # break by scope name for determinism.
    @($script:PimEngineProviders.Values |
        Sort-Object @{ e = { if ($_.order) { [int]$_.order } else { 100 } } }, @{ e = { "$($_.scope)" } } |
        ForEach-Object { $_.scope })
}

# ---- legacy scope aliases (v1 CSV engine name -> REST provider scopes) -----
function Get-PimEngineScopeAliasMap {
    <#
      🔴 BUG-134 -- THREE SCHEDULED JOBS HAVE BEEN PERMANENT, SILENT NO-OPS SINCE THE REST ENGINE
      REPLACED THE CSV ENGINE, AND THE WORST OF THEM IS THE ONE THAT APPLIES A DELEGATION.

      The v1 CSV engine took -Scope names like 'GroupsAssignment' (PIM-Baseline-Management-CSV-
      PIM4GroupsAssignmentOnly). The REST engine registers providers under DIFFERENT names --
      the one that nests a PIM-ROLE group into its permission groups is 'GroupMembers'. The
      shipped job schedule was never retranslated, so:

        delta-groups-assign   -> 'GroupsAssignment'          -> NO PROVIDER  (nesting never ran)
        delta-groups-deploy   -> 'GroupsCreateModifyPolicy'  -> NO PROVIDER  (group create/owners/AU-members never ran)
        delta-workloads       -> 'Workloads'                 -> NO PROVIDER  (Defender/Intune/app-role never ran)

      Invoke-PimEngineScope answers an unknown scope with { ok=$false; detail='no provider...' }
      and no counts; the scheduler formatted the missing counts and recorded the tick SUCCEEDED.
      Measured on the internal environment 2026-09-12: `delta-groups-assign  engine Delta
      [GroupsAssignment] GroupsAssignment:c/u/r` -- blank where every working sibling printed
      `AdministrativeUnits:c16/u0/r0`. An operator's delegation was authored, committed, shown
      correctly on the Access map, and NEVER APPLIED to Entra.

      🪤 FIXING THE SHIPPED DEFAULT IS NOT ENOUGH -- the same trap as
      Disable-PimUnconfiguredIntegrationJobs. Get-PimJobSchedule returns the STORED JobSchedule
      when there is one, so every environment whose cadences were ever touched in the GUI carries
      its own copy of the broken scope names, and a new default never reaches it. The translation
      therefore lives where the scope is RESOLVED, so an existing deployment is repaired by
      rolling the image -- no per-customer database surgery.

      🔑 Two of these three are genuine SCOPE GROUPS and stay: one job that drives several
      providers (the group + its owners + its AU membership; the three workload-RBAC providers).
      'GroupsAssignment' was a pure misnomer, so the shipped default now names 'GroupMembers'
      directly and the alias remains only to repair environments carrying a stored schedule.
      Every expansion is logged when it fires, and the release gate
      (tests/Test-PimJobScopeBinding.ps1) asserts that every scope in the shipped schedule -- and
      every target named here -- resolves to a registered provider, so this cannot rot again.
    #>
    [ordered]@{
        # the v1 "assignments" pass == nesting role groups into permission groups
        'groupsassignment'         = @('GroupMembers')
        # the v1 "create/modify" pass == deploy the group itself, its owners, its AU membership.
        # Policy is NOT included: 'GroupsPolicies' has its own working job (delta-policies), and
        # duplicating it here would re-read every group's member policy twice an hour for nothing.
        'groupscreatemodifypolicy' = @('Groups','AdministrativeUnitMembers','GroupOwners')
        # the v1 umbrella name for workload RBAC: the three dedicated providers PLUS the v1 connector
        # dispatcher over PIM-Assignments-Workloads (the entity v1 itself applied, and the one the
        # migration imports -- without it here, migrated workload rows only ran once a day).
        'workloads'                = @('DefenderXdrRoles','IntuneRoles','EntraAppRole','WorkloadConnectors')

        # --- scope groups closing the sub-daily coverage gap (BUG-137) ------------------
        # 🔴 Found by the coverage report in tests/Test-PimJobScopeBinding.ps1 while fixing
        # BUG-134: SEVEN registered providers were reached by NOTHING except the daily
        # `full-reconcile`. Four of them carry desired state an operator authors in the Manager,
        # so the user-visible symptom is identical to the delegation bug -- "I saved it and
        # nothing happened" -- just with a 24-hour ceiling instead of forever:
        #   AdminMembers      (PIM-Assignments-Admins)      -- which admins hold which PIM group
        #   RolesAUs          (PIM-Assignments-Roles-AUs)   -- role assignments scoped to an AU
        #   EntraRolesDirect  (v1-style direct assignments)
        #   EntraRolePolicies (PIM-Assignments-Roles-Groups) -- policy on an Entra role
        # Grouped onto the EXISTING jobs rather than added as new rows: these are not
        # independently interesting to an operator (they are part of "admins", "PIM for Entra
        # roles" and "policies" respectively), and a Jobs list padded with rows nobody asked for
        # is its own complaint (BUG-92). Targets are listed in provider order.
        # The three left daily are deliberate: AccessReviews (attestation cadence is daily by
        # nature), AdminOffboarding (destructive; -Prune + Enforce gated) and
        # HybridAdProvisioning (plan-only -- the write is the hybrid worker's).
        'adminaccounts'            = @('Admins','AdminMembers')
        'entraroleassignments'     = @('EntraRoles','RolesAUs','EntraRolesDirect')
        'pimpolicies'              = @('GroupsPolicies','EntraRolePolicies')
    }
}

function Resolve-PimEngineScope {
    <#
      Resolve a job's -Scope token to the REST scopes that will actually run.
      Returns @{ ok; scopes; alias; requested; missing; detail }.
      PURE (no Graph, no SQL) so the release gate can assert the whole job schedule offline.
    #>
    param([Parameter(Mandatory)][string]$Scope)
    $req = "$Scope".Trim()
    $key = $req.ToLowerInvariant()
    # SCOPE LIST ("Groups,GroupOwners,AzRes"): the SQL change detector arms ONE trigger per change carrying
    # exactly the scopes the changed entities feed, instead of 'All' (a trigger:All run took 13-26 minutes
    # on internal where the scopes a single delegation needs take seconds). Each part resolves through the
    # single-token logic below (aliases included), the union is de-duplicated and run in PROVIDER ORDER --
    # the same rule the alias branch uses -- and ONE unresolvable part fails the whole list (BUG-134: a
    # partly-bound list must not read as success). 'All' anywhere in the list means all scopes.
    if ($req.Contains(',')) {
        $parts = @(@($req -split ',') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($parts.Count -eq 1) { return (Resolve-PimEngineScope -Scope $parts[0]) }
        if ($parts.Count -eq 0) {
            return [pscustomobject]@{ ok=$false; scopes=@(); alias=$false; requested=$req; missing=@($req)
                detail="scope list '$req' names no scope" }
        }
        $seen = @{}; $union = New-Object System.Collections.Generic.List[string]
        $missingL = New-Object System.Collections.Generic.List[string]
        $wantAll = $false
        foreach ($p in $parts) {
            if ($p.ToLowerInvariant() -eq 'all') { $wantAll = $true; continue }
            $pr = Resolve-PimEngineScope -Scope $p
            if (-not $pr.ok) { foreach ($m in @($pr.missing)) { if ("$m".Trim()) { $missingL.Add("$m") } }; continue }
            foreach ($s in @($pr.scopes)) {
                $prov = Get-PimEngineProvider -Scope $s
                $canon = if ($prov -and "$($prov.scope)".Trim()) { "$($prov.scope)" } else { "$s" }
                $k = $canon.ToLowerInvariant()
                if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $union.Add($canon) }
            }
        }
        if ($missingL.Count) {
            return [pscustomobject]@{ ok=$false; scopes=@(); alias=$true; requested=$req; missing=@($missingL.ToArray())
                detail="scope list '$req' has no provider for [$(@($missingL.ToArray()) -join ', ')]" }
        }
        if ($wantAll) {
            $allS = @(Get-PimEngineScopes)
            return [pscustomobject]@{ ok=$true; scopes=$allS; alias=$true; requested=$req; missing=@()
                detail="scope list '$req' includes All -> all registered scopes" }
        }
        $targets = @($union.ToArray() | Sort-Object @{ e = { $pv = Get-PimEngineProvider -Scope $_; if ($pv -and $pv.order) { [int]$pv.order } else { 100 } } }, @{ e = { "$_" } })
        return [pscustomobject]@{ ok=$true; scopes=$targets; alias=$true; requested=$req; missing=@()
            detail="scope list '$req' -> [$($targets -join ', ')]" }
    }
    if ($key -eq 'all') {
        return [pscustomobject]@{ ok=$true; scopes=@(Get-PimEngineScopes); alias=$false; requested=$req; missing=@(); detail='all registered scopes' }
    }
    if (Get-PimEngineProvider -Scope $req) {
        return [pscustomobject]@{ ok=$true; scopes=@($req); alias=$false; requested=$req; missing=@(); detail='registered provider' }
    }
    $map = Get-PimEngineScopeAliasMap
    if ($map.Contains($key)) {
        $targets = @($map[$key])
        # An alias whose TARGET is also unregistered must not read as a success -- that would
        # simply move the silent no-op one level down.
        $missing = @($targets | Where-Object { -not (Get-PimEngineProvider -Scope $_) })
        if ($missing.Count) {
            return [pscustomobject]@{ ok=$false; scopes=@(); alias=$true; requested=$req; missing=$missing
                detail="legacy scope '$req' maps to [$($targets -join ', ')] but no provider is registered for [$($missing -join ', ')]" }
        }
        # Run a group in PROVIDER ORDER, not map order: a group that deploys a group and then
        # nests into it must not depend on someone keeping the literal list sorted by hand.
        $targets = @($targets | Sort-Object @{ e = { $p = Get-PimEngineProvider -Scope $_; if ($p -and $p.order) { [int]$p.order } else { 100 } } })
        return [pscustomobject]@{ ok=$true; scopes=$targets; alias=$true; requested=$req; missing=@()
            detail="scope group '$req' -> [$($targets -join ', ')]" }
    }
    [pscustomobject]@{ ok=$false; scopes=@(); alias=$false; requested=$req; missing=@($req)
        detail="no provider for scope '$req' (registered: $((Get-PimEngineScopes) -join ', '))" }
}

# ---- default desired/live helpers -----------------------------------------
function Get-PimCentralAdminEntityName {
    # REQUIREMENTS 68.6 row 35: central admins imported from an MSP master live in their OWN entity,
    # separate from the slave's Account-Definitions-Admins. Identical literal in PIM-Downlink.ps1
    # Invoke-PimDownlinkAdminApply (tests/Test-PimDownlink.ps1 asserts they match).
    'Account-Definitions-Admins-Central'
}

function Test-PimAdminRowIsCentral {
    # PURE. A central (MSP-master-governed) admin row, as the engine and Manager see it.
    param([object]$Row)
    if ($null -eq $Row) { return $false }
    $src = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains('AdminSource')) { $src = $Row['AdminSource'] } }
    elseif ($Row.PSObject.Properties['AdminSource']) { $src = $Row.AdminSource }
    return ("$src".Trim() -ieq 'central')
}

function Get-PimDesiredRows {
    # 68.6 row 35 -- the admin definitions a slave governs are ITS OWN rows plus the central admins
    # the downlink imported into a separate entity. They are returned together so no provider can
    # treat a central admin as unmanaged (and prune it); each central row is stamped
    # AdminSource=central so governance follows its source. A local row always wins a name clash
    # (the customer's own admin is never replaced by an import); the clash is reported.
    param([Parameter(Mandatory)][string]$Entity)
    if ($Entity -ne 'Account-Definitions-Admins') { return @(Get-PimDesiredRowsFromStore -Entity $Entity) }
    $local = @(Get-PimDesiredRowsFromStore -Entity $Entity)
    $localResolved = $true
    if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey($Entity)) { $localResolved = [bool]$global:PIM_DesiredResolved[$Entity] }
    $centralEntity = Get-PimCentralAdminEntityName
    $central = @(Get-PimDesiredRowsFromStore -Entity $centralEntity -AbsentIsResolved)
    $centralResolved = [bool]$global:PIM_DesiredResolved[$centralEntity]
    # Fail CLOSED: if either half could not be read, the combined set is not authoritative.
    $global:PIM_DesiredResolved[$Entity] = ($localResolved -and $centralResolved)
    if (-not $central.Count) { return $local }
    $names = @{}
    foreach ($l in $local) { if ($null -ne $l) { $n = "$($l.UserName)".Trim().ToLowerInvariant(); if ($n) { $names[$n] = $true } } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($l in $local) { $out.Add($l) }
    foreach ($c in $central) {
        if ($null -eq $c) { continue }
        $n = "$($c.UserName)".Trim().ToLowerInvariant()
        if ($n -and $names.ContainsKey($n)) {
            Write-Warning "  [engine] central admin '$($c.UserName)' has the same UserName as one of this tenant's own admins -- the local row wins; the import is ignored (rename one of them)."
            continue
        }
        $copy = [pscustomobject]@{}
        foreach ($p in $c.PSObject.Properties) { $copy | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force }
        $copy | Add-Member -NotePropertyName AdminSource -NotePropertyValue 'central' -Force
        $out.Add($copy)
    }
    return $out.ToArray()
}

function Get-PimDesiredRowsFromStore {
    # DESIRED comes from SQL (pim.Rows) when the SQL store is active, else in-memory
    # ($global:PIM_DesiredRows[$entity]) for tests/offline.
    # NB: Get-PimSqlRows REQUIRES -ConnectionString. It was called without one, so it
    # errored silently -> 0 desired (the engine appeared to do nothing). Resolve the CS
    # from the engine CS / in-memory CS / build from $global:PIM_SqlServer+Database.
    param([Parameter(Mandatory)][string]$Entity,
          # The central-admin entity is legitimately absent everywhere except on an MSP slave, so
          # "no in-memory rows for it" is a resolved empty set there, not an unknown one.
          [switch]$AbsentIsResolved)
    # Resolution tracking: a disable pass must distinguish "desired set is genuinely
    # empty (resolved, 0 rows)" from "the read FAILED, so we don't actually know the
    # desired set" -- the latter must never be treated as authoritative. We stamp the
    # outcome into $global:PIM_DesiredResolved[$Entity] so PIM-DisableGuard can refuse a
    # disable when the read for an account-disable scope was not positively resolved.
    if ($null -eq $global:PIM_DesiredResolved -or -not ($global:PIM_DesiredResolved -is [hashtable])) { $global:PIM_DesiredResolved = @{} }
    if (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue) {
        $cs = if ($global:PIM_EngineSqlCs) { $global:PIM_EngineSqlCs }
              elseif ($global:PIM_SqlConnectionString) { $global:PIM_SqlConnectionString }
              elseif ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and ($global:PIM_SqlServer -or $global:PIM_SqlConnStringVault)) { Get-PimSqlConnectionString }
              else { $null }
        if ($cs) {
            try { $rows = @(Get-PimSqlRows -ConnectionString $cs -Entity $Entity); $global:PIM_DesiredResolved[$Entity] = $true; return $rows }
            catch { Write-Warning "  [engine] SQL desired read failed for '$Entity': $($_.Exception.Message)"; $global:PIM_DesiredResolved[$Entity] = $false; return @() }
        }
    }
    if ($global:PIM_DesiredRows -and $global:PIM_DesiredRows.ContainsKey($Entity)) { $global:PIM_DesiredResolved[$Entity] = $true; return @($global:PIM_DesiredRows[$Entity]) }
    # No SQL store AND no in-memory rows for this entity -> we did not positively resolve it.
    $global:PIM_DesiredResolved[$Entity] = [bool]$AbsentIsResolved
    return @()
}

# ---- engine change audit (§70.15 LOG-01 / LOG-04, 2026-09-13) ---------------
# Operator: "audit trail is lacking vital information. this must be detailed and relevant for ciso and
# compliance team and security team and show real roles, real groups, real resources, real people".
# The Manager recorded who ASKED; the engine -- which MAKES the directory change -- printed `[+] <guid|key>`
# to a container log and recorded nothing. Every applied or failed item now writes ONE pim.AuditEvents row:
#   Action  engine.<scope>.<create|update|remove>   Actor engine   Result ok|error
#   Target  the readable sentence (Get-PimFailureItemLabel: group/user, role, scope, type)
#   After   key, entity, the desired/live row, the error when it failed, and the job that ran it
#   CorrelationId = the scheduler job run (Invoke-PimScheduledJob), so a request -> run -> change joins up.
# Best-effort by design: the directory change already happened, and an audit sink failure never fails the
# run -- but it is reported (Write-PimAuditEvent / the warning below), never swallowed silently.
function Write-PimEngineChangeAudit {
    param([string]$Scope, [string]$Entity, [string]$Op, [object]$Item, [string]$Result = 'ok', [string]$ErrorMessage = '')
    if ($global:WhatIfMode) { return }
    try {
        $row = $null
        if ($Item) {
            if ("$Op" -eq 'Remove') { $row = if ($Item.PSObject.Properties['row'] -and $null -ne $Item.row) { $Item.row } elseif ($Item.PSObject.Properties['live']) { $Item.live } else { $null } }
            elseif ($Item.PSObject.Properties['desired']) { $row = $Item.desired }
        }
        $key = if ($Item -and $Item.PSObject.Properties['key']) { "$($Item.key)" } else { '' }
        $label = ''
        if (Get-Command Get-PimFailureItemLabel -ErrorAction SilentlyContinue) { try { $label = Get-PimFailureItemLabel -Key $key -Row $row } catch { $label = '' } }
        $snap = if (Get-Command ConvertTo-PimFailureRowSnapshot -ErrorAction SilentlyContinue) { ConvertTo-PimFailureRowSnapshot -Row $row } else { $row }
        $verb = switch ("$Op") { 'Create' { 'create' } 'Update' { 'update' } 'Remove' { 'remove' } default { "$Op".ToLowerInvariant() } }
        $after = [ordered]@{
            summary = $(if ($label) { $label } else { $key })
            scope = $Scope; entity = $Entity; op = $Op; key = $key
            row = $snap
            job = "$($global:PIM_JobName)"
        }
        if ($ErrorMessage) { $after['error'] = $ErrorMessage }
        # LOG-02: a provider that knows the exact before/after (policy rules) attaches it to the item.
        if ($Item -and $Item.PSObject.Properties['pimAuditDetail'] -and $null -ne $Item.pimAuditDetail) {
            $after['detail'] = $Item.pimAuditDetail
            if ($Item.pimAuditDetail.policy) {
                $n = @($Item.pimAuditDetail.rules).Count
                $label = "PIM policy of $($Item.pimAuditDetail.policy): $n rule(s) changed" + $(if ($Item.pimAuditDetail.approvedPlan) { ' (approved mass-change plan)' } else { '' })
                $after['summary'] = $label
            }
        }
        $action = "engine.$("$Scope".ToLowerInvariant()).$verb"
        $target = if ($label) { $label } else { "$Entity $key" }
        $corr = "$($global:PIM_JobCorrelationId)"
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action $action -Target $target -After $after -Result $Result -Actor 'engine' -CorrelationId $corr | Out-Null
            return
        }
        $cs = $null
        if ("$($global:PIM_EngineSqlCs)".Trim()) { $cs = "$($global:PIM_EngineSqlCs)" }
        elseif ("$($global:PIM_SqlConnectionString)".Trim()) { $cs = "$($global:PIM_SqlConnectionString)" }
        if ($cs -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
            Write-PimSqlAuditEvent -ConnectionString $cs -Actor 'engine' -ActorSource 'engine' -Action $action -Target $target -After $after -Result $Result -CorrelationId $corr
        }
    } catch { Write-Warning ("    [audit] engine change {0} {1} was NOT recorded: {2}" -f $Op, $(if ($Item) { $Item.key } else { '' }), $_.Exception.Message) }
}

# ---- orchestrator ---------------------------------------------------------
function Invoke-PimEngineScope {
    # -Changes feeds a COMMIT-QUEUE-FED delta: when supplied, the scope still diffs
    # desired-vs-live, but only create/update/remove rows whose (entity,key) is present
    # in $Changes are acted on. This is how a commit trigger applies just what changed
    # (vs. -Mode Full = whole-scope reconcile, or -Mode Delta with no -Changes = create/
    # update everything that differs). Each $Changes item = @{ Entity; Key }.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Scope,
        [ValidateSet('Full','Delta')][string]$Mode = 'Delta',
        [switch]$WhatIf,
        [switch]$Prune,                              # destructive: actually remove live-not-in-desired (Full only)
        [hashtable]$Context = @{},
        [object[]]$Changes
    )
    $p = Get-PimEngineProvider -Scope $Scope
    if (-not $p) { return [pscustomobject]@{ scope=$Scope; ok=$false; detail="no provider for scope '$Scope'" } }

    # --- FEATURE GATE (REQUIREMENTS s29/s30) ----------------------------------
    # A provider that maps to a CUSTOMIZABLE capability carries a `feature` key (a
    # PIM-FeatureCatalog key). When that feature is disabled (kill switch off) or
    # unlicensed for the active edition, the scope NO-OPs: no diff, no writes, no
    # sends -- regardless of trigger (Full/Delta/queue). Core scopes carry no
    # `feature` key and are never gated. The gate is fail-safe (unknown key => off).
    if ($p.feature -and (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue)) {
        if (-not (Test-PimFeatureAvailable -Key "$($p.feature)")) {
            return [pscustomobject]@{ scope=$Scope; mode=$Mode; whatIf=[bool]$WhatIf; create=0; update=0; remove=0; nochange=0; applied=0; skipped=0; errors=0; plan=@(); ok=$true; skippedFeature="$($p.feature)" }
        }
    }

    # Assignment scopes depend on groups/AUs/admins an earlier scope may have just created.
    # INCREMENTAL refresh: those creates are appended to the directory cache by
    # Add-PimContextObject as they happen, so we only need the cache LOADED here -- never a
    # full Build-PimContext -Refresh (which re-fetched the whole tenant before every scope).
    # refreshBefore now just guarantees the cache exists.
    if ($p.refreshBefore -and (Get-Command Build-PimContext -ErrorAction SilentlyContinue) -and -not $Global:PimContextBuiltAt) {
        try { Build-PimContext | Out-Null } catch { Write-Warning "  [engine] context load before '$Scope' failed: $($_.Exception.Message)" }
    }

    # PERFORMANCE (2026-09-13): when this call CANNOT prune, every removal the diff can produce (type change,
    # type leftover, targeted Remove row) names a principal that a desired or Remove row names -- so a provider
    # may read live state for those principals only instead of its whole BUG-17 universe (AdminMembers and
    # GroupMembers do: Get-PimLiveGroupMembershipsByPrincipal). Full + -Prune always reads everything.
    # Kill switch: NarrowDeltaMembershipReads = false.
    $__narrow = -not (($Mode -eq 'Full') -and $Prune)
    if ($__narrow -and (Get-Command Test-PimNarrowDeltaMembershipReadsEnabled -ErrorAction SilentlyContinue) -and -not (Test-PimNarrowDeltaMembershipReadsEnabled)) { $__narrow = $false }
    $Context['__pimLiveNarrow'] = $__narrow
    $Context['__pimLiveNarrowReason'] = "$Mode, no prune"

    $desired = @(& $p.GetDesired $Context)
    $live    = @(& $p.GetLive    $Context)
    # Destructive prune (remove live items not in desired) is gated TWICE:
    #   1. -Mode Full AND -Prune must BOTH be set (Full alone reconciles create/update only).
    #      A partial/non-authoritative desired set must never silently disable real admins.
    #   2. Never prune a scope whose desired set is EMPTY -- an empty desired is almost always
    #      "this scope wasn't seeded / wasn't loaded", not "delete everything live".
    #      EXCEPTION: a provider may set allowEmptyDesiredPrune=$true when an EMPTY desired
    #      is intentional + authoritative AND its GetLive already restricts the live set to
    #      exactly the items that should be removed (e.g. the AdminOffboarding scope, whose
    #      live = only the memberships held by explicitly-offboarded admins). Such a scope is
    #      a remove-only diff by construction, so the "0 desired = wrong store" heuristic
    #      doesn't apply.
    $doPrune = ($Mode -eq 'Full') -and $Prune
    if ($doPrune -and @($desired).Count -eq 0 -and -not $p.allowEmptyDesiredPrune) {
        Write-Host ("[engine] {0,-20} prune SKIPPED -- desired set is empty (refusing to remove {1} live items; not authoritative)" -f $Scope, @($live).Count) -ForegroundColor Yellow
        $doPrune = $false
    }
    # v1 parity (68.6 rows 24-25): a provider may name explicit Remove rows (GetRemoveRows) and a
    # type-neutral key (TypeKeyOf). Both are optional; a provider with neither diffs exactly as before.
    # Targeted removals run in EVERY mode (no -Prune): the row itself says what to remove, as in v1.
    $removeRows = @()
    if ($p.GetRemoveRows) { $removeRows = @(& $p.GetRemoveRows $Context | Where-Object { $null -ne $_ }) }
    $cmp = @{ Desired = $desired; Live = $live; KeyOf = $p.KeyOf; Equal = $p.Equal; Prune = $doPrune }
    if ($removeRows.Count) { $cmp['RemoveRows'] = $removeRows }
    if ($p.TypeKeyOf) {
        $cmp['TypeKeyOf'] = $p.TypeKeyOf
        $__lo = $null
        if (Get-Command Get-PimPolicySetting -ErrorAction SilentlyContinue) { $__lo = Get-PimPolicySetting -Name 'RemoveTypeLeftovers' -Default $null }
        elseif ($null -ne $global:PIM_RemoveTypeLeftovers) { $__lo = $global:PIM_RemoveTypeLeftovers }
        if ("$__lo".Trim() -match '^(?i)(true|1|yes|on)$') { $cmp['RemoveTypeLeftovers'] = $true }
    }
    $diff = Compare-PimDesiredVsLive @cmp
    # How many live items each Remove row revokes (both types). Its row is deleted only when ALL applied.
    $__rowTotal = @{}
    foreach ($__x in @($diff.remove)) { if ($__x -and $__x.PSObject.Properties['rowKey'] -and $__x.rowKey) { $__rowTotal[$__x.rowKey] = 1 + [int]$__rowTotal[$__x.rowKey] } }
    $__absent = @($diff.absent); $__conflicts = @($diff.conflicts)
    if ($__absent.Count) {
        Write-Host ("[engine] {0}: {1} Remove row(s) name an assignment that is already absent -- nothing to remove (idempotent): {2}" -f `
            $Scope, $__absent.Count, ((@($__absent | Select-Object -First 5 | ForEach-Object { $_.key })) -join ', ')) -ForegroundColor DarkGray
    }
    foreach ($__c in $__conflicts) {
        Write-Warning ("[engine] {0}: Remove row '{1}' names an assignment that another row ASSIGNS -- nothing removed. Delete one of the two rows." -f $Scope, $__c.key)
    }

    # Commit-queue-fed delta: restrict the diff to only the queued (entity,key) pairs.
    if ($PSBoundParameters.ContainsKey('Changes') -and $null -ne $Changes) {
        $ent = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
        $allow = @{}
        foreach ($c in @($Changes)) {
            $ce = "$(if ($c.Entity) { $c.Entity } else { $c.entity })"
            $ck = "$(if ($c.Key) { $c.Key } else { $c.key })"
            if ($ce -and $ce.ToLowerInvariant() -eq $ent.ToLowerInvariant() -and $ck) { $allow[$ck.Trim().ToLowerInvariant()] = $true }
        }
        $sel = { param($arr) @($arr | Where-Object { $allow.ContainsKey("$($_.key)".Trim().ToLowerInvariant()) }) }
        # NB: re-wrap each result in @() at the call site -- `& $sel` unwraps a single-element
        # array back to a scalar, and `.Count` on a lone PSCustomObject is $null under StrictMode -Off.
        $diff = [pscustomobject]@{ create = @(& $sel $diff.create); update = @(& $sel $diff.update); remove = @(& $sel $diff.remove); nochange = @($diff.nochange) }
    }

    # --- ACCOUNT-DISABLE CIRCUIT BREAKER (incident 2026-06-15) -----------------------
    # A provider that disables ACCOUNTS via its remove path (accountEnabled=$false) is
    # the highest-blast-radius operation in the engine: its GetLive is the whole tenant
    # user population, so a wrong/empty desired set turns every scanned user into a
    # "remove" -> mass account disable. Such a provider sets isAccountDisable=$true; we
    # then gate its removals through PIM-DisableGuard (feature opt-in + positively-
    # resolved desired set + blast-radius cap). On a trip we DROP every remove for this
    # scope (disable NOTHING -- never a partial mass-disable), log loudly and alert.
    # This runs for BOTH plan (WhatIf) and apply so a plan shows the abort too.
    $script:__disableAborted = $null

    # --- BUG-14 (break-glass) + BUG-13 (multi-domain / unmanaged) --------------------
    # Runs BEFORE the circuit breaker on purpose: an account that must never be disabled
    # should not even count toward the blast radius it is measured against. Otherwise a
    # handful of break-glass and other-domain accounts could trip the breaker and mask a
    # real problem -- or, worse, be counted as "acceptable" collateral under the cap.
    if ($p.isAccountDisable -and @($diff.remove).Count -gt 0 -and (Get-Command Select-PimDisableRemovals -ErrorAction SilentlyContinue)) {
        $sel = Select-PimDisableRemovals -Remove @($diff.remove) -Desired @($desired)
        if (@($sel.breakGlass).Count -gt 0) {
            Write-Host ("[engine] {0}: {1} BREAK-GLASS account(s) excluded from the disable set -- never removable: {2}" -f `
                $Scope, @($sel.breakGlass).Count, (($sel.breakGlass) -join ', ')) -ForegroundColor Yellow
        }
        if (@($sel.unmanaged).Count -gt 0) {
            # 🔴 71.22 -- A REPORT, AND ONLY A REPORT (operator, 2026-09-16: "i dont like flow 3
            # and that should be removed"). These are live admin accounts the desired set does not
            # contain. Seeing them is useful; acting on them is not, because "absent from the
            # desired set" and "half the desired set failed to load" look exactly the same here.
            Write-Host ("[engine] {0}: {1} UNMANAGED admin account(s) are NOT in the desired set: {2}" -f `
                $Scope, @($sel.unmanaged).Count, (($sel.unmanaged) -join ', ')) -ForegroundColor Yellow
            Write-Host ("[engine] {0}: REPORT ONLY -- PIM never disables an account because it is absent from the desired set. To disable one of these, say so on its row (AccountStatus=Disabled, or an AutoDisableDate in the past); to stop seeing it, add it to the definitions." -f $Scope) -ForegroundColor Yellow
        }
        $diff = [pscustomobject]@{ create = @($diff.create); update = @($diff.update); remove = @($sel.remove); nochange = @($diff.nochange) }
    }

    if ($p.isAccountDisable -and @($diff.remove).Count -gt 0 -and (Get-Command Test-PimDisablePassAllowed -ErrorAction SilentlyContinue)) {
        $resolvedFlag = $null
        $ent = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
        if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey($ent)) { $resolvedFlag = [bool]$global:PIM_DesiredResolved[$ent] }
        $decision = Test-PimDisablePassAllowed -ToDisable (@($diff.remove).Count) -Scanned (@($live).Count) -Desired $desired -DesiredResolved $resolvedFlag -FeatureOverride $p.disableFeatureOverride
        if (-not $decision.allowed) {
            if (Get-Command Write-PimDisableAbortAlert -ErrorAction SilentlyContinue) { Write-PimDisableAbortAlert -Scope $Scope -Decision $decision }
            else { Write-Host ("[engine] {0}: account-disable ABORTED [{1}] -- {2}" -f $Scope, $decision.tripped, $decision.reason) -ForegroundColor Red }
            # Drop ALL removes for this scope -- the safe outcome is to disable nothing.
            $diff = [pscustomobject]@{ create = @($diff.create); update = @($diff.update); remove = @(); nochange = @($diff.nochange) }
            $script:__disableAborted = $decision.tripped
        }
    }

    # --- G4: UNIVERSAL REMOVAL BUDGET (operator directive 2026-08-06) -----------------
    # The breaker above guards ONE provider class (isAccountDisable = Admins). This caps
    # removals in EVERY scope, so a -Prune on RolesAUs / GroupMembers / AzRes cannot wipe
    # the live set (BUG-11) and no scope can quietly remove more than the budget.
    # ALWAYS ON -- not opt-in, not environment-aware, hard ceiling of 5. A trip drops the
    # WHOLE remove set for the scope (never a partial mass-removal) and EMAILS the operator.
    # Runs for plan AND apply, so a -WhatIf plan shows the abort too.
    # A TYPE CHANGE removes the old type, so it counts against the same budget as any removal, and
    # a trip holds it whole (never "create the new type but keep the old one" -- that is the widening
    # 68.6 row 25 exists to stop). Targeted removals and type changes that are held are REPORTED as
    # failed items (they are explicit desired state that did not apply); a held PRUNE keeps its
    # original behaviour (alert only).
    $__held = New-Object System.Collections.Generic.List[object]
    $__retype = @(@($diff.update) | Where-Object { $_ -and $_.PSObject.Properties['typeChange'] -and $_.typeChange })
    $__rmTotal = @($diff.remove).Count + $__retype.Count
    $__heldCand = @(@(@($diff.remove) + $__retype) | Where-Object { $_ -and (($_.PSObject.Properties['targeted'] -and $_.targeted) -or ($_.PSObject.Properties['typeChange'] -and $_.typeChange)) })
    $__keepUpdate = @(@($diff.update) | Where-Object { -not ($_.PSObject.Properties['typeChange'] -and $_.typeChange) })
    if ($__rmTotal -gt 0 -and (Get-Command Test-PimRemoveBudgetAllowed -ErrorAction SilentlyContinue)) {
        $rb = Test-PimRemoveBudgetAllowed -ToRemove $__rmTotal -Scope $Scope -Scanned (@($live).Count) -Operation 'remove'
        if (-not $rb.allowed) {
            if (Get-Command Write-PimRemoveBudgetAlert -ErrorAction SilentlyContinue) { Write-PimRemoveBudgetAlert -Decision $rb }
            else { Write-Host ("[engine] {0}: REMOVAL BUDGET exceeded -- {1}" -f $Scope, $rb.reason) -ForegroundColor Red }
            $diff = [pscustomobject]@{ create = @($diff.create); update = $__keepUpdate; remove = @(); nochange = @($diff.nochange) }
            foreach ($__x in $__heldCand) { $__held.Add([pscustomobject]@{ item = $__x; budget = $rb.budget; toRemove = $__rmTotal }) }
            if (-not $script:__disableAborted) { $script:__disableAborted = 'remove-budget' }
        }
    }

    # Progress logging (the old engine logged every step; customers expect to see it).
    $tag = if ($WhatIf) { 'PLAN' } else { 'APPLY' }
    Write-Host ("[engine] {0,-20} {1} {2}  desired={3} live={4}  create={5} update={6} remove={7} nochange={8}" -f `
        $Scope, $Mode, $tag, @($desired).Count, @($live).Count, $diff.create.Count, $diff.update.Count, $diff.remove.Count, $diff.nochange.Count) -ForegroundColor Cyan

    $plan = New-Object System.Collections.Generic.List[object]
    $do = {
        param($op,$item,$handlerName)
        $entity = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
        if (Get-Command New-PimChange -ErrorAction SilentlyContinue) {
            $payload = if ($op -eq 'Remove') { $item.live } else { $item.desired }
            $plan.Add((New-PimChange -Entity $entity -Key "$($item.key)" -Op $op -By 'engine' -Payload $payload))
        } else { $plan.Add([pscustomobject]@{ entity=$entity; key="$($item.key)"; op=$op }) }
        $sym = switch ($op) { 'Create' { '+' } 'Update' { '~' } 'Remove' { '-' } default { '?' } }
        $__isRetype = ($op -eq 'Update' -and $item.PSObject.Properties['typeChange'] -and $item.typeChange)
        # Keep the scheduler lease alive through a long scope, and stop writing if another runner
        # has taken it (PIM-Scheduler.ps1 Invoke-PimSchedulerLeaseHeartbeat; no-op outside a tick).
        if (-not $WhatIf -and (Get-Command Invoke-PimSchedulerLeaseHeartbeat -ErrorAction SilentlyContinue) -and -not (Invoke-PimSchedulerLeaseHeartbeat)) {
            $script:__skipped++
            Write-Host ("    [s] {0} (skipped -- the scheduler lease was lost to another runner; that run applies it)" -f $item.key) -ForegroundColor DarkYellow
            return
        }
        if (-not $WhatIf -and ($p.$handlerName -or ($__isRetype -and $p.ApplyRemove -and $p.ApplyCreate))) {
            try {
                # BUG-35a: a handler that RETURNS WITHOUT ACTING must not be counted as applied.
                # AdminOffboarding's ApplyRemove does exactly that in the default Report mode --
                # it prints "would offboard" and returns -- yet the run still summarised
                # `remove=1 applied=1`, making a dry run indistinguishable from a real change in
                # the one number an operator reads. A handler now signals this by returning an
                # object carrying `pimApplied = $false`; anything else (including the API
                # responses every other handler returns) still counts as applied, so this is
                # additive and cannot change existing behaviour.
                #
                # 🔒 DO NOT "FIX" THIS BY TREATING A BARE $null AS NOT-APPLIED. That looks like the
                # obvious repair (a handler that returns nothing surely did nothing), and it is wrong.
                # SURVEYED, all 30 Apply* handlers in PIM-EngineProviders.ps1, 2026-08-27 -- TWO of
                # them ACT and legitimately return nothing, so the flip would report real changes as
                # un-applied, which is the same defect pointing the other way:
                #   * GroupOwners.ApplyCreate      -- POSTs owners/$ref, pipes it to Out-Null, and its
                #                                     success path ends on `if (-not $ok) { throw }`.
                #   * GroupsPolicies.ApplyUpdate   -- every rule goes through Invoke-PimPolicyRulePatch,
                #     (and its ApplyCreate,           which itself is `... | Out-Null; return`. This is
                #      which delegates to it)         the hottest handler there is: u112 in one run.
                # 🪤 The survey also killed the assumption that sent it looking. A Graph 204 (every
                # PATCH / DELETE / $ref POST -- Admins.ApplyUpdate+ApplyRemove, AuMembers.ApplyCreate,
                # Defender/Intune/AppRole.ApplyRemove) does NOT come back as $null: Invoke-RestMethod
                # yields the EMPTY STRING, which is non-null, so those handlers are unaffected either
                # way. Measured on pwsh 7.6.3 AND Windows PowerShell 5.1 -- both hosts agree.
                # The correct repair is the one already in use: a handler that does not act SAYS SO
                # with `pimApplied = $false`. Fixed that way in Admins.ApplyRemove (both guards) and
                # HybridAdProvisioning.ApplyCreate; AdminOffboarding + AdminTap already did.
                if ($__isRetype) {
                    # 68.6 row 25 -- TYPE CHANGE, REMOVAL FIRST. The old type goes before the new one
                    # is created, in both directions: if the second step fails the principal holds LESS
                    # than the row asks for (the next run re-creates), never MORE. Create-first would
                    # leave Eligible+Active (Eligible->Active) or keep Active (Active->Eligible) on a
                    # failed removal -- the widening this exists to stop.
                    $__rm = & $p.ApplyRemove ([pscustomobject]@{ key = "$($item.replacesKey)"; live = $item.live; typeChange = $true }) $Context
                    $__refused = @(@($__rm) | Where-Object { $null -ne $_ -and $_.PSObject -and ($_.PSObject.Properties.Name -contains 'pimApplied') -and (-not $_.pimApplied) }).Count -gt 0
                    if ($__refused) {
                        $__r = [pscustomobject]@{ pimApplied = $false; reason = "the old type ($($item.replacesKey)) was not removed, so the new type was NOT created (removal-first)" }
                    } else {
                        try { $__r = & $p.ApplyCreate $item $Context }
                        catch { throw ("type change: the old assignment '{0}' was REMOVED, but creating the new one failed (the next run retries the create): {1}" -f $item.replacesKey, $_.Exception.Message) }
                    }
                } else {
                    $__r = & $p.$handlerName $item $Context
                }
                $__reported = $false
                foreach ($__o in @($__r)) {
                    if ($null -ne $__o -and $__o.PSObject -and ($__o.PSObject.Properties.Name -contains 'pimApplied') -and (-not $__o.pimApplied)) { $__reported = $true }
                }
                if ($__reported) {
                    $script:__skipped++
                    Write-Host ("    [r] {0} (reported only -- NOT applied)" -f $item.key) -ForegroundColor DarkYellow
                } else {
                    $script:__applied++; Write-Host ("    [{0}] {1}" -f $sym, $item.key) -ForegroundColor Green
                    Write-PimEngineChangeAudit -Scope $Scope -Entity $entity -Op $op -Item $item -Result 'ok'
                    if ($op -eq 'Remove' -and $item.PSObject.Properties['targeted'] -and $item.targeted -and $null -ne $item.row -and $item.rowKey) {
                        $script:__rowDone[$item.rowKey] = 1 + [int]$script:__rowDone[$item.rowKey]; $script:__rowObj[$item.rowKey] = $item.row
                    }
                }
            }
            catch {
                $em = "$($_.Exception.Message)"
                # Already-exists / conflict = the desired setting is already in place -> validate-and-skip,
                # not a failure (idempotent re-run). Mirrors the legacy "RoleAssignmentExists ... skipping".
                if ($em -match '(?i)RoleAssignmentExists|already exist|references already exist|ConflictingObjects|existing assignment|A conflicting object|RoleAssignmentRequestPolicyValidationFailed.*active|The Role assignment already exists') {
                    $script:__skipped++; Write-Host ("    [=] {0} (exists -- validated, skipped)" -f $item.key) -ForegroundColor DarkGray
                } else {
                    # 🔴 §70.19 (2026-09-13): "Nesting is currently not supported" (an ACTIVE group nesting into a
                    # role-assignable group) used to be a separate branch that counted a SKIP and printed a yellow
                    # line. The delegation never deployed, the job read ok, the Manager's Engine errors showed
                    # nothing, and only verify-convergence complained 18 hours later with no cause. It is a
                    # failure of the row, so it is recorded like one: ENTRA-NESTING-ROLE-ASSIGNABLE, fix = Eligible.
                    $script:__errors++; Write-Host ("    [x] {0} {1} FAILED: {2}" -f $op, $item.key, $em) -ForegroundColor Red
                    Write-PimEngineChangeAudit -Scope $Scope -Entity $entity -Op $op -Item $item -Result 'error' -ErrorMessage $em
                    # Keep WHAT failed and WHY as data, not only as a log line nobody can reach from the
                    # Manager (operator, 2026-09-12: "the eror msg was useless"). PIM-FailureCatalog.ps1.
                    if (Get-Command New-PimEngineItemFailure -ErrorAction SilentlyContinue) {
                        # A targeted removal carries the Remove ROW it came from -- that is the row the
                        # operator can find (and fix) in the grid, not the live object.
                        $__row = if ($op -eq 'Remove') { if ($null -ne $item.row) { $item.row } else { $item.live } } else { $item.desired }
                        # The item's failure is already COUNTED above; only its classification is lost here,
                        # and that must be said rather than swallowed.
                        try { $script:__failures.Add((New-PimEngineItemFailure -Scope $Scope -Entity $entity -Op $op -Key "$($item.key)" -Message $em -Row $__row)) }
                        catch { Write-Warning ("    [engine] could not classify the failure of {0}: {1}" -f $item.key, $_.Exception.Message) }
                    }
                }
            }
        } else {
            Write-Host ("    [{0}] {1} (plan)" -f $sym, $item.key) -ForegroundColor DarkGray
        }
    }
    $script:__applied = 0; $script:__errors = 0; $script:__skipped = 0
    $script:__failures = New-Object System.Collections.Generic.List[object]
    $script:__rowDone = @{}; $script:__rowObj = @{}   # Remove rows: revoked item count + the row, by row key
    # Held by the removal budget (68.6 row 24): explicit Remove rows / type changes that did NOT apply.
    # A plan (WhatIf) only shows them; an apply counts each as a failed item with the reason, so the
    # job cannot read as "done" while the rows it was asked to apply were held.
    foreach ($__h in $__held) {
        $__it = $__h.item
        $__hOp = if ($__it.PSObject.Properties['desired'] -and $null -ne $__it.desired) { 'Update' } else { 'Remove' }
        $__what = if ($__it.PSObject.Properties['typeChange'] -and $__it.typeChange) { 'type change (removes the old assignment type)' } else { 'Remove row' }
        $__hMsg = ("REMOVE-BUDGET-HELD: {0} NOT applied -- this run would remove {1} item(s) in scope '{2}', over the per-run removal budget of {3}, so NOTHING was removed in this scope. Check that the Remove rows and assignment-type changes for this scope are intended, then apply them in batches of at most {3}." -f $__what, $__h.toRemove, $Scope, $__h.budget)
        Write-Host ("    [h] {0} HELD: {1}" -f $__it.key, $__hMsg) -ForegroundColor Red
        if ($WhatIf) { continue }
        $script:__errors++
        if (Get-Command New-PimEngineItemFailure -ErrorAction SilentlyContinue) {
            $__hRow = if ($__it.PSObject.Properties['row'] -and $null -ne $__it.row) { $__it.row } elseif ($__hOp -eq 'Update') { $__it.desired } else { $__it.live }
            $__hEnt = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
            try { $script:__failures.Add((New-PimEngineItemFailure -Scope $Scope -Entity $__hEnt -Op $__hOp -Key "$($__it.key)" -Message $__hMsg -Row $__hRow)) }
            catch { Write-Warning ("    [engine] could not classify the held item {0}: {1}" -f $__it.key, $_.Exception.Message) }
        }
    }
    foreach ($i in $diff.create) { & $do 'Create' $i 'ApplyCreate' }
    foreach ($i in $diff.update) { & $do 'Update' $i 'ApplyUpdate' }
    foreach ($i in $diff.remove) { & $do 'Remove' $i 'ApplyRemove' }   # only present in Full
    # A Remove row REVOKES a delegation and is then DELETED, so nothing re-applies it (operator 2026-09-13:
    # "remove was to revoke a delegation which must be removed deleted so it doesnt reapply"; in the old
    # files the rows were forgotten after the first run). Deleted only when EVERY live item it names
    # (eligible and active) was revoked, or nothing was live. Held, failed or refused revokes keep the row.
    $__rowsDone = 0
    if (-not $WhatIf) {
        $__fullyDone = @(foreach ($__rk in @($script:__rowDone.Keys)) { if ([int]$script:__rowDone[$__rk] -ge [int]$__rowTotal[$__rk]) { $script:__rowObj[$__rk] } })
        $__doneRows = @(@($__fullyDone) + @(@($__absent) | ForEach-Object { $_.row }) | Where-Object { $null -ne $_ })
        if ($__doneRows.Count) {
            $__rdEnt = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
            $__rowsDone = Complete-PimRemoveRows -Entity $__rdEnt -Rows $__doneRows -Scope $Scope
        }
    }
    Write-Host ("[engine] {0,-20} done  applied={1} skipped={2} errors={3}" -f $Scope, $script:__applied, $script:__skipped, $script:__errors) -ForegroundColor $(if ($script:__errors) { 'Yellow' } else { 'Green' })
    # The CURRENTLY-FAILING set for this scope (SQL). A WhatIf run applied nothing, so it proves nothing
    # about what is failing and must not clear or replace the record.
    if (-not $WhatIf -and (Get-Command Update-PimEngineItemFailures -ErrorAction SilentlyContinue)) {
        [void](Update-PimEngineItemFailures -Scope $Scope -Failures $script:__failures.ToArray())
    }

    return [pscustomobject]@{
        scope=$Scope; mode=$Mode; whatIf=[bool]$WhatIf
        create=$diff.create.Count; update=$diff.update.Count; remove=$diff.remove.Count; nochange=$diff.nochange.Count
        applied=$script:__applied; skipped=$script:__skipped; errors=$script:__errors; plan=$plan.ToArray(); ok=($script:__errors -eq 0)
        disableAborted=$script:__disableAborted
        failures=$script:__failures.ToArray()
        held=$__held.Count; absent=$__absent.Count; conflicts=$__conflicts.Count
        removeRowsDone=$__rowsDone
    }
}

function Complete-PimRemoveRows {
    <#
      Delete Remove rows whose work is done. Each row is re-read by its store key first and deleted ONLY if
      it still says Action=Remove -- a row somebody changed back to Assign since this run read it is kept.
      SQL store when active (audited), else the in-memory desired rows used offline. Returns the count.
    #>
    param([Parameter(Mandatory)][string]$Entity, [object[]]$Rows = @(), [string]$Scope = '')
    $isRemove = {
        param($r)
        $a = if ($r -is [System.Collections.IDictionary]) { $r['Action'] } else { $pp = $r.PSObject.Properties['Action']; if ($pp) { $pp.Value } else { $null } }
        "$a".Trim() -ieq 'Remove'
    }
    $cs = $null
    if ((Get-Command Get-PimSqlRow -ErrorAction SilentlyContinue) -and (Get-Command Remove-PimSqlRow -ErrorAction SilentlyContinue)) {
        $cs = if ($global:PIM_EngineSqlCs) { $global:PIM_EngineSqlCs }
              elseif ($global:PIM_SqlConnectionString) { $global:PIM_SqlConnectionString }
              elseif ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and ($global:PIM_SqlServer -or $global:PIM_SqlConnStringVault)) { Get-PimSqlConnectionString }
              else { $null }
    }
    $deleted = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r -or -not (& $isRemove $r)) { continue }
        if ($cs) {
            $key = if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) { "$(Get-PimStoreRowKey -Base $Entity -Row $r)".Trim() } else { '' }
            if (-not $key) { Write-Warning ("  [engine] {0}: a finished Remove row in '{1}' has no store key -- it was NOT deleted; delete it by hand." -f $Scope, $Entity); continue }
            try {
                $cur = Get-PimSqlRow -ConnectionString $cs -Entity $Entity -Key $key
                if ($null -eq $cur -or -not (& $isRemove $cur)) { continue }
                Remove-PimSqlRow -ConnectionString $cs -Entity $Entity -Key $key
                $deleted.Add($key)
                if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
                    try { [void](Write-PimAuditEvent -Action 'row.remove.completed' -Target "$Entity|$key" -Before $cur) } catch { Write-Warning ("  [engine] Remove row '{0}' deleted but NOT audited: {1}" -f $key, $_.Exception.Message) }
                }
            } catch { Write-Warning ("  [engine] {0}: could not delete the finished Remove row '{1}' from '{2}' (it stays and is re-checked next run): {3}" -f $Scope, $key, $Entity, $_.Exception.Message) }
        } elseif ($global:PIM_DesiredRows -is [hashtable] -and $global:PIM_DesiredRows.ContainsKey($Entity)) {
            # Offline store: match by row CONTENT (the pipeline may re-wrap the object) and drop one copy.
            $want = $r | ConvertTo-Json -Depth 8 -Compress
            $kept = New-Object System.Collections.Generic.List[object]; $hit = $false
            foreach ($x in @($global:PIM_DesiredRows[$Entity])) {
                if (-not $hit -and $null -ne $x -and ($x | ConvertTo-Json -Depth 8 -Compress) -eq $want) { $hit = $true; continue }
                $kept.Add($x)
            }
            if ($hit) { $global:PIM_DesiredRows[$Entity] = $kept.ToArray(); $deleted.Add('(in-memory)') }
        }
    }
    if ($deleted.Count) {
        Write-Host ("[engine] {0}: {1} Remove row(s) done -- deleted from {2} (a Remove row is a one-time task)" -f $Scope, $deleted.Count, $Entity) -ForegroundColor DarkCyan
    }
    return $deleted.Count
}

function Get-PimEngineQueueChanges {
    # Pull PENDING commit-queue rows as {Entity,Key} pairs for a queue-fed delta. Uses
    # the SQL change queue when available; returns @() otherwise.
    param([string]$ConnectionString)
    $cs = if ($ConnectionString) { $ConnectionString }
          elseif ($global:PIM_EngineSqlCs) { $global:PIM_EngineSqlCs }
          elseif ($global:PIM_SqlConnectionString) { $global:PIM_SqlConnectionString }
          elseif (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) { Get-PimSqlConnectionString }
          else { $null }
    if (-not $cs -or -not (Get-Command Get-PimSqlChangeQueue -ErrorAction SilentlyContinue)) { return @() }
    try { return @(Get-PimSqlChangeQueue -ConnectionString $cs -Status 'pending' | ForEach-Object { [pscustomobject]@{ Entity = "$($_.Entity)"; Key = "$($_.Key)" } }) }
    catch { Write-Warning "  [engine] queue read failed: $($_.Exception.Message)"; return @() }
}

function Invoke-PimEngineDiscoverySweep {
    # End-of-run discovery sweep (REQUIREMENTS §8): enumerate Azure scopes + Power BI
    # workspaces (LIVE, best-effort), reconcile against the existing definitions, and run
    # each reconcile plan through the per-resource-type AUTO-CREATE policy
    # ($global:PIM_DiscoveryAutoCreate; default 'flag' for every type). Emits
    # resource.discovered / resource.autocreate run-log lines. 'pending' stages a desired
    # row for review; 'auto' enqueues a Create on the normal change queue (no prune from
    # this path). Skipped entirely when every type's policy is 'flag' (nothing to stage)
    # AND there is nothing to flag -- but we always RUN it so new resources are at least
    # flagged, matching the legacy resource.discovered behaviour. -WhatIf logs only.
    [CmdletBinding()]
    param([switch]$WhatIf, [string]$ConnectionString)
    if (-not (Get-Command Resolve-PimDiscoveryPolicyPlan -ErrorAction SilentlyContinue)) { return }
    # --- FEATURE GATE (REQUIREMENTS s29) -- discovery sweep is an advanced feature.
    # Disabled/unlicensed => the whole sweep no-ops (no enumeration, no auto-create).
    if ((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and -not (Test-PimFeatureAvailable -Key 'discovery.sweep')) {
        return
    }
    $cs = if ("$ConnectionString".Trim()) { $ConnectionString }
          elseif ($global:PIM_EngineSqlCs) { $global:PIM_EngineSqlCs }
          elseif ($global:PIM_SqlConnectionString) { $global:PIM_SqlConnectionString }
          else { $null }
    $policyMap = $global:PIM_DiscoveryAutoCreate
    Write-Host "[engine] discovery sweep        per-type auto-create policy (default flag)" -ForegroundColor Cyan
    # Existing resource definitions (for reconcile create/rename/orphan). Best-effort.
    $existing = @()
    if ($cs -and (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) {
        try { $existing = @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Definitions-Resources') } catch {}
    }
    # --- Azure subscriptions / management groups ---
    if (Get-Command Get-PimLiveAzureScopes -ErrorAction SilentlyContinue) {
        $az = @()
        try { $az = @(Get-PimLiveAzureScopes -IncludeManagementGroups) } catch { Write-Warning "  [discovery] Azure scope enumeration failed: $($_.Exception.Message)" }
        if (@($az).Count) {
            try {
                $plan = Get-PimAzureReconcilePlan -Discovered $az -Existing $existing
                [void](Invoke-PimDiscoveryAutoCreate -Plan $plan -PolicyMap $policyMap -DefinitionEntity 'PIM-Definitions-Resources' -ConnectionString $cs -WhatIf:$WhatIf)
            } catch { Write-Warning "  [discovery] Azure reconcile failed: $($_.Exception.Message)" }
        }
    }
    # --- Power BI workspaces ---
    # Power BI is its own advanced (Pro) connector feature: skip just this part when
    # it is disabled/unlicensed even if the overall discovery sweep is on.
    $pbiOk = (-not (Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue)) -or (Test-PimFeatureAvailable -Key 'connectors.powerbi' -Quiet)
    if ($pbiOk -and (Get-Command Get-PimLivePowerBiWorkspaces -ErrorAction SilentlyContinue)) {
        $ws = @()
        try { $ws = @(Get-PimLivePowerBiWorkspaces) } catch { Write-Warning "  [discovery] Power BI enumeration failed: $($_.Exception.Message)" }
        if (@($ws).Count) {
            try {
                $plan = Get-PimPowerBiReconcilePlan -Discovered $ws -Existing $existing
                [void](Invoke-PimDiscoveryAutoCreate -Plan $plan -PolicyMap $policyMap -ResourceType 'PowerBIWorkspace' -DefinitionEntity 'PIM-Definitions-Resources' -ConnectionString $cs -WhatIf:$WhatIf)
            } catch { Write-Warning "  [discovery] Power BI reconcile failed: $($_.Exception.Message)" }
        }
    }
}

function Get-PimContextMaxAgeSeconds {
    # BUG-19: how stale the directory snapshot may be when an engine run STARTS.
    # Small on purpose: this is a per-run freshness bound, not the 5-minute cache
    # window Build-PimContext applies to incidental callers. It exists as a knob
    # only so a caller that fans out one Invoke-PimEngine per scope inside a
    # single tick does not re-fetch the directory 19 times.
    $v = $global:PIM_ContextMaxAgeSeconds
    if ($null -eq $v -or "$v" -eq '') { return 30 }
    $n = 0; if (-not [int]::TryParse("$v", [ref]$n)) { return 30 }
    if ($n -lt 0) { return 0 }
    return $n
}

function Update-PimEngineRunContext {
    # BUG-19 -- REFRESH THE DIRECTORY SNAPSHOT AT THE START OF EVERY ENGINE RUN.
    #
    # Before this, the ONLY path that ever built the context was
    # Ensure-PimContextLoaded, whose whole body is
    #     if (-not $Global:PimContextBuiltAt) { Build-PimContext }
    # -- no -Refresh, no age check. So the FIRST build in a process was the LAST:
    # Build-PimContext's own -Refresh/$CacheSeconds were unreachable on this path,
    # and the scheduler (a while($true) loop that calls Invoke-PimEngine IN-PROCESS
    # every $IntervalSeconds) kept reconciling against the directory as it looked
    # when the container started -- for the life of the container.
    #
    # What that cost, observed live 2026-08-06: after two AUs were deleted out of
    # band, five consecutive passes reported "AdministrativeUnits live=18 create=0
    # nochange=2" for AUs that no longer existed, and every dependent member write
    # 404'd on the dead ids. "nochange" is the one word an operator reads as
    # reconciled, so a stale snapshot is worse than a failure.
    #
    # Deliberately at the RUN boundary, not per scope: every scope in one run then
    # shares a single consistent snapshot (a mid-run re-fetch could hand a later
    # scope a directory that does not contain what an earlier scope just created,
    # and Entra's list endpoints lag creates by seconds -- see TEST-16).
    [CmdletBinding()]
    param([switch]$Quiet)
    if (-not (Get-Command Build-PimContext -ErrorAction SilentlyContinue)) { return $false }
    $maxAge = Get-PimContextMaxAgeSeconds
    try {
        Build-PimContext -CacheSeconds $maxAge | Out-Null
        return $true
    } catch {
        # Never fail a run because the refresh failed: an older snapshot still
        # beats no run at all. But SAY so -- silence here is how BUG-19 hid.
        if (-not $Quiet) { Write-Warning "  [engine] directory-context refresh failed: $($_.Exception.Message) -- continuing on the previous snapshot (age unknown)" }
        return $false
    }
}

function Invoke-PimEngine {
    # Run one scope, or all registered scopes (Scope='All').
    #   -Mode Full           : whole-scope reconcile (create/update; prune ONLY with -Prune)
    #   -Mode Full -Prune    : also REMOVE live items not in the desired set (destructive,
    #                          opt-in -- guarded so a partial desired set can't disable real
    #                          admins; an empty desired scope is never pruned)
    #   -Mode Delta          : create/update everything that differs (no prune)
    #   -Mode Delta -FromQueue / -Changes : apply ONLY the queued (entity,key) changes
    # -WhatIf = plan only. This is the entrypoint the scheduler/launcher calls.
    [CmdletBinding()]
    param([string]$Scope='All', [ValidateSet('Full','Delta')][string]$Mode='Delta', [switch]$WhatIf, [switch]$Prune, [hashtable]$Context=@{}, [object[]]$Changes, [switch]$FromQueue)
    # BUG-19: bound how stale the directory snapshot can be at the start of a run.
    [void](Update-PimEngineRunContext)
    if ($FromQueue -and -not $PSBoundParameters.ContainsKey('Changes')) { $Changes = Get-PimEngineQueueChanges }
    $useChanges = ($FromQueue -or $PSBoundParameters.ContainsKey('Changes'))
    $common = @{ Mode = $Mode; WhatIf = $WhatIf; Prune = $Prune; Context = $Context }
    if ($useChanges) { $common['Changes'] = @($Changes) }

    # 🔴 BUG-134: AN UNSERVED SCOPE IS A CONFIGURATION ERROR, NOT AN EMPTY RESULT.
    # This used to fall straight through to Invoke-PimEngineScope, which answers an unknown
    # scope with { ok=$false; detail='no provider...' } and NO counts -- and every caller
    # (scheduler, launcher, queue-apply) formatted the blank counts and moved on. Three shipped
    # jobs pointed at v1 CSV scope names the REST engine never registered, so they did nothing
    # for months while reporting success. Resolve (translating the known v1 names) and THROW on
    # anything that still doesn't bind, so a misconfigured scope fails loudly on its first tick.
    # See Get-PimEngineScopeAliasMap for the measurement and why the fix lives at resolve time.
    $res = Resolve-PimEngineScope -Scope $Scope
    if (-not $res.ok) { throw "[engine] $($res.detail)" }
    if ($res.alias) { Write-Host "[engine] $($res.detail)" -ForegroundColor Yellow }

    $out = New-Object System.Collections.Generic.List[object]
    $__nScopes = @($res.scopes).Count; $__iScope = 0
    foreach ($s in @($res.scopes)) {
        $out.Add((Invoke-PimEngineScope -Scope $s @common))
        $__iScope++
        # §70.22: a scheduler tick sets this so committed queue actions (TAP re-issue, revoke) are applied between the
        # scopes of a long multi-scope run instead of after it. Never on the last scope, never in a plan; output discarded.
        if ($__iScope -lt $__nScopes -and -not $WhatIf -and $global:PIM_BetweenScopesHook -is [scriptblock]) {
            try { $null = @(& $global:PIM_BetweenScopesHook) } catch { Write-Verbose "between-scopes hook: $($_.Exception.Message)" }
        }
    }
    # Preserve the single-scope return shape callers depend on (one object, not a 1-element array).
    if (@($res.scopes).Count -eq 1 -and -not $res.alias) { return $out[0] }
    return $out.ToArray()
}
