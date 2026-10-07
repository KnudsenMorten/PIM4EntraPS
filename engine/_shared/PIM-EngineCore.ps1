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
# §88 commit watcher: the engine records what it did with every WATCHED key (free; loaded with the core).
if (-not (Get-Command Update-PimCommitOutcomes -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-CommitWatch.ps1'))) { . (Join-Path $PSScriptRoot 'PIM-CommitWatch.ps1') }
# SEC-80: a prune removes only what PIM manages (the managed-key ledger). Loaded with the core so no run prunes without it.
if (-not (Get-Command Split-PimPruneByLedger -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-ManagedKeys.ps1'))) { . (Join-Path $PSScriptRoot 'PIM-ManagedKeys.ps1') }
# §96.6 / GUARD-1.6: releasing a guard (one guard, one scope, one run or until <= 24 h, bound to the plan hash). Loaded with
# the core so a held plan is always recorded for the Guards page and a release is always honoured.
if (-not (Get-Command Invoke-PimGuardHoldOrRelease -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-GuardRelease.ps1'))) { . (Join-Path $PSScriptRoot 'PIM-GuardRelease.ps1') }
# Ledger confirmations (D2) need the newer ledger functions even where an older copy was loaded first.
if (-not (Get-Command Set-PimManagedKeyConfirmations -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-ManagedKeys.ps1'))) { . (Join-Path $PSScriptRoot 'PIM-ManagedKeys.ps1') }
# CONFIG-1.1 / 96.1: the applied outcome per row + the per-key commit resolution (BUG-294) read the change journal.
if (-not (Get-Command Resolve-PimJournalCommitForKey -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-CommitJournal.ps1'))) { . (Join-Path $PSScriptRoot 'PIM-CommitJournal.ps1') }
# 96.5: the daily reconcile's removal of PIM-managed leftovers (report-only by default) is planned inside the scope pass.
if (-not (Get-Command Get-PimReconcileRemovalPlan -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PIM-ReconcileRemoval.ps1'))) { . (Join-Path $PSScriptRoot 'PIM-ReconcileRemoval.ps1') }

# ---- pure diff core (testable, no I/O) ------------------------------------
function Get-PimChangeFieldDiff {
    <#
      §79.3 (operator 2026-09-25: mails must carry "detailed information like configuration drift"). A drift
      'changed' item used to say only WHICH object differs. This names HOW: every scalar field present on both
      sides whose value differs, as "Field: live -> desired". Pure; a provider's shapes may be hashtables or
      objects. Collections and nested objects are skipped (their text form is not a readable difference), and the
      list is capped so one exotic row cannot bloat the stored drift document.
    #>
    param([AllowNull()][object]$Live, [AllowNull()][object]$Desired, [int]$Max = 6)
    if ($null -eq $Live -or $null -eq $Desired) { return '' }
    $props = {
        param($o)
        $h = [ordered]@{}
        if ($o -is [System.Collections.IDictionary]) { foreach ($k in $o.Keys) { $h["$k"] = $o[$k] } }
        else { foreach ($p in $o.PSObject.Properties) { $h[$p.Name] = $p.Value } }
        $h
    }
    $l = & $props $Live; $d = & $props $Desired
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($k in $d.Keys) {
        if (-not $l.Contains($k)) { continue }
        $dv = $d[$k]; $lv = $l[$k]
        $scalar = { param($v) $null -eq $v -or $v -is [string] -or $v -is [ValueType] }
        if (-not ((& $scalar $dv) -and (& $scalar $lv))) { continue }
        if ("$lv" -ceq "$dv") { continue }
        $show = { param($v) $s = "$v"; if (-not $s.Trim()) { '(empty)' } elseif ($s.Length -gt 60) { $s.Substring(0, 57) + '...' } else { $s } }
        $out.Add(("{0}: {1} -> {2}" -f $k, (& $show $lv), (& $show $dv)))
        if ($out.Count -ge $Max) { break }
    }
    return ($out -join '; ')
}

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

    # ---- THE OTHER ASSIGNMENT TYPE IS A SEPARATE DELEGATION, NOT A REPLACEMENT ------------
    # 🔴 OPERATOR, 2026-09-20 -- THE TYPE-CHANGE RULE IS WITHDRAWN. It used to work like this:
    # a desired row with no live match of its OWN type, but whose group+role existed live with the
    # OTHER type, was not a create -- it was paired with that live item as a "type change", and the
    # orchestrator DELETED the live assignment before creating the new one (68.6 row 25).
    #
    # That made the engine decide, by itself, to destroy live privileged access. Two things are wrong
    # with it, and the operator named both:
    #   1. "we must support the same delegation in both active and eligible types, that is very common,
    #      not a mistake, so dont replace that" -- e.g. Active at the AU (L2) and Eligible at L1 for the
    #      same delegation. Both types coexisting is a SUPPORTED design, so the other type is never
    #      evidence that this row supersedes it.
    #   2. "engine can newer make such a judgement automatic. it can only be done from operator."
    #      Nobody wrote "remove". The row carries a TYPE; the deletion was inferred from a mismatch --
    #      and a mismatch has causes that are not a decision at all: an incomplete live read (MEASURED
    #      on internal 2026-09-19 23:33, where a short preload turned 9 correct Eligible assignments
    #      into 9 planned deletions), a wizard default, a v1 import, or Entra refusing Active on a
    #      role-assignable group -- which mismatches FOREVER, so it retried the delete on every run.
    #
    # So a desired row whose own type is not live is simply a CREATE. The live item of the other type
    # is left exactly as it is. The ONLY way a live assignment is removed is an explicit Action=Remove
    # row the operator staged and committed (the -RemoveRows path below), which is unchanged.
    # 🪤 -RemoveTypeLeftovers went with it: its whole job was to delete "the other type", which is the
    # very thing that is now supported. It is accepted and IGNORED so an environment that still carries
    # the setting keeps starting; tests/Test-PimAssignmentParity.ps1 pins that it removes nothing.
    if ($TypeKeyOf -and $RemoveTypeLeftovers) {
        Write-Host '  [engine] RemoveTypeLeftovers is set but is NO LONGER HONOURED: both assignment types for one delegation are supported, and only an Action=Remove row removes an assignment.' -ForegroundColor DarkYellow
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
    # REQUIREMENTS 68.6 row 35: central admins imported from a managing tenant live in their OWN entity,
    # separate from the managed tenant's Account-Definitions-Admins. Identical literal in PIM-Downlink.ps1
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
    # 68.6 row 35 -- the admin definitions a managed tenant governs are ITS OWN rows plus the central admins
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
          # The central-admin entity is legitimately absent everywhere except on a managed tenant, so
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
        # AUDIT-1 actor (operator 2026-10-05: "actor must be the person who a) triggered it and b) approved it if enabled"):
        # the commit that asked for this change names the person; the engine is only the one that carried it out. The
        # attribution index is read once per run. No commit names it (a reconcile, an expiry): the actor stays 'engine'.
        $actor = 'engine'
        $after['jobRun'] = $corr
        # BUG-294 (96.1): the commit is resolved per key AND per operation from the change journal (a create credits the
        # commit that added the row); the latest-wins attribution answers only where the journal does not.
        try {
            $att = Resolve-PimEngineChangeCommit -Entity $Entity -Op $Op -Row $row
            if ($att) {
                $actor = "$($att.InitiatedBy)"
                $after['initiatedBy'] = "$($att.InitiatedBy)"
                if ("$($att.ApprovedBy)".Trim()) { $after['approvedBy'] = "$($att.ApprovedBy)" }
                $after['commitId'] = "$($att.CommitId)"
                $after['appliedBy'] = 'engine'
                $after['commitFrom'] = "$($att.via)"
                $corr = "$($att.CommitId)"
            } else { $after['initiatedBy'] = 'engine (no commit names this change: a scheduled reconcile or an automatic step)' }
        } catch { $actor = 'engine' }
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action $action -Target $target -After $after -Result $Result -Actor $actor -CorrelationId $corr | Out-Null
            return
        }
        $cs = $null
        if ("$($global:PIM_EngineSqlCs)".Trim()) { $cs = "$($global:PIM_EngineSqlCs)" }
        elseif ("$($global:PIM_SqlConnectionString)".Trim()) { $cs = "$($global:PIM_SqlConnectionString)" }
        if ($cs -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
            Write-PimSqlAuditEvent -ConnectionString $cs -Actor $actor -ActorSource 'engine' -Action $action -Target $target -After $after -Result $Result -CorrelationId $corr
        }
    } catch { Write-Warning ("    [audit] engine change {0} {1} was NOT recorded: {2}" -f $Op, $(if ($Item) { $Item.key } else { '' }), $_.Exception.Message) }
}

function Get-PimEngineItemStoreRefs {
    <#
      The stored row(s) an engine item may have come from, as @(@{ entity; key }): the row's SourceEntity, then the item's
      entity, each with Get-PimStoreRowKey of the row (the same mapping the attribution uses). Empty when nothing maps.
    #>
    param([string]$Entity, [AllowNull()][object]$Row)
    if ($null -eq $Row -or -not (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue)) { return @() }
    $f = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { "$($o[$n])" } elseif ($o.PSObject.Properties[$n]) { "$($o.$n)" } else { '' } }
    $bases = New-Object System.Collections.Generic.List[string]
    $se = (& $f $Row 'SourceEntity').Trim(); if ($se) { $bases.Add($se) }
    if ("$Entity".Trim() -and -not ($bases -contains "$Entity".Trim())) { $bases.Add("$Entity".Trim()) }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($b in $bases) {
        $k = ''; try { $k = "$(Get-PimStoreRowKey -Base $b -Row $Row)".Trim() } catch { $k = '' }
        if ($k) { $out.Add(@{ entity = $b; key = $k }) }
    }
    return @($out.ToArray())
}

function ConvertTo-PimJournalRowArray {
    # pwsh 7 throws "Argument types do not match" on @() over a List[object] taken from a hashtable -- .ToArray() it.
    param([AllowNull()][object]$Rows)
    if ($null -eq $Rows) { return ,@() }
    if ($Rows -is [System.Collections.Generic.List[object]]) { return ,$Rows.ToArray() }
    return ,@($Rows)
}

function Resolve-PimEngineChangeCommit {
    <#
      Which commit asked for this change? (96.1 / BUG-294). Reads the change journal (recent window) and the attribution once
      per engine run (the job's correlation id), then:
        1. the JOURNAL, per store row the item maps to (Get-PimEngineItemStoreRefs) and per operation
           (Resolve-PimJournalCommitForKey: a create credits the commit that ADDED the row); for the definitions family
           also by group tag across every PIM-Definitions-* entity;
        2. else the latest-wins ATTRIBUTION (pim.ChangeAttribution, incl. the 'name:<GroupName>' alias).
      Returns { CommitId; InitiatedBy; ApprovedBy; CommittedUtc; Entity; Key; via = journal | attribution } or $null.
    #>
    param([string]$Entity, [string]$Op = '', [AllowNull()][object]$Row)
    if ($null -eq $Row) { return $null }
    $corr = "$($global:PIM_JobCorrelationId)"
    $acs = if ("$($global:PIM_EngineSqlCs)".Trim()) { "$($global:PIM_EngineSqlCs)" } elseif ("$($global:PIM_SqlConnectionString)".Trim()) { "$($global:PIM_SqlConnectionString)" } else { '' }
    if (Get-Command Get-PimCommitJournalKeyIndex -ErrorAction SilentlyContinue) {
        if ("$($global:PIM_CommitJournalKeyIndexRun)" -ne $corr -or $null -eq $global:PIM_CommitJournalKeyIndex) {
            $global:PIM_CommitJournalKeyIndex = if ($acs) { Get-PimCommitJournalKeyIndex -ConnectionString $acs } else { @{} }
            $global:PIM_CommitJournalKeyIndexRun = $corr
        }
    }
    $jix = $global:PIM_CommitJournalKeyIndex
    if ($jix -is [hashtable] -and $jix.Count -and (Get-Command Resolve-PimJournalCommitForKey -ErrorAction SilentlyContinue)) {
        $refs = @(Get-PimEngineItemStoreRefs -Entity $Entity -Row $Row)
        foreach ($ref in $refs) {
            $h = $jix[("{0}|{1}" -f $ref.entity, $ref.key).ToLowerInvariant()]
            if ($h) {
                $j = Resolve-PimJournalCommitForKey -History (ConvertTo-PimJournalRowArray $h) -Op $Op
                if ($j) { return [pscustomobject]@{ CommitId = "$($j.CommitId)"; InitiatedBy = "$($j.InitiatedBy)"; ApprovedBy = $j.ApprovedBy; CommittedUtc = $j.CommittedUtc; Entity = "$($j.Entity)"; Key = "$($j.Key)"; via = 'journal' } }
            }
        }
        # The definitions family: a policy / owner / AU change names the group, not the definitions entity it is stored in.
        $rf = { param($n) if ($Row -is [System.Collections.IDictionary]) { "$($Row[$n])" } elseif ($Row.PSObject.Properties[$n]) { "$($Row.$n)" } else { '' } }
        $fam = @(@((& $rf 'SourceEntity'), "$Entity") | Where-Object { $_ -match '^(?i)PIM-Definitions' })
        $tag = & $rf 'GroupTag'
        if ($fam.Count -and "$tag".Trim()) {
            $best = $null
            foreach ($ik in @($jix.Keys)) {
                $parts = $ik.Split('|', 2)
                if ($parts.Count -eq 2 -and $parts[0] -like 'pim-definitions-*' -and $parts[1] -eq "$tag".Trim().ToLowerInvariant()) {
                    $j = Resolve-PimJournalCommitForKey -History (ConvertTo-PimJournalRowArray $jix[$ik]) -Op $Op
                    if ($j -and (-not $best -or [long]$j.Id -gt [long]$best.Id)) { $best = $j }
                }
            }
            if ($best) { return [pscustomobject]@{ CommitId = "$($best.CommitId)"; InitiatedBy = "$($best.InitiatedBy)"; ApprovedBy = $best.ApprovedBy; CommittedUtc = $best.CommittedUtc; Entity = "$($best.Entity)"; Key = "$($best.Key)"; via = 'journal' } }
        }
    }
    if (Get-Command Resolve-PimChangeAttribution -ErrorAction SilentlyContinue) {
        if ("$($global:PIM_ChangeAttributionRun)" -ne $corr -or $null -eq $global:PIM_ChangeAttributionIndex) {
            $global:PIM_ChangeAttributionIndex = if ($acs -and (Get-Command Get-PimChangeAttributionIndex -ErrorAction SilentlyContinue)) { Get-PimChangeAttributionIndex -ConnectionString $acs } else { @{} }
            $global:PIM_ChangeAttributionRun = $corr
        }
        $att = Resolve-PimChangeAttribution -Index $global:PIM_ChangeAttributionIndex -Entity $Entity -Row $Row
        if ($att) { return [pscustomobject]@{ CommitId = "$($att.CommitId)"; InitiatedBy = "$($att.InitiatedBy)"; ApprovedBy = $att.ApprovedBy; CommittedUtc = $att.CommittedUtc; Entity = "$($att.Entity)"; Key = "$($att.Key)"; via = 'attribution' } }
    }
    return $null
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
        [object[]]$Changes,
        # 96.5 purpose 2 -- only the daily reconcile passes it: 'report' plans + reports which PIM-managed leftovers it WOULD
        # remove (nothing is removed); 'enforce' also removes the ones every rule allows. Empty = not a reconcile.
        [string]$ReconcileRemoval = ''
    )
    $__rrMode = "$ReconcileRemoval".Trim().ToLowerInvariant()
    if ($__rrMode -and $__rrMode -ne 'enforce') { $__rrMode = 'report' }
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
            # REQ-U (2026-09-19): the skip carries its REASON (skippedReason) so the drift snapshot can say
            # "not checked -- <reason>" instead of counting a gated area as checked and clean.
            return [pscustomobject]@{ scope=$Scope; mode=$Mode; whatIf=[bool]$WhatIf; create=0; update=0; remove=0; nochange=0; applied=0; skipped=0; errors=0; plan=@(); ok=$true
                skippedFeature="$($p.feature)"; skippedReason=(Get-PimFeatureSkipReason -Key "$($p.feature)"); notChecked=$true }
        }
    }
    # REQ-U: per-scope warnings a provider raises (e.g. the Groups provider keeping a workload group whose binding
    # provider is gated off) travel back in the scope result, so the run's job log / alerting can name them.
    $Context['__pimScopeWarnings'] = New-Object System.Collections.Generic.List[string]
    $Context['__pimLiveReadError'] = $null
    # Per-scope read-quality flags (the Context is shared by every scope of a run): a partial read in one scope must not
    # be taken for one in the next. SEC-80: __pimLiveNarrowed = the provider read only the principals the rows name.
    $Context['__pimLiveIncomplete'] = $null; $Context['__pimLiveNarrowed'] = $false
    # REQ-U wave 2: structured live FINDINGS a provider raises from its own live read (the workload providers' orphan
    # group / unmanaged binding / wrong permissions warnings). They travel back as the scope result's `findings`; the
    # drift snapshot lists and counts them (PIM-DriftSnapshot.ps1).
    $Context['__pimLiveFindings'] = New-Object System.Collections.Generic.List[object]
    # REQ-WHATIF (77.1): a policy provider prints its current -> new impact report on EVERY WhatIf run that would
    # change something, not only when the breaker holds -- so a WhatIf (drift snapshot, -WhatIf run) previews it.
    $Context['__pimWhatIf'] = [bool]$WhatIf

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
    # 96.5: the reconcile's removal plan looks for leftovers whose rows are GONE, i.e. principals no row names any more -- a
    # narrowed read would never see them. The daily reconcile reads the whole scope.
    if ($__rrMode -and $Mode -eq 'Full') { $__narrow = $false }
    if ($__narrow -and (Get-Command Test-PimNarrowDeltaMembershipReadsEnabled -ErrorAction SilentlyContinue) -and -not (Test-PimNarrowDeltaMembershipReadsEnabled)) { $__narrow = $false }
    $Context['__pimLiveNarrow'] = $__narrow
    $Context['__pimLiveNarrowReason'] = "$Mode, no prune"

    $desired = @(& $p.GetDesired $Context)
    $live    = @(& $p.GetLive    $Context)
    # REQ-U (2026-09-19): a provider whose LIVE read failed (a 403, a missing permission, an API that answered an
    # error) says so in $Context['__pimLiveReadError'] instead of handing back an empty live set. An empty live set
    # is NOT "nothing there": diffed, it reads as "everything missing" (and a create would duplicate what exists),
    # and in a drift check it reads as checked. The scope is therefore NOT CHECKED and applies nothing.
    $__lre = "$($Context['__pimLiveReadError'])".Trim()
    if ($__lre) {
        Write-Warning ("[engine] {0}: the live state could NOT be read -- nothing was compared and nothing applied (NOT CHECKED): {1}" -f $Scope, $__lre)
        return [pscustomobject]@{ scope=$Scope; mode=$Mode; whatIf=[bool]$WhatIf; create=0; update=0; remove=0; nochange=0; applied=0; skipped=0; errors=0; plan=@()
            ok=$false; notChecked=$true; error="the live state could not be read: $__lre"; detail="${Scope}: the live state could not be read -- not checked, nothing applied: $__lre"
            warnings=@($Context['__pimScopeWarnings']) }
    }
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
    # §96.6: what kind of run this is -- a hold is cleared only by the same kind of run that recorded it, and the releases
    # this run used are returned with the scope result.
    $__runKind = "$Mode$(if ($Prune) { '+Prune' })$(if ($PSBoundParameters.ContainsKey('Changes') -and $null -ne $Changes) { '+Queue' })"
    $__guardReleases = New-Object System.Collections.Generic.List[object]
    $__canRelease = [bool](Get-Command Invoke-PimGuardHoldOrRelease -ErrorAction SilentlyContinue)
    # GUARD-1 'engine.empty-desired' (2026-10-05): a FULL prune run remembers each scope's desired count, and alerts ONCE
    # when a scope that had definitions now has none while live items remain (gate 2 below then refuses the prune). Plans
    # (-WhatIf) and the remove-only scopes (allowEmptyDesiredPrune) are not counted. Never throws.
    $__edT = $null
    if ($doPrune -and -not $WhatIf -and -not $p.allowEmptyDesiredPrune -and (Get-Command Invoke-PimEmptyDesiredGuard -ErrorAction SilentlyContinue)) {
        $__edT = Invoke-PimEmptyDesiredGuard -Scope $Scope -DesiredCount @($desired).Count -LiveCount @($live).Count
    }
    if ($doPrune -and -not $WhatIf -and $__canRelease -and @($desired).Count -gt 0) { [void](Clear-PimGuardHold -GuardId 'engine.empty-desired' -Scope $Scope -RunKind $__runKind) }
    $__emptyDesiredRead = $false
    if ($doPrune -and @($desired).Count -eq 0 -and -not $p.allowEmptyDesiredPrune) {
        # REQ-AU-DRIFT-1 (operator 2026-09-30: "List extras, read-only"): the DRIFT SNAPSHOT may still LIST what is live in a
        # scope that has no rows -- hand-made AU-scoped roles were invisible until the first Roles-AUs row existed. Only a
        # plan (-WhatIf) that the drift snapshot asked for ($global:PIM_DriftReadPlan); every other run -- above all
        # every run that WRITES -- still never prunes an empty scope.
        if ($WhatIf -and $global:PIM_DriftReadPlan) {
            $__emptyDesiredRead = $true
            Write-Host ("[engine] {0,-20} no definitions -- drift read lists {1} live item(s) as extras (plan only, nothing is removed)" -f $Scope, @($live).Count) -ForegroundColor DarkYellow
        } else {
            # §96.6: the empty-desired gate is releasable for ONE run, bound to the plan (the live keys it would prune). A hold
            # is recorded only once the gate has tripped for this scope (the transition), so a scope nobody defines stays
            # silent. Released, the prune still removes only ledger keys (SEC-80) and the removal budget still caps it.
            $__edRel = $null
            if (-not $WhatIf -and $__canRelease -and @($live).Count -gt 0) {
                $__edKeys = @(@($live) | ForEach-Object { try { "$(& $p.KeyOf $_)" } catch { '' } } | Where-Object { $_ })
                $__edHolding = [bool]($__edT -and $__edT.trip) -or [bool](Get-PimGuardHold -Holds @(Get-PimGuardHolds) -GuardId 'engine.empty-desired' -Scope $Scope)
                $__edRel = Invoke-PimGuardHoldOrRelease -GuardId 'engine.empty-desired' -Scope $Scope -Keys $__edKeys -Count @($live).Count -RunKind $__runKind `
                    -Measured @{ desired = 0; live = @($live).Count } -NoHold:(-not $__edHolding)
            }
            if ($__edRel -and $__edRel.released) {
                $__guardReleases.Add([pscustomobject]@{ guardId = 'engine.empty-desired'; releaseId = "$($__edRel.release.id)"; planHash = $__edRel.planHash })
                Write-Host ("[engine] {0,-20} desired set is empty -- prune RELEASED for this run (managed items only, the removal budget still applies)" -f $Scope) -ForegroundColor Magenta
            } else {
                Write-Host ("[engine] {0,-20} prune SKIPPED -- desired set is empty (refusing to remove {1} live items; not authoritative)" -f $Scope, @($live).Count) -ForegroundColor Yellow
                $doPrune = $false
            }
        }
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

    # --- SEC-80 (§33.38): A PRUNE REMOVES ONLY WHAT PIM MANAGES ------------------------------------------------------
    # Operator 2026-10-06: "it must only impact defined perm per pim manager def, not things like delegations or admins
    # that exist outside pim manager". A prune item is a live item no desired row has -- and a provider's live read is wider
    # than PIM's definitions (every member of a PIM group, every grant a PIM group holds). The managed-key ledger
    # (PIM-ManagedKeys.ps1) holds what PIM has matched to a row or created from one; a prune keeps only those, and every
    # other item is UNMANAGED: reported, never removed. Targeted Action=Remove rows pass (the row is the definition).
    # Fail closed: no ledger (unreadable, no store, module missing) = nothing is pruned. The DRIFT READ (a plan that can
    # never write) still lists every extra -- listing them is its job (BUG-269).
    $__driftReadPlan = [bool]($WhatIf -and $global:PIM_DriftReadPlan)
    $__ledger = $null; $__ledgerCs = $null; $__ledgerErr = ''
    if ($p.ApplyRemove -and (Get-Command Get-PimManagedKeys -ErrorAction SilentlyContinue)) {
        if (-not ($global:PIM_ManagedKeysStore -is [hashtable]) -and (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue)) {
            try { $__ledgerCs = Get-PimSqlSettingsConnectionString } catch { $__ledgerCs = $null }
        }
        if (($global:PIM_ManagedKeysStore -is [hashtable]) -or $__ledgerCs) {
            try { $__ledger = Get-PimManagedKeys -ConnectionString $__ledgerCs -Scope $Scope }
            catch { $__ledger = $null; $__ledgerErr = "$($_.Exception.Message)" }
        } else { $__ledgerErr = 'no SQL store' }
    } elseif (-not $p.ApplyRemove) { $__ledger = @{} }   # a provider that cannot remove manages nothing removable
    $__unmanaged = @()
    if ($doPrune -and -not $__driftReadPlan) {
        if (Get-Command Split-PimPruneByLedger -ErrorAction SilentlyContinue) {
            $__sp = Split-PimPruneByLedger -Remove @($diff.remove) -Ledger $__ledger
            $__keepRm = @($__sp.remove); $__unmanaged = @($__sp.unmanaged)
        } else {
            $__keepRm = @(@($diff.remove) | Where-Object { $_ -and $_.PSObject.Properties['targeted'] -and $_.targeted })
            $__unmanaged = @(@($diff.remove) | Where-Object { $_ -and -not ($_.PSObject.Properties['targeted'] -and $_.targeted) })
            $__ledgerErr = 'the managed-key ledger module is not loaded'
        }
        # §96.6: an UNREADABLE ledger is a guard ('engine.ledger-unreadable'): it holds the prune, records the held plan and
        # trips GUARD-1; a SuperAdmin may release exactly that plan for ONE run (the removal budget below still applies).
        if ($__unmanaged.Count -and $null -eq $__ledger -and $__ledgerErr -and -not $WhatIf -and $__canRelease) {
            $__lgKeys = @(@($__unmanaged) | ForEach-Object { "$($_.key)" })
            $__lg = Invoke-PimGuardHoldOrRelease -GuardId 'engine.ledger-unreadable' -Scope $Scope -Keys $__lgKeys -Count $__unmanaged.Count -RunKind $__runKind -Measured @{ unmanaged = $__unmanaged.Count }
            if ($__lg.released) {
                $__guardReleases.Add([pscustomobject]@{ guardId = 'engine.ledger-unreadable'; releaseId = "$($__lg.release.id)"; planHash = $__lg.planHash })
                Write-Host ("[engine] {0,-20} the managed-key ledger could not be read ({1}) -- prune RELEASED for this run: {2} item(s)" -f $Scope, $__ledgerErr, $__unmanaged.Count) -ForegroundColor Magenta
                $__keepRm = @(@($__keepRm) + @($__unmanaged)); $__unmanaged = @()
            } elseif (Get-Command Invoke-PimGuardTrip -ErrorAction SilentlyContinue) {
                [void](Invoke-PimGuardTrip -GuardId 'engine.ledger-unreadable' -Outcome refused -Area $Scope -Job 'engine' -HeldCount $__unmanaged.Count `
                    -Title ("{0}: the managed-key ledger could not be read -- {1} prune item(s) held" -f $Scope, $__unmanaged.Count) `
                    -Detail ("The prune of {0} removes only what PIM manages, and the list of what PIM manages could not be read ({1}). Nothing was removed." -f $Scope, $__ledgerErr) `
                    -ActionText 'Fix the store access. If the held items must go now, review them on Audit & Settings > Guards and release that plan for one run.' `
                    -Measured @{ held = $__unmanaged.Count })
            }
        } elseif ($doPrune -and -not $WhatIf -and $__canRelease -and $null -ne $__ledger) { [void](Clear-PimGuardHold -GuardId 'engine.ledger-unreadable' -Scope $Scope -RunKind $__runKind) }
        if ($__unmanaged.Count) {
            if ($null -eq $__ledger -and $__ledgerErr) {
                Write-Warning ("[engine] {0}: the managed-key ledger could not be read ({1}) -- the prune removes NOTHING this run ({2} item(s) left alone)." -f $Scope, $__ledgerErr, $__unmanaged.Count)
            }
            Write-Host ("[engine] {0,-20} {1} live item(s) are not defined in PIM Manager -- left alone, never pruned (report only): {2}{3}" -f `
                $Scope, $__unmanaged.Count, ((@($__unmanaged | Select-Object -First 5 | ForEach-Object { $_.key })) -join ', '), $(if ($__unmanaged.Count -gt 5) { ', ...' } else { '' })) -ForegroundColor DarkYellow
        }
        $diff = [pscustomobject]@{ create = @($diff.create); update = @($diff.update); remove = @($__keepRm); nochange = @($diff.nochange)
                                   absent = @($diff.absent); conflicts = @($diff.conflicts) }
    }

    # --- 96.5 PURPOSE 2: THE DAILY RECONCILE'S REMOVAL OF PIM-MANAGED LEFTOVERS ------------------------------------------
    # Operator 2026-10-06: remove pending removals "only the ones that has been part of pim (not just recognized in the
    # platform, but have been active in the platform) ... except if a similar has been configured"; admins never. Every live
    # item no row has is checked against rules 1-5 (PIM-ReconcileRemoval.ps1). REPORT (the default) only plans and reports;
    # ENFORCE hands the qualifying items to the normal remove path below (break-glass, budget, audit, applied outcome).
    # A real prune (-Prune) has its own path above and is not planned twice. Never fails the pass.
    $__rrPlan = $null
    if ($__rrMode -and $Mode -eq 'Full' -and -not $doPrune -and -not $__driftReadPlan -and $p.ApplyRemove -and (Get-Command Get-PimReconcileRemovalPlan -ErrorAction SilentlyContinue)) {
        try {
            $__rrBudget = -1; if (Get-Command Get-PimRemoveBudget -ErrorAction SilentlyContinue) { try { $__rrBudget = [int](Get-PimRemoveBudget) } catch { $__rrBudget = -1 } }
            $__rrCs = $__ledgerCs
            if (-not $__rrCs -and -not ($global:PIM_ManagedKeysStore -is [hashtable]) -and (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue)) { try { $__rrCs = Get-PimSqlSettingsConnectionString } catch { $__rrCs = $null } }
            $__rrLabel = $null
            if (Get-Command Get-PimFailureItemLabel -ErrorAction SilentlyContinue) { $__rrLabel = { param($c) Get-PimFailureItemLabel -Key "$($c.key)" -Row $c.live } }
            $__rrPlan = Get-PimReconcileRemovalPlan -Scope $Scope -Provider $p -Desired @($desired) -Live @($live) -KeyOf $p.KeyOf -HasTypes:([bool]$p.TypeKeyOf) `
                -ClaimedKeys @(@($diff.remove) | Where-Object { $_ } | ForEach-Object { "$($_.key)" }) -LedgerConnectionString "$__rrCs" -Mode $__rrMode `
                -Budget $__rrBudget -AlreadyRemoving @($diff.remove).Count -LabelOf $__rrLabel
            $__rrHeld = @($__rrPlan.items | Where-Object { -not $_.eligible }).Count
            if ([int]$__rrPlan.candidates -gt 0) {
                Write-Host ("[engine] {0,-20} reconcile ({1}): {2} live item(s) not in the configuration -- would remove {3}, {4} held by a rule{5}" -f `
                    $Scope, $__rrMode, $__rrPlan.candidates, $__rrPlan.wouldRemove, $__rrHeld, $(if ($__rrMode -eq 'report') { ' (REPORT ONLY: nothing is removed)' } else { '' })) -ForegroundColor DarkYellow
            }
            if ($__rrMode -eq 'enforce' -and @($__rrPlan.eligible).Count) {
                $__rrAdd = @(foreach ($__e in @($__rrPlan.eligible)) { [pscustomobject]@{ key = "$($__e.key)"; live = $__e.live; reconcileRemoval = $true } })
                $diff = [pscustomobject]@{ create = @($diff.create); update = @($diff.update); remove = @(@($diff.remove) + $__rrAdd); nochange = @($diff.nochange)
                                           absent = @($diff.absent); conflicts = @($diff.conflicts) }
            }
            $__rrPlan.eligible = @()   # the live objects are not carried in the result; the verdicts are
        } catch {
            Write-Warning ("[engine] {0}: the reconcile removal plan could not be made (nothing is removed by it this run): {1}" -f $Scope, $_.Exception.Message)
            $__rrPlan = [pscustomobject]@{ scope = $Scope; class = ''; mode = $__rrMode; candidates = 0; wouldRemove = 0; eligible = @(); items = @(); heldBy = @{}; error = "$($_.Exception.Message)" }
        }
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

    # --- 🔴 IMP-33 (2026-09-18): THE UNMANAGED-ADMIN REPORT RUNS ON EVERY PASS, AND IS STORED ---------
    # The block above only runs when the diff proposes removals, which a Delta pass never does -- so on EFIF
    # `Admins desired=5 live=14` ran every 5 minutes and nothing ever named the nine accounts in between (six
    # of them real admins with no TAP healing, no reminders, no review). Classify the WHOLE live set with the
    # same pure classifier (desired identities fall out as attributable, break-glass is excluded) and store
    # the result for the Manager. REPORT ONLY -- this touches no account. Logged only when the set CHANGES.
    if ($p.isAccountDisable -and (Get-Command Save-PimUnmanagedAdminReport -ErrorAction SilentlyContinue)) {
        try {
            $__ent = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
            $__res = $null
            if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey($__ent)) { $__res = [bool]$global:PIM_DesiredResolved[$__ent] }
            $__all = Select-PimDisableRemovals -Remove @($live) -Desired @($desired)
            $__cs = if ($global:PIM_EngineSqlCs) { $global:PIM_EngineSqlCs }
                    elseif ($global:PIM_SqlConnectionString) { $global:PIM_SqlConnectionString }
                    elseif ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and ($global:PIM_SqlServer -or $global:PIM_SqlConnStringVault)) { Get-PimSqlConnectionString }
                    else { $null }
            $__sv = Save-PimUnmanagedAdminReport -Scope $Scope -Unmanaged @($__all.unmanaged) -BreakGlass @($__all.breakGlass) -DesiredResolved $__res -ConnectionString $__cs
            if ($__sv.ok -and $__sv.changed) {
                Write-Host ("[engine] {0}: unmanaged admin accounts now {1} (REPORT ONLY, shown in the Manager): {2}" -f `
                    $Scope, @($__sv.accounts).Count, ((@($__sv.accounts)) -join ', ')) -ForegroundColor Yellow
            }
        } catch { }   # a report can never fail the pass
    }

    if ($p.isAccountDisable -and @($diff.remove).Count -gt 0 -and (Get-Command Test-PimDisablePassAllowed -ErrorAction SilentlyContinue)) {
        $resolvedFlag = $null
        $ent = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
        if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey($ent)) { $resolvedFlag = [bool]$global:PIM_DesiredResolved[$ent] }
        $decision = Test-PimDisablePassAllowed -ToDisable (@($diff.remove).Count) -Scanned (@($live).Count) -Desired $desired -DesiredResolved $resolvedFlag -FeatureOverride $p.disableFeatureOverride
        # §96.6: ONLY the blast-radius trip (G2) is releasable -- never the opt-in (G3) or an unresolved desired set (G1). A
        # release of exactly this disable set lifts the caps for ONE run to the plan's count, at most 50 accounts and 25 %
        # (literal ceilings -- the breaker's own). The break-glass accounts were taken out of the set above, before this.
        if (-not $decision.allowed -and "$($decision.tripped)" -eq 'mass-disable' -and -not $WhatIf -and $__canRelease) {
            $__dN = @($diff.remove).Count; $__dS = @($live).Count
            $__dPct = if ($__dS -gt 0) { 100.0 * $__dN / $__dS } else { -1 }
            $__dg = Invoke-PimGuardHoldOrRelease -GuardId 'engine.disable-guard' -Scope $Scope -Keys @(@($diff.remove) | ForEach-Object { "$($_.key)" }) -Count $__dN -Percent $__dPct `
                -RunKind $__runKind -Measured @{ toDisable = $__dN; scanned = $__dS }
            if ($__dg.released) {
                $__d2 = Test-PimDisablePassAllowed -ToDisable $__dN -Scanned $__dS -Desired $desired -DesiredResolved $resolvedFlag -FeatureOverride $p.disableFeatureOverride `
                    -MaxCount ([Math]::Min([int]$__dg.release.raiseTo, 50)) -MaxPercent 25
                if ($__d2.allowed) {
                    $__guardReleases.Add([pscustomobject]@{ guardId = 'engine.disable-guard'; releaseId = "$($__dg.release.id)"; planHash = $__dg.planHash })
                    $decision = $__d2
                }
            }
        } elseif (-not $WhatIf -and $__canRelease -and $decision.allowed) { [void](Clear-PimGuardHold -GuardId 'engine.disable-guard' -Scope $Scope -RunKind $__runKind) }
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
    # BUG-269 (operator 2026-10-01: "fix"): the DRIFT READ is a plan that can never write, and its job is to LIST what is
    # there -- a budget trip dropped the whole list, so a scope with 6+ extras showed 0 extras and "in sync". On the drift
    # read the list is KEPT and the scope is marked over the budget (an apply would hold it). The budget still guards
    # every other plan and every run that writes.
    $__overBudget = $null
    $__driftRead = [bool]($WhatIf -and $global:PIM_DriftReadPlan)
    if ($__rmTotal -gt 0 -and $__driftRead -and (Get-Command Test-PimRemoveBudgetAllowed -ErrorAction SilentlyContinue)) {
        $rbd = Test-PimRemoveBudgetAllowed -ToRemove $__rmTotal -Scope $Scope -Scanned (@($live).Count) -Operation 'remove'
        if (-not $rbd.allowed) {
            $__overBudget = [pscustomobject]@{ toRemove = $__rmTotal; budget = $rbd.budget }
            # The GUARD-1 trip 'drift.over-remove-budget' (2026-10-05) is TURNED OFF (operator 2026-10-07: "this particular guard
            # should be turned off, as nothing happens automatically"): the drift read is a plan that never writes, and nothing
            # acts on an extra until an operator chooses on the Drift page -- the warning protected against nothing. The items
            # are still listed; the real removal budget ('engine.remove-budget') still guards every run that writes.
            Write-Host ("[engine] {0,-20} drift read: {1} removal(s) are over the removal budget ({2}) -- LISTED; an apply would hold them" -f $Scope, $__rmTotal, $rbd.budget) -ForegroundColor DarkYellow
        }
    }
    if ($__rmTotal -gt 0 -and -not $__driftRead -and (Get-Command Test-PimRemoveBudgetAllowed -ErrorAction SilentlyContinue)) {
        # The BREAKDOWN goes with the count: the alert must be able to say whether these are assignment
        # type changes (which delete the old type first) or rows the operator marked Action=Remove.
        # Without it the mail read as "the engine decided to delete 9 things" (operator, 2026-09-20).
        $rb = Test-PimRemoveBudgetAllowed -ToRemove $__rmTotal -Scope $Scope -Scanned (@($live).Count) -Operation 'remove' `
                -TypeChanges (@($__retype).Count + @(@($diff.remove) | Where-Object { $_ -and $_.PSObject.Properties['typeChange'] -and $_.typeChange }).Count) `
                -RemoveRows  (@(@($diff.remove) | Where-Object { $_ -and $_.PSObject.Properties['targeted'] -and $_.targeted }).Count)
        # §96.6 / BUG-291: G4 is releasable for EXACTLY this set (plan hash), one run, at most 50 (PIM-GuardRelease.ps1).
        if (-not $WhatIf -and $__canRelease) {
            $__g4 = Resolve-PimRemoveBudgetRelease -Decision $rb -Scope $Scope -Remove @($diff.remove) -Retype @($__retype) -Scanned @($live).Count -RunKind $__runKind
            if ($__g4) { $__guardReleases.Add($__g4.used); $rb = $__g4.decision }
        }
        if (-not $rb.allowed) {
            # A -WhatIf (plan / verify) run removes nothing: it is logged, never mailed as an engine failure.
            if (Get-Command Write-PimRemoveBudgetAlert -ErrorAction SilentlyContinue) { Write-PimRemoveBudgetAlert -Decision $rb -PlanOnly:([bool]$WhatIf) }
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
    # §88 commit watcher: what this run did with each item, by its pim.Rows entity + key (Get-PimCommitWatchItemRef).
    # Collected always, written once at the end of a real (not WhatIf) run, and only for keys a commit waits for.
    $script:__watch = New-Object System.Collections.Generic.List[object]
    $watchAdd = {
        param($wOp, $wItem, $wResult, $wReason)
        if ($WhatIf -or -not (Get-Command Get-PimCommitWatchItemRef -ErrorAction SilentlyContinue)) { return }
        try {
            $wEnt = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
            $ref = Get-PimCommitWatchItemRef -Entity $wEnt -Item $wItem -Op $wOp
            if ($ref) { $script:__watch.Add([pscustomobject]@{ entity = $ref.entity; key = $ref.key; action = "$wOp"; result = "$wResult"; reason = "$wReason" }) }
        } catch { }
    }
    # CONFIG-1.1 / 96.1: the APPLIED OUTCOME per row -- what this pass did in the tenant for each item a commit names
    # (created / updated / removed / already present / failed + error), written once at the end of a real run. D2: an item
    # PIM CREATED is CONFIRMED in the ledger with the commit + store row it came from. Never fails the pass.
    $outcomeAdd = {
        param($oOp, $oItem, $oOutcome, $oErr)
        if ($WhatIf) { return }
        try {
            $oEnt = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
            $oRow = if ("$oOp" -eq 'Remove') { if ($oItem.PSObject.Properties['row'] -and $null -ne $oItem.row) { $oItem.row } elseif ($oItem.PSObject.Properties['live']) { $oItem.live } else { $null } } elseif ($oItem.PSObject.Properties['desired']) { $oItem.desired } else { $null }
            $oCommit = $null
            if (Get-Command Resolve-PimEngineChangeCommit -ErrorAction SilentlyContinue) { $oCommit = Resolve-PimEngineChangeCommit -Entity $oEnt -Op "$oOp" -Row $oRow }
            if ($oCommit -and (Get-Command New-PimCommitAppliedRecord -ErrorAction SilentlyContinue)) {
                $oRec = New-PimCommitAppliedRecord -Commit $oCommit -Scope "$Scope" -LiveKey "$($oItem.key)" -Op "$oOp" -Outcome $oOutcome -ErrorMessage "$oErr" -JobRun "$($global:PIM_JobCorrelationId)"
                if ($oRec) { $script:__outcomes.Add($oRec) }
            }
            if ("$oOp" -eq 'Create' -and $oOutcome -eq 'ok') {
                $oRef = $null
                if ($oCommit -and "$($oCommit.Entity)" -and "$($oCommit.Key)") { $oRef = @{ entity = "$($oCommit.Entity)"; key = "$($oCommit.Key)" } }
                else { $oRefs = @(Get-PimEngineItemStoreRefs -Entity $oEnt -Row $oRow); if ($oRefs.Count) { $oRef = $oRefs[0] } }
                $script:__confirm.Add(@{ key = "$($oItem.key)"; commitId = $(if ($oCommit) { "$($oCommit.CommitId)" } else { '' })
                                         sourceEntity = $(if ($oRef) { "$($oRef.entity)" } else { '' }); sourceKey = $(if ($oRef) { "$($oRef.key)" } else { '' }) })
            }
        } catch { Write-Verbose ("applied outcome of {0} not recorded: {1}" -f $oItem.key, $_.Exception.Message) }
    }
    $do = {
        param($op,$item,$handlerName)
        $entity = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
        if (Get-Command New-PimChange -ErrorAction SilentlyContinue) {
            $payload = if ($op -eq 'Remove') { $item.live } else { $item.desired }
            $__chg = New-PimChange -Entity $entity -Key "$($item.key)" -Op $op -By 'engine' -Payload $payload
            # §79.3: an Update says WHAT differs (live -> desired), so drift and its mail can name it.
            if ($op -eq 'Update' -and $__chg) { $__chg | Add-Member -NotePropertyName diff -NotePropertyValue (Get-PimChangeFieldDiff -Live $item.live -Desired $item.desired) -Force }
            $plan.Add($__chg)
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
                # 🔴 THE REMOVAL-FIRST TYPE CHANGE IS GONE (operator, 2026-09-20). It used to call
                # ApplyRemove on the live assignment of the other type and only then ApplyCreate --
                # i.e. it DELETED live privileged access that no row had asked to remove. Both types of
                # one delegation are supported, so there is nothing to replace: see the diff above.
                # $__isRetype can no longer be true (Get-PimEngineDiff emits no typeChange item); the
                # guard stays as a tripwire so a re-introduction fails loudly instead of deleting again.
                if ($__isRetype) {
                    throw ("REFUSED: a 'type change' reached the orchestrator for '{0}'. The engine does not replace one assignment type with the other -- both are supported, and only an Action=Remove row removes an assignment. This item was NOT applied." -f $item.key)
                }
                $__r = & $p.$handlerName $item $Context
                $__reported = $false
                foreach ($__o in @($__r)) {
                    if ($null -ne $__o -and $__o.PSObject -and ($__o.PSObject.Properties.Name -contains 'pimApplied') -and (-not $__o.pimApplied)) { $__reported = $true }
                }
                if ($__reported) {
                    & $watchAdd $op $item 'waiting' 'reported only -- not applied by this run (a hold or report mode)'
                    $script:__skipped++
                    # 2026-09-21 (operator, on a held run: "terrible error messages"): a hold reported 117 identical
                    # "[r] ... (reported only)" lines. The first 3 are listed; the rest are counted before the done line.
                    $script:__reportedShown = 1 + [int]$script:__reportedShown
                    if ($script:__reportedShown -le 3) { Write-Host ("    [r] {0} (reported only -- NOT applied)" -f $item.key) -ForegroundColor DarkYellow }
                } else {
                    $script:__applied++; Write-Host ("    [{0}] {1}" -f $sym, $item.key) -ForegroundColor Green
                    & $watchAdd $op $item 'ok' ''
                    # SEC-80: what PIM created now belongs to it; what it removed no longer does.
                    if ($op -eq 'Create') { $script:__createdKeys.Add("$($item.key)") } elseif ($op -eq 'Remove') { $script:__removedKeys.Add("$($item.key)") }
                    if ($op -eq 'Remove' -and $item.PSObject.Properties['reconcileRemoval'] -and $item.reconcileRemoval) { $script:__rrRemoved++ }
                    Write-PimEngineChangeAudit -Scope $Scope -Entity $entity -Op $op -Item $item -Result 'ok'
                    & $outcomeAdd $op $item 'ok' ''
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
                    & $watchAdd 'NoChange' $item 'ok' ''
                    if ($op -eq 'Create') { $script:__createdKeys.Add("$($item.key)") }   # SEC-80: it is there, as the row asks
                    # 96.1: 'already present' -- and D2: NOT confirmed (it may have existed before PIM asked for it).
                    & $outcomeAdd $op $item 'exists' ''
                } else {
                    # 🔴 §70.19 (2026-09-13): "Nesting is currently not supported" (an ACTIVE group nesting into a
                    # role-assignable group) used to be a separate branch that counted a SKIP and printed a yellow
                    # line. The delegation never deployed, the job read ok, the Manager's Engine errors showed
                    # nothing, and only verify-convergence complained 18 hours later with no cause. It is a
                    # failure of the row, so it is recorded like one: ENTRA-NESTING-ROLE-ASSIGNABLE, fix = Eligible.
                    $script:__errors++; Write-Host ("    [x] {0} {1} FAILED: {2}" -f $op, $item.key, $em) -ForegroundColor Red
                    & $watchAdd $op $item 'failed' $em
                    Write-PimEngineChangeAudit -Scope $Scope -Entity $entity -Op $op -Item $item -Result 'error' -ErrorMessage $em
                    & $outcomeAdd $op $item 'error' $em
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
    $script:__applied = 0; $script:__errors = 0; $script:__skipped = 0; $script:__reportedShown = 0
    $script:__createdKeys = New-Object System.Collections.Generic.List[string]; $script:__removedKeys = New-Object System.Collections.Generic.List[string]
    $script:__failures = New-Object System.Collections.Generic.List[object]
    $script:__outcomes = New-Object System.Collections.Generic.List[object]; $script:__confirm = New-Object System.Collections.Generic.List[object]
    $script:__rrRemoved = 0
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
        & $watchAdd $__hOp $__it 'held' $__hMsg
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
    # §88: an item the platform already matches is LIVE for the watcher.
    foreach ($i in $diff.nochange) { & $watchAdd 'NoChange' $i 'ok' '' }
    # A Remove row REVOKES a delegation and is then DELETED, so nothing re-applies it (operator 2026-09-13:
    # "remove was to revoke a delegation which must be removed deleted so it doesnt reapply"; in the old
    # files the rows were forgotten after the first run). Deleted only when EVERY live item it names
    # (eligible and active) was revoked, or nothing was live. Held, failed or refused revokes keep the row.
    # 🔴 2026-09-20 -- "ABSENT" IS ONLY TRUE IF THE LIVE READ WAS COMPLETE.
    # An absent Remove row means "nothing of this delegation is live, so the revoke is already done" --
    # and the row is then DELETED from pim.Rows. That verdict comes straight from the live set, so a
    # read that was short by even one item silently throws away a revoke the operator staged and
    # committed, and the revoke never happens. (The FULLY-DONE half is safe either way: those rows were
    # observed live and really were removed by this run.) A provider that cannot prove its live read was
    # complete sets __pimLiveIncomplete; absent rows are then kept and re-checked next run.
    $__liveIncomplete = "$($Context['__pimLiveIncomplete'])".Trim()
    $__rowsDone = 0
    if (-not $WhatIf) {
        $__fullyDone = @(foreach ($__rk in @($script:__rowDone.Keys)) { if ([int]$script:__rowDone[$__rk] -ge [int]$__rowTotal[$__rk]) { $script:__rowObj[$__rk] } })
        $__absentRows = @(@($__absent) | ForEach-Object { $_.row })
        if ($__liveIncomplete -and @($__absentRows).Count) {
            Write-Warning ("  [engine] {0}: {1} Remove row(s) look already-done, but the live read was NOT proven complete ({2}) -- they are KEPT and re-checked next run, never deleted on an unproven 'absent'." -f $Scope, @($__absentRows).Count, $__liveIncomplete)
            $__absentRows = @()
        }
        # 🔴 BUG-267 (2.4.464) -- a COMPLETE read can still LAG: PIM's schedule list does not show a request made seconds
        # earlier, so "absent" on one read deleted a Remove row whose delegation was about to appear (ig798 E2E run 1).
        # An absent row is now deleted only when a second read at least 10 min after the first still finds it absent.
        # BUG-284 (2026-10-04): the directory work of this run is DONE at this point. A bookkeeping fault here failed the
        # whole run -- every admin delta read "failed" while the removal had landed. It is now a warning that says WHERE it
        # threw; the rows stay and are re-checked next run (fail safe: a Remove row is never deleted on an error).
        try {
            if (@($__absentRows).Count) {
                $__rdEntA = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
                $__absentRows = @(Select-PimConfirmedAbsentRemoveRows -Entity $__rdEntA -Rows $__absentRows -Scope $Scope)
            }
            $__doneRows = @(@($__fullyDone) + @($__absentRows) | Where-Object { $null -ne $_ })
            if ($__doneRows.Count) {
                $__rdEnt = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
                $__rowsDone = Complete-PimRemoveRows -Entity $__rdEnt -Rows $__doneRows -Scope $Scope
            }
        } catch {
            Write-Warning ("  [engine] {0}: the finished Remove rows were NOT cleaned up (they stay and are re-checked next run): {1} | {2}" -f $Scope, $_.Exception.Message, (Get-PimEngineErrorWhere -ErrorRecord $_))
        }
    }
    # SEC-80: keep the managed-key ledger in step with this pass -- what PIM matched to a row or created joins it, what PIM
    # removed leaves it, and (only after a COMPLETE live read: not narrowed, not partial) what is no longer live leaves it.
    # Never fails the run; a ledger that falls behind only makes a later prune remove LESS (fail safe).
    if (-not $WhatIf -and $p.ApplyRemove -and $null -ne $__ledger -and (Get-Command Update-PimManagedKeys -ErrorAction SilentlyContinue)) {
        try {
            $__liveComplete = (-not "$($Context['__pimLiveIncomplete'])".Trim()) -and (-not $Context['__pimLiveNarrowed'])
            $__liveKeys = if ($__liveComplete) { @($live | Where-Object { $null -ne $_ } | ForEach-Object { "$(& $p.KeyOf $_)" }) } else { @() }
            $__ld = Get-PimManagedKeysDelta -Ledger $__ledger -Matched @(@(@($diff.nochange) + @($diff.update)) | Where-Object { $_ } | ForEach-Object { "$($_.key)" }) `
                -Created @($script:__createdKeys.ToArray()) -Removed @($script:__removedKeys.ToArray()) -LiveKeys $__liveKeys -LiveComplete:$__liveComplete
            if (@($__ld.add).Count -or @($__ld.remove).Count) {
                [void](Update-PimManagedKeys -ConnectionString $__ledgerCs -Scope $Scope -Add @($__ld.add) -Remove @($__ld.remove))
            }
        } catch {
            Write-Warning ("  [engine] {0}: the managed-key ledger was NOT updated (a later prune removes less, never more): {1}" -f $Scope, $_.Exception.Message)
        }
        # D2 (96.5): CONFIRM what PIM created this pass; and on a FULL pass, what a commit's failed create left live after all
        # (the live read now matches it). A key PIM only matched is never confirmed. A ledger that falls behind only makes
        # the reconcile remove LESS.
        if (Get-Command Set-PimManagedKeyConfirmations -ErrorAction SilentlyContinue) {
            try {
                $__conf = New-Object System.Collections.Generic.List[object]
                foreach ($__c in $script:__confirm) { $__conf.Add($__c) }
                if ($Mode -eq 'Full' -and (Get-Command Get-PimCommitAppliedFailedCreates -ErrorAction SilentlyContinue)) {
                    $__matched = @(@(@($diff.nochange) + @($diff.update)) | Where-Object { $_ } | ForEach-Object { "$($_.key)" })
                    if ($__matched.Count) {
                        $__fc = Get-PimCommitAppliedFailedCreates -ConnectionString "$__ledgerCs" -Scope $Scope -LiveKeys $__matched
                        foreach ($__fk in @($__fc.Keys)) { $__conf.Add(@{ key = $__fk; commitId = "$($__fc[$__fk].commitId)"; sourceEntity = "$($__fc[$__fk].sourceEntity)"; sourceKey = "$($__fc[$__fk].sourceKey)" }) }
                    }
                }
                if ($__conf.Count) { [void](Set-PimManagedKeyConfirmations -ConnectionString $__ledgerCs -Scope $Scope -Items @($__conf.ToArray())) }
            } catch {
                Write-Warning ("  [engine] {0}: the ledger confirmations were NOT recorded (the reconcile removes less, never more): {1}" -f $Scope, $_.Exception.Message)
            }
        }
    }
    # CONFIG-1.1 / 96.1: the applied outcome per row, one round trip per pass. Never fails the run.
    if (-not $WhatIf -and $script:__outcomes.Count -and (Get-Command Save-PimCommitAppliedOutcomes -ErrorAction SilentlyContinue)) {
        try {
            $__ocs = $null
            if (-not ($global:PIM_CommitAppliedStore -is [System.Collections.Generic.List[object]]) -and (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue)) { try { $__ocs = Get-PimSqlSettingsConnectionString } catch { $__ocs = $null } }
            [void](Save-PimCommitAppliedOutcomes -ConnectionString "$__ocs" -Items @($script:__outcomes.ToArray()))
        } catch {
            Write-Warning ("  [engine] {0}: the applied outcome of {1} item(s) was NOT recorded: {2}" -f $Scope, $script:__outcomes.Count, $_.Exception.Message)
        }
    }
    if ([int]$script:__reportedShown -gt 3) { Write-Host ("    [r] ... and {0} more reported only -- NOT applied (same reason as above)" -f ([int]$script:__reportedShown - 3)) -ForegroundColor DarkYellow }
    Write-Host ("[engine] {0,-20} done  applied={1} skipped={2} errors={3}" -f $Scope, $script:__applied, $script:__skipped, $script:__errors) -ForegroundColor $(if ($script:__errors) { 'Yellow' } else { 'Green' })
    # The CURRENTLY-FAILING set for this scope (SQL). A WhatIf run applied nothing, so it proves nothing
    # about what is failing and must not clear or replace the record.
    if (-not $WhatIf -and (Get-Command Update-PimEngineItemFailures -ErrorAction SilentlyContinue)) {
        try { [void](Update-PimEngineItemFailures -Scope $Scope -Failures $script:__failures.ToArray()) }
        catch { Write-Warning ("  [engine] {0}: the failing-items record was NOT updated: {1} | {2}" -f $Scope, $_.Exception.Message, (Get-PimEngineErrorWhere -ErrorRecord $_)) }
    }
    # §88 commit watcher: the per-key outcomes + "a CLEAN pass covered these entities" (no error, nothing held). Never
    # fails the run; only when a SQL store is reachable (an offline / fixed-provider run records nothing).
    if (-not $WhatIf -and (Get-Command Update-PimCommitOutcomes -ErrorAction SilentlyContinue) -and (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue)) {
        $__wcs = $null; try { $__wcs = Get-PimSqlSettingsConnectionString } catch { $__wcs = $null }
        if ($__wcs) {
            # a clean pass (no error, nothing held) covers every entity THIS scope applies -- Update-PimCommitOutcomes
            # keeps only those (Test-PimCommitWatchScopeApplies)
            $__clean = if ($script:__errors -eq 0) { @(Get-PimCommitWatchPlatformEntities) } else { @() }
            try { Update-PimCommitOutcomes -ConnectionString $__wcs -Items $script:__watch.ToArray() -CleanEntities $__clean -Scope "$Scope" -Mode "$Mode" }
            catch { Write-Warning ("  [engine] {0}: the commit watcher was NOT updated: {1} | {2}" -f $Scope, $_.Exception.Message, (Get-PimEngineErrorWhere -ErrorRecord $_)) }
        }
    }

    return [pscustomobject]@{
        scope=$Scope; mode=$Mode; whatIf=[bool]$WhatIf
        create=$diff.create.Count; update=$diff.update.Count; remove=$diff.remove.Count; nochange=$diff.nochange.Count
        applied=$script:__applied; skipped=$script:__skipped; errors=$script:__errors; plan=$plan.ToArray(); ok=($script:__errors -eq 0)
        disableAborted=$script:__disableAborted
        failures=$script:__failures.ToArray()
        held=$__held.Count; absent=$__absent.Count; conflicts=$__conflicts.Count
        removeRowsDone=$__rowsDone
        unmanaged=@($__unmanaged).Count           # SEC-80: live items a prune left alone (not defined in PIM Manager)
        guardReleases=$__guardReleases.ToArray()  # §96.6: the guard releases this run used ({ guardId; releaseId; planHash })
        reconcileRemoval=$__rrPlan                # 96.5: the daily reconcile's removal plan (report / enforce), $null otherwise
        reconcileRemoved=[int]$script:__rrRemoved # 96.5: how many of them an ENFORCE pass really removed
        appliedOutcomes=$script:__outcomes.Count  # 96.1: rows recorded in pim.CommitApplied by this pass
        noDefinitions=[bool]$__emptyDesiredRead   # REQ-AU-DRIFT-1: extras listed from a scope with no rows (drift read only)
        overRemoveBudget=$__overBudget            # BUG-269: drift read only -- { toRemove; budget } when an apply would hold
        warnings=@($Context['__pimScopeWarnings'])
        # .ToArray(), never @(): pwsh 7 throws "Argument types do not match" on @() over a List[object] from a hashtable.
        findings=$(if ($Context['__pimLiveFindings'] -is [System.Collections.Generic.List[object]]) { $Context['__pimLiveFindings'].ToArray() } else { @() })
    }
}

function Get-PimFeatureSkipReason {
    # REQ-U. The plain reason a gated scope did not run: the feature is switched off, or not licensed for this edition.
    param([Parameter(Mandatory)][string]$Key)
    $label = ''
    if (Get-Command Get-PimFeatureCatalogEntry -ErrorAction SilentlyContinue) {
        try { $e = Get-PimFeatureCatalogEntry -Key $Key; if ($e) { $label = "$($e.label)" } } catch { $label = '' }
    }
    $what = if ($label) { "the feature '$label' ($Key)" } else { "the feature '$Key'" }
    # REQ-Y: a Pro feature without a Pro licence says so, with the contact and the register command.
    if (Get-Command Test-PimFeatureProLicence -ErrorAction SilentlyContinue) {
        try { $pl = Test-PimFeatureProLicence -Key $Key; if ($pl -and $pl.required -and -not $pl.ok) { return "$($pl.message)" } } catch { }
    }
    $enabled = $true
    if (Get-Command Test-PimFeatureEnabled -ErrorAction SilentlyContinue) {
        try { $enabled = [bool](Test-PimFeatureEnabled -Key $Key) } catch { $enabled = $false }
    }
    if (-not $enabled) { return "$what is turned off" }
    return "$what is not licensed for this edition"
}

function Get-PimEngineErrorWhere {
    # BUG-284 / IMP-269: "at <function>, <file>: line <n>" of an error record's first frame -- no folder, no data.
    param([AllowNull()][object]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return '' }
    foreach ($l in @("$($ErrorRecord.ScriptStackTrace)" -split "`r?`n")) {
        if ("$l".Trim() -match '^at (?<fn>[^,]*), (?<file>.*): line (?<n>\d+)') {
            return ("at {0}, {1}: line {2}" -f "$($Matches.fn)".Trim(), ("$($Matches.file)" -split '[\\/]')[-1], $Matches.n)
        }
    }
    return ''
}

function Select-PimConfirmedAbsentRemoveRows {
    <#
      BUG-267. -Rows: Remove rows this run found ABSENT (nothing of the delegation live). Returns only the rows that
      were ALSO absent on an earlier read at least -MinMinutes (10) before; the others are stamped (first-absent, in
      pim.Settings 'RemoveRowAbsentSeen', "<entity>|<row key>" -> utc) and kept, so the next run re-reads them -- and
      revokes them if the lagging delegation has appeared by then. A stamp of this entity whose row is no longer absent
      is dropped (the two reads must be consecutive); stamps older than 7 days are pruned.
      No SQL store (offline runs, fixed providers -- nothing lags there) = the rows are returned as they are.
      -Load / -Save inject the stamp map (tests).
    #>
    param([Parameter(Mandatory)][string]$Entity, [object[]]$Rows = @(), [string]$Scope = '', [datetime]$NowUtc = [datetime]::UtcNow,
          [int]$MinMinutes = 10, [scriptblock]$Load, [scriptblock]$Save)
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if (-not $rows.Count) { return @() }
    if (-not $Load -or -not $Save) {
        $cs = $null
        if ((Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue) -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) {
            $cs = if ($global:PIM_EngineSqlCs) { $global:PIM_EngineSqlCs } elseif ($global:PIM_SqlConnectionString) { $global:PIM_SqlConnectionString }
                  elseif ((Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) -and ($global:PIM_SqlServer -or $global:PIM_SqlConnStringVault)) { Get-PimSqlConnectionString } else { $null }
        }
        if (-not $cs) { return $rows }
        # 🔴 PLAIN scriptblocks, NO .GetNewClosure() (2.4.466): a closure is bound to a new module and cannot see
        # Get-PimSqlSetting dot-sourced into the engine's SCRIPT scope -- 2.4.464 failed every stamp read that way (safe:
        # rows kept, but never cleared). Invoked below, inside this function, they see $cs by dynamic scope.
        $Load = { Get-PimSqlSetting -ConnectionString $cs -Name 'RemoveRowAbsentSeen' }
        $Save = { param($m) Set-PimSqlSetting -ConnectionString $cs -Name 'RemoveRowAbsentSeen' -ValueJson ($m | ConvertTo-Json -Depth 3 -Compress) }
    }
    $now = $NowUtc.ToUniversalTime()
    $map = [ordered]@{}
    # pwsh 7's ConvertFrom-Json turns an ISO string into a [datetime] (local kind) -- normalise every value to 'o' UTC text.
    $norm = { param($v) if ($v -is [datetime]) { $v.ToUniversalTime().ToString('o') } else { "$v" } }
    try {
        $cur = & $Load
        if ($cur -is [System.Collections.IDictionary]) { foreach ($k in $cur.Keys) { $map["$k"] = & $norm $cur[$k] } }
        elseif ($cur) { foreach ($pp in $cur.PSObject.Properties) { $map[$pp.Name] = & $norm $pp.Value } }
    } catch {
        # Cannot prove an earlier absent read -> keep every row (never delete on one read); next run tries again.
        Write-Warning ("  [engine] {0}: {1} absent Remove row(s) KEPT -- the first-absent stamps could not be read: {2}" -f $Scope, $rows.Count, $_.Exception.Message)
        return @()
    }
    $orig = ($map | ConvertTo-Json -Depth 3 -Compress)
    $prefix = "$Entity|"
    $absentKeys = @{}; $confirmed = @(); $waiting = 0
    foreach ($r in $rows) {
        $rk = if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) { "$(Get-PimStoreRowKey -Base $Entity -Row $r)".Trim() } else { '' }
        if (-not $rk) { $waiting++; continue }   # no key -> cannot stamp -> never deleted on one read
        $k = "$prefix$rk"; $absentKeys[$k] = $true
        $first = $null; if ($map.Contains($k)) { try { $first = ([datetime]::Parse("$($map[$k])", [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)) } catch { $first = $null } }
        if ($first -and ($now - $first).TotalMinutes -ge $MinMinutes) { $confirmed += $r; $map.Remove($k) }
        else { if (-not $first) { $map[$k] = $now.ToString('o') }; $waiting++ }
    }
    foreach ($k in @($map.Keys)) {
        $drop = ("$k".StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) -and -not $absentKeys.ContainsKey($k))
        if (-not $drop) { try { $drop = ($now - [datetime]::Parse("$($map[$k])", [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)).TotalDays -gt 7 } catch { $drop = $true } }
        if ($drop) { $map.Remove($k) }
    }
    if (($map | ConvertTo-Json -Depth 3 -Compress) -ne $orig) {
        try { & $Save $map } catch { Write-Warning ("  [engine] {0}: first-absent stamps not saved ({1}) -- the rows stay and are re-checked" -f $Scope, $_.Exception.Message); return @() }
    }
    if ($waiting) { Write-Host ("[engine] {0}: {1} Remove row(s) found nothing live -- KEPT until a read at least {2} min later confirms it (a just-made assignment can lag the live read)" -f $Scope, $waiting, $MinMinutes) -ForegroundColor DarkGray }
    return $confirmed
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

function Get-PimStoreManagedRowCount {
    <#
      §79.15 -- how many rows the store MANAGES (definitions and assignments). 0 = nothing is defined; -1 = could not be
      counted (the gate treats both as "touch nothing"). Reads through Get-PimDesiredRows, the same source every provider
      uses, and stops at the first entity that has rows.
      R25-32 (decided): PIM-Definitions-Resources is deliberately NOT in the list. The discovery sweep writes rows there by
      itself (auto-create policy, PIM-EngineCore discovery), so counting them would let a store the operator never filled
      unlock the engine on the next run -- exactly what this gate exists to stop. A store that ALSO has any operator-defined
      row counts through the other entities, and then Resources rows are managed like every other row.
    #>
    $entities = @('Account-Definitions-Admins', 'Account-Definitions-Admins-Central',
                  'PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks',
                  'PIM-Definitions-Departments', 'PIM-Definitions-Processes', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg',
                  'PIM-Definitions-AU', 'PIM-Assignments-Admins', 'PIM-Assignments-Groups', 'PIM-Assignments-Roles-Groups',
                  'PIM-Assignments-Roles-AUs', 'PIM-Assignments-Azure-Resources', 'PIM-Assignments-Workloads', 'PIM-Assignments-Roles-Direct',
                  'PIM-Assignments-AppRole', 'PIM-Assignments-Defender', 'PIM-Assignments-Intune')
    if (-not (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue)) { return -1 }
    $n = 0; $readOk = 0
    foreach ($e in $entities) {
        try { $c = @(Get-PimDesiredRows -Entity $e | Where-Object { $null -ne $_ }).Count; $readOk++; $n += $c; if ($n -gt 0) { return $n } } catch { }
    }
    if ($readOk -eq 0) { return -1 }
    return $n
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
    #   -ReconcileRemoval report|enforce : the DAILY RECONCILE (96.5) -- also plan the removal of PIM-managed leftovers
    #                          (report = plan + store the report, remove nothing; enforce = remove what every rule allows)
    param([string]$Scope='All', [ValidateSet('Full','Delta')][string]$Mode='Delta', [switch]$WhatIf, [switch]$Prune, [hashtable]$Context=@{}, [object[]]$Changes, [switch]$FromQueue,
          [string]$ReconcileRemoval = '')
    # BUG-19: bound how stale the directory snapshot can be at the start of a run.
    [void](Update-PimEngineRunContext)
    if ($FromQueue -and -not $PSBoundParameters.ContainsKey('Changes')) { $Changes = Get-PimEngineQueueChanges }
    $useChanges = ($FromQueue -or $PSBoundParameters.ContainsKey('Changes'))
    $common = @{ Mode = $Mode; WhatIf = $WhatIf; Prune = $Prune; Context = $Context }
    if ($useChanges) { $common['Changes'] = @($Changes) }
    $__rrRun = "$ReconcileRemoval".Trim().ToLowerInvariant()
    if ($__rrRun) { if ($__rrRun -ne 'enforce') { $__rrRun = 'report' }; $common['ReconcileRemoval'] = $__rrRun }

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
    # 🔒 §79.15 CRITICAL GATE (operator 2026-09-25): "as the definitions are empty (no rows), then engine must not touch
    # anythin - no admins, no groups, no pim etc". A store that manages nothing is a store nobody has filled -- a fresh
    # install, a failed import, a wiped database -- never an instruction. So when not ONE managed row exists, EVERY scope
    # is skipped before it reads or writes anything (a Full -Prune on an empty desired set would otherwise target
    # everything live). Fail closed: a store that cannot be COUNTED is treated the same way.
    $__managed = Get-PimStoreManagedRowCount
    if ($__managed -le 0) {
        $why = if ($__managed -lt 0) { 'the managed rows could not be counted' } else { 'the store defines nothing (0 managed rows)' }
        Write-Host ("[engine] CRITICAL GATE: {0} -- the engine touches NOTHING (no admins, no groups, no policies, no assignments). Define what PIM manages first." -f $why) -ForegroundColor Red
        foreach ($s in @($res.scopes)) {
            # BUG-286 (ig798, 2026-10-04): a store that defines nothing has NOTHING failing. The scopes never run under this
            # gate, so their failure slice was never replaced and the last failures (deleted E2E rows) kept the banner red
            # for days. Clear each skipped scope's slice -- only on a real run, never a plan; never fatal.
            if (-not $WhatIf -and (Get-Command Update-PimEngineItemFailures -ErrorAction SilentlyContinue)) {
                try { [void](Update-PimEngineItemFailures -Scope $s -Failures @()) } catch { Write-Warning "[engine] could not clear the failures of '$s' under the empty-store gate: $($_.Exception.Message)" }
            }
            # R25-32: skipped is a COUNT everywhere (Invoke-PimEngineCore sums it as [int] under Stop -- the text crashed the run,
            # an alert every tick); the reason has its own field.
            $out.Add([pscustomobject]@{ scope = $s; ok = $true; skipped = 0; skipReason = 'no-managed-rows'; detail = "skipped: $why"
                desired = 0; live = 0; create = 0; update = 0; remove = 0; nochange = 0; errors = 0; plan = @() })
        }
        if (@($res.scopes).Count -eq 1 -and -not $res.alias) { return $out[0] }
        return $out.ToArray()
    }
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
    # §83: the upcoming extensions the assignment scopes saw this run -> pim.Settings 'AutoExtendOutlook' (the monthly report
    # and the owner page read it). Best effort: a failed save never fails the run; the next run saves it.
    if (Get-Command Save-PimAutoExtendOutlook -ErrorAction SilentlyContinue) {
        try { [void](Save-PimAutoExtendOutlook) } catch { Write-Warning "[auto-extend] the upcoming-extension list was not saved: $($_.Exception.Message)" }
    }
    # 96.5: the daily reconcile's removal report (would remove N, held by rule X) -> pim.TenantCache 'reconcile-removal', for
    # the Jobs page. Only a real run; a failed save never fails the run (the next run saves it).
    if ($__rrRun -and $Mode -eq 'Full' -and -not $WhatIf -and (Get-Command ConvertTo-PimReconcileRemovalReport -ErrorAction SilentlyContinue)) {
        try {
            $__plans = @(foreach ($__o in $out) { if ($__o -and $__o.PSObject.Properties['reconcileRemoval'] -and $null -ne $__o.reconcileRemoval) { $__o.reconcileRemoval } })
            $__rem = 0; foreach ($__o in $out) { if ($__o -and $__o.PSObject.Properties['reconcileRemoved']) { $__rem += [int]$__o.reconcileRemoved } }
            $__doc = ConvertTo-PimReconcileRemovalReport -Plans $__plans -Mode $__rrRun -CorrelationId "$($global:PIM_JobCorrelationId)" -Removed $__rem
            $__where = Save-PimReconcileRemovalReport -Doc $__doc
            Write-Host ("[reconcile] {0} -> {1}" -f $__doc.summary, $__where) -ForegroundColor DarkYellow
        } catch { Write-Warning "[reconcile] the removal report was not saved: $($_.Exception.Message)" }
    }
    # Preserve the single-scope return shape callers depend on (one object, not a 1-element array).
    if (@($res.scopes).Count -eq 1 -and -not $res.alias) { return $out[0] }
    return $out.ToArray()
}
