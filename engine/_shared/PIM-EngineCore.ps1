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
        [switch]$Prune                               # remove live not in desired (Full)
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
    if ($Prune) {
        foreach ($l in @($Live)) {
            if ($null -eq $l) { continue }
            $k = "$(& $KeyOf $l)".Trim(); $lk = $k.ToLowerInvariant()
            if ($lk -and -not $desKeys.ContainsKey($lk)) { $remove.Add([pscustomobject]@{ key=$k; live=$l }) }
        }
    }
    return [pscustomobject]@{ create=$create.ToArray(); update=$update.ToArray(); remove=$remove.ToArray(); nochange=$nochange.ToArray() }
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

# ---- default desired/live helpers -----------------------------------------
function Get-PimDesiredRows {
    # DESIRED comes from SQL (pim.Rows) when the SQL store is active, else in-memory
    # ($global:PIM_DesiredRows[$entity]) for tests/offline.
    # NB: Get-PimSqlRows REQUIRES -ConnectionString. It was called without one, so it
    # errored silently -> 0 desired (the engine appeared to do nothing). Resolve the CS
    # from the engine CS / in-memory CS / build from $global:PIM_SqlServer+Database.
    param([Parameter(Mandatory)][string]$Entity)
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
    $global:PIM_DesiredResolved[$Entity] = $false
    return @()
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
    $diff = Compare-PimDesiredVsLive -Desired $desired -Live $live -KeyOf $p.KeyOf -Equal $p.Equal -Prune:$doPrune

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
            # Reported, never silent. These are admin accounts the desired set cannot
            # attribute -- typically a different verified domain (BUG-13). Treating them
            # as removals is what made Admin-PAW-* and the engine's own account look
            # disposable.
            Write-Host ("[engine] {0}: {1} UNMANAGED admin account(s) are NOT in the desired set: {2}" -f `
                $Scope, @($sel.unmanaged).Count, (($sel.unmanaged) -join ', ')) -ForegroundColor Yellow
            Write-Host ("[engine] {0}: the desired set is AUTHORITATIVE (MSP model) -- an admin who has left is SUPPOSED to be deprovisioned here, so these remain removable, subject to the disable opt-in, the circuit breaker and the G4 budget. Set `$global:PIM_RemoveUnmanagedAdmins=`$false for report-only." -f $Scope) -ForegroundColor Yellow
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
    if (@($diff.remove).Count -gt 0 -and (Get-Command Test-PimRemoveBudgetAllowed -ErrorAction SilentlyContinue)) {
        $rb = Test-PimRemoveBudgetAllowed -ToRemove (@($diff.remove).Count) -Scope $Scope -Scanned (@($live).Count) -Operation 'remove'
        if (-not $rb.allowed) {
            if (Get-Command Write-PimRemoveBudgetAlert -ErrorAction SilentlyContinue) { Write-PimRemoveBudgetAlert -Decision $rb }
            else { Write-Host ("[engine] {0}: REMOVAL BUDGET exceeded -- {1}" -f $Scope, $rb.reason) -ForegroundColor Red }
            $diff = [pscustomobject]@{ create = @($diff.create); update = @($diff.update); remove = @(); nochange = @($diff.nochange) }
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
        if (-not $WhatIf -and $p.$handlerName) {
            try {
                # BUG-35a: a handler that RETURNS WITHOUT ACTING must not be counted as applied.
                # AdminOffboarding's ApplyRemove does exactly that in the default Report mode --
                # it prints "would offboard" and returns -- yet the run still summarised
                # `remove=1 applied=1`, making a dry run indistinguishable from a real change in
                # the one number an operator reads. A handler now signals this by returning an
                # object carrying `pimApplied = $false`; anything else (including the API
                # responses every other handler returns) still counts as applied, so this is
                # additive and cannot change existing behaviour.
                $__r = & $p.$handlerName $item $Context
                $__reported = $false
                foreach ($__o in @($__r)) {
                    if ($null -ne $__o -and $__o.PSObject -and ($__o.PSObject.Properties.Name -contains 'pimApplied') -and (-not $__o.pimApplied)) { $__reported = $true }
                }
                if ($__reported) {
                    $script:__skipped++
                    Write-Host ("    [r] {0} (reported only -- NOT applied)" -f $item.key) -ForegroundColor DarkYellow
                } else {
                    $script:__applied++; Write-Host ("    [{0}] {1}" -f $sym, $item.key) -ForegroundColor Green
                }
            }
            catch {
                $em = "$($_.Exception.Message)"
                # Already-exists / conflict = the desired setting is already in place -> validate-and-skip,
                # not a failure (idempotent re-run). Mirrors the legacy "RoleAssignmentExists ... skipping".
                if ($em -match '(?i)RoleAssignmentExists|already exist|references already exist|ConflictingObjects|existing assignment|A conflicting object|RoleAssignmentRequestPolicyValidationFailed.*active|The Role assignment already exists') {
                    $script:__skipped++; Write-Host ("    [=] {0} (exists -- validated, skipped)" -f $item.key) -ForegroundColor DarkGray
                } elseif ($em -match '(?i)Nesting is currently not supported') {
                    # Entra forbids nesting a group INTO a role-assignable group. Not retryable and
                    # not an engine fault -- the data models an unsupported nesting. Skip + warn.
                    $script:__skipped++; Write-Host ("    [!] {0} (skipped -- Entra: no group nesting into role-assignable groups; fix the data)" -f $item.key) -ForegroundColor Yellow
                } else {
                    $script:__errors++; Write-Host ("    [x] {0} {1} FAILED: {2}" -f $op, $item.key, $em) -ForegroundColor Red
                }
            }
        } else {
            Write-Host ("    [{0}] {1} (plan)" -f $sym, $item.key) -ForegroundColor DarkGray
        }
    }
    $script:__applied = 0; $script:__errors = 0; $script:__skipped = 0
    foreach ($i in $diff.create) { & $do 'Create' $i 'ApplyCreate' }
    foreach ($i in $diff.update) { & $do 'Update' $i 'ApplyUpdate' }
    foreach ($i in $diff.remove) { & $do 'Remove' $i 'ApplyRemove' }   # only present in Full
    Write-Host ("[engine] {0,-20} done  applied={1} skipped={2} errors={3}" -f $Scope, $script:__applied, $script:__skipped, $script:__errors) -ForegroundColor $(if ($script:__errors) { 'Yellow' } else { 'Green' })

    return [pscustomobject]@{
        scope=$Scope; mode=$Mode; whatIf=[bool]$WhatIf
        create=$diff.create.Count; update=$diff.update.Count; remove=$diff.remove.Count; nochange=$diff.nochange.Count
        applied=$script:__applied; skipped=$script:__skipped; errors=$script:__errors; plan=$plan.ToArray(); ok=($script:__errors -eq 0)
        disableAborted=$script:__disableAborted
    }
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
    if ("$Scope".ToLowerInvariant() -eq 'all') {
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($s in (Get-PimEngineScopes)) { $out.Add((Invoke-PimEngineScope -Scope $s @common)) }
        return $out.ToArray()
    }
    return Invoke-PimEngineScope -Scope $Scope @common
}
