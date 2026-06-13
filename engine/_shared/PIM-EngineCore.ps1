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
function Get-PimEngineScopes { @($script:PimEngineProviders.Values | ForEach-Object { $_.scope }) }

# ---- default desired/live helpers -----------------------------------------
function Get-PimDesiredRows {
    # DESIRED comes from SQL (pim.Rows) when the SQL store is active, else in-memory
    # ($global:PIM_DesiredRows[$entity]) for tests/offline.
    param([Parameter(Mandatory)][string]$Entity)
    if (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue) { try { return @(Get-PimSqlRows -Entity $Entity) } catch {} }
    if ($global:PIM_DesiredRows -and $global:PIM_DesiredRows.ContainsKey($Entity)) { return @($global:PIM_DesiredRows[$Entity]) }
    return @()
}

# ---- orchestrator ---------------------------------------------------------
function Invoke-PimEngineScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Scope,
        [ValidateSet('Full','Delta')][string]$Mode = 'Delta',
        [switch]$WhatIf,
        [hashtable]$Context = @{}
    )
    $p = Get-PimEngineProvider -Scope $Scope
    if (-not $p) { return [pscustomobject]@{ scope=$Scope; ok=$false; detail="no provider for scope '$Scope'" } }

    $desired = @(& $p.GetDesired $Context)
    $live    = @(& $p.GetLive    $Context)
    $diff = Compare-PimDesiredVsLive -Desired $desired -Live $live -KeyOf $p.KeyOf -Equal $p.Equal -Prune:($Mode -eq 'Full')

    $plan = New-Object System.Collections.Generic.List[object]
    $applied = 0; $errors = 0
    $do = {
        param($op,$item,$handlerName)
        $entity = if ($p.entity) { "$($p.entity)" } else { "$Scope" }
        if (Get-Command New-PimChange -ErrorAction SilentlyContinue) {
            $payload = if ($op -eq 'Remove') { $item.live } else { $item.desired }
            $plan.Add((New-PimChange -Entity $entity -Key "$($item.key)" -Op $op -By 'engine' -Payload $payload))
        } else { $plan.Add([pscustomobject]@{ entity=$entity; key="$($item.key)"; op=$op }) }
        if (-not $WhatIf -and $p.$handlerName) {
            try { & $p.$handlerName $item $Context | Out-Null; $script:__applied++ } catch { $script:__errors++; Write-Warning "engine ${Scope} ${op} $($item.key): $($_.Exception.Message)" }
        }
    }
    $script:__applied = 0; $script:__errors = 0
    foreach ($i in $diff.create) { & $do 'Create' $i 'ApplyCreate' }
    foreach ($i in $diff.update) { & $do 'Update' $i 'ApplyUpdate' }
    foreach ($i in $diff.remove) { & $do 'Remove' $i 'ApplyRemove' }   # only present in Full

    return [pscustomobject]@{
        scope=$Scope; mode=$Mode; whatIf=[bool]$WhatIf
        create=$diff.create.Count; update=$diff.update.Count; remove=$diff.remove.Count; nochange=$diff.nochange.Count
        applied=$script:__applied; errors=$script:__errors; plan=$plan.ToArray(); ok=($script:__errors -eq 0)
    }
}

function Invoke-PimEngine {
    # Run one scope, or all registered scopes (Scope='All'). Mode Full/Delta. WhatIf =
    # plan only. This is the entrypoint the scheduler/launcher calls.
    [CmdletBinding()]
    param([string]$Scope='All', [ValidateSet('Full','Delta')][string]$Mode='Delta', [switch]$WhatIf, [hashtable]$Context=@{})
    if ("$Scope".ToLowerInvariant() -eq 'all') {
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($s in (Get-PimEngineScopes)) { $out.Add((Invoke-PimEngineScope -Scope $s -Mode $Mode -WhatIf:$WhatIf -Context $Context)) }
        return $out.ToArray()
    }
    return Invoke-PimEngineScope -Scope $Scope -Mode $Mode -WhatIf:$WhatIf -Context $Context
}
