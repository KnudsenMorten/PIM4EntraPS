# PIM4EntraPS -- Azure scope auto-discovery + reconcile.
# Dot-sourced by PIM-Functions.psm1 (needs PIM-PermissionWizard.ps1 for the
# scope-depth/plane helpers) and standalone by the pim-manager.
#
# The connector/engine discovers Azure management groups + subscriptions (+ RGs).
# This module RECONCILES the discovered tree against the existing PIM definitions:
#   - NEW scope, no definition           -> Create (auto-import if it matches a rule)
#   - scope MOVED/RENAMED (new expected   -> Rename (old groupName -> new), so the
#     name; e.g. a sub moved under a new      group is renamed in place instead of
#     management group changes level/plane)   leaving an orphan + a duplicate
#   - definition whose scope is GONE     -> Orphan (flag for removal)
# Pure planner (testable offline); the reconcile output feeds the change queue
# (PIM-ChangeQueue.ps1) so a commit applies just the deltas.

Set-StrictMode -Off

function Get-PimAzureStableKey {
    # Stable identity of a scope across renames/moves: subscription GUID, or the
    # management-group name, or sub/rg. (A sub keeps its GUID when moved under a
    # new MG; that's what lets us detect a move as a rename, not an orphan.)
    param([Parameter(Mandatory)][string]$ScopePath)
    $p = "$ScopePath".Trim().TrimEnd('/')
    $mSub = [regex]::Match($p, '(?i)/subscriptions/([^/]+)')
    if ($mSub.Success) {
        $rg = [regex]::Match($p, '(?i)/resourceGroups/([^/]+)')
        if ($rg.Success) { return ("sub:" + $mSub.Groups[1].Value + "/rg:" + $rg.Groups[1].Value).ToLowerInvariant() }
        return ("sub:" + $mSub.Groups[1].Value).ToLowerInvariant()
    }
    $mMg = [regex]::Match($p, '(?i)/managementGroups/([^/]+)')
    if ($mMg.Success) { return ("mg:" + $mMg.Groups[1].Value).ToLowerInvariant() }
    if ($p -eq '/' -or $p -eq '') { return 'tenantroot' }
    return $p.ToLowerInvariant()
}

function Get-PimAzureScopeDerivation {
    # Scope-only definition derivation (no role segment) -- the permission-group
    # CONTAINER the business later links roles to. Name:
    #   PIM-Azure-{ScopeName}-L{level}-T{tier}-{plane}-{domain}
    param(
        [Parameter(Mandatory)][ValidateSet('tenantRoot','managementGroup','subscription','resourceGroup','resource')][string]$ScopeType,
        [string]$ScopePath, [string]$ScopeName, [int]$ManagementGroupDepth = 1
    )
    $level = Get-PimAzureScopeDepth -ScopeType $ScopeType -ScopePath $ScopePath -ManagementGroupDepth $ManagementGroupDepth
    $tier  = if ($ScopeType -eq 'tenantRoot') { 0 } else { 1 }
    $plane = Get-PimAzurePlane -ScopeType $ScopeType -ScopePath $ScopePath -ScopeName $ScopeName
    $hay   = ("$ScopePath $ScopeName").ToLowerInvariant()
    $domain = if ($plane -eq 'WDP' -and ($hay -match '(storage|sql|data)')) { 'DAT' } else { 'RES' }
    $seg = if ("$ScopeName".Trim()) { ConvertTo-PimNameSegment $ScopeName } else { ConvertTo-PimNameSegment $ScopeType }
    $name = New-PimPermissionGroupName -Service 'Azure' -Name $seg -Level $level -Tier $tier -Code $plane -Domain $domain
    return [pscustomobject]@{ level = $level; tier = $tier; plane = $plane; domain = $domain; groupName = $name }
}

function Test-PimAutoImport {
    # Does a discovered scope match an auto-import rule? A rule:
    #   @{ scopeTypes=@('subscription','managementGroup'); minLevel=0; maxLevel=4; roles=@(...) }
    # (e.g. "new landing zones on level <= 4 auto-import"). No rules -> $false
    # (discovered but pending a human decision).
    param([Parameter(Mandatory)][object]$Scope, [object[]]$Rules = @())
    $lvl = Get-PimAzureScopeDepth -ScopeType $Scope.scopeType -ScopePath $Scope.scopePath -ManagementGroupDepth ([int]("$($Scope.mgmtGroupDepth)" -as [int]))
    foreach ($r in @($Rules)) {
        $types = @(@($r.scopeTypes) | ForEach-Object { "$_".ToLowerInvariant() })
        if ($types.Count -gt 0 -and $types -notcontains "$($Scope.scopeType)".ToLowerInvariant()) { continue }
        if ($null -ne $r.minLevel -and "$($r.minLevel)" -ne '' -and $lvl -lt [int]$r.minLevel) { continue }
        if ($null -ne $r.maxLevel -and "$($r.maxLevel)" -ne '' -and $lvl -gt [int]$r.maxLevel) { continue }
        return $true
    }
    return $false
}

function Get-PimAzureReconcilePlan {
    # Discovered scopes vs existing definitions -> create / rename / orphan /
    # unchanged. Each discovered/existing item: @{ scopeType; scopePath; scopeName;
    # mgmtGroupDepth }; existing items also carry groupName (current).
    param(
        [object[]]$Discovered = @(),
        [object[]]$Existing = @(),
        [object[]]$AutoImportRules = @()
    )
    $exIndex = @{}
    foreach ($e in @($Existing)) { $exIndex[(Get-PimAzureStableKey -ScopePath "$($e.scopePath)")] = $e }
    $create = New-Object System.Collections.Generic.List[object]
    $rename = New-Object System.Collections.Generic.List[object]
    $unchanged = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($d in @($Discovered)) {
        $k = Get-PimAzureStableKey -ScopePath "$($d.scopePath)"
        $seen[$k] = $true
        $exp = Get-PimAzureScopeDerivation -ScopeType $d.scopeType -ScopePath "$($d.scopePath)" -ScopeName "$($d.scopeName)" -ManagementGroupDepth ([int]("$($d.mgmtGroupDepth)" -as [int]))
        if ($exIndex.ContainsKey($k)) {
            $cur = $exIndex[$k]
            if ("$($cur.groupName)" -ne "$($exp.groupName)") {
                $rename.Add([pscustomobject]@{ stableKey = $k; scopePath = "$($d.scopePath)"; from = "$($cur.groupName)"; to = "$($exp.groupName)"; expected = $exp })
            } else {
                $unchanged.Add([pscustomobject]@{ stableKey = $k; scopePath = "$($d.scopePath)"; groupName = "$($exp.groupName)" })
            }
        } else {
            $auto = Test-PimAutoImport -Scope $d -Rules $AutoImportRules
            $create.Add([pscustomobject]@{ stableKey = $k; scopePath = "$($d.scopePath)"; scopeName = "$($d.scopeName)"; expected = $exp; autoImport = $auto })
        }
    }
    $orphan = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Existing)) {
        $k = Get-PimAzureStableKey -ScopePath "$($e.scopePath)"
        if (-not $seen.ContainsKey($k)) { $orphan.Add([pscustomobject]@{ stableKey = $k; scopePath = "$($e.scopePath)"; groupName = "$($e.groupName)" }) }
    }
    return [pscustomobject]@{
        create = $create.ToArray(); rename = $rename.ToArray(); orphan = $orphan.ToArray(); unchanged = $unchanged.ToArray()
        summary = [ordered]@{ create = $create.Count; rename = $rename.Count; orphan = $orphan.Count; unchanged = $unchanged.Count
                              autoCreate = @($create | Where-Object { $_.autoImport }).Count }
    }
}

# Turn a reconcile plan into change-queue records (PIM-ChangeQueue.ps1): auto-imports
# -> Create; renames -> Update (carry from/to); orphans -> Remove (only when
# -IncludeOrphanRemovals, since removing is destructive). Non-auto creates are
# left out (they need a human decision in the GUI).
function ConvertTo-PimReconcileQueueChanges {
    param(
        [Parameter(Mandatory)][object]$Plan,
        [string]$Entity = 'PIM-Definitions-Resources',
        [switch]$IncludeOrphanRemovals,
        [string]$By = 'azure-discovery'
    )
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Plan.create)) {
        if (-not $c.autoImport) { continue }
        $out.Add((New-PimChange -Entity $Entity -Key "$($c.expected.groupName)" -Op Create -Payload $c.expected -By $By))
    }
    foreach ($r in @($Plan.rename)) {
        $out.Add((New-PimChange -Entity $Entity -Key "$($r.to)" -Op Update -Payload ([pscustomobject]@{ rename = $true; from = "$($r.from)"; to = "$($r.to)"; expected = $r.expected }) -By $By))
    }
    if ($IncludeOrphanRemovals) {
        foreach ($o in @($Plan.orphan)) { $out.Add((New-PimChange -Entity $Entity -Key "$($o.groupName)" -Op Remove -By $By)) }
    }
    return $out.ToArray()
}
