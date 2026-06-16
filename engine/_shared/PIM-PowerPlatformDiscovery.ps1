# PIM4EntraPS -- Power Platform environment auto-discovery + reconcile.
# Dot-sourced by PIM-Functions.psm1 (needs PIM-PermissionWizard.ps1 for the
# name grammar + PIM-ChangeQueue.ps1 for New-PimChange) and standalone by the
# pim-manager.
#
# Power Platform (Power Apps / Power Automate / Dataverse) is a DISTINCT workload
# from Power BI workspaces (REQUIREMENTS §8). New Power Platform ENVIRONMENTS
# (default, production, sandbox, developer, ...) appear over time; each becomes a
# delegable surface. This module discovers them (live listing is the launcher's
# job, via the BAP admin API) and RECONCILES the discovered environments against
# the existing PIM definitions, EXACTLY like the Azure scope reconcile:
#   - NEW environment, no definition         -> Create (auto-import only if a rule matches)
#   - environment RENAMED (displayName drift) -> Rename (old groupName -> new)
#   - definition whose environment is GONE    -> Orphan (flag for removal)
# PROPOSE-don't-auto-map by default: with no rules every discovery is a pending
# human decision (same contract as new subs/MGs). Pure planner, testable offline;
# the reconcile output feeds the change queue so a commit applies just the deltas.

Set-StrictMode -Off

function Get-PimPowerPlatformStableKey {
    # Stable identity of an environment across renames: its environment NAME (the
    # GUID-like immutable id, e.g. 'Default-<tenantGuid>' or a 'xxxxxxxx-....'),
    # NOT the displayName (which the admin can change). That's what lets a rename
    # be detected as a rename instead of an orphan + a duplicate.
    param([Parameter(Mandatory)][string]$EnvironmentName)
    return ("ppenv:" + "$EnvironmentName".Trim()).ToLowerInvariant()
}

function Get-PimPowerPlatformDerivation {
    # Scope-only definition derivation for one Power Platform environment -- the
    # permission-group CONTAINER the business later links environment roles to.
    # Power Platform environment admin is a workload data-plane surface:
    #   tier 1 (not the directory control plane), plane WDP, domain RES,
    #   level by environment kind (Production tighter than Sandbox/Developer).
    # Name:  PIM-PowerPlatform-{EnvName}-L{level}-T1-WDP-RES
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [string]$EnvironmentType = 'Production'
    )
    $tier = 1
    $code = 'WDP'      # workload data plane (the app's own RBAC, not Entra/Azure)
    $domain = 'RES'
    # Production/default environments hold business-critical apps+data -> tighter
    # (lower) level; sandbox/trial/developer are looser.
    $level = switch -Regex ("$EnvironmentType") {
        '(?i)default|production' { 3 }
        '(?i)sandbox|trial'     { 4 }
        '(?i)developer|teams'   { 5 }
        default                 { 4 }
    }
    $seg = if ("$DisplayName".Trim()) { ConvertTo-PimNameSegment $DisplayName } else { ConvertTo-PimNameSegment $EnvironmentType }
    $name = New-PimPermissionGroupName -Service 'PowerPlatform' -Name $seg -Level $level -Tier $tier -Code $code -Domain $domain
    return [pscustomobject]@{ level = $level; tier = $tier; plane = $code; domain = $domain; environmentType = "$EnvironmentType"; groupName = $name }
}

function Test-PimPowerPlatformAutoImport {
    # Does a discovered environment match an auto-import rule? A rule:
    #   @{ environmentTypes=@('Sandbox','Developer'); minLevel=4; maxLevel=9 }
    # (e.g. "auto-import sandbox/dev envs on level >= 4"). No rules -> $false
    # (discovered but PENDING a human decision -- propose, never auto-map).
    param([Parameter(Mandatory)][object]$Environment, [object[]]$Rules = @())
    $der = Get-PimPowerPlatformDerivation -DisplayName "$($Environment.displayName)" -EnvironmentType "$($Environment.environmentType)"
    $lvl = $der.level
    foreach ($r in @($Rules)) {
        $types = @(@($r.environmentTypes) | ForEach-Object { "$_".ToLowerInvariant() })
        if ($types.Count -gt 0 -and $types -notcontains "$($Environment.environmentType)".ToLowerInvariant()) { continue }
        if ($null -ne $r.minLevel -and "$($r.minLevel)" -ne '' -and $lvl -lt [int]$r.minLevel) { continue }
        if ($null -ne $r.maxLevel -and "$($r.maxLevel)" -ne '' -and $lvl -gt [int]$r.maxLevel) { continue }
        return $true
    }
    return $false
}

function Get-PimPowerPlatformReconcilePlan {
    # Discovered environments vs existing definitions -> create / rename / orphan /
    # unchanged. Each discovered item: @{ environmentName; displayName; environmentType }.
    # Existing items: @{ environmentName; groupName }.
    param(
        [object[]]$Discovered = @(),
        [object[]]$Existing = @(),
        [object[]]$AutoImportRules = @()
    )
    $exIndex = @{}
    foreach ($e in @($Existing)) { $exIndex[(Get-PimPowerPlatformStableKey -EnvironmentName "$($e.environmentName)")] = $e }
    $create = New-Object System.Collections.Generic.List[object]
    $rename = New-Object System.Collections.Generic.List[object]
    $unchanged = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($d in @($Discovered)) {
        $k = Get-PimPowerPlatformStableKey -EnvironmentName "$($d.environmentName)"
        $seen[$k] = $true
        $exp = Get-PimPowerPlatformDerivation -DisplayName "$($d.displayName)" -EnvironmentType "$($d.environmentType)"
        if ($exIndex.ContainsKey($k)) {
            $cur = $exIndex[$k]
            if ("$($cur.groupName)" -ne "$($exp.groupName)") {
                $rename.Add([pscustomobject]@{ stableKey = $k; environmentName = "$($d.environmentName)"; from = "$($cur.groupName)"; to = "$($exp.groupName)"; expected = $exp })
            } else {
                $unchanged.Add([pscustomobject]@{ stableKey = $k; environmentName = "$($d.environmentName)"; groupName = "$($exp.groupName)" })
            }
        } else {
            $auto = Test-PimPowerPlatformAutoImport -Environment $d -Rules $AutoImportRules
            $create.Add([pscustomobject]@{ stableKey = $k; environmentName = "$($d.environmentName)"; displayName = "$($d.displayName)"; expected = $exp; autoImport = $auto })
        }
    }
    $orphan = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Existing)) {
        $k = Get-PimPowerPlatformStableKey -EnvironmentName "$($e.environmentName)"
        if (-not $seen.ContainsKey($k)) { $orphan.Add([pscustomobject]@{ stableKey = $k; environmentName = "$($e.environmentName)"; groupName = "$($e.groupName)" }) }
    }
    return [pscustomobject]@{
        create = $create.ToArray(); rename = $rename.ToArray(); orphan = $orphan.ToArray(); unchanged = $unchanged.ToArray()
        summary = [ordered]@{ create = $create.Count; rename = $rename.Count; orphan = $orphan.Count; unchanged = $unchanged.Count
                              autoCreate = @($create | Where-Object { $_.autoImport }).Count }
    }
}

function ConvertTo-PimPowerPlatformQueueChanges {
    # Reconcile plan -> change-queue records (PIM-ChangeQueue.ps1). Auto-imports ->
    # Create; renames -> Update (carry from/to); orphans -> Remove (only with
    # -IncludeOrphanRemovals, since removing is destructive). Non-auto creates are
    # LEFT OUT -- they need a human decision in the GUI (propose, never auto-map).
    param(
        [Parameter(Mandatory)][object]$Plan,
        [string]$Entity = 'PIM-Definitions-Services',
        [switch]$IncludeOrphanRemovals,
        [string]$By = 'powerplatform-discovery'
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

# Normalise a raw BAP admin-API environment record into the discovery shape the
# planner consumes. The launcher fetches the list LIVE (GET
# https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2021-04-01)
# and pipes each .value item through this. Pure shaping -- no network here.
function ConvertFrom-PimPowerPlatformEnvironment {
    param([Parameter(Mandatory)][object]$Raw)
    $name = "$($Raw.name)"
    $disp = "$($Raw.properties.displayName)"
    $type = "$($Raw.properties.environmentSku)"
    if (-not $type) { $type = "$($Raw.properties.environmentType)" }
    return [pscustomobject]@{ environmentName = $name; displayName = $disp; environmentType = $type }
}
