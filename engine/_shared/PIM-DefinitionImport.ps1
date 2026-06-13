# PIM4EntraPS -- connector role-definition import.
# Dot-sourced by PIM-Functions.psm1 (needs PIM-PermissionWizard.ps1) and the
# pim-manager.
#
# Connectors expose live roles (Get-PimWorkloadRoles). This turns "new roles in a
# workload/service" into PIM permission DEFINITIONS:
#   - MANUAL import: a super-admin imports the latest definitions (all candidates)
#   - AUTO import: keyed by service-type (entra/azure/workload) + tier + level, so
#     e.g. new landing zones / new entra roles at a given level auto-become
#     definitions and the business can then link roles/tasks/dept/org/processes
# Pure planner (testable); output feeds the change queue (PIM-ChangeQueue.ps1).

Set-StrictMode -Off

function Get-PimRoleDerivation {
    # Derive a single role's definition facets per service type.
    param([Parameter(Mandatory)][string]$ServiceType, [Parameter(Mandatory)][string]$RoleName, [string]$Workload)
    switch ("$ServiceType".ToLowerInvariant()) {
        'entra'    { return (Get-PimEntraDerivation -Roles @($RoleName)) }
        'workload' { return (Get-PimWorkloadDerivation -Workload $(if ("$Workload".Trim()) { $Workload } else { 'Workload' }) -Roles @($RoleName)) }
        default    { throw "Get-PimRoleDerivation: import is role-based for 'entra'/'workload' only ('azure' is scope-based -- use PIM-AzureDiscovery)." }
    }
}

function Test-PimDefinitionAutoImport {
    # Does a derived definition match an auto-import policy entry? Policy entry:
    #   @{ serviceType='entra'; maxTierNum=0; minLevel=1; maxLevel=2 }
    #   @{ serviceType='workload'; workloads=@('defender','powerbi') }
    param(
        [Parameter(Mandatory)][string]$ServiceType,
        [int]$Tier, [int]$Level, [string]$Workload,
        [object[]]$Policy = @()
    )
    foreach ($r in @($Policy)) {
        if ("$($r.serviceType)".ToLowerInvariant() -ne "$ServiceType".ToLowerInvariant()) { continue }
        if ($null -ne $r.maxTierNum -and "$($r.maxTierNum)" -ne '' -and $Tier -gt [int]$r.maxTierNum) { continue }
        if ($null -ne $r.minLevel  -and "$($r.minLevel)"  -ne '' -and $Level -lt [int]$r.minLevel) { continue }
        if ($null -ne $r.maxLevel  -and "$($r.maxLevel)"  -ne '' -and $Level -gt [int]$r.maxLevel) { continue }
        $wls = @(@($r.workloads) | ForEach-Object { "$_".ToLowerInvariant() })
        if ($wls.Count -gt 0 -and $wls -notcontains "$Workload".ToLowerInvariant()) { continue }
        return $true
    }
    return $false
}

function Get-PimDefinitionImportPlan {
    # Live roles -> import plan. Roles already represented (their derived
    # groupName is in $ExistingGroupNames) are 'existing'; the rest are candidates,
    # split into autoCreate (match policy) and manual (need a super-admin click).
    param(
        [Parameter(Mandatory)][string]$ServiceType,
        [object[]]$LiveRoles = @(),                # objects with .name
        [string[]]$ExistingGroupNames = @(),
        [string]$Workload,
        [object[]]$Policy = @()
    )
    $have = @{}; foreach ($n in @($ExistingGroupNames)) { $have["$n".ToLowerInvariant()] = $true }
    $auto = New-Object System.Collections.Generic.List[object]
    $manual = New-Object System.Collections.Generic.List[object]
    $existing = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($LiveRoles)) {
        $rn = "$($r.name)"; if (-not $rn.Trim()) { continue }
        $d = Get-PimRoleDerivation -ServiceType $ServiceType -RoleName $rn -Workload $Workload
        $entry = [pscustomobject]@{ role = $rn; groupName = "$($d.groupName)"; tier = $d.tier; level = $d.level; plane = $d.plane; kind = $d.kind; derivation = $d }
        if ($have.ContainsKey("$($d.groupName)".ToLowerInvariant())) { $existing.Add($entry); continue }
        if (Test-PimDefinitionAutoImport -ServiceType $ServiceType -Tier ([int]$d.tier) -Level ([int]$d.level) -Workload $Workload -Policy $Policy) { $auto.Add($entry) }
        else { $manual.Add($entry) }
    }
    return [pscustomobject]@{
        serviceType = "$ServiceType"; workload = "$Workload"
        autoCreate = $auto.ToArray(); manual = $manual.ToArray(); existing = $existing.ToArray()
        summary = [ordered]@{ autoCreate = $auto.Count; manual = $manual.Count; existing = $existing.Count }
    }
}

function ConvertTo-PimImportQueueChanges {
    # Import plan -> change-queue Create records. By default only autoCreate; pass
    # -IncludeManual for a super-admin "import all latest" action.
    param(
        [Parameter(Mandatory)][object]$Plan,
        [string]$Entity = 'PIM-Definitions-Services',
        [switch]$IncludeManual,
        [string]$By = 'definition-import'
    )
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($Plan.autoCreate)) { $out.Add((New-PimChange -Entity $Entity -Key "$($c.groupName)" -Op Create -Payload $c.derivation -By $By)) }
    if ($IncludeManual) { foreach ($c in @($Plan.manual)) { $out.Add((New-PimChange -Entity $Entity -Key "$($c.groupName)" -Op Create -Payload $c.derivation -By $By)) } }
    return $out.ToArray()
}
