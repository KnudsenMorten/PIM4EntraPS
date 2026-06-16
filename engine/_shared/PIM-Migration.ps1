#Requires -Version 5.1
# PIM4EntraPS -- v1 -> v2 migration path (REQUIREMENTS § 18 "Migrate ... off v1").
#
# Reads a v1 (legacy) PIM baseline -- a flat "this user gets this role, directly" list
# (the v1 model assigned PIM directory roles / Azure roles DIRECTLY to the admin) --
# and maps it onto the v2 GROUP-CENTRIC model:
#
#   v1: admin --(direct)--> role
#   v2: admin --(member of)--> PIM group --(holds)--> role
#       i.e. one PIM-Definitions-Roles group per distinct role, then
#            PIM-Assignments-Roles-Groups (group -> role) +
#            PIM-Assignments-Admins (admin -> group).
#
# This module is PLAN-ONLY. It is pure (no live calls, no writes to Entra/Azure/SQL,
# no overwrite of customer CSVs). It returns a migration plan object the caller may
# render as a report or hand to the Manager's Review & Save. Mirrors the engine's
# "propose, never auto-apply" tenet (cf. discovery auto-map gate).
#
# Sources accepted:
#   * a v1 CSV with columns ~ UserPrincipalName/User + RoleName/Role [+ Scope] [+ AssignmentType]
#   * a v1 'Custom-Policies.ps1'-style PS data file that assigns to $PIM_* / $Custom_*
#     arrays of [pscustomobject]/hashtable rows (read via a sandboxed dot-source).
#
# PS 5.1-safe: @() wraps whole pipelines, no ?./??, no ImportFromPem, no Set-Content.

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Column resolution -- v1 baselines vary; accept the common aliases.
# ---------------------------------------------------------------------------
function Get-PimV1RowValue {
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)][string[]]$Names)
    foreach ($n in $Names) {
        if ($Row -is [hashtable]) {
            foreach ($k in @($Row.Keys)) { if ("$k" -ieq $n) { return "$($Row[$k])".Trim() } }
        } else {
            $p = $Row.PSObject.Properties | Where-Object { $_.Name -ieq $n } | Select-Object -First 1
            if ($p) { return "$($p.Value)".Trim() }
        }
    }
    return ''
}

# ---------------------------------------------------------------------------
# Read a v1 baseline into a normalised list of @{ User; Role; Scope; AssignmentType }.
# ---------------------------------------------------------------------------
function Import-PimV1Baseline {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Import-PimV1Baseline: file not found: $Path" }
    $ext  = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    $rows = New-Object System.Collections.Generic.List[object]

    if ($ext -eq '.csv') {
        $delim = ';'
        $first = (Get-Content -LiteralPath $Path -TotalCount 1)
        if ("$first".IndexOf(';') -lt 0 -and "$first".IndexOf(',') -ge 0) { $delim = ',' }
        $raw = @(Import-Csv -LiteralPath $Path -Delimiter $delim)
        foreach ($r in $raw) { [void]$rows.Add($r) }
    } elseif ($ext -eq '.ps1') {
        # Sandbox the dot-source: run in a child scope, harvest $PIM_* / $Custom_* /
        # $*Polic* / $*Assignment* array variables, never touch the parent runspace.
        $sb = [scriptblock]::Create((Get-Content -LiteralPath $Path -Raw))
        $found = New-Object System.Collections.Generic.List[object]
        & {
            . $sb 4>$null 3>$null 2>$null
            $vars = Get-Variable -Scope Local | Where-Object {
                $_.Name -match '(?i)polic|assign|role|admin|custom|pim' -and $null -ne $_.Value
            }
            foreach ($v in $vars) {
                foreach ($item in @($v.Value)) {
                    if ($item -is [pscustomobject] -or $item -is [hashtable]) { [void]$found.Add($item) }
                }
            }
        }
        foreach ($r in $found) { [void]$rows.Add($r) }
    } else {
        throw "Import-PimV1Baseline: unsupported extension '$ext' (expected .csv or .ps1)."
    }

    $norm = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        $user = Get-PimV1RowValue -Row $r -Names @('UserPrincipalName', 'UPN', 'User', 'Username', 'Member', 'Admin', 'Owner')
        $role = Get-PimV1RowValue -Row $r -Names @('RoleName', 'Role', 'RoleDefinitionName', 'DirectoryRole', 'AzureRole')
        if (-not $user -and -not $role) { continue }
        [void]$norm.Add([pscustomobject]@{
            User           = $user
            Role           = $role
            Scope          = (Get-PimV1RowValue -Row $r -Names @('Scope', 'Resource', 'ScopeId', 'AdministrativeUnit', 'AU', 'Directory'))
            AssignmentType = (Get-PimV1RowValue -Row $r -Names @('AssignmentType', 'Type', 'State'))
        })
    }
    return @($norm.ToArray())
}

# ---------------------------------------------------------------------------
# Map normalised v1 rows -> v2 group-centric plan.
#   * one group per distinct role (tag/name from the naming convention)
#   * one Roles-Groups row per group (group -> role)
#   * one Assignments-Admins row per (user, group) pair
# ---------------------------------------------------------------------------
function ConvertTo-PimV2MigrationPlan {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][object[]]$V1Rows,
        [string]$DefaultAssignmentType = 'Eligible',
        [int]$DefaultExpiryDays = 365
    )
    $hasNaming = [bool](Get-Command Resolve-PimGroupName -ErrorAction SilentlyContinue)

    $groups        = @{}    # tag -> group def
    $rolesGroups   = New-Object System.Collections.Generic.List[object]
    $adminAssigns  = New-Object System.Collections.Generic.List[object]
    $warnings      = New-Object System.Collections.Generic.List[object]
    $admins        = @{}    # upn -> $true
    $seenAdminGrp  = @{}    # "upn|tag" -> $true (dedupe)

    foreach ($row in @($V1Rows)) {
        $user = "$($row.User)".Trim()
        $role = "$($row.Role)".Trim()
        if (-not $role) {
            if ($user) { [void]$warnings.Add("Row for '$user' has no role -- skipped.") }
            continue
        }
        # role tag: dash-cased role label, prefixed ROLE- (matches v2 sample data shape).
        $rolePart = if ($hasNaming) { ConvertTo-PimNamePart $role } else { ($role -replace '\s+', '-' -replace '[^A-Za-z0-9.\-]', '') }
        $tag      = "ROLE-$rolePart"
        $atype    = if ("$($row.AssignmentType)".Trim()) {
                        switch -Regex ("$($row.AssignmentType)") { '(?i)active|permanent|assigned' { 'Active' } default { 'Eligible' } }
                    } else { $DefaultAssignmentType }

        if (-not $groups.ContainsKey($tag)) {
            $gname = if ($hasNaming) { Resolve-PimGroupName -Role $rolePart } else { "PIM-$rolePart" }
            $groups[$tag] = [pscustomobject]@{
                GroupName        = $gname
                GroupTag         = $tag
                GroupDescription = "Migrated from v1 direct assignment of role '$role'."
                IsRoleAssignable = 'TRUE'
                SourceRole       = $role
            }
            [void]$rolesGroups.Add([pscustomobject]@{
                GroupTag           = $tag
                RoleDefinitionName = $role
                AssignmentType     = $atype
                Action             = 'Assign'
                AutoExtend         = 'TRUE'
                NumOfDaysWhenExpire = $DefaultExpiryDays
                Permanent          = 'FALSE'
                Scope              = "$($row.Scope)".Trim()
            })
        }

        if ($user) {
            $admins[$user.ToLowerInvariant()] = $user
            $key = ($user.ToLowerInvariant() + '|' + $tag.ToLowerInvariant())
            if (-not $seenAdminGrp.ContainsKey($key)) {
                $seenAdminGrp[$key] = $true
                [void]$adminAssigns.Add([pscustomobject]@{
                    Username           = $user
                    GroupTag           = $tag
                    AssignmentType     = $atype
                    Action             = 'Assign'
                    AutoExtend         = 'TRUE'
                    NumOfDaysWhenExpire = $DefaultExpiryDays
                    Permanent          = 'FALSE'
                })
            } else {
                [void]$warnings.Add("Duplicate v1 assignment '$user' -> '$role' collapsed into one v2 membership.")
            }
        }
    }

    $groupDefs = @(@($groups.Values) | Sort-Object GroupTag)
    return [pscustomobject]@{
        SourceRowCount      = @($V1Rows).Count
        Definitions         = $groupDefs                       # -> PIM-Definitions-Roles
        RolesGroups         = @($rolesGroups.ToArray())        # -> PIM-Assignments-Roles-Groups
        AdminAssignments    = @($adminAssigns.ToArray())       # -> PIM-Assignments-Admins
        DistinctAdmins      = @(@($admins.Values) | Sort-Object)
        DistinctRoleCount   = $groupDefs.Count
        Warnings            = @($warnings.ToArray())
    }
}

# ---------------------------------------------------------------------------
# Render the plan as a human-readable migration report (string). Non-destructive --
# the caller decides whether to write the proposed rows; this only describes them.
# ---------------------------------------------------------------------------
function Format-PimMigrationReport {
    [CmdletBinding()] param([Parameter(Mandatory)]$Plan)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('PIM4EntraPS -- v1 -> v2 migration plan (PROPOSAL, no writes performed)')
    [void]$sb.AppendLine('====================================================================')
    [void]$sb.AppendLine(("v1 source rows read .......... {0}" -f $Plan.SourceRowCount))
    [void]$sb.AppendLine(("distinct roles -> groups ..... {0}" -f $Plan.DistinctRoleCount))
    [void]$sb.AppendLine(("distinct admins .............. {0}" -f @($Plan.DistinctAdmins).Count))
    [void]$sb.AppendLine(("admin->group memberships ..... {0}" -f @($Plan.AdminAssignments).Count))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Proposed PIM groups (PIM-Definitions-Roles):')
    foreach ($g in @($Plan.Definitions)) {
        [void]$sb.AppendLine(("  + {0}   [tag {1}]  <- role '{2}'" -f $g.GroupName, $g.GroupTag, $g.SourceRole))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Proposed group->role bindings (PIM-Assignments-Roles-Groups):')
    foreach ($r in @($Plan.RolesGroups)) {
        [void]$sb.AppendLine(("  {0} -> {1} ({2}, {3}d)" -f $r.GroupTag, $r.RoleDefinitionName, $r.AssignmentType, $r.NumOfDaysWhenExpire))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Proposed admin->group memberships (PIM-Assignments-Admins):')
    foreach ($a in @($Plan.AdminAssignments)) {
        [void]$sb.AppendLine(("  {0} member-of {1} ({2})" -f $a.Username, $a.GroupTag, $a.AssignmentType))
    }
    if (@($Plan.Warnings).Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('Warnings:')
        foreach ($w in @($Plan.Warnings)) { [void]$sb.AppendLine(("  ! {0}" -f $w)) }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('NEXT: review the proposed rows, then commit them through the Manager (Review & Save)')
    [void]$sb.AppendLine('      or the SQL store. The v1 source is read-only; nothing was modified.')
    return $sb.ToString()
}

# ---------------------------------------------------------------------------
# One-call convenience: path -> plan (+ optional report text on the object).
# ---------------------------------------------------------------------------
function Invoke-PimV1Migration {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [string]$DefaultAssignmentType = 'Eligible',
        [int]$DefaultExpiryDays = 365
    )
    $v1   = Import-PimV1Baseline -Path $Path
    $plan = ConvertTo-PimV2MigrationPlan -V1Rows $v1 -DefaultAssignmentType $DefaultAssignmentType -DefaultExpiryDays $DefaultExpiryDays
    Add-Member -InputObject $plan -NotePropertyName SourcePath -NotePropertyValue $Path -Force
    Add-Member -InputObject $plan -NotePropertyName Report     -NotePropertyValue (Format-PimMigrationReport -Plan $plan) -Force
    return $plan
}
