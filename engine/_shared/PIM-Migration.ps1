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
# IMP-49 h -- read a v1 PS DATA file WITHOUT executing it.
# ---------------------------------------------------------------------------
function Get-PimV1DataExpression {
    # The expression a statement holds when it is ONE bare expression (no command, no pipeline), else $null.
    param($Statement)
    if ($null -eq $Statement) { return $null }
    $n = $Statement.GetType().Name
    if ($n -eq 'CommandExpressionAst') { return $Statement.Expression }
    if ($n -eq 'PipelineAst' -and @($Statement.PipelineElements).Count -eq 1 -and $Statement.PipelineElements[0].GetType().Name -eq 'CommandExpressionAst') { return $Statement.PipelineElements[0].Expression }
    return $null
}

function ConvertFrom-PimV1DataAst {
    # PURE. A literal-data AST node -> its value. THROWS on anything that is not literal data.
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Ast)
    switch ($Ast.GetType().Name) {
        'ConstantExpressionAst'       { return $Ast.Value }
        'StringConstantExpressionAst' { return $Ast.Value }
        'ExpandableStringExpressionAst' {
            if (@($Ast.NestedExpressions).Count) { throw "line $($Ast.Extent.StartLineNumber): a string with an embedded expression is not data" }
            return $Ast.Value
        }
        'VariableExpressionAst' {
            $n = "$($Ast.VariablePath.UserPath)".ToLowerInvariant()
            if ($n -eq 'true') { return $true }; if ($n -eq 'false') { return $false }; if ($n -eq 'null') { return $null }
            throw "line $($Ast.Extent.StartLineNumber): variable `$$($Ast.VariablePath.UserPath) is not data"
        }
        'ArrayLiteralAst'    { return ,@($Ast.Elements | ForEach-Object { ConvertFrom-PimV1DataAst -Ast $_ }) }
        'ArrayExpressionAst' {
            $out = New-Object System.Collections.Generic.List[object]
            foreach ($st in @($Ast.SubExpression.Statements)) {
                $ex = Get-PimV1DataExpression -Statement $st
                if (-not $ex) { throw "line $($st.Extent.StartLineNumber): only literal data may appear inside @( ... )" }
                $v = ConvertFrom-PimV1DataAst -Ast $ex
                foreach ($x in @($v)) { $out.Add($x) }
            }
            return ,$out.ToArray()
        }
        'HashtableAst' {
            $h = @{}
            foreach ($kv in $Ast.KeyValuePairs) {
                $k = ConvertFrom-PimV1DataAst -Ast $kv.Item1
                $vs = $kv.Item2
                $ex = Get-PimV1DataExpression -Statement $vs
                if (-not $ex) { throw "line $($vs.Extent.StartLineNumber): a hashtable value must be literal data" }
                $h["$k"] = ConvertFrom-PimV1DataAst -Ast $ex
            }
            return $h
        }
        'ConvertExpressionAst' {
            $tn = "$($Ast.Type.TypeName.FullName)".ToLowerInvariant()
            $v = ConvertFrom-PimV1DataAst -Ast $Ast.Child
            if ($tn -in @('pscustomobject','psobject','system.management.automation.pscustomobject')) { return [pscustomobject]$v }
            if ($tn -in @('ordered','hashtable')) { return $v }
            if ($tn -in @('string','int','bool','datetime')) { return $v }
            throw "line $($Ast.Extent.StartLineNumber): cast to [$($Ast.Type.TypeName.FullName)] is not allowed in a data file"
        }
        'ParenExpressionAst' {
            $ex = Get-PimV1DataExpression -Statement $Ast.Pipeline
            if (-not $ex) { throw "line $($Ast.Extent.StartLineNumber): only literal data may appear in ( ... )" }
            return (ConvertFrom-PimV1DataAst -Ast $ex)
        }
        'UnaryExpressionAst' {
            if ("$($Ast.TokenKind)" -eq 'Minus' -and $Ast.Child.GetType().Name -eq 'ConstantExpressionAst') { return -1 * $Ast.Child.Value }
            throw "line $($Ast.Extent.StartLineNumber): expression is not data"
        }
        default { throw "line $($Ast.Extent.StartLineNumber): '$($Ast.GetType().Name)' is not literal data -- the file is PARSED, never run" }
    }
}

function Read-PimV1DataFile {
    # IMP-49 h. The rows held by top-level `$Name = <literal data>` assignments whose name looks like a v1 data
    # variable (polic|assign|role|admin|custom|pim). Parsed via the AST; NOTHING in the file is executed.
    # THROWS on a parse error or on a matching assignment whose value is not literal data.
    param([Parameter(Mandatory)][string]$Path)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $Path).Path, [ref]$tokens, [ref]$errors)
    if (@($errors).Count) { throw ("Import-PimV1Baseline: '{0}' does not parse: {1}" -f $Path, (@($errors | Select-Object -First 3 | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" }) -join '; ')) }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($st in @($ast.EndBlock.Statements)) {
        if ($st.GetType().Name -ne 'AssignmentStatementAst') { continue }
        if ($st.Left.GetType().Name -ne 'VariableExpressionAst') { continue }
        $name = "$($st.Left.VariablePath.UserPath)"
        if ($name -notmatch '(?i)polic|assign|role|admin|custom|pim') { continue }
        $ex = Get-PimV1DataExpression -Statement $st.Right
        if (-not $ex) { throw ("Import-PimV1Baseline: `${0} (line {1}) is not literal data -- the file is PARSED, never run" -f $name, $st.Extent.StartLineNumber) }
        $val = ConvertFrom-PimV1DataAst -Ast $ex
        foreach ($item in @($val)) { if ($item -is [pscustomobject] -or $item -is [System.Collections.IDictionary]) { $out.Add($item) } }
    }
    return $out.ToArray()
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
        # 🔴 IMP-49 h (ss33.28): this DOT-SOURCED the operator-supplied file -- "sandboxed" only in the sense of a
        # child scope, which is not a sandbox: any command in the file (a download, a Remove-Item, a Connect-*)
        # ran with the caller's identity. The file is now PARSED, never executed: only top-level assignments of
        # LITERAL data ($PIM_X = @( [pscustomobject]@{...}, @{...} )) are read, through the AST. Anything that is
        # not data (a command, a variable reference, a subexpression) is refused with the line it is on.
        $found = New-Object System.Collections.Generic.List[object]
        foreach ($item in @(Read-PimV1DataFile -Path $Path)) { [void]$found.Add($item) }
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
