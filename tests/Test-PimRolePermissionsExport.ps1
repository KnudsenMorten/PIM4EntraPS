#Requires -Version 5.1
<#
  Offline tests for the Role Lookup CSV-export decision core
  (engine/_shared/PIM-RolePermissionsExport.ps1 -- REQUIREMENTS.md §28 [L5]
  "copy/export of role permissions for least-privilege tickets" + [H5]
  "export/print on operational views").

  Proves, with NO server / SQL / tenant, that each of the four Role Lookup
  result shapes flattens to a correct, spreadsheet-SAFE CSV:

    1. ConvertTo-PimRolePermissionsCsv -- a role's concrete permissions
       (allowed/excluded resource + data actions) one row per action, with
       namespace -- the [L5] least-privilege-ticket export.
    2. ConvertTo-PimRolesByActionCsv  -- "which roles grant action X", ranked
       least-privilege first, broad/wildcard flagged.
    3. ConvertTo-PimRoleReachersCsv   -- "who can activate a role", with path.
    4. ConvertTo-PimRoleCompareCsv    -- both / only-A / only-B buckets.

  And that the shared cell guard neutralises CSV formula-injection identically
  to the audit export + the GUI csvCell. PURE. Exits 0 (green) / 1 (red).
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-RolePermissionsExport.ps1"

$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

Write-Host "=== PIM-RolePermissionsExport tests ([L5]/[H5] Role Lookup export) ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Formula-injection guard (the hard rule -- export must be safe).
# ---------------------------------------------------------------------------
Assert '= formula is neutralised'      ((ConvertTo-PimRolePermCsvCell '=1+1').StartsWith("'="))
Assert '+ formula is neutralised'      ((ConvertTo-PimRolePermCsvCell '+SUM(A1)').StartsWith("'+"))
Assert '- formula is neutralised'      ((ConvertTo-PimRolePermCsvCell '-2+3').StartsWith("'-"))
Assert '@ formula is neutralised'      ((ConvertTo-PimRolePermCsvCell '@cmd').StartsWith("'@"))
Assert 'tab-led value is neutralised'  ((ConvertTo-PimRolePermCsvCell "`tx").StartsWith("'"))
Assert 'plain value is untouched'      ((ConvertTo-PimRolePermCsvCell 'Global Administrator') -eq 'Global Administrator')
Assert 'comma value is quoted'         ((ConvertTo-PimRolePermCsvCell 'a,b') -eq '"a,b"')
Assert 'embedded quote is doubled'     ((ConvertTo-PimRolePermCsvCell 'say "hi"') -eq '"say ""hi"""')
Assert 'newline value is quoted'       ((ConvertTo-PimRolePermCsvCell "l1`nl2") -match '(?s)^".*"$')
Assert 'null becomes empty'            ((ConvertTo-PimRolePermCsvCell $null) -eq '')

# ---------------------------------------------------------------------------
# 2. ConvertTo-PimRolePermCsv shape (CRLF, header, row).
# ---------------------------------------------------------------------------
$oneRow = New-Object System.Collections.Generic.List[object]
$oneRow.Add(@('Global Reader', 'microsoft.directory/users/read')) | Out-Null
$csv = ConvertTo-PimRolePermCsv -Headers @('Role', 'Action') -Rows $oneRow.ToArray()
$lines = $csv -split "`r`n"
Assert 'header row present'      ($lines[0] -eq 'Role,Action')
Assert 'data row present'        ($lines[1] -eq 'Global Reader,microsoft.directory/users/read')
Assert 'CRLF line endings'       ($csv.Contains("`r`n"))

# ---------------------------------------------------------------------------
# 3. Get-PimRolePermResourceActions -- flatten a roleDefinition.
# ---------------------------------------------------------------------------
$role = [pscustomobject]@{
    displayName     = 'User Administrator'
    isBuiltIn       = $true
    rolePermissions = @(
        [pscustomobject]@{
            allowedResourceActions  = @('microsoft.directory/users/basic/update', 'microsoft.directory/users/password/update', 'microsoft.directory/users/basic/update')
            excludedResourceActions = @('microsoft.directory/users/delete')
            allowedDataActions      = @()
            excludedDataActions     = @()
        }
    )
}
$acts = Get-PimRolePermResourceActions -Role $role
Assert 'flatten de-dupes repeated action'  (@($acts | Where-Object { $_.action -eq 'microsoft.directory/users/basic/update' }).Count -eq 1)
Assert 'flatten keeps excluded action'      (@($acts | Where-Object { $_.kind -eq 'excluded' }).Count -eq 1)
Assert 'namespace derived from action'      ((@($acts | Where-Object { $_.action -like '*basic/update' })[0]).namespace -eq 'microsoft.directory')
Assert 'flatten handles null role'          (@(Get-PimRolePermResourceActions -Role $null).Count -eq 0)

# hashtable shape works too (wrap in @() -- a single-element return unwraps to a scalar)
$roleHt = @{ displayName = 'X'; rolePermissions = @( @{ allowedResourceActions = @('ns/a/read') } ) }
Assert 'flatten accepts hashtable role'     (@(Get-PimRolePermResourceActions -Role $roleHt).Count -eq 1)

# ---------------------------------------------------------------------------
# 4. ConvertTo-PimRolePermissionsCsv -- the [L5] role-permission export.
# ---------------------------------------------------------------------------
$permCsv = ConvertTo-PimRolePermissionsCsv -Role $role
$pl = $permCsv -split "`r`n"
Assert 'perm CSV header'                ($pl[0] -eq 'Role,Permission,Namespace,Action')
Assert 'perm CSV stamps role name'      ($permCsv -match 'User Administrator')
Assert 'perm CSV labels allowed'        ($permCsv -match 'Allowed action')
Assert 'perm CSV labels excluded'       ($permCsv -match 'Excluded action')
Assert 'perm CSV row count = actions+1' ($pl.Count -eq (1 + @(Get-PimRolePermResourceActions -Role $role).Count))
# explicit RoleName override wins
$permCsv2 = ConvertTo-PimRolePermissionsCsv -Role $role -RoleName 'Ticket Role'
Assert 'perm CSV honours RoleName override' ($permCsv2 -match 'Ticket Role')
# empty role -> just a header, no crash
$permEmpty = ConvertTo-PimRolePermissionsCsv -Role ([pscustomobject]@{ displayName = 'Empty'; rolePermissions = @() })
Assert 'perm CSV empty-role -> header only' ((($permEmpty -split "`r`n").Count) -eq 1)

# ---------------------------------------------------------------------------
# 5. ConvertTo-PimRolesByActionCsv -- ranked least-privilege-first export.
# ---------------------------------------------------------------------------
$matches = @(
    [pscustomobject]@{ role = 'User Administrator'; totalActions = 40; viaWildcard = $false; matchedActions = @('microsoft.directory/users/password/update') }
    [pscustomobject]@{ role = 'Global Administrator'; totalActions = 9000; viaWildcard = $true; matchedActions = @('microsoft.directory/*') }
)
$baCsv = ConvertTo-PimRolesByActionCsv -Matches $matches
$bl = $baCsv -split "`r`n"
Assert 'by-action CSV header'           ($bl[0] -eq 'Rank,Role,TotalActions,Broad,MatchedActions')
Assert 'by-action rank starts at 1'     ($bl[1] -match '^1,User Administrator,40,no,')
Assert 'by-action flags broad/wildcard' ($bl[2] -match '^2,Global Administrator,9000,yes,')
Assert 'by-action empty -> header only' ((((ConvertTo-PimRolesByActionCsv -Matches @()) -split "`r`n").Count) -eq 1)

# ---------------------------------------------------------------------------
# 6. ConvertTo-PimRoleReachersCsv -- who-can-activate with path.
# ---------------------------------------------------------------------------
$reachers = @(
    [pscustomobject]@{ displayName = 'Alice'; purpose = 'Cloud Engineer'; pathText = 'PIM-ROLE-CloudEngineer -> PIM-Entra-UserAdmin' }
    [pscustomobject]@{ person = 'bob@x'; purpose = ''; pathText = 'direct' }
)
$rvCsv = ConvertTo-PimRoleReachersCsv -Role 'User Administrator' -Reachers $reachers
$rl = $rvCsv -split "`r`n"
Assert 'reachers CSV header'            ($rl[0] -eq 'Role,Who,Purpose,Path')
Assert 'reachers CSV stamps role'       ($rl[1] -match '^User Administrator,Alice,Cloud Engineer,')
Assert 'reachers CSV falls back to person' ($rvCsv -match 'bob@x')
Assert 'reachers empty -> header only'  ((((ConvertTo-PimRoleReachersCsv -Role 'r' -Reachers @()) -split "`r`n").Count) -eq 1)
# a pathText containing a comma must be quoted (RFC-4180)
$rvComma = ConvertTo-PimRoleReachersCsv -Role 'r' -Reachers @( [pscustomobject]@{ displayName = 'C'; pathText = 'a, b, c' } )
Assert 'reachers quotes comma in path'  ($rvComma -match '"a, b, c"')

# ---------------------------------------------------------------------------
# 7. ConvertTo-PimRoleCompareCsv -- both / only-A / only-B.
# ---------------------------------------------------------------------------
$cmp = [pscustomobject]@{
    both  = @([pscustomobject]@{ displayName = 'Alice' })
    onlyA = @([pscustomobject]@{ displayName = 'Bob' })
    onlyB = @('Carol')   # plain string also supported
}
$cmpCsv = ConvertTo-PimRoleCompareCsv -Comparison $cmp -RoleA 'GA' -RoleB 'PRA'
Assert 'compare CSV header'             (($cmpCsv -split "`r`n")[0] -eq 'Bucket,Who')
Assert 'compare CSV both bucket'        ($cmpCsv -match 'Both roles,Alice')
Assert 'compare CSV only-A labelled'    ($cmpCsv -match 'Only GA,Bob')
Assert 'compare CSV only-B + plain str' ($cmpCsv -match 'Only PRA,Carol')
Assert 'compare null -> header only'    ((((ConvertTo-PimRoleCompareCsv -Comparison $null) -split "`r`n").Count) -eq 1)

# ---------------------------------------------------------------------------
# 8. End-to-end injection safety through the high-level exporters.
# ---------------------------------------------------------------------------
$evilRole = [pscustomobject]@{ displayName = '=cmd|calc'; rolePermissions = @( @{ allowedResourceActions = @('=HYPERLINK("evil")') } ) }
$evilCsv = ConvertTo-PimRolePermissionsCsv -Role $evilRole
Assert 'perm export neutralises evil role name'   ($evilCsv -match "'=cmd")
Assert 'perm export neutralises evil action'      ($evilCsv -match "'=HYPERLINK")

Write-Host ""
Write-Host ("RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
