<#
.SYNOPSIS
    Check-PIM-Groups-IsRoleAssignable - engine script in the PIM4EntraPS solution.

.NOTES
    Solution       : PIM4EntraPS
    File           : Check-PIM-Groups-IsRoleAssignable.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
$groups = get-mggroup -All

$Groups | where-object { $_.DisplayName -like "PIM-Entra-ID*" }

$Groups | where-object { $_.DisplayName -like "PIM-Entra-ID*" -and $_.IsAssignableToRole -eq $false }

$Groups | where-object { $_.DisplayName -like "PIM-Entra-ID*" -and $_.IsAssignableToRole -eq $true }



