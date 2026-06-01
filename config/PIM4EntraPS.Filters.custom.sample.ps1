#Requires -Version 5.1
<#
.SYNOPSIS
    CUSTOMER TEMPLATE -- copy this file to PIM4EntraPS.Filters.custom.ps1
    and override the scriptblocks you need to change. The .custom.ps1 file
    is .gitignored and never leaves your VM.

.HOW IT WORKS
    Initialize-LauncherConfig loads PIM4EntraPS.Filters.locked.ps1 FIRST, then
    loads your .custom.ps1 SECOND. Hashtable keys you reassign overwrite the
    locked defaults. Keys you leave alone keep the locked scriptblock.
#>

# Example 1: customer uses tag-based admin identification.
# $global:PIM_Filters.AdminCandidate = {
#     param($user)
#     $user.AdditionalProperties.extensionAttribute1 -eq 'PIM-Admin'
# }

# Example 2: PIM groups use a different prefix (e.g. 'pim-grp-' instead of 'PIM-').
# $global:PIM_Filters.PimGroup = {
#     param($group)
#     $group.DisplayName -like 'pim-grp-*'
# }

# Example 3: customer never uses AD-synced resource groups.
# $global:PIM_Filters.PimGroupResourceSyncAD = { param($group) $false }

# Example 4: customer allows additional roles in AUs (e.g. Exchange Admin).
# $global:PIM_Filters.AURoleAllowed = {
#     param($role)
#     $role.DisplayName -in @(
#         'Authentication Administrator'
#         'User Administrator'
#         'Exchange Administrator'
#         'Intune Administrator'
#     )
# }

# Example 5: restrict Azure scope to production subs by tag.
# $global:PIM_Filters.AzureSubscription = {
#     param($sub)
#     $sub.Tags['environment'] -eq 'production'
# }
