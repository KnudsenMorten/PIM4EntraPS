#Requires -Version 5.1
<#
.SYNOPSIS
    CUSTOMER TEMPLATE -- copy this file to PIM4EntraPS.NamingConventions.custom.ps1
    and edit only the patterns you need to override. The .custom.ps1 file is
    .gitignored and never leaves your VM.

.HOW IT WORKS
    Initialize-LauncherConfig loads PIM4EntraPS.NamingConventions.locked.ps1 FIRST,
    then loads your .custom.ps1 SECOND. Anything you set here overwrites the
    locked defaults. Anything you leave unset keeps the locked default.
#>

# Example: customer uses a different admin prefix and Danish department codes.
# Uncomment + edit the lines you actually want to change:

# $global:PIM_NamingConventions.AdminAccountPattern = 'a-{Owner}'
# $global:PIM_NamingConventions.AdminAccountUpnSuffix = '@adm.contoso.com'
# $global:PIM_NamingConventions.PimGroupPattern = 'pim-grp-{Role}-{Department}-prod'
# $global:PIM_NamingConventions.PimGroupAuPattern = 'pim-grp-{Role}-au-{AdminUnit}-prod'
# $global:PIM_NamingConventions.ResourceGroupPattern = 'rg-prd-pim-tier{Tier}'
