<#
.SYNOPSIS
    GetNumberOfROles - engine script in the PIM4EntraPS solution.

.NOTES
    Solution       : PIM4EntraPS
    File           : GetNumberOfROles.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
#------------------------------------------------------------------------------------------------------------
# Loading Functions, Connectivity & Default variables
#------------------------------------------------------------------------------------------------------------
    $global:PathScripts = "c:\scripts"
    Write-Output ""
    Write-Output "Script Directory -> $($global:PathScripts)"

    # v2 AutomationFramework bootstrap (replaces v1 Connect_Azure.ps1 chain).
    # One call to Initialize-PlatformAutomationFramework does cert-based
    # Connect-AzAccount, fetches Modern secrets from KV, populates
    # $global:HighPriv_* / $global:AzureTenantId (public contract), and
    # dot-sources Layer-1 platform-defaults.ps1. Zero v1 module imports.
    $repoRoot = $PSScriptRoot
    while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
        $repoRoot = Split-Path -Parent $repoRoot
    }
    if (-not $repoRoot) {
        throw "AutomationFramework bootstrap: cannot find FUNCTIONS\AutomateITPS\AutomateITPS.psd1 walking up from '$PSScriptRoot'."
    }
    $global:PathScripts = $repoRoot
    Import-Module (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Global -Force -WarningAction SilentlyContinue
    $null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets


# Get count of EntraID Roles
$EntraRoles = (Get-MgRoleManagementDirectoryRoleDefinition).count
write-host "Entra ID Roles -> $($EntraRoles)"

# Get count of Roles in Azure Resources
$Headers = Get-AzAccessTokenManagement
$AzScope = "/providers/Microsoft.Management/managementGroups/f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e"
$AzGraphUri = "https://management.azure.com" + $AzScope + "/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
$Response   = invoke-webrequest -UseBasicParsing -Method GET -Uri $AzGraphUri -Headers $Headers
$AzureRoles = (($Response.Content | ConvertFrom-Json).value).count

write-host "Azure Roles -> $($AzureRoles)"
