#Requires -Version 5.1
<#
.SYNOPSIS
    One-time fix: removes MFA requirement from the Admin Eligibility assignment rule
    across ALL Entra ID role PIM policies.

.DESCRIPTION
    Some Entra ID role PIM policies have "Require MFA on eligible assignment"
    (Enablement_Admin_Eligibility rule) enabled. This blocks app-only automation
    from making eligible assignments because apps cannot satisfy MFA interactively.

    This script sets enabledRules = @() on the Enablement_Admin_Eligibility rule
    for every Entra ID role policy in the tenant — a one-time fix.

    Run once as a privileged admin (Privileged Role Administrator or Global Administrator)
    who has already satisfied MFA in their session.

.NOTES
    Author : Morten Knudsen (fix script)
    Requires: Microsoft.Graph.Identity.Governance module + RoleManagement.ReadWrite.Directory permission
#>

Connect-MgGraph

Write-Host ""
Write-Host "======================================================================"
Write-Host " Fix-PIM-Policy-MFA-AdminEligibility"
Write-Host " Clears MFA requirement from Admin Eligibility rule - all roles"
Write-Host "======================================================================"
Write-Host ""

#----------------------------------------------------------------------
# Load PIM-Functions so we can use PIM_Policy_Check_Update
#----------------------------------------------------------------------
$ScriptDirectory  = $PSScriptRoot
$FunctionsPath    = "c:\scripts\Functions\PIM-Functions.psm1"

If (!(Test-Path $FunctionsPath)) {
    Write-Host "ERROR: Cannot find PIM-Functions.psm1 at $FunctionsPath" -ForegroundColor Red
    Write-Host "       Place this script in the same folder as PIM-Functions.psm1" -ForegroundColor Red
    Exit 1
}

Import-Module $FunctionsPath -Global -Force -WarningAction SilentlyContinue
Write-Host "Loaded PIM-Functions.psm1" -ForegroundColor Green

#----------------------------------------------------------------------
# Get all Entra ID role PIM policies (with rules expanded)
#----------------------------------------------------------------------
Write-Host ""
Write-Host "Fetching all Entra ID role PIM policies ... Please Wait"

$Uri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=rules"

Try {
    $AllPolicies = Invoke-MgGraphRequestPS -Uri $Uri -Method GET -OutputType PSObject
}
Catch {
    Write-Host "ERROR fetching policies: $($_.Exception.Message)" -ForegroundColor Red
    Exit 1
}

$PolicyCount = ($AllPolicies | Measure-Object).Count
Write-Host "Found $PolicyCount role policies" -ForegroundColor Cyan
Write-Host ""

#----------------------------------------------------------------------
# Get role display names for readable output
#----------------------------------------------------------------------
$RoleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition | Select-Object Id, DisplayName

#----------------------------------------------------------------------
# Process each policy
#----------------------------------------------------------------------
$Fixed   = 0
$Skipped = 0
$Errors  = 0
$Pos     = 0

ForEach ($Policy in $AllPolicies) {
    $Pos++

    # Resolve role display name from policy id (format: Policy_<tenantId>_<roleId>)
    $RoleId          = $Policy.id.Split("_")[2]
    $RoleDisplayName = ($RoleDefinitions | Where-Object { $_.Id -eq $RoleId }).DisplayName
    If (!$RoleDisplayName) { $RoleDisplayName = $RoleId }

    Write-Host "[ $Pos / $PolicyCount ] $RoleDisplayName" -NoNewline

    # Check current state of Enablement_Admin_Eligibility rule
    $CurrentRule = $Policy.rules | Where-Object { $_.id -eq "Enablement_Admin_Eligibility" }

    If ($CurrentRule) {
        $CurrentEnabledRules = $CurrentRule.enabledRules
        If ($CurrentEnabledRules -and $CurrentEnabledRules.Count -gt 0) {
            Write-Host " — has enabledRules: [$($CurrentEnabledRules -join ', ')] — FIXING" -ForegroundColor Yellow

            Try {
                PIM_Policy_Check_Update `
                    -RuleId     "Enablement_Admin_Eligibility" `
                    -RuleType   "EnablementRule" `
                    -Policy     $Policy `
                    -PIM_API    "MicrosoftGraph" `
                    -enabledRules        @() `
                    -caller              "Admin" `
                    -Operations          "All" `
                    -Level               "Eligibility" `
                    -inheritableSettings @() `
                    -enforcedSettings    @()

                Write-Host "   OK - Cleared MFA requirement for $RoleDisplayName" -ForegroundColor Green
                $Fixed++
            }
            Catch {
                Write-Host "   ERROR: $($_.Exception.Message)" -ForegroundColor Red
                $Errors++
            }
        }
        Else {
            Write-Host " — already clear, skipping" -ForegroundColor Green
            $Skipped++
        }
    }
    Else {
        Write-Host " — rule not found, skipping" -ForegroundColor DarkGray
        $Skipped++
    }
}

#----------------------------------------------------------------------
# Summary
#----------------------------------------------------------------------
Write-Host ""
Write-Host "======================================================================"
Write-Host " Done"
Write-Host "   Fixed   : $Fixed"
Write-Host "   Skipped : $Skipped (already correct)"
Write-Host "   Errors  : $Errors"
Write-Host "======================================================================"
Write-Host ""
