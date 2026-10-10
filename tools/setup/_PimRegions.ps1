#Requires -Version 5.1
<#
.SYNOPSIS
    PURE. The ONE list of Azure regions PIM is hosted in, and the check every entry point runs BEFORE anything is created.

.DESCRIPTION
    BUG-299 (2026-10-10): install-parameters.json offered northeurope and germanywestcentral, which Setup-PimContainers
    refused at the infra step -- AFTER the prerequisites (resource group, VNet, registry, SQL) had been created. The list
    lives here only; _PimSetupShared.ps1 (Assert-PimSetupRegion, Setup-PimContainers), _PimGuidedInstall.ps1
    (Test-PimInstallConfig), Invoke-PimDeployAll.ps1 (preflight, before the prereq step) and the multi-tenant build config
    check (engine/msp/PIM-MspBuild.ps1) all read it, and tests/Test-PimGuidedInstall.ps1 asserts install-parameters.json
    offers exactly this list.

    Region allow-list. EU-only hosting. France is REFUSED (data residency).
    swedencentral added 2026-08-09 (operator decision): a FRESH subscription refuses new resources in
    westeurope/northeurope -- see New-PimHostingPrerequisites.ps1's -Location default. Sweden Central is EU; the explicit
    denial is France. Widening the list is an operator decision, not a code fix.
#>

# The lists are LITERALS inside the functions on purpose: a $script: variable read from a child scope (a script that
# dot-sources this file inside a function) can be $null, and "-notin $null" would then refuse every region.
function Get-PimSetupAllowedRegions {
    # PURE. The approved hosting regions.
    return @('westeurope', 'denmarkeast', 'swedencentral')
}

function Get-PimSetupDeniedRegions {
    # PURE. Regions refused outright (data residency).
    return @('francecentral', 'francesouth')
}

function Test-PimSetupRegion {
    # PURE. '' when -Location is an approved hosting region, else the customer-language reason it is refused.
    param([AllowEmptyString()][string]$Location)
    $allowed = @(Get-PimSetupAllowedRegions)
    $norm = ("$Location" -replace '\s', '').ToLowerInvariant()
    if ($norm -in @(Get-PimSetupDeniedRegions)) {
        return "Region '$Location' is not allowed for PIM hosting (data residency). Use West Europe ('westeurope'), Denmark East ('denmarkeast') or Sweden Central ('swedencentral') -- never France."
    }
    if ($norm -notin $allowed) {
        return "Region '$Location' is not an approved PIM hosting region. Approved: $($allowed -join ', '). (France is explicitly disallowed.)"
    }
    return ''
}

# kept for existing readers (Assert-PimSetupRegion in _PimSetupShared.ps1, tests)
$script:PimAllowedRegions = @(Get-PimSetupAllowedRegions)
$script:PimDeniedRegions  = @(Get-PimSetupDeniedRegions)
