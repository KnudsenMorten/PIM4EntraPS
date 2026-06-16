#requires -Version 5.1
<#
.SYNOPSIS
    DEPRECATED redirect -> tools/setup/Install-PimEngineAppRegistration.ps1 (pure REST).

.DESCRIPTION
    This was the Microsoft.Graph PowerShell SDK installer. The engine, and the whole
    setup/deploy family, are now pure REST + certificate (no Graph/Az modules) -- so
    the canonical installer lives at:

        tools/setup/Install-PimEngineAppRegistration.ps1

    which is a SUPERSET of this one (same eight Graph app-roles + Exchange.ManageAsApp,
    plus RoleManagementPolicy.ReadWrite.Directory; Azure RBAC default-ON; writes the
    engine identity into LauncherConfig.custom.ps1) and authenticates by borrowing the
    caller's `az login` token instead of pulling in the SDK.

    This shim forwards every parameter to the REST script so existing call sites keep
    working. It maps the old -AzureRbac switch (default OFF here) to the REST script's
    -SkipAzureRbac (default ON there): if you do NOT pass -AzureRbac, this shim passes
    -SkipAzureRbac to preserve the old default; pass -AzureRbac to enable it.
    -ExportPfxPath is no longer supported by the REST installer (it never minted a PFX
    for export); if supplied, the shim warns and ignores it.

.NOTES
    Constraints: REST + certificate, PS 5.1-safe, no Microsoft.Graph / Az modules,
    no device-code. See docs/REQUIREMENTS.md §19 (REST migration).
#>
[CmdletBinding()]
param(
    [string]$DisplayName = 'PIM4EntraPS Engine',
    [string]$TenantId,
    [string]$ExistingThumbprint,
    [string]$CertSubject = 'CN=PIM4EntraPS-Engine',
    [ValidateRange(1,5)][int]$CertValidityYears = 2,
    [string]$ExportPfxPath,
    [switch]$GrantConsent,
    [switch]$AzureRbac,
    [switch]$IncludeExchange,
    [switch]$MachineStore = $true
)

$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$rest = Join-Path (Split-Path -Parent $here) 'tools\setup\Install-PimEngineAppRegistration.ps1'
if (-not (Test-Path -LiteralPath $rest)) {
    throw "Pure-REST installer not found at '$rest'. The legacy SDK installer has been retired; restore tools/setup/Install-PimEngineAppRegistration.ps1."
}

Write-Host "[redirect] setup/Install-PimEngineAppRegistration.ps1 (SDK) is deprecated -> tools/setup (pure REST)." -ForegroundColor Yellow

if ($ExportPfxPath) {
    Write-Host "  [warn] -ExportPfxPath is not supported by the REST installer and is ignored." -ForegroundColor Yellow
}

$fwd = @{
    DisplayName       = $DisplayName
    CertSubject       = $CertSubject
    CertValidityYears = $CertValidityYears
    MachineStore      = $MachineStore
}
if ($TenantId)            { $fwd.TenantId = $TenantId }
if ($ExistingThumbprint)  { $fwd.ExistingThumbprint = $ExistingThumbprint }
if ($GrantConsent)        { $fwd.GrantConsent = $true }
if ($IncludeExchange)     { $fwd.IncludeExchange = $true }
# old default = no Azure RBAC; REST default = DO assign (so pass -SkipAzureRbac unless asked).
if (-not $AzureRbac)      { $fwd.SkipAzureRbac = $true }

& $rest @fwd
