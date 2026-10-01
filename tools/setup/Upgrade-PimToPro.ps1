#Requires -Version 5.1
<#
.SYNOPSIS
    Upgrade a COMMUNITY installation to PRO, after its Pro licence is registered: install the in-cloud updater on the
    customer ring, so the environment receives Pro releases by itself from now on.

.DESCRIPTION
    BUG-277 (2026-10-01). Registering a Pro licence (Settings > Edition, or Set-PimLicense.ps1) switches the Pro features
    on at once -- no redeploy. What it cannot do by itself is change HOW the environment is updated: a Community install
    has no in-cloud updater (it updates with Update-PimCommunity.ps1 from GitHub), and a Pro environment is updated by its
    updater, through the customer ring, from the Pro update feed you receive with your licence.

    This is that one step. It re-runs the deploy with the parameters your last successful deploy saved (the same profile
    Update-PimCommunity.ps1 uses), adding:
      * -UpdateSourceUrlTemplate  the Pro update feed you received with your licence;
      * -UpdateRing 2             the customer ring (releases reach it only after they are approved for customers).
    Every step that is already current is skipped; the 'updater' step installs the nightly updater job. From then on the
    environment updates itself: do NOT keep running Update-PimCommunity.ps1 -- its git version is not what the ring
    approves, and the ring gate will say so.

    Until this has run, the licence is registered and Update-PimCommunity.ps1 keeps working (the ring gate recognises the
    install as "upgrade pending", and the roll is audited).

.PARAMETER SourceUrlTemplate
    The Pro update feed: an https URL containing {version}, as you received it with your licence.
.PARAMETER TenantId
    Which saved deploy profile to use when there is more than one on this machine.
.PARAMETER ProfilePath
    A profile file to use directly.
.PARAMETER Apply
    Install the updater. Without it the deploy prints its plan only.

.EXAMPLE
    .\tools\setup\Upgrade-PimToPro.ps1 -SourceUrlTemplate 'https://<store>/<container>/pim-src-{version}.tar.gz?<access>'          # the plan
    .\tools\setup\Upgrade-PimToPro.ps1 -SourceUrlTemplate 'https://<store>/<container>/pim-src-{version}.tar.gz?<access>' -Apply   # upgrade
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceUrlTemplate,
    [string]$TenantId,
    [string]$ProfilePath,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimDeployProfile.ps1')

$src = "$SourceUrlTemplate".Trim()
if ($src -notmatch '^https://[^\s]+$') { throw 'the Pro update feed must be an https URL (as you received it with your licence)' }
if ($src -notmatch '\{version\}') { throw 'the Pro update feed must contain {version} (the updater puts the approved version there)' }

# --- which profile (the same rule as Update-PimCommunity.ps1) ------------------------------------------------------
if (-not "$ProfilePath".Trim()) {
    $dir = Get-PimDeployProfileDir
    $all = @(if (Test-Path $dir) { Get-ChildItem -Path $dir -Filter '*.json' -File })
    if ("$TenantId".Trim()) { $all = @($all | Where-Object { $_.Name -like "$($TenantId.Trim())-*" }) }
    if (-not $all.Count) { throw "no deploy profile found in $dir$(if ($TenantId) { " for tenant $TenantId" }). Run README step 3 (Invoke-PimDeployAll.ps1 ... -Apply) once; it saves the profile this upgrade re-uses." }
    if ($all.Count -gt 1) { throw "more than one deploy profile in ${dir}: $(@($all.Name) -join ', ') -- pick one with -TenantId or -ProfilePath" }
    $ProfilePath = $all[0].FullName
}
$prof = Read-PimDeployProfile -Path $ProfilePath
Write-Host "deploy profile : $ProfilePath (saved $($prof.savedUtc), deployed version $($prof.version))" -ForegroundColor Cyan
if (@($prof.omitted).Count) { Write-Host "not in the profile (they carry a secret): $(@($prof.omitted) -join ', ') -- pass them again if the deploy asks" -ForegroundColor Yellow }

$deployArgs = Get-PimProUpgradeDeployArgs -Parameters $prof.parameters -SourceUrlTemplate $src -Apply:$Apply
Write-Host 'upgrade        : the in-cloud updater on ring 2 (customer), reading the Pro update feed' -ForegroundColor Green
$global:LASTEXITCODE = 0
& (Join-Path $PSScriptRoot 'Invoke-PimDeployAll.ps1') @deployArgs
$code = $LASTEXITCODE
if (-not $code -and $Apply) {
    Write-Host ''
    Write-Host 'Upgraded: this environment now updates itself through the customer ring. Stop using Update-PimCommunity.ps1.' -ForegroundColor Green
}
exit $code
