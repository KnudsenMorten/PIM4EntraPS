#requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS — update all hosted containers to a new image (zero-downtime), or roll back.

.DESCRIPTION
    One image (pim-manager:<tag>) runs every worker. This builds a new tag in ACR (unless
    -SkipBuild) and rolls each container app to it via `az containerapp update --image`,
    which creates a NEW REVISION and shifts traffic with no downtime (min-1 replica). Apps
    pull via their AcrPull managed identity, so no registry creds are needed at update time.

    -Rollback <revisionSuffix> reactivates a prior revision instead of building/updating
    (instant rollback). List revisions with: az containerapp revision list -n <app> -g <rg>.

.EXAMPLE
    .\Update-PimContainers.ps1 -ImageTag 1.1.7
    Build 1.1.7 from current source and roll manager + all workers to it.

.EXAMPLE
    .\Update-PimContainers.ps1 -ImageTag 1.1.5 -SkipBuild
    Roll all apps to an existing tag (no rebuild).

.NOTES
    Re-runnable. Safe: each app updates independently; a failed app doesn't block the rest.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ImageTag,
    [string]$ResourceGroup = 'rg-pim-manager-web',
    [string]$AcrName       = 'acrsecurityinsight',
    [string]$ImageRepo     = 'pim-manager',
    [string[]]$Apps        = @('ca-pim-manager','ca-pim-scheduler','ca-pim-engine','ca-pim-connector','ca-pim-deltaqueue','ca-pim-discovery'),
    [switch]$SkipBuild,
    [string]$Rollback      # revision NAME to reactivate (rollback mode; ignores ImageTag/build)
)
$ErrorActionPreference = 'Stop'
$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = (Resolve-Path (Join-Path $here '..\..\..\..')).Path   # AutomateIT repo root
$image = "$AcrName.azurecr.io/$ImageRepo`:$ImageTag"
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }

# only act on apps that actually exist
$existing = @($Apps | Where-Object { az containerapp show -g $ResourceGroup -n $_ --query name -o tsv 2>$null })
Step ("apps present: " + ($existing -join ', '))

if ($Rollback) {
    foreach ($app in $existing) {
        $rev = az containerapp revision list -g $ResourceGroup -n $app --query "[?contains(name,'$Rollback')].name | [0]" -o tsv 2>$null
        if ($rev -and $PSCmdlet.ShouldProcess($app,"rollback to $rev")) {
            az containerapp revision activate -g $ResourceGroup -n $app --revision $rev -o none
            az containerapp ingress traffic set -g $ResourceGroup -n $app --revision-weight "$rev=100" -o none 2>$null
            Write-Host "  $app -> $rev (100%)" -ForegroundColor Green
        }
    }
    Step 'Rollback done.'; return
}

if (-not $SkipBuild) {
    Step "Build $image from $repoRoot"
    if ($PSCmdlet.ShouldProcess($image,'az acr build')) {
        Push-Location $repoRoot
        try { az acr build -r $AcrName -t "$ImageRepo`:$ImageTag" -f SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile . }
        finally { Pop-Location }
    }
}

foreach ($app in $existing) {
    Step "Roll $app -> $ImageTag"
    if ($PSCmdlet.ShouldProcess($app,"update --image $image")) {
        az containerapp update -g $ResourceGroup -n $app --image $image -o none
        $rev = az containerapp revision list -g $ResourceGroup -n $app --query "[0].name" -o tsv 2>$null
        Write-Host "  $app new revision: $rev" -ForegroundColor Green
    }
}
Step "Done. All apps on $ImageTag (zero-downtime rolling revisions; rollback with -Rollback <oldRevision>)."
