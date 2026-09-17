#Requires -Version 5.1
<#
.SYNOPSIS
    71.35 -- deploy the MSP master's signed-baseline PUBLISH job (ca-pim-publish): a Container Apps job on the master's own
    environment, daily cron + on demand, running as its SYSTEM-ASSIGNED managed identity. No certificate, no secret, no
    SAS, no account key -- in the job, in its environment variables, or on this host.

.DESCRIPTION
    Operator decision 2026-09-17 ("go with cloud job publish"): the bundle publish leaves the MSP management host.
    Idempotent. In order:
      1. resolve the signing key over ARM: its VERSIONED key URL is pinned in the job (a key roll is a deliberate
         redeploy, never a silent switch -- see New-PimBaselineSigningKey.ps1)
      2. create / update the job (same image and YAML shape as ca-pim-update / ca-pim-downlink-s6); the image pull uses
         the Manager app's registry identity when it has one, else the job's own identity with AcrPull
      3. READ BACK: provisioningState Succeeded, the env carries exactly the planned values
      4. the identity's ONLY grants (Get-PimBaselinePublishJobGrants): Storage Blob Data Contributor on the bundle
         CONTAINER, Key Vault Crypto User on the signing KEY -- each read back
      5. SQL: the identity joins grp-pim-sql-admins (members only; never creates the group or moves the admin)
    It does NOT start the job: the build's 'publish' step does (Start-PimBaselinePublish.ps1), after this has converged.

    NETWORK. The job runs in the master's Container Apps subnet. The bundle store's firewall allows that subnet (the
    build's publishnetwork + storage steps put the Microsoft.Storage service endpoint on it and the VNet rule on the
    store BEFORE default-action Deny), so the job can write and can read the blob back anonymously.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$EnvName,
    [Parameter(Mandatory)][string]$AcrName,
    [string]$ImageRepo = 'pim-manager',
    [string]$ImageTag,
    [string]$JobName = 'ca-pim-publish',
    [string]$ManagerApp = 'ca-pim-manager',
    [string]$Cron = '0 4 * * *',
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [Parameter(Mandatory)][string]$StorageAccount,
    [string]$Container = 'baselines',
    [string]$StorageResourceGroup,
    [Parameter(Mandatory)][string]$KeyVaultName,
    [string]$KeyVaultResourceGroup,
    [string]$KeyName = 'pim-baseline-signing',
    [ValidateRange(2, 365)][int]$ValidDays = 30,
    [string]$Scope = 'fleet',
    [string]$RegistryIdentityResourceId,
    [string]$SqlAdminGroupName = 'grp-pim-sql-admins',
    # (71.33: no -UseSignedInAccount -- every call here runs as the az context the build established, the signed-in
    # administrator or the certificate identity alike; there is no identity choice to make.)
    [switch]$SkipSqlAdminGroup
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $solRoot 'engine\_shared\PIM-Baseline.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-BaselinePublish.ps1')
. (Join-Path $here '_PimAz.ps1')                 # the guarded az shadow (an az WARNING on stderr must not abort)
. (Join-Path $here '_PimUpdateRing.ps1')          # New-PimSubscriptionArmInvoker, ConvertTo-PimJobEnvMap
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

$sub = @('--subscription', $SubscriptionId)
if (-not "$StorageResourceGroup".Trim()) { $StorageResourceGroup = $ResourceGroup }
if (-not "$KeyVaultResourceGroup".Trim()) { $KeyVaultResourceGroup = $ResourceGroup }
if (-not "$ImageTag".Trim()) {
    $vf = Join-Path $solRoot 'VERSION'
    if (Test-Path -LiteralPath $vf) { $ImageTag = (Get-Content -LiteralPath $vf -Raw).Trim().TrimStart([char]0xFEFF) }
}
if (-not "$ImageTag".Trim()) { throw '-ImageTag is required (no VERSION file to default from).' }
$image = "$AcrName.azurecr.io/$ImageRepo" + ':' + "$ImageTag".Trim()
$arm = New-PimSubscriptionArmInvoker -SubscriptionId $SubscriptionId
Write-Host "`n=== PIM signed-baseline publish job ($JobName) ===" -ForegroundColor Cyan
Note "environment $EnvName / $ResourceGroup ; image $image ; cron $Cron (UTC)"

# ---- 1. the signing key (ARM; versioned URL) -----------------------------------------------------------------------
$keyPath = "/subscriptions/$SubscriptionId/resourceGroups/$KeyVaultResourceGroup/providers/Microsoft.KeyVault/vaults/$KeyVaultName/keys/$KeyName"
$key = $null
try { $key = & $arm -Method GET -Path $keyPath -ApiVersion '2023-07-01' } catch { if ("$($_.Exception.Message)" -notmatch 'HTTP 404') { throw } }
if (-not $key) { throw "signing key '$KeyName' not found in vault '$KeyVaultName' -- run New-PimBaselineSigningKey.ps1 (the build's signingkey step) first." }
$keyCheck = Get-PimBaselineSigningKeyPlan -Existing $key
if ($keyCheck.action -ne 'none') { throw "REFUSED: signing key '$KeyName': $($keyCheck.reason)" }
$signingKeyId = "$($key.properties.keyUriWithVersion)".Trim()
Note "signing key $signingKeyId"

# ---- 2. the job ---------------------------------------------------------------------------------------------------
$envId = "$(az containerapp env show @sub -g $ResourceGroup -n $EnvName --query id -o tsv 2>$null)".Trim()
if (-not $envId) { throw "Container Apps environment '$EnvName' not found in $ResourceGroup." }
$location = "$(az containerapp env show @sub -g $ResourceGroup -n $EnvName --query location -o tsv 2>$null)".Trim()
$exists = [bool](@(az containerapp job list @sub -g $ResourceGroup --query "[].name" -o tsv 2>$null) | Where-Object { "$_".Trim() -eq $JobName })
if (-not "$RegistryIdentityResourceId".Trim()) {
    $mgrReg = "$(az containerapp show @sub -g $ResourceGroup -n $ManagerApp --query "properties.configuration.registries[0].identity" -o tsv 2>$null)".Trim()
    if (-not $mgrReg) { $mgrReg = "$(az containerapp show @sub -g $ResourceGroup -n $ManagerApp --query "configuration.registries[0].identity" -o tsv 2>$null)".Trim() }
    if ($mgrReg -and $mgrReg -ne 'system') { $RegistryIdentityResourceId = $mgrReg; Note "registry identity inherited from $ManagerApp (it already pulls this image)" }
}
$spec = Get-PimBaselinePublishJobSpec -JobName $JobName -Image $image -EnvironmentId $envId -Location $location -Cron $Cron `
            -RegistryServer "$AcrName.azurecr.io" -RegistryIdentity $(if ("$RegistryIdentityResourceId".Trim()) { "$RegistryIdentityResourceId".Trim() } else { 'system' }) `
            -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -StorageAccount $StorageAccount -Container $Container `
            -SigningKeyId $signingKeyId -ValidDays $ValidDays -Scope $Scope -Exists $exists
if (-not $spec.ok) { throw "REFUSED: $($spec.reason)" }
Note ("env: " + ((@($spec.env.Keys) | ForEach-Object { "$_=$($spec.env[$_])" }) -join '  '))
$yamlPath = Join-Path ([IO.Path]::GetTempPath()) ("pim-publish-job-{0}.yaml" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
$action = if ($exists) { 'update' } else { 'create' }
if ($PSCmdlet.ShouldProcess($JobName, "$action the publish job")) {
    Set-Content -LiteralPath $yamlPath -Value $spec.yaml -Encoding ascii
    try {
        Step "$action $JobName"
        $ok = $false
        foreach ($wait in @(0, 15, 30, 60)) {
            if ($wait) { Note "  retrying in ${wait}s"; Start-Sleep -Seconds $wait }
            $global:LASTEXITCODE = 0
            az containerapp job $action @sub -g $ResourceGroup -n $JobName --yaml $yamlPath -o none
            if ($LASTEXITCODE -eq 0) { $ok = $true; break }
            $st = "$(az containerapp job show @sub -g $ResourceGroup -n $JobName --query properties.provisioningState -o tsv 2>$null)".Trim()
            if ($st -notmatch '(?i)InProgress|Waiting') { break }
        }
        if (-not $ok) { throw "'az containerapp job $action' FAILED for $JobName (see the error above)." }
    } finally { Remove-Item -LiteralPath $yamlPath -Force -ErrorAction SilentlyContinue }
}
if ($WhatIfPreference) { Note 'WhatIf: stopping before the read-back and the grants'; return }

# ---- 3. read back ------------------------------------------------------------------------------------------------
$jobPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName"
$jobObj = & $arm -Method GET -Path $jobPath -ApiVersion '2024-03-01'
$prov = "$($jobObj.properties.provisioningState)"
if ($prov -ne 'Succeeded') { throw "job '$JobName' provisioningState='$prov' (expected Succeeded) -- it will never execute. Most common cause: the pull identity has no AcrPull." }
$envBack = ConvertTo-PimJobEnvMap -Job $jobObj -ContainerName $JobName
$bad = @(foreach ($k in @($spec.env.Keys)) { if ("$($envBack[$k])" -cne "$($spec.env[$k])") { $k } })
if ($bad.Count) { throw "read-back FAILED: env $($bad -join ', ') not stored as planned" }
$oid = "$($jobObj.identity.principalId)".Trim()
if (-not $oid) { throw "$JobName has no SYSTEM-ASSIGNED identity -- it could not authenticate to SQL, Key Vault or storage." }
Note "read back: provisioningState Succeeded, env exact, system identity $oid"

# ---- 4. grants: container + key scope only -------------------------------------------------------------------------
$grants = @(Get-PimBaselinePublishJobGrants -SubscriptionId $SubscriptionId -StorageResourceGroup $StorageResourceGroup -StorageAccount $StorageAccount `
               -Container $Container -KeyVaultResourceGroup $KeyVaultResourceGroup -KeyVaultName $KeyVaultName -KeyName $KeyName)
if (-not "$RegistryIdentityResourceId".Trim()) {
    $acrId = "$(az acr show @sub -n $AcrName --query id -o tsv 2>$null)".Trim()
    if ($acrId) { $grants += [pscustomobject]@{ role = 'AcrPull'; scope = $acrId; why = 'pull its own image (no registry identity to inherit)' } }
}
foreach ($gr in $grants) {
    Step "$($gr.role) on $($gr.scope) -- $($gr.why)"
    $have = @(az role assignment list @sub --assignee $oid --scope $gr.scope --query "[].roleDefinitionName" -o tsv 2>$null | ForEach-Object { "$_".Trim() })
    if ($have -contains $gr.role) { Note 'already assigned'; continue }
    az role assignment create @sub --assignee-object-id $oid --assignee-principal-type ServicePrincipal --role $gr.role --scope $gr.scope -o none --only-show-errors
    $after = @(az role assignment list @sub --assignee $oid --scope $gr.scope --query "[].roleDefinitionName" -o tsv 2>$null | ForEach-Object { "$_".Trim() })
    if ($after -notcontains $gr.role) { throw "read-back FAILED: '$($gr.role)' is not assigned on $($gr.scope) -- the publish would 403." }
    Note 'granted + read back'
}

# ---- 5. SQL admin group (members only) ------------------------------------------------------------------------------
if (-not $SkipSqlAdminGroup) {
    Step "SQL admin group '$SqlAdminGroupName' -- $JobName's system identity"
    . (Join-Path $here '_PimSqlAdminGroup.ps1')
    $inv = New-PimSqlAdminGroupInvokers -SubscriptionId $SubscriptionId
    $srvRes = Resolve-PimSqlServerFromFqdn -Arm $inv.Arm -SubscriptionId $SubscriptionId -Server "$SqlServerFqdn"
    if (-not $srvRes) { throw "SQL server '$SqlServerFqdn' is not in subscription $SubscriptionId." }
    $g = Invoke-PimSqlAdminGroupStep -Graph $inv.Graph -Arm $inv.Arm -TenantId $inv.TenantId -SubscriptionId $SubscriptionId `
             -ResourceGroup $ResourceGroup -SqlResourceGroup $srvRes.resourceGroup -SqlServerName $srvRes.name `
             -GroupName $SqlAdminGroupName -UpdateJobName '' -ExtraMembers @([pscustomobject]@{ objectId = $oid; label = "publish job identity $JobName" }) `
             -Mode membersOnly -NoDiscovery
    Write-PimSqlAdminGroupReport -Result $g
    if (-not $g.ok -or $g.blocked) { throw "$JobName's identity could not be made a member of '$SqlAdminGroupName' -- it cannot read the master store." }
    Note "member of '$SqlAdminGroupName', the Entra admin of $($srvRes.name)"
}

Write-Host "==> $JobName deployed: cron '$Cron' (UTC), signing key $KeyName, store $StorageAccount/$Container. Start it now: Start-PimBaselinePublish.ps1 (the build's publish step)." -ForegroundColor Green
exit 0
