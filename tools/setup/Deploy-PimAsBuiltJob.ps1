#Requires -Version 5.1
<#
.SYNOPSIS
    PIM REQUIREMENTS 100.61 -- deploy the as-built job (caj-pim-asbuilt): the Container Apps job that renders this installation's
    as-built PDF and writes it to the PIM storage account (container 'asbuilt', deleted after 1 day). REST / ARM only.

.DESCRIPTION
    Framework DOCS/REQUIREMENTS.md 8.12 (replacement contract, owner 2026-10-10). Idempotent. In order:
      1. the PIM storage account (-StorageAccount, else the default name Get-PimAsBuiltStorageAccountName): created when
         missing -- StorageV2, TLS 1.2, HTTPS only, NO shared-key access, NO anonymous blob access (Entra tokens only), on
         every installation, internal ones included (owner 2026-10-10: the on-demand fetch is only via the Support app): the
         blob is readable only by the Support app's identity after the customer's Grant-PimSupportAccess -Level asbuilt
      2. the container 'asbuilt' (control plane, private) and the lifecycle rule 'pim-asbuilt-delete-after-1-day' (every other
         rule of the account's management policy is kept)
      3. the job: MANUAL trigger, the same image as the Manager, tools/pim-engine/asbuilt-job-entry.ps1, SYSTEM-ASSIGNED
         identity (the image pull uses the Manager's registry identity when it has one) -- read back
      4. the job identity's ONLY Azure right: Storage Blob Data Contributor on the container 'asbuilt' (+ AcrPull on the registry
         when there is no registry identity to inherit) -- read back
      5. the custom role 'PIM Manager as-built runner (<rg>)' (start the job + read its executions; assignable in this resource
         group) -- created here so Grant-PimSupportAccess.ps1 only has to ASSIGN it, with the customer's consent
      6. SQL: the view pim.vw_AsBuiltSettings (people and secrets reduced to counts IN SQL) and the job identity's own contained
         user (from its app id as a SID) with SELECT on that view only -- read back; and pim.Settings 'AsBuiltInstallFacts'
         { region; network; resourceGroup; recordedUtc } (the facts the store cannot know otherwise)
    It does NOT start the job and grants NOTHING to the Invardia Support app (Grant-PimSupportAccess.ps1 does, on consent).

.EXAMPLE
    .\Deploy-PimAsBuiltJob.ps1 -SubscriptionId <s> -ResourceGroup rg-pim -EnvName cae-pim -AcrName acrpim -SqlServerFqdn sql-pim.database.windows.net
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$EnvName,
    [Parameter(Mandatory)][string]$AcrName,
    [string]$ImageRepo = 'pim-manager',
    [string]$ImageTag,
    [string]$JobName = 'caj-pim-asbuilt',
    [string]$ManagerApp = 'ca-pim-manager',
    [Parameter(Mandatory)][string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$StorageAccount,
    [string]$RegistryIdentityResourceId,
    [switch]$SkipSqlGrant
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
. (Join-Path $solRoot 'engine\_shared\PIM-AsBuilt.ps1')
. (Join-Path $here '_PimUpdateRing.ps1')          # ConvertTo-PimJobEnvMap
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

$S = "$SubscriptionId".Trim()
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }
if (-not "$ImageTag".Trim()) {
    $vf = Join-Path $solRoot 'VERSION'
    if (Test-Path -LiteralPath $vf) { $ImageTag = (Get-Content -LiteralPath $vf -Raw).Trim().TrimStart([char]0xFEFF) }
}
if (-not "$ImageTag".Trim()) { throw '-ImageTag is required (no VERSION file to default from).' }
if (-not "$StorageAccount".Trim()) { $StorageAccount = Get-PimAsBuiltStorageAccountName -SubscriptionId $S -ResourceGroup $ResourceGroup }
$container = Get-PimAsBuiltContainerName
$image = "$AcrName.azurecr.io/$ImageRepo" + ':' + "$ImageTag".Trim()
Write-Host "`n=== PIM Manager as-built job ($JobName) ===" -ForegroundColor Cyan
Note "environment $EnvName / $ResourceGroup ; image $image ; store $StorageAccount/$container"

# ---- the Container Apps environment: where, and internal or external (the facts the store cannot know) -------------
$envObj = Get-PimArmAcaEnv -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $EnvName -ErrorAsNull
if (-not $envObj) { throw "Container Apps environment '$EnvName' not found in $ResourceGroup." }
$envId = "$($envObj.id)".Trim(); $location = "$($envObj.location)".Trim()
$network = if ([bool]$envObj.properties.vnetConfiguration.internal) { 'internal' } else { 'external' }
$region = ("$location" -replace '\s', '').ToLowerInvariant()
Note "region $region ; network $network"

# ---- 1. the storage account (Entra-only) --------------------------------------------------------------------------
if ($PSCmdlet.ShouldProcess($StorageAccount, 'create / harden the PIM storage account')) {
    Step "storage account $StorageAccount"
    $sa = Get-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -ErrorAsNull
    if (-not $sa) { $sa = New-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -Location $location -Sku Standard_LRS -Kind StorageV2 -AllowBlobPublicAccess $false; Note 'created' }
    $fix = @{}
    if ($sa.properties.allowSharedKeyAccess -ne $false) { $fix['allowSharedKeyAccess'] = $false }
    if ($sa.properties.allowBlobPublicAccess -ne $false) { $fix['allowBlobPublicAccess'] = $false }
    if ("$($sa.properties.minimumTlsVersion)" -ne 'TLS1_2') { $fix['minimumTlsVersion'] = 'TLS1_2' }
    if ($sa.properties.supportsHttpsTrafficOnly -ne $true) { $fix['supportsHttpsTrafficOnly'] = $true }
    # Owner 2026-10-10: the fetch is ONLY via the Support app, on EVERY installation (internal ones included): the account keeps
    # an Entra-only public endpoint; its only reader is the Support app after the customer's -Level asbuilt grant (+ the job as writer).
    if ("$($sa.properties.publicNetworkAccess)" -notin @('', 'Enabled')) { $fix['publicNetworkAccess'] = 'Enabled' }
    if ($fix.Count) { [void](Update-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount -Properties $fix); Note "hardened: $(@($fix.Keys) -join ', ')" }
    $sa = Get-PimArmStorageAccount -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $StorageAccount
    if ($sa.properties.allowSharedKeyAccess -ne $false -or $sa.properties.allowBlobPublicAccess -ne $false) { throw "read-back FAILED: $StorageAccount still allows shared-key or anonymous access." }
    if ("$($sa.properties.publicNetworkAccess)" -notin @('', 'Enabled')) { throw "read-back FAILED: $StorageAccount public network access is '$($sa.properties.publicNetworkAccess)' -- the Support app could not fetch the PDF." }
    Note 'read back: Entra-only public endpoint (no shared key, no anonymous access), TLS 1.2 -- readable only by the Support app after the customer''s grant'

    # ---- 2. the container + the 1-day lifecycle rule -------------------------------------------------------------
    Step "container '$container' + lifecycle rule (delete after 1 day)"
    $c = Get-PimArmBlobContainer -SubscriptionId $S -ResourceGroup $ResourceGroup -Account $StorageAccount -Name $container -ErrorAsNull
    if (-not $c) { [void](Set-PimArmBlobContainer -SubscriptionId $S -ResourceGroup $ResourceGroup -Account $StorageAccount -Name $container -Create -PublicAccess None); Note 'container created (private)' }
    elseif ("$($c.properties.publicAccess)" -notin @('', 'None')) { [void](Set-PimArmBlobContainer -SubscriptionId $S -ResourceGroup $ResourceGroup -Account $StorageAccount -Name $container -PublicAccess None); Note 'container made private' }
    $polPath = Get-PimArmResourceId $S $ResourceGroup 'Microsoft.Storage/storageAccounts' $StorageAccount 'managementPolicies/default'
    $want = Get-PimAsBuiltLifecyclePolicy -Container $container
    $cur = Invoke-PimSetupArm -Path $polPath -ApiVersion (Get-PimSetupApiVersion storage) -NotFoundOk -ErrorAsNull
    $keep = @(@($cur.properties.policy.rules) | Where-Object { $_ -and "$($_.name)" -ne 'pim-asbuilt-delete-after-1-day' })
    $want.properties.policy.rules = @($keep) + @($want.properties.policy.rules)
    [void](Invoke-PimSetupArm -Method PUT -Path $polPath -Body $want -ApiVersion (Get-PimSetupApiVersion storage))
    $back = Invoke-PimSetupArm -Path $polPath -ApiVersion (Get-PimSetupApiVersion storage)
    $rule = @($back.properties.policy.rules | Where-Object { "$($_.name)" -eq 'pim-asbuilt-delete-after-1-day' }) | Select-Object -First 1
    if (-not $rule -or [int]$rule.definition.actions.baseBlob.delete.daysAfterModificationGreaterThan -ne 1 -or @($rule.definition.filters.prefixMatch) -notcontains "$container/") { throw 'read-back FAILED: the 1-day lifecycle rule is not in place.' }
    Note "read back: rule 'pim-asbuilt-delete-after-1-day' (prefix $container/, 1 day)$(if ($keep.Count) { "; $($keep.Count) other rule(s) kept" })"
}

# ---- 3. the job ---------------------------------------------------------------------------------------------------
$exists = [bool](Get-PimArmAcaJob -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $JobName -ErrorAsNull)
if (-not "$RegistryIdentityResourceId".Trim()) {
    $mgrApp = Get-PimArmAcaApp -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $ManagerApp -ErrorAsNull
    $mgrReg = if ($mgrApp) { "$(@($mgrApp.properties.configuration.registries)[0].identity)".Trim() } else { '' }
    if ($mgrReg -and $mgrReg -ne 'system') { $RegistryIdentityResourceId = $mgrReg; Note "registry identity inherited from $ManagerApp" }
}
$spec = Get-PimAsBuiltJobSpec -JobName $JobName -Image $image -EnvironmentId $envId -Location $location -RegistryServer "$AcrName.azurecr.io" `
            -RegistryIdentity $(if ("$RegistryIdentityResourceId".Trim()) { "$RegistryIdentityResourceId".Trim() } else { 'system' }) `
            -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -StorageAccount $StorageAccount -Container $container -Exists $exists
if (-not $spec.ok) { throw "REFUSED: $($spec.reason)" }
$action = if ($exists) { 'update' } else { 'create' }
if ($PSCmdlet.ShouldProcess($JobName, "$action the as-built job (manual trigger)")) {
    Step "$action $JobName"
    [void](Set-PimArmAcaJob -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $JobName -Resource $spec.resource -Create:(-not $exists))
}
if ($WhatIfPreference) { Note 'WhatIf: stopping before the read-back and the grants'; return }
$jobObj = Get-PimArmAcaJob -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $JobName
if ("$($jobObj.properties.provisioningState)" -ne 'Succeeded') { throw "job '$JobName' provisioningState='$($jobObj.properties.provisioningState)' (expected Succeeded)." }
if ("$($jobObj.properties.configuration.triggerType)" -ne 'Manual') { throw "read-back FAILED: $JobName is not a manual-trigger job." }
$envBack = ConvertTo-PimJobEnvMap -Job $jobObj -ContainerName $JobName
$bad = @(foreach ($k in @($spec.env.Keys)) { if ("$($envBack[$k])" -cne "$($spec.env[$k])") { $k } })
if ($bad.Count) { throw "read-back FAILED: env $($bad -join ', ') not stored as planned" }
$oid = "$($jobObj.identity.principalId)".Trim()
if (-not $oid) { throw "$JobName has no SYSTEM-ASSIGNED identity -- it could not authenticate to SQL or storage." }
Note "read back: manual trigger, env exact, system identity $oid"

# ---- 4. the job identity's grants: the container only (+ AcrPull without a registry identity) ----------------------
$grants = @(@{ role = 'Storage Blob Data Contributor'; scope = (Get-PimArmResourceId $S $ResourceGroup 'Microsoft.Storage/storageAccounts' $StorageAccount "blobServices/default/containers/$container"); why = 'write the as-built PDF' })
if (-not "$RegistryIdentityResourceId".Trim()) {
    $acrId = "$((Find-PimArmAcr -SubscriptionId $S -Name $AcrName).id)".Trim()
    if ($acrId) { $grants += @{ role = 'AcrPull'; scope = $acrId; why = 'pull its own image (no registry identity to inherit)' } }
}
foreach ($gr in $grants) {
    Step "$($gr.role) on $($gr.scope) -- $($gr.why)"
    $have = @(try { Get-PimArmRoleAssignments -Scope $gr.scope -PrincipalId $oid -SubscriptionId $S } catch { @() }) | ForEach-Object { "$($_.roleDefinitionName)".Trim() }
    if ($have -contains $gr.role) { Note 'already assigned'; continue }
    try { [void](New-PimArmRoleAssignment -Scope $gr.scope -PrincipalId $oid -PrincipalType ServicePrincipal -Role $gr.role -SubscriptionId $S) } catch { Warn "  $($_.Exception.Message)" }
    $after = @(try { Get-PimArmRoleAssignments -Scope $gr.scope -PrincipalId $oid -SubscriptionId $S } catch { @() }) | ForEach-Object { "$($_.roleDefinitionName)".Trim() }
    if ($after -notcontains $gr.role) { throw "read-back FAILED: '$($gr.role)' is not assigned on $($gr.scope)." }
    Note 'granted + read back'
}

# ---- 5. the custom role the support app is later ASSIGNED (start + read executions; nothing else) -------------------
$rd = Get-PimAsBuiltRoleDefinition -SubscriptionId $S -ResourceGroup $ResourceGroup
Step "custom role '$($rd.body.properties.roleName)' ($($script:PimAsBuiltRoleActions -join ', '))"
try {
    [void](Invoke-PimSetupArm -Method PUT -Path $rd.path -Body $rd.body -ApiVersion (Get-PimSetupApiVersion authorization))
    $rb = Invoke-PimSetupArm -Path $rd.path -ApiVersion (Get-PimSetupApiVersion authorization)
    $acts = @($rb.properties.permissions | ForEach-Object { $_.actions } | ForEach-Object { "$_" })
    if (@(Compare-Object $acts $script:PimAsBuiltRoleActions).Count) { throw "it reads back with actions $($acts -join ', ')" }
    Note 'created / converged + read back'
} catch { Warn "  the custom role was not created ($($_.Exception.Message)) -- Grant-PimSupportAccess.ps1 creates it when it runs with Owner / User Access Administrator." }

# ---- 6. SQL: the view, the job's reader user, the install facts -----------------------------------------------------
if (-not $SkipSqlGrant) {
    . (Join-Path $here '_PimSetupShared.ps1')        # Get-PimSqlContainedUserSql / read-back / Resolve-PimMiAppId
    . (Join-Path $here '_PimSqlAdminGroup.ps1')      # New-PimSqlAdminGroupInvokers (tenant-checked)
    . (Join-Path $solRoot 'engine\_shared\PIM-SqlStore.ps1')   # Resolve-PimSqlClientType
    $view = 'pim.vw_AsBuiltSettings'
    $revoke = @('db_owner', 'db_datawriter', 'db_ddladmin', 'db_datareader')
    Step "SQL: $JobName's identity gets SELECT on $view only (people and secrets reduced in SQL)"
    $inv = New-PimSqlAdminGroupInvokers -SubscriptionId $S
    $graphInv = $inv.Graph
    $miAppId = Resolve-PimMiAppId -ObjectId $oid -What $JobName -Lookup { param($id) try { "$((& $graphInv -Method GET -Path ("/servicePrincipals/$id" + '?$select=appId')).appId)".Trim() } catch { '' } }
    if (-not "$miAppId".Trim()) { throw "could not resolve the app id of $JobName's identity ($oid) -- cannot create its database user." }
    $sqlTok = ''
    try { $sqlTok = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId "$($inv.TenantId)")".Trim() } catch { $sqlTok = '' }
    if (-not $sqlTok) { throw "no Azure SQL token for subscription $S (sign in first) -- cannot create $JobName's database user." }
    $grantSql = Get-PimSqlContainedUserSql -DbUserName $JobName -AppId $miAppId -SelectObjects @($view) -RevokeRoles $revoke
    $readSql  = Get-PimSqlContainedUserReadBackSql -DbUserName $JobName -AppId $miAppId -Roles $revoke -SelectObjects @($view)
    $factsJson = ([ordered]@{ region = $region; network = $network; resourceGroup = $ResourceGroup; recordedUtc = [datetime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress)
    $factsSql = "MERGE pim.Settings AS t USING (SELECT N'AsBuiltInstallFacts' AS Name, @v AS V) AS s ON t.Name = s.Name WHEN MATCHED THEN UPDATE SET ValueJson = s.V, UpdatedUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, ValueJson, UpdatedUtc) VALUES (s.Name, s.V, SYSUTCDATETIME());"
    $rowBack = $null
    $sqlType = Resolve-PimSqlClientType
    $conn = $sqlType::new("Server=tcp:$SqlServerFqdn,1433;Database=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30")
    $conn.AccessToken = $sqlTok; $sqlTok = $null
    try {
        $conn.Open()
        $cmd = $conn.CreateCommand(); $cmd.CommandText = (Get-PimAsBuiltViewSql); [void]$cmd.ExecuteNonQuery()
        $cmd = $conn.CreateCommand(); $cmd.CommandText = $grantSql; [void]$cmd.ExecuteNonQuery()
        $cmd = $conn.CreateCommand(); $cmd.CommandText = $factsSql; [void]$cmd.Parameters.AddWithValue('@v', $factsJson); [void]$cmd.ExecuteNonQuery()
        $cmd = $conn.CreateCommand(); $cmd.CommandText = $readSql
        $rdr = $cmd.ExecuteReader()
        try {
            if ($rdr.Read()) {
                $h = [ordered]@{}
                for ($i = 0; $i -lt $rdr.FieldCount; $i++) { $h[$rdr.GetName($i)] = $(if ($rdr.IsDBNull($i)) { $null } else { $rdr.GetValue($i) }) }
                $rowBack = [pscustomobject]$h
            }
        } finally { $rdr.Close() }
    } catch {
        throw ("could not prepare $SqlServerFqdn/$SqlDatabase for $JobName from this host: $($_.Exception.Message). " +
               'This host must reach the SQL server and its identity must be a member of the SQL admin group (as for every store step of the build).')
    } finally { $conn.Close(); $conn.Dispose() }
    $verdict = Test-PimSqlContainedUserReadBack -Row $rowBack -RevokeRoles $revoke -SelectObjects @($view) -DbUserName $JobName
    if (-not $verdict.ok) { throw "read-back FAILED for $JobName's database user: $($verdict.problems -join '; ')" }
    Note "read back: contained user '$JobName' (SID from app id $miAppId), SELECT on $view, no fixed database role; AsBuiltInstallFacts recorded ($region, $network)"
} else {
    Warn "-SkipSqlGrant: $JobName's identity got NO database user -- the job fails until it can SELECT pim.vw_AsBuiltSettings."
}

Write-Host "==> $JobName deployed (manual trigger). The PDF lands in https://$StorageAccount.blob.core.windows.net/$container/<execution>.pdf and is deleted after 1 day. Support access: Grant-PimSupportAccess.ps1 (with the customer's consent)." -ForegroundColor Green
exit 0
