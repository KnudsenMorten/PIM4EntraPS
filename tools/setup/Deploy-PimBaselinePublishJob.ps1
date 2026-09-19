#Requires -Version 5.1
<#
.SYNOPSIS
    71.35 -- deploy the MSP master's signed-baseline PUBLISH job (ca-pim-publish): a Container Apps job on the master's own
    environment, on the cadence set in the master's Manager (Job schedule; daily when nothing is set -- the job's trigger
    fires every 5 minutes and it gates itself) + on demand, running as its SYSTEM-ASSIGNED managed identity. No certificate, no secret, no
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
      5. SQL (SEC-39): the identity gets its OWN contained database user, created from its app id as a SID (never
         FROM EXTERNAL PROVIDER), with SELECT on exactly the objects the job reads (Get-PimBaselinePublishSqlReads) and
         no fixed role -- read back. It is NOT a member of grp-pim-sql-admins: that group is the server's Entra admin,
         i.e. full administration of the store, and the job only reads. An identity an earlier version put in the
         group is taken OUT of it (read back), after the reader user is proven.
    It does NOT start the job: the build's 'publish' step does (Start-PimBaselinePublish.ps1), after this has converged.
    The SQL step connects from THIS host as the az context the build established (a member of the SQL admin group),
    so this host must reach the SQL server -- the same requirement every other store step of the build has.

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
    # Every 5 minutes (operator 2026-09-18: the cadence is set in the Manager's Job schedule). The job GATES ITSELF against
    # the master's own PublishSchedule (engine/_shared/PIM-JobCadence.ps1); nothing set = daily, as the old '0 4 * * *'.
    [string]$Cron = '*/5 * * * *',
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
    # SEC-39: only used to take the job's identity OUT of the group if an earlier version put it there.
    [string]$SqlAdminGroupName = 'grp-pim-sql-admins',
    # (71.33: no -UseSignedInAccount -- every call here runs as the az context the build established, the signed-in
    # administrator or the certificate identity alike; there is no identity choice to make.)
    # Skip the SQL reader-user step (the job then cannot read the store until its user is created another way).
    [Alias('SkipSqlAdminGroup')][switch]$SkipSqlGrant
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
            -SigningKeyId $signingKeyId -ValidDays $ValidDays -Scope $Scope -Exists $exists `
            -DeployedUtc ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture))
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

# ---- 5. SQL: its OWN least-privilege READER user -- never the SQL admin group (SEC-39) ------------------------------
# SEC-39 -- THIS USED TO ADD THE JOB'S IDENTITY TO grp-pim-sql-admins, the SQL server's Entra ADMIN: full administration
# of the master registry for a job that only SELECTs from four tables. A compromise of the publish job (or of anything
# able to run as it) would then have been able to rewrite who is an MSP admin in every managed tenant. It now gets a
# contained user created from its app id as a SID (FROM EXTERNAL PROVIDER fails on these servers), with SELECT on exactly
# what the producer reads and NO fixed role (a broader role an older run granted is taken back). Read back, then -- and
# only then -- an earlier version's group membership is removed, so the job is never without access.
if (-not $SkipSqlGrant) {
    . (Join-Path $here '_PimSetupShared.ps1')        # Get-PimSqlContainedUserSql / read-back / Get-PimBaselinePublishSqlReads / Resolve-PimMiAppId
    . (Join-Path $here '_PimSqlAdminGroup.ps1')      # New-PimSqlAdminGroupInvokers (tenant-checked) / Remove-PimSqlAdminGroupMember
    foreach ($dep in @('engine\_shared\PIM-Rest.ps1', 'engine\_shared\PIM-SqlStore.ps1')) { . (Join-Path $solRoot $dep) }   # Resolve-PimSqlClientType
    $sqlReads = @(Get-PimBaselinePublishSqlReads)
    # The cadence (PIM-JobCadence.ps1): SELECT on the two control views, INSERT/UPDATE on the one CHECK-OPTION view onto the
    # job's own PublishLastRun row. Never a right on pim.Settings itself (it also holds who is SuperAdmin).
    $ctl      = Get-PimPublishJobControlObjects
    $sqlSel   = @(@($sqlReads) + @($ctl.select) | Select-Object -Unique)
    $sqlWrite = @($ctl.write)
    $revoke   = @('db_owner', 'db_datawriter', 'db_ddladmin', 'db_datareader')
    Step "SQL: $JobName's identity gets a READER user on $SqlServerFqdn/$SqlDatabase (SELECT on $($sqlReads -join ', '); cadence views $($ctl.select -join ', '), INSERT/UPDATE on $($sqlWrite -join ', ')) -- not the SQL admin group"
    $inv = New-PimSqlAdminGroupInvokers -SubscriptionId $SubscriptionId
    $graphInv = $inv.Graph
    # The app id through the TENANT-CHECKED Graph invoker (not an unscoped `az ad sp show`), bounded retry for a new identity.
    $miAppId = Resolve-PimMiAppId -ObjectId $oid -What $JobName -Lookup {
        param($id)
        try { "$((& $graphInv -Method GET -Path ("/servicePrincipals/$id" + '?$select=appId')).appId)".Trim() } catch { '' }
    }
    if (-not "$miAppId".Trim()) { throw "could not resolve the app id of $JobName's identity ($oid) -- cannot create its database user." }
    # A SQL token for the az context the build established -- scoped to THIS subscription, and its tenant checked.
    $tokRaw = @(az account get-access-token --subscription $SubscriptionId --resource https://database.windows.net/ -o json 2>$null) -join "`n"
    $tokObj = $null; try { $tokObj = $tokRaw | ConvertFrom-Json } catch { $tokObj = $null }
    if (-not $tokObj -or -not "$($tokObj.accessToken)".Trim()) { throw "no Azure SQL token for subscription $SubscriptionId (sign in first) -- cannot create $JobName's database user." }
    if ("$($tokObj.tenant)".Trim() -and "$($tokObj.tenant)".Trim().ToLowerInvariant() -ne "$($inv.TenantId)".Trim().ToLowerInvariant()) {
        throw "the SQL token is for tenant '$($tokObj.tenant)', not '$($inv.TenantId)' -- REFUSING."
    }
    $grantSql = Get-PimSqlContainedUserSql -DbUserName $JobName -AppId $miAppId -SelectObjects $sqlSel -WriteObjects $sqlWrite -RevokeRoles $revoke
    $readSql  = Get-PimSqlContainedUserReadBackSql -DbUserName $JobName -AppId $miAppId -Roles $revoke -SelectObjects $sqlSel -WriteObjects $sqlWrite
    $rowBack = $null
    $sqlType = Resolve-PimSqlClientType
    $conn = $sqlType::new("Server=tcp:$SqlServerFqdn,1433;Database=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30")
    $conn.AccessToken = "$($tokObj.accessToken)"
    try {
        $conn.Open()
        # The two cadence views first (idempotent), so the grant below has objects to grant on.
        $cmd = $conn.CreateCommand(); $cmd.CommandText = (Get-PimPublishJobControlViewSql); [void]$cmd.ExecuteNonQuery()
        $cmd = $conn.CreateCommand(); $cmd.CommandText = $grantSql; [void]$cmd.ExecuteNonQuery()
        $cmd = $conn.CreateCommand(); $cmd.CommandText = $readSql
        $rd = $cmd.ExecuteReader()
        try {
            if ($rd.Read()) {
                $h = [ordered]@{}
                for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }
                $rowBack = [pscustomobject]$h
            }
        } finally { $rd.Close() }
    } catch {
        throw ("could not create $JobName's database user on $SqlServerFqdn/$SqlDatabase from this host: $($_.Exception.Message). " +
               'This host must reach the SQL server and its az identity must be a member of the SQL admin group (as for every store step of the build).')
    } finally { $conn.Close(); $conn.Dispose(); $tokObj = $null }
    # FAIL CLOSED on a missing table: the producer reads a SELECT that is refused exactly like a table that is absent, and
    # for pim.TenantRoleProjection "absent" means "project everything". A master registry without these is not ready.
    $absent = @()
    if ($rowBack) { $absent = @($sqlSel | Where-Object { $p = $rowBack.PSObject.Properties["sel_$("$_".Replace('.', '_'))"]; $p -and ($null -eq $p.Value -or $p.Value -is [DBNull]) }) }
    if ($absent.Count) { throw "the master store $SqlDatabase has no $($absent -join ', ') -- apply the registry schema (Initialize-PimMasterRegistry.ps1) first (the cadence views need pim.Settings, which the Manager creates); the job's reader user was NOT proven." }
    $verdict = Test-PimSqlContainedUserReadBack -Row $rowBack -RevokeRoles $revoke -SelectObjects $sqlSel -WriteObjects $sqlWrite -DbUserName $JobName
    if (-not $verdict.ok) { throw "read-back FAILED for $JobName's database user: $($verdict.problems -join '; ')" }
    Note "read back: contained user '$JobName' (SID from app id $miAppId), SELECT on $($sqlSel -join ', '), INSERT/UPDATE on $($sqlWrite -join ', '), no fixed database role"

    # An earlier version made the identity a member of the SQL admin group. Take it out -- the reader user above is proven.
    $rm = Remove-PimSqlAdminGroupMember -Graph $inv.Graph -MemberObjectId $oid -GroupName $SqlAdminGroupName -Label "publish job identity $JobName"
    if (-not $rm.ok) { throw "$JobName's identity is STILL a member of '$SqlAdminGroupName' (full SQL administration): $($rm.problem). Remove it by hand -- its reader user is in place." }
    if ($rm.removed) { Note "removed from '$SqlAdminGroupName' (an earlier version's full-admin membership; read back)" }
    else { Note "not a member of '$SqlAdminGroupName' (correct)" }
} else {
    Warn "-SkipSqlGrant: $JobName's identity got NO database user from this run -- the publish fails until it can SELECT what it reads (see Get-PimBaselinePublishSqlReads in _PimSetupShared.ps1)."
}

Write-Host "==> $JobName deployed: cron '$Cron' (UTC), signing key $KeyName, store $StorageAccount/$Container. Start it now: Start-PimBaselinePublish.ps1 (the build's publish step)." -ForegroundColor Green
exit 0
