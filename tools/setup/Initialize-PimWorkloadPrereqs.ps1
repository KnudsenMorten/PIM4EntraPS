#Requires -Version 5.1
<#
.SYNOPSIS
    REQ-U (prereqs) / 97.1 -- FIX the prerequisites of ONE workload PIM delegates into that PIM cannot fix itself, and
    check them. You sign in in the browser; no PowerShell modules, no certificate.

.DESCRIPTION
    PIM checks every workload prerequisite an API can answer ITSELF, every day (job 'workload-prereqs'; "Check again" on
    the prerequisite chips in PIM Manager). This script is for what needs a PERSON with more rights than the engine has:
    creating the Power BI admin-API security group and adding the engine to it, switching on the Fabric tenant setting,
    enabling Microsoft Sentinel on a dedicated workspace, assigning User Access Administrator at an Azure scope. (Missing
    Graph application permissions of the engine are granted with Grant-PimEnginePermissions.ps1 -- PIM Manager shows that
    command when it applies.) PIM Manager shows the exact command for this environment on the prerequisite chip.

    Download (one file, nothing else needed):
        Invoke-WebRequest https://invardia.com/support/pim/Initialize-PimWorkloadPrereqs.ps1 -OutFile Initialize-PimWorkloadPrereqs.ps1

    Per workload it CHECKS every prerequisite in the catalog (engine\_shared\PIM-WorkloadPrereqs.ps1 -- the engine's
    self-check, the Manager and the tests use the same definitions) and FIXES what an API can fix, reading every change back:
      DefenderXdr  engine Graph role RoleManagement.ReadWrite.Defender (grant) | Unified RBAC answers (beta
                   roleManagement/defender/roleDefinitions) | activated workloads (PORTAL ONLY, inferred from the live
                   roles) | Data Operations: Sentinel enabled on a workspace (ARM onboardingStates) and connected to the
                   Defender portal / data lake (PORTAL ONLY). -SkipDataOperations when no Data Operations role is used.
                   -EnableSentinel (OPT-IN, billed per GB ingested): enables Sentinel on a DEDICATED security workspace
                   (-SentinelWorkspaceId, else law-sentinel-<suffix> in -ResourceGroup, created empty when missing);
                   refused on PIM's own log workspace (law-pim-*).
      Intune       engine Graph role DeviceManagementRBAC.ReadWrite.All (grant) | deviceManagement/roleDefinitions answers.
      PowerBI      security group (create) | engine identity is a member (add) | no admin-consent Power BI application
                   permission on it (Microsoft's rule for read-only admin APIs; reported, never removed automatically) |
                   Fabric tenant setting "Service principals can access read-only admin APIs" for that group (Fabric
                   admin API, keeping every existing group; portal step when the caller may not).
      AzureRbac    User Access Administrator (or Owner) for the engine identity at every scope in your
                   PIM-Assignments-Azure-Resources rows (+ -AzureScope). Assigning it is OPT-IN
                   (-GrantAzureUserAccessAdministrator): it is standing privilege (SEC-34).
      EntraRoles   the full Graph role map (grant; from the repository only) | the AAD_PREMIUM_P2 service plan.
    What only a human can do is reported with the exact portal path and the Microsoft Learn link; confirm it with the
    Confirm button on the prerequisite in PIM Manager (or -ConfirmPortalStep <check id> here) -- recorded as "confirmed",
    attested, never as verified.

    RECORDING. When -SqlServerFqdn is given and the identity can reach the store (a member of its SQL admin group), the
    result is MERGED into pim.Settings 'WorkloadPrereqs' (a confirmation made in PIM Manager is kept), read back and
    audited. Otherwise nothing is recorded here: press Check again in PIM Manager -- PIM checks it itself. -WhatIf changes
    nothing, not even the store.

    IDENTITY, one of:
      (default)            browser sign-in as you (auth code + PKCE; Microsoft Edge, the default browser when Edge is
                           missing): Microsoft Graph, plus Azure when the workload needs it. No modules, no secret.
      -UseSignedInAccount  the account signed in to az in this window -- the Invardia Support app session opened by
                           Invardia's connect script, or a person (az login).
      -ClientId + -CertThumbprint  a certificate identity (repository only; kept for existing automation, never shown by
                           PIM Manager).
    The caller needs, for the checks: Application.Read.All, Group.Read.All, Organization.Read.All, the Defender / Intune
    read permissions, Reader on the workspaces / scopes; for the fixes: AppRoleAssignment.ReadWrite.All,
    Group.ReadWrite.All (or GroupMember.ReadWrite.All), a Fabric administrator, User Access Administrator at the scope.
    A check the caller cannot read is recorded as NOT CHECKED with the reason -- never as passed.

.EXAMPLE
    .\Initialize-PimWorkloadPrereqs.ps1 -Workload PowerBI -TenantId <tenant-id> -EngineObjectId <engine-object-id>

.EXAMPLE
    # Sentinel on a dedicated workspace for Defender Data Operations roles (opt-in: billed per GB ingested):
    .\Initialize-PimWorkloadPrereqs.ps1 -Workload DefenderXdr -TenantId <tenant-id> -SubscriptionId <hosting-subscription-id> -ResourceGroup <resource-group> -EnableSentinel
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('DefenderXdr', 'Intune', 'PowerBI', 'AzureRbac', 'EntraRoles')][string]$Workload,
    [Parameter(Mandatory)][string]$TenantId,
    # The HOSTING subscription + resource group (where ca-pim-tick runs): finds the engine identity when -EngineObjectId is
    # not given, and holds the dedicated Sentinel workspace. Every ARM call names its full path -- no default az context.
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$TickJobName = 'ca-pim-tick',
    # The environment's store. Optional: without it (or without access to it) the result is not recorded here.
    [string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    # Certificate identity (repository only, back-compat) -- OR -UseSignedInAccount -- OR neither: browser sign-in.
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount,
    # Browser sign-in: $true (default) opens Microsoft Edge, $false the default browser.
    [bool]$UseEdge = $true,
    # The ENGINE identity (PIM Manager shows its object id); otherwise the hosted tick job's managed identity.
    [string]$EngineObjectId,
    [string]$EngineAppId,
    # Only with an engine APPLICATION whose certificate is on this host: lets PowerBI test the admin API as the engine.
    [string]$EngineCertThumbprint,
    [string[]]$ConfirmPortalStep = @(),
    [switch]$SkipDataOperations,
    [string]$SentinelWorkspaceId,
    [switch]$EnableSentinel,
    [string]$PowerBiSecurityGroupName = 'grp-pim-powerbi-admin-api',
    [string[]]$AzureScope = @(),
    [switch]$GrantAzureUserAccessAdministrator
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Rest.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-WorkloadPrereqs.ps1')
. (Join-Path $PSScriptRoot '_PimWorkloadPrereqRunner.ps1')
. (Join-Path $PSScriptRoot '_PimEnginePermissions.ps1')   # browser sign-in (auth code + PKCE) -- the Grant-PimEnginePermissions pattern
# Repository-only helpers: the store (Connect-PimSetupStore, the SQL writer) and the one Graph role map. The published
# standalone file has neither; it then fixes and checks, and PIM's own self-check records the result.
foreach ($__f in @('_PimSetupShared.ps1', '_PimSetupSql.ps1')) { $__p = Join-Path $PSScriptRoot $__f; if (Test-Path -LiteralPath $__p) { . $__p } }
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }

if ("$TenantId".Trim() -notmatch '^[0-9a-fA-F-]{36}$') { throw "-TenantId must be the tenant GUID (got '$TenantId')." }
$unknown = @($ConfirmPortalStep | Where-Object { "$_".Trim() -and -not (Get-PimWorkloadPrereqCheckDef -Id "$_".Trim()) })
if ($unknown.Count) { throw "-ConfirmPortalStep: unknown check id(s): $($unknown -join ', '). Known for ${Workload}: $((@((Get-PimWorkloadPrereqCatalog -Workload $Workload)[$Workload].checks) | ForEach-Object { $_.id }) -join ', ')" }
$hasStoreHelpers = [bool](Get-Command Connect-PimSetupStore -ErrorAction SilentlyContinue)

# ---- identity --------------------------------------------------------------------------------------------------------
$mode = if ("$ClientId".Trim() -or "$CertThumbprint".Trim()) { 'certificate' } elseif ($UseSignedInAccount) { 'signedIn' } else { 'browser' }
if ($mode -eq 'certificate' -and $UseSignedInAccount) { throw 'pick ONE identity: -ClientId/-CertThumbprint (certificate) or -UseSignedInAccount.' }
if ($mode -eq 'certificate' -and (-not "$ClientId".Trim() -or -not "$CertThumbprint".Trim())) { throw 'certificate identity: give both -ClientId and -CertThumbprint (or neither, to sign in in the browser).' }
if ($mode -eq 'certificate' -and (-not $hasStoreHelpers -or -not "$SqlServerFqdn".Trim())) { throw 'the certificate identity runs from the PIM repository with -SqlServerFqdn. Without them, run this script with no identity parameters: you sign in in the browser.' }

Step "Workload prerequisites: $Workload (tenant $TenantId)"
$cs = $null
if ($mode -eq 'certificate') {
    $cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint
} elseif ($mode -eq 'signedIn' -and $hasStoreHelpers -and "$SqlServerFqdn".Trim()) {
    $cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -UseSignedInAccount
} elseif ($mode -eq 'signedIn') {
    # The az session in this window (the Invardia Support app, or a person) -- PIM-Rest's az path, tenant asserted per token.
    foreach ($g in 'PIM_ClientId', 'PIM_CertThumbprint', 'PIM_ClientSecret') { Set-Variable -Scope Global -Name $g -Value $null }
    $global:PIM_UseManagedIdentity = $false; $global:PIM_Interactive = $false; $global:PIM_TenantId = "$TenantId".Trim()
} else {
    # Browser sign-in (97.1, framework rule 3). Graph with the delegated scopes THIS workload's checks and fixes need;
    # Azure (+ the store / Fabric through its refresh token) only when the workload needs them.
    foreach ($g in 'PIM_ClientId', 'PIM_CertThumbprint', 'PIM_ClientSecret') { Set-Variable -Scope Global -Name $g -Value $null }
    $global:PIM_UseManagedIdentity = $false; $global:PIM_Interactive = $true; $global:PIM_TenantId = "$TenantId".Trim()
    $graphScopes = @('Application.Read.All', 'AppRoleAssignment.ReadWrite.All') + @(switch ($Workload) {
        'DefenderXdr' { 'RoleManagement.Read.Defender' }
        'Intune'      { 'DeviceManagementRBAC.Read.All' }
        'PowerBI'     { 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All' }
        'EntraRoles'  { 'Organization.Read.All' }
    })
    Write-Host "Signing in to Microsoft Graph in the browser (permissions asked: $($graphScopes -join ', '))..." -ForegroundColor Yellow
    try { $gt = Get-PimEpInteractiveToken -ClientId (Get-PimEpGraphCliClientId) -Scopes $graphScopes -Tenant $TenantId -UseEdge $UseEdge }
    catch { throw ("Sign-in failed: $($_.Exception.Message)`n$(Get-PimEpBrokenAuthHelp)") }
    $gc = ConvertFrom-PimEpJwtClaims "$($gt.access_token)"
    if (-not $gc -or "$($gc.tid)" -ne "$TenantId".Trim()) { throw "REFUSING: the browser sign-in landed in tenant '$($gc.tid)', expected '$TenantId'. Sign in with an account of that tenant." }
    $account = "$(if ($gc.upn) { $gc.upn } elseif ($gc.preferred_username) { $gc.preferred_username } else { $gc.unique_name })"
    Add-PimRestSessionToken -Resource 'graph' -Token "$($gt.access_token)" -ExpiresUtc ((Get-Date).ToUniversalTime().AddSeconds([int]$gt.expires_in - 60))
    $global:PIM_SetupActor = $account
    $needArm = ($Workload -in @('DefenderXdr', 'AzureRbac')) -or -not "$EngineObjectId$EngineAppId".Trim() -or ($Workload -eq 'PowerBI') -or "$SqlServerFqdn".Trim()
    if ($needArm) {
        Write-Host 'Signing in to Azure (same account)...' -ForegroundColor Yellow
        try {
            $at = Get-PimEpInteractiveToken -ClientId (Get-PimEpAzurePowerShellClientId) -Scopes @((Get-PimEpArmScope)) -Tenant $TenantId -UseEdge $UseEdge -LoginHint $account
            if ("$((ConvertFrom-PimEpJwtClaims "$($at.access_token)").tid)" -ne "$TenantId".Trim()) { throw 'the Azure sign-in landed in another tenant' }
            Add-PimRestSessionToken -Resource 'arm' -Token "$($at.access_token)" -ExpiresUtc ((Get-Date).ToUniversalTime().AddSeconds([int]$at.expires_in - 60))
            # The same sign-in's refresh token, for the store (when recording) and Fabric (Power BI) -- no extra prompt.
            $more = @(); if ("$SqlServerFqdn".Trim()) { $more += 'https://database.windows.net' }; if ($Workload -eq 'PowerBI') { $more += 'https://api.fabric.microsoft.com' }
            foreach ($aud in $more) {
                try {
                    $rt = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
                        client_id = (Get-PimEpAzurePowerShellClientId); grant_type = 'refresh_token'; refresh_token = "$($at.refresh_token)"; scope = "$aud/.default offline_access" }
                    Add-PimRestSessionToken -Resource $aud -Token "$($rt.access_token)" -ExpiresUtc ((Get-Date).ToUniversalTime().AddSeconds([int]$rt.expires_in - 60))
                } catch { Note "no token for $aud from this sign-in ($($_.Exception.Message)) -- what needs it is reported as not checked" }
            }
        } catch { Write-Warning "Azure sign-in failed: $($_.Exception.Message) -- the Azure checks are reported as not checked." }
    }
    if ("$SqlServerFqdn".Trim() -and $hasStoreHelpers) {
        $global:PIM_SqlServer = "$SqlServerFqdn".Trim(); $global:PIM_SqlDatabase = "$SqlDatabase".Trim()
        try { $cs = Get-PimSqlConnectionString -Server $global:PIM_SqlServer -Database $global:PIM_SqlDatabase } catch { $cs = $null }
    }
}

# The CALLER's Graph token: asserted to be for this tenant, and read for what it may do (a 403 is only evidence about
# the tenant when the caller holds the permission -- Get-PimPrereqProbeVerdict).
$claims = ConvertFrom-PimPrereqJwt -Token (Get-PimRestToken -Resource 'graph' -TenantId $TenantId)
if (-not $claims -or "$($claims.tid)" -ne "$TenantId".Trim()) { throw "REFUSING: the Graph token is for tenant '$($claims.tid)', expected '$TenantId'." }
$ranBy = if ("$($claims.upn)".Trim()) { "$($claims.upn)" } elseif ("$($global:PIM_SetupActor)".Trim()) { "$($global:PIM_SetupActor)" } else { "app $($claims.appid)" }
Note "caller: $ranBy"

$engine = Resolve-PimPrereqEngineIdentity -EngineObjectId $EngineObjectId -EngineAppId $EngineAppId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -TickJobName $TickJobName
Note "engine identity: $($engine.displayName) ($($engine.objectId), $($engine.kind))"

$roleMap = @{}; $roleNames = @()
if (Get-Command Get-PimGraphAppRoleMap -ErrorAction SilentlyContinue) { $roleMap = Get-PimGraphAppRoleMap -RoleSet Engine; $roleNames = @(Get-PimEngineSpnGraphRoles) }
$toolVersion = if (Get-Command Get-PimSetupSolutionVersion -ErrorAction SilentlyContinue) { Get-PimSetupSolutionVersion } else { "$(Get-PimEpSolutionVersion)" -replace '^v', '' }

$__cmdlet = $PSCmdlet   # captured for the -WhatIf / -Confirm gate the runner calls before every change
$ctx = @{
    tenantId = "$TenantId".Trim(); engine = $engine; callerClaims = $claims; ranBy = $ranBy
    roleMap = $roleMap; engineRoleNames = @($roleNames)
    confirm = @($ConfirmPortalStep); skipDataOperations = [bool]$SkipDataOperations; sentinelWorkspaceId = $SentinelWorkspaceId
    enableSentinel = [bool]$EnableSentinel; hostingSubscriptionId = $SubscriptionId; hostingResourceGroup = $ResourceGroup; pollSeconds = 5
    powerBiGroupName = $PowerBiSecurityGroupName; azureScopes = @($AzureScope); grantUaa = [bool]$GrantAzureUserAccessAdministrator
    engineCertThumbprint = $EngineCertThumbprint; graphSp = $null; engineAssignments = $null; azureRows = @()
    should = { param($t, $a) $__cmdlet.ShouldProcess($t, $a) }.GetNewClosure()
}
if ($Workload -eq 'AzureRbac' -and $cs) {
    try { $ctx.azureRows = @(Get-PimSqlRows -ConnectionString $cs -Entity 'PIM-Assignments-Azure-Resources') }
    catch { if ($mode -eq 'certificate') { throw }; Note "the delegation rows could not be read from the store ($($_.Exception.Message)) -- pass -AzureScope to check a scope" }
}
if ($Workload -eq 'EntraRoles' -and -not $roleNames.Count) { Note 'the engine Graph role list is checked by PIM itself (and granted with Grant-PimEnginePermissions.ps1); this standalone script checks the licence.' }

$checks = @(Invoke-PimWorkloadPrereqRun -Workload $Workload -Ctx $ctx)
$result = Get-PimWorkloadPrereqResult -Workload $Workload -Checks $checks -RanUtc ([datetime]::UtcNow) -RanBy $ranBy `
            -ToolVersion $toolVersion -TenantId $TenantId -EngineIdentity "$($engine.displayName) ($($engine.objectId))" -EngineObjectId "$($engine.objectId)"

foreach ($c in $checks) {
    $col = switch ($c.status) { { $_ -in 'ok', 'fixed', 'confirmed', 'skipped' } { 'Green' } 'failed' { 'Red' } default { 'Yellow' } }
    Write-Host ("  [{0,-10}] {1}{2}" -f $c.status, $c.name, $(if (-not $c.required) { ' (optional)' })) -ForegroundColor $col
    if ($c.detail) { Note "   $($c.detail)" }
    if ($c.manualStep) { Write-Host "      TO DO: $($c.manualStep)" -ForegroundColor Yellow; Write-Host "      Learn: $($c.learn)" -ForegroundColor DarkYellow }
}
$stateCol = switch ($result.state) { 'ok' { 'Green' } 'failed' { 'Red' } default { 'Yellow' } }
Write-Host "  => $Workload prerequisites: $($result.state.ToUpperInvariant())" -ForegroundColor $stateCol

$recorded = $false
if ($cs -and $PSCmdlet.ShouldProcess("pim.Settings WorkloadPrereqs", "record the $Workload result")) {
    try {
        $cur = Get-PimSqlSetting -ConnectionString $cs -Name 'WorkloadPrereqs'
        if ($cur -is [string] -and "$cur".Trim()) { $cur = $cur | ConvertFrom-Json }
        $old = Get-PimWorkloadPrereqStoredRecord -Stored $cur -Workload $Workload
        $before = $null
        if ($old) { $before = @{ state = "$($old.state)"; ranUtc = (ConvertTo-PimWorkloadPrereqUtcText -Value $old.ranUtc) } }
        # 97.1: MERGED, not replaced -- a confirmation made in PIM Manager, or a result the engine verified, is kept where
        # this run could not decide (Merge-PimWorkloadPrereqRecord).
        $mergedRec = Merge-PimWorkloadPrereqRecord -Stored $old -Fresh $result
        $merged = Merge-PimWorkloadPrereqsSetting -Current $cur -Result $mergedRec
        Set-PimSqlSetting -ConnectionString $cs -Name 'WorkloadPrereqs' -ValueJson (ConvertTo-Json -InputObject $merged -Depth 12 -Compress)
        $back = Get-PimSqlSetting -ConnectionString $cs -Name 'WorkloadPrereqs'
        if ($back -is [string] -and "$back".Trim()) { $back = $back | ConvertFrom-Json }
        $bw = Get-PimWorkloadPrereqStoredRecord -Stored $back -Workload $Workload
        $backRan = if ($bw) { ConvertTo-PimWorkloadPrereqUtcText -Value $bw.ranUtc } else { '' }
        if (-not $bw -or "$($bw.state)" -ne $mergedRec.state -or $backRan -ne $mergedRec.ranUtc) { throw "read-back FAILED: pim.Settings WorkloadPrereqs.$Workload is '$($bw.state)' @ '$backRan', expected '$($mergedRec.state)' @ '$($mergedRec.ranUtc)'." }
        Write-PimSetupAudit -ConnectionString $cs -Action 'settings.workloadprereqs.record' -Target "WorkloadPrereqs:$Workload" -Before $before -After @{ state = $mergedRec.state; ranUtc = $mergedRec.ranUtc; failed = @($mergedRec.failed); pending = @($mergedRec.pending) }
        $recorded = $true
        Note 'recorded in pim.Settings WorkloadPrereqs (merged) and read back -- the Manager shows it on the template cards and Coverage & gaps.'
        if ($mergedRec.state -ne $result.state) { Note "recorded state: $($mergedRec.state) (kept from earlier: confirmations / results this run could not decide)" }
        $result = $mergedRec
    } catch {
        if ($mode -eq 'certificate') { throw }
        Write-Warning "not recorded in the store ($($_.Exception.Message)). Press Check again on the prerequisite in PIM Manager -- PIM checks it itself."
    }
}
if (-not $recorded -and -not $WhatIfPreference) { Note 'Next: press Check again on this prerequisite in PIM Manager -- PIM checks it itself and records the result.' }
if ($result.state -eq 'failed') { exit 1 }
if ($result.state -ne 'ok') { exit 2 }
exit 0
