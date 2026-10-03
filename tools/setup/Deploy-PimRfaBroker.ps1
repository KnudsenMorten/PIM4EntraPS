#Requires -Version 5.1
<#
.SYNOPSIS
  §82 P4 -- deploy the PUBLIC RFA broker (Pro): its store, its network, its Container Apps environment and app, the
  rights, Easy Auth. REQUIREMENTS §82.6 (Shared / Island placement), §90.

.DESCRIPTION
  PLAN ONLY unless -Apply: prints every step (Get-PimRfaBrokerDeployPlan, offline-tested). With -Apply each step runs
  through az with an explicit --subscription; every step is idempotent (create-or-skip) and the run stops at the first
  failure. Use an isolated AZURE_CONFIG_DIR signed in for the PIM tenant -- never the machine's default context.

  Cost (West Europe, 2026-10): the public environment's load balancer ~125 kr./month when no public environment can be
  shared; the app scales to zero (cold start ~10-20 s; -MinReplicas 1 keeps one warm: ~50-80 kr./month); storage
  tables cost cents. Check the price before -Apply.

  FOLLOW-UP STEPS (2026-10-03): with -Apply, the three steps after the app run THEMSELVES when their inputs are given:
    api audience   -TenantId                                  -> Set-PimRfaBrokerApiAuth.ps1 -Apply (-ApiAppDisplayName)
    mail           -TenantId + -AdminAppId + -AdminCertThumbprint -> Initialize-PimMailSender.ps1 for the broker's identity
                   (Exchange RBAC needs an application identity; signed-in, it stays a printed NEXT step)
    settings       -SqlServerFqdn (+ -AdminAppId/-AdminCertThumbprint, or -UseSignedInAccount) -> pim.Settings RfaSettings
                   (store + portal URL, the API app ids kept) and the feature gates rfa.portal + api.broker switched ON
  A missing input prints that step's NEXT command, exactly as before.

.EXAMPLE
  .\Deploy-PimRfaBroker.ps1 -SubscriptionId <pim sub> -ResourceGroup rg-automateit-x -VnetName vnet-pim -SubnetPrefix 10.20.8.0/27 `
     -PimSubnetPrefixes 10.20.0.0/23 -StorageAccountName strfax01 -Image acrx.azurecr.io/pim-manager:2.4.478 -AcrName acrx `
     -SenderMailbox pim-noreply@contoso.com -EngineIdentityPrincipalIds <tick MI principal id>          # plan only
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
    [ValidateSet('Shared', 'Island')][string]$Placement = 'Shared',
    [string]$RfaSubscriptionId = '', [string]$RfaResourceGroup = '', [string]$Location = 'westeurope',
    [string]$VnetName = '', [string]$SubnetName = 'snet-pim-rfa', [string]$SubnetPrefix = '',
    [string[]]$PimSubnetPrefixes = @(),
    [Parameter(Mandatory)][string]$StorageAccountName,
    [string]$EnvironmentName = 'cae-pim-rfa', [string]$AppName = 'ca-pim-rfa',
    [Parameter(Mandatory)][string]$Image, [string]$AcrName = '',
    [Parameter(Mandatory)][string]$SenderMailbox, [string]$TenantName = '',
    [Parameter(Mandatory)][string[]]$EngineIdentityPrincipalIds,
    [string[]]$ApiAllowedIps = @(), [int]$MinReplicas = 0, [string]$ExistingEnvironmentName = '',
    # --- the follow-up steps (see FOLLOW-UP STEPS) ---
    [string]$TenantId = '', [string]$ApiAppDisplayName = 'PIM access request API', [string]$AzureConfigDir = '',
    [string]$AdminAppId = '', [string]$AdminCertThumbprint = '', [switch]$UseSignedInAccount,
    [string]$SqlServerFqdn = '', [string]$SqlDatabase = 'PimPlatform',
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimRfaBrokerPlan.ps1')
$plan = Get-PimRfaBrokerDeployPlan -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Placement $Placement -RfaSubscriptionId $RfaSubscriptionId `
    -RfaResourceGroup $RfaResourceGroup -Location $Location -VnetName $VnetName -SubnetName $SubnetName -SubnetPrefix $SubnetPrefix -PimSubnetPrefixes $PimSubnetPrefixes `
    -StorageAccountName $StorageAccountName -EnvironmentName $EnvironmentName -AppName $AppName -Image $Image -AcrName $AcrName -SenderMailbox $SenderMailbox `
    -TenantName $TenantName -EngineIdentityPrincipalIds $EngineIdentityPrincipalIds -ApiAllowedIps $ApiAllowedIps -MinReplicas $MinReplicas -ExistingEnvironmentName $ExistingEnvironmentName
if (-not $plan.ok) { throw "REFUSED: $($plan.reason)" }
Write-Host "RFA broker deploy -- placement $($plan.placement)$(if (-not $Apply) { ' -- PLAN ONLY (add -Apply to run)' })" -ForegroundColor Cyan
$i = 0; foreach ($s in $plan.steps) { $i++; Write-Host ("  {0,2}. [{1}] {2}" -f $i, $s.id, $s.what) }
if (-not $Apply) { return }

function Invoke-Az {
    # az with an explicit subscription; returns parsed JSON (or $null), throws with az's own message on failure.
    param([Parameter(Mandatory)][string]$Sub, [Parameter(Mandatory)][string[]]$AzArgs, [switch]$AllowNotFound)
    $out = & az @AzArgs --subscription $Sub -o json 2>&1
    if ($LASTEXITCODE -ne 0) {
        $txt = (@($out) | ForEach-Object { "$_" }) -join ' '
        if ($AllowNotFound -and $txt -match '(?i)not ?found|ResourceNotFound|could not be found') { return $null }
        throw "az $($AzArgs[0..2] -join ' ') failed: $txt"
    }
    # stdout only: az writes warnings (e.g. the 32-bit cryptography notice) to stderr, which 2>&1 mixes in as ErrorRecords
    # -- parsed as part of the JSON they made every result $null (found deploying internal, 2026-10-02)
    $j = (@($out) | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" }) -join "`n"
    if ("$j".Trim()) { try { return ($j | ConvertFrom-Json) } catch { return $null } }
    return $null
}

$appPrincipal = $null; $storageId = $null; $appFqdn = ''
$followUps = New-Object System.Collections.Generic.List[string]
foreach ($s in $plan.steps) {
    Write-Host "== [$($s.id)] $($s.what)" -ForegroundColor Cyan
    $a = $s.args
    switch -Wildcard ($s.id) {
        'rg' { [void](Invoke-Az -Sub $s.sub -AzArgs @('group', 'create', '-n', $a.name, '-l', $a.location)) }
        'storage' {
            $st = Invoke-Az -Sub $s.sub -AzArgs @('storage', 'account', 'show', '-g', $s.rg, '-n', $a.name) -AllowNotFound
            if (-not $st) { $st = Invoke-Az -Sub $s.sub -AzArgs @('storage', 'account', 'create', '-g', $s.rg, '-n', $a.name, '-l', $a.location, '--sku', 'Standard_LRS', '--kind', 'StorageV2', '--allow-shared-key-access', 'false', '--min-tls-version', $a.minTls, '--allow-blob-public-access', 'false', '--https-only', 'true') }
            if ("$($st.allowSharedKeyAccess)" -ne 'False' -and "$($st.allowSharedKeyAccess)" -ne 'false') { [void](Invoke-Az -Sub $s.sub -AzArgs @('storage', 'account', 'update', '-g', $s.rg, '-n', $a.name, '--allow-shared-key-access', 'false')) }
            $storageId = "$($st.id)"
        }
        'tables' { foreach ($t in $a.tables) { [void](Invoke-Az -Sub $s.sub -AzArgs @('storage', 'table', 'create', '--account-name', $a.account, '--auth-mode', 'login', '-n', $t)) } }
        'vnet' {
            if (-not (Invoke-Az -Sub $s.sub -AzArgs @('network', 'vnet', 'show', '-g', $s.rg, '-n', $a.name) -AllowNotFound)) { [void](Invoke-Az -Sub $s.sub -AzArgs @('network', 'vnet', 'create', '-g', $s.rg, '-n', $a.name, '-l', $a.location, '--address-prefixes', $a.prefix)) }
        }
        'nsg' {
            if (-not (Invoke-Az -Sub $s.sub -AzArgs @('network', 'nsg', 'show', '-g', $s.rg, '-n', $a.name) -AllowNotFound)) { [void](Invoke-Az -Sub $s.sub -AzArgs @('network', 'nsg', 'create', '-g', $s.rg, '-n', $a.name, '-l', $a.location)) }
            $prio = 100
            foreach ($d in @($a.denyTo)) {
                [void](Invoke-Az -Sub $s.sub -AzArgs @('network', 'nsg', 'rule', 'create', '-g', $s.rg, '--nsg-name', $a.name, '-n', "deny-pim-$prio", '--priority', "$prio", '--direction', 'Outbound', '--access', 'Deny', '--protocol', '*', '--destination-address-prefixes', $d, '--destination-port-ranges', '*'))
                $prio++
            }
        }
        'subnet' {
            $sn = Invoke-Az -Sub $s.sub -AzArgs @('network', 'vnet', 'subnet', 'show', '-g', $s.rg, '--vnet-name', $a.vnet, '-n', $a.name) -AllowNotFound
            if (-not $sn) { [void](Invoke-Az -Sub $s.sub -AzArgs @('network', 'vnet', 'subnet', 'create', '-g', $s.rg, '--vnet-name', $a.vnet, '-n', $a.name, '--address-prefixes', $a.prefix, '--network-security-group', $a.nsg, '--delegations', $a.delegation)) }
        }
        'env' {
            if (-not (Invoke-Az -Sub $s.sub -AzArgs @('containerapp', 'env', 'show', '-g', $s.rg, '-n', $a.name) -AllowNotFound)) {
                $snId = "$((Invoke-Az -Sub $s.sub -AzArgs @('network', 'vnet', 'subnet', 'show', '-g', $s.rg, '--vnet-name', $a.vnet, '-n', $a.subnet)).id)"
                [void](Invoke-Az -Sub $s.sub -AzArgs @('containerapp', 'env', 'create', '-g', $s.rg, '-n', $a.name, '-l', $a.location, '--infrastructure-subnet-resource-id', $snId, '--internal-only', 'false'))
            }
        }
        'env-existing' {
            $ev = Invoke-Az -Sub $s.sub -AzArgs @('containerapp', 'env', 'show', '-g', $s.rg, '-n', $a.name)
            if ("$($ev.properties.vnetConfiguration.internal)" -match '^(?i)true$') { throw "the environment '$($a.name)' is INTERNAL -- the broker must be reachable from the internet; deploy it in its own public environment (omit -ExistingEnvironmentName)" }
        }
        'app' {
            $app = Invoke-Az -Sub $s.sub -AzArgs @('containerapp', 'show', '-g', $s.rg, '-n', $a.name) -AllowNotFound
            $envVars = @($a.envVars.Keys | ForEach-Object { "$_=$($a.envVars[$_])" })
            if (-not $app) {
                $cargs = @('containerapp', 'create', '-g', $s.rg, '-n', $a.name, '--environment', $a.environment, '--image', $a.image, '--system-assigned', '--ingress', 'external', '--target-port', "$($a.targetPort)",
                           '--min-replicas', "$($a.minReplicas)", '--max-replicas', "$($a.maxReplicas)", '--cpu', '0.25', '--memory', '0.5Gi', '--command') + @($a.command[0]) + @('--args') + @($a.command[1..($a.command.Count - 1)]) + @('--env-vars') + $envVars
                if ("$($a.acr)".Trim()) { $cargs += @('--registry-server', "$($a.acr).azurecr.io", '--registry-identity', 'system') }
                $app = Invoke-Az -Sub $s.sub -AzArgs $cargs
            }
            $appPrincipal = "$($app.identity.principalId)"
            $appFqdn = "$($app.properties.configuration.ingress.fqdn)"
            Write-Host "   app identity: $appPrincipal   url: https://$($app.properties.configuration.ingress.fqdn)" -ForegroundColor DarkGray
        }
        'role-*' {
            $principal = if ($a.principal -eq 'app') { $appPrincipal } else { $a.principal }
            if (-not $principal) { throw 'the app identity is unknown (the app step did not run)' }
            if (-not $storageId) { $storageId = "$((Invoke-Az -Sub $plan.steps[0].sub -AzArgs @('storage', 'account', 'show', '-g', $s.rg, '-n', $StorageAccountName)).id)" }
            $have = @(Invoke-Az -Sub $s.sub -AzArgs @('role', 'assignment', 'list', '--assignee', $principal, '--scope', $storageId))
            if (-not @($have | Where-Object { "$($_.roleDefinitionName)" -eq $a.role }).Count) {
                [void](Invoke-Az -Sub $s.sub -AzArgs @('role', 'assignment', 'create', '--assignee-object-id', $principal, '--assignee-principal-type', 'ServicePrincipal', '--role', $a.role, '--scope', $storageId))
            }
        }
        'auth' {
            # Easy Auth only serves the Entra APPLICATION tokens on /api/v1 (the PIN portal and API keys work without it),
            # so a failure here is a warning with the next step, never a stopped deploy.
            try { [void](Invoke-Az -Sub $s.sub -AzArgs @('containerapp', 'auth', 'update', '-g', $s.rg, '-n', $a.app, '--unauthenticated-client-action', 'AllowAnonymous', '--enabled', 'true')) }
            catch { Write-Warning "   Easy Auth could not be switched on yet ($($_.Exception.Message)) -- Entra application tokens are refused until it is; API keys and the portal work." }
            if ("$TenantId".Trim()) {
                $aa = @{ SubscriptionId = $s.sub; ResourceGroup = $s.rg; BrokerApp = $a.app; TenantId = $TenantId; ApiAppDisplayName = $ApiAppDisplayName; Apply = $true }
                if ("$AzureConfigDir".Trim()) { $aa['AzureConfigDir'] = $AzureConfigDir }
                try { & (Join-Path $PSScriptRoot 'Set-PimRfaBrokerApiAuth.ps1') @aa | Out-Host; $followUps.Add('api audience: registered') }
                catch { Write-Warning "   the API audience could not be registered: $($_.Exception.Message)"; $followUps.Add('api audience: FAILED -- re-run Set-PimRfaBrokerApiAuth.ps1 -Apply') }
            } else {
                Write-Host "   NEXT: Set-PimRfaBrokerApiAuth.ps1 -SubscriptionId $($s.sub) -ResourceGroup $($s.rg) -BrokerApp $($a.app) -TenantId <tenant>  (registers the API audience so Entra application tokens are accepted; plans unless -Apply)" -ForegroundColor Yellow
            }
        }
        'ip' { foreach ($ip in @($a.allow)) { [void](Invoke-Az -Sub $s.sub -AzArgs @('containerapp', 'ingress', 'access-restriction', 'set', '-g', $s.rg, '-n', $a.app, '--rule-name', ("allow-" + ($ip -replace '[./]', '-')), '--ip-address', $ip, '--action', 'Allow')) } }
        'mail' {
            if ("$TenantId".Trim() -and "$AdminAppId".Trim() -and "$AdminCertThumbprint".Trim() -and $appPrincipal) {
                $mb, $dom = "$SenderMailbox".Split('@', 2)
                $ma = @{ TenantId = $TenantId; AdminAppId = $AdminAppId; AdminCertThumbprint = $AdminCertThumbprint; MailboxName = $mb; MailDomain = $dom; ManagedIdentityObjectId = @($appPrincipal) }
                try { & (Join-Path $PSScriptRoot 'Initialize-PimMailSender.ps1') @ma | Out-Host; $followUps.Add("mail: the broker sends as $SenderMailbox (Exchange-scoped)") }
                catch { Write-Warning "   the broker's send right could not be set: $($_.Exception.Message)"; $followUps.Add('mail: FAILED -- run Initialize-PimMailSender.ps1 for the broker identity') }
            } else {
                Write-Host "   NEXT: Initialize-PimMailSender.ps1 ... -ManagedIdentityObjectId $appPrincipal  (Exchange-scoped send as $SenderMailbox only; needs an admin application identity -- pass -TenantId -AdminAppId -AdminCertThumbprint to do it here)" -ForegroundColor Yellow
            }
        }
        'settings' {
            if ("$SqlServerFqdn".Trim() -and $appFqdn -and (("$AdminAppId".Trim() -and "$AdminCertThumbprint".Trim()) -or $UseSignedInAccount)) {
                try {
                    $sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
                    if ($UseSignedInAccount) { . (Join-Path $PSScriptRoot '_PimSignedIn.ps1'); Set-PimSignedInGlobals -TenantId $TenantId }
                    else { $global:PIM_TenantId = $TenantId; $global:PIM_SqlClientId = $AdminAppId; $global:PIM_SqlCertThumbprint = $AdminCertThumbprint }
                    $global:PIM_SqlServer = $SqlServerFqdn; $global:PIM_SqlDatabase = $SqlDatabase; $global:PIM_UseGraphSdk = $false
                    . (Join-Path $sol 'engine\_shared\PIM-Rest.ps1'); . (Join-Path $sol 'engine\_shared\PIM-SqlStore.ps1')
                    $cs = Get-PimSqlConnectionString
                    $rs = New-PimRfaBrokerSettingsValue -Current (Get-PimSqlSetting -ConnectionString $cs -Name 'RfaSettings') -StoreAccount $StorageAccountName -PortalUrl "https://$appFqdn"
                    Set-PimSqlSetting -ConnectionString $cs -Name 'RfaSettings' -Value $rs
                    $fg = New-PimRfaBrokerFeatureGatesValue -Current (Get-PimSqlSetting -ConnectionString $cs -Name 'FeatureGates')
                    Set-PimSqlSetting -ConnectionString $cs -Name 'FeatureGates' -Value $fg
                    $back = Get-PimSqlSetting -ConnectionString $cs -Name 'RfaSettings'
                    if ("$($back.storeAccount)" -ne $StorageAccountName) { throw 'RfaSettings did not read back' }
                    $followUps.Add("settings: RfaSettings -> $StorageAccountName + https://$appFqdn; rfa.portal + api.broker ON (read back)")
                } catch { Write-Warning "   PIM's settings could not be written: $($_.Exception.Message)"; $followUps.Add("settings: FAILED -- Manager > Settings > RFA broker & API: store '$StorageAccountName', portal URL https://$appFqdn") }
            } else {
                Write-Host "   NEXT: Manager > Settings > RFA broker & API: store '$StorageAccountName', portal URL https://$(if ($appFqdn) { $appFqdn } else { '<app fqdn>' })  (or pass -SqlServerFqdn with -AdminAppId/-AdminCertThumbprint or -UseSignedInAccount to do it here)" -ForegroundColor Yellow
            }
        }
    }
}
foreach ($f in $followUps) { Write-Host "   follow-up -- $f" -ForegroundColor $(if ($f -match 'FAILED') { 'Yellow' } else { 'Green' }) }
Write-Host 'RFA broker deployed. The engine starts publishing on its next rfa-sync run once the settings name the store.' -ForegroundColor Green
if (@($followUps | Where-Object { $_ -match 'FAILED' }).Count) { $global:LASTEXITCODE = 1; exit 1 }
