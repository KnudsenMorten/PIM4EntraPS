#Requires -Version 5.1
<#
.SYNOPSIS
  §82 P4 -- deploy the PUBLIC RFA broker (Pro): its store, its network, its Container Apps environment and app, the
  rights, Easy Auth. REQUIREMENTS §82.6 (Shared / Island placement), §90.

.DESCRIPTION
  PLAN ONLY unless -Apply: prints every step (Get-PimRfaBrokerDeployPlan, offline-tested). With -Apply each step runs
  over ARM REST (PIM-Rest's one token client: the calling run's session, else the Invardia Support app's session, else
  the person signed in in the browser -- no az, 100.41 / framework 12.17), every call naming its step's subscription in
  the path; every step is idempotent (create-or-skip) and the run stops at the first failure. Pass -TenantId to pin the
  sign-in to the PIM tenant.

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
    [string]$TenantId = '', [string]$ApiAppDisplayName = 'PIM access request API',
    [string]$AzureConfigDir = '',   # IGNORED since 100.41 (no az): kept so existing command lines still bind

    [string]$AdminAppId = '', [string]$AdminCertThumbprint = '', [switch]$UseSignedInAccount,
    [string]$SqlServerFqdn = '', [string]$SqlDatabase = 'PimPlatform',
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
if ("$AzureConfigDir".Trim()) { Write-Host '  -AzureConfigDir is ignored: this script no longer uses the az CLI (100.41) -- it signs in through PIM-Rest.' -ForegroundColor DarkYellow }
. (Join-Path $PSScriptRoot '_PimRfaBrokerPlan.ps1')
$plan = Get-PimRfaBrokerDeployPlan -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Placement $Placement -RfaSubscriptionId $RfaSubscriptionId `
    -RfaResourceGroup $RfaResourceGroup -Location $Location -VnetName $VnetName -SubnetName $SubnetName -SubnetPrefix $SubnetPrefix -PimSubnetPrefixes $PimSubnetPrefixes `
    -StorageAccountName $StorageAccountName -EnvironmentName $EnvironmentName -AppName $AppName -Image $Image -AcrName $AcrName -SenderMailbox $SenderMailbox `
    -TenantName $TenantName -EngineIdentityPrincipalIds $EngineIdentityPrincipalIds -ApiAllowedIps $ApiAllowedIps -MinReplicas $MinReplicas -ExistingEnvironmentName $ExistingEnvironmentName
if (-not $plan.ok) { throw "REFUSED: $($plan.reason)" }
Write-Host "RFA broker deploy -- placement $($plan.placement)$(if (-not $Apply) { ' -- PLAN ONLY (add -Apply to run)' })" -ForegroundColor Cyan
$i = 0; foreach ($s in $plan.steps) { $i++; Write-Host ("  {0,2}. [{1}] {2}" -f $i, $s.id, $s.what) }
if (-not $Apply) { return }

# 100.41 (framework 12.17 NO-AZ): every step is ARM REST through PIM-Rest's ONE token client (engine/_shared/PIM-ArmSetup.ps1),
# each call naming its step's subscription in the path. A calling run's REST session is used as it is; standalone, the
# Invardia Support app's session or the person signed in. No az, no default context.
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) {
    $cn = @{ SubscriptionId = $SubscriptionId }; if ("$TenantId".Trim()) { $cn.TenantId = $TenantId }
    [void](Connect-PimSetupRest @cn)
}
$net = Get-PimSetupApiVersion network
function Get-RfaArm([string]$Id, [string]$Kind = 'network') { Invoke-PimSetupArm -Path $Id -ApiVersion (Get-PimSetupApiVersion $Kind) -NotFoundOk }
function Set-RfaArm([string]$Id, $Body, [string]$Kind = 'network') {
    # PUT then wait: a create that returns as soon as ARM accepts it is not done (BUG-44)
    $v = Get-PimSetupApiVersion $Kind
    [void](Invoke-PimSetupArm -Method PUT -Path $Id -Body $Body -ApiVersion $v)
    $st = Wait-PimArmProvisioned -Path $Id -ApiVersion $v
    if ($st -match '(?i)^(Failed|Canceled|NotFound|TimedOut)') { throw "$(($Id -split '/')[-1]) did not provision ($st)" }
    Invoke-PimSetupArm -Path $Id -ApiVersion $v
}

$appPrincipal = $null; $storageId = $null; $appFqdn = ''
$followUps = New-Object System.Collections.Generic.List[string]
foreach ($s in $plan.steps) {
    Write-Host "== [$($s.id)] $($s.what)" -ForegroundColor Cyan
    $a = $s.args
    switch -Wildcard ($s.id) {
        'rg' { [void](Set-PimArmResourceGroup -SubscriptionId $s.sub -Name $a.name -Location $a.location) }
        'storage' {
            $st = Get-PimArmStorageAccount -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.name
            if (-not $st) { $st = New-PimArmStorageAccount -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.name -Location $a.location -Sku Standard_LRS -Kind StorageV2 -AllowBlobPublicAccess $false }
            # az storage account create --allow-shared-key-access false --min-tls-version T --https-only true: ARM's create
            # above sets TLS 1.2 + https-only; shared-key access (and a different TLS floor) is a PATCH of just those.
            $fix = @{}
            if ("$($st.properties.allowSharedKeyAccess)" -notmatch '^(?i)false$') { $fix.allowSharedKeyAccess = $false }
            if ("$($a.minTls)".Trim() -and "$($st.properties.minimumTlsVersion)" -ne "$($a.minTls)") { $fix.minimumTlsVersion = "$($a.minTls)" }
            if ($fix.Count) { [void](Update-PimArmStorageAccount -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.name -Properties $fix) }
            $storageId = "$($st.id)"
        }
        'tables' {
            # az storage table create --auth-mode login: the CONTROL-plane table PUT (idempotent; no data role, no network rule needed)
            foreach ($t in $a.tables) {
                [void](Invoke-PimSetupArm -Method PUT -Path (Get-PimArmResourceId $s.sub $s.rg 'Microsoft.Storage/storageAccounts' $a.account "tableServices/default/tables/$t") -Body @{ properties = @{} } -ApiVersion (Get-PimSetupApiVersion storage))
            }
        }
        'vnet' {
            if (-not (Get-PimArmVnet -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.name)) { [void](New-PimArmVnet -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.name -Location $a.location -AddressPrefixes @($a.prefix)) }
        }
        'nsg' {
            $nsgId = Get-PimArmResourceId $s.sub $s.rg 'Microsoft.Network/networkSecurityGroups' $a.name
            if (-not (Get-RfaArm $nsgId)) { [void](Set-RfaArm $nsgId @{ location = $a.location; properties = @{} }) }
            $prio = 100
            foreach ($d in @($a.denyTo)) {
                # az network nsg rule create deny-pim-<prio> (PUT by name: a re-run rewrites the same rule)
                [void](Set-RfaArm "$nsgId/securityRules/deny-pim-$prio" @{ properties = @{ priority = $prio; direction = 'Outbound'; access = 'Deny'; protocol = '*'
                    sourceAddressPrefix = '*'; sourcePortRange = '*'; destinationAddressPrefix = "$d"; destinationPortRange = '*' } })
                $prio++
            }
        }
        'subnet' {
            $snId = Get-PimArmResourceId $s.sub $s.rg 'Microsoft.Network/virtualNetworks' $a.vnet "subnets/$($a.name)"
            if (-not (Get-RfaArm $snId)) {
                [void](Set-RfaArm $snId @{ properties = @{ addressPrefix = $a.prefix
                    networkSecurityGroup = @{ id = (Get-PimArmResourceId $s.sub $s.rg 'Microsoft.Network/networkSecurityGroups' $a.nsg) }
                    delegations = @(@{ name = 'delegation'; properties = @{ serviceName = $a.delegation } }) } })
            }
        }
        'env' {
            if (-not (Get-PimArmAcaEnv -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.name)) {
                $sn = Get-PimArmSubnet -SubscriptionId $s.sub -ResourceGroup $s.rg -VnetName $a.vnet -Name $a.subnet
                if (-not $sn) { throw "subnet $($a.vnet)/$($a.subnet) not found" }
                # What `az containerapp env create` did client-side when no workspace was named: create one beside the
                # environment ("workspace-<rg><random>") and log there. ARM itself will not -- it needs a workspace.
                $genLaw = ('workspace-' + (($s.rg -replace '[^A-Za-z0-9-]', '').ToLowerInvariant()) + ([guid]::NewGuid().ToString('N').Substring(0, 4)))
                if ($genLaw.Length -gt 63) { $genLaw = $genLaw.Substring(0, 59) + $genLaw.Substring($genLaw.Length - 4) }
                $gen = New-PimArmLogAnalytics -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $genLaw -Location $a.location
                $lawKey = Get-PimArmLogAnalyticsKey -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $genLaw
                [void](Set-PimArmAcaEnv -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.name -Create -Location $a.location -Properties @{
                    vnetConfiguration    = @{ infrastructureSubnetId = "$($sn.id)"; internal = $false }
                    workloadProfiles     = @(@{ name = 'Consumption'; workloadProfileType = 'Consumption' })
                    appLogsConfiguration = @{ destination = 'log-analytics'; logAnalyticsConfiguration = @{ customerId = "$($gen.properties.customerId)".Trim(); sharedKey = "$lawKey".Trim() } } })
            }
        }
        'env-existing' {
            $ev = Get-PimArmAcaEnv -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.name
            if (-not $ev) { throw "the environment '$($a.name)' was not found in $($s.rg)" }
            if ("$($ev.properties.vnetConfiguration.internal)" -match '^(?i)true$') { throw "the environment '$($a.name)' is INTERNAL -- the broker must be reachable from the internet; deploy it in its own public environment (omit -ExistingEnvironmentName)" }
        }
        'app' {
            $app = Get-PimArmAcaApp -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.name
            if (-not $app) {
                # az containerapp create --system-assigned --ingress external --cpu 0.25 --memory 0.5Gi --command/--args
                # --env-vars [--registry-identity system]: the app as ARM takes it, one PUT of the whole resource.
                $ev = Get-PimArmAcaEnv -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.environment
                if (-not $ev) { throw "Container Apps environment '$($a.environment)' not found in '$($s.rg)'" }
                $cfg = @{ activeRevisionsMode = 'Single'; ingress = @{ external = $true; targetPort = [int]$a.targetPort; transport = 'auto'; allowInsecure = $false } }
                if ("$($a.acr)".Trim()) { $cfg.registries = @(@{ server = "$($a.acr).azurecr.io"; identity = 'system' }) }
                $container = @{ name = $a.name; image = $a.image; resources = @{ cpu = 0.25; memory = '0.5Gi' }
                                command = @($a.command[0]); args = @($a.command[1..($a.command.Count - 1)])
                                env = @($a.envVars.Keys | ForEach-Object { @{ name = "$_"; value = "$($a.envVars[$_])" } }) }
                $props = @{ managedEnvironmentId = "$($ev.id)"; configuration = $cfg
                            template = @{ containers = @($container); scale = @{ minReplicas = [int]$a.minReplicas; maxReplicas = [int]$a.maxReplicas } } }
                if (@($ev.properties.workloadProfiles | Where-Object { $_ -and "$($_.name)" -eq 'Consumption' }).Count) { $props.workloadProfileName = 'Consumption' }
                $app = Set-PimArmAcaApp -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.name -Create -Resource @{ location = "$($ev.location)"; identity = @{ type = 'SystemAssigned' }; properties = $props }
            }
            $appPrincipal = "$($app.identity.principalId)"
            $appFqdn = "$($app.properties.configuration.ingress.fqdn)"
            Write-Host "   app identity: $appPrincipal   url: https://$($app.properties.configuration.ingress.fqdn)" -ForegroundColor DarkGray
        }
        'role-*' {
            $principal = if ($a.principal -eq 'app') { $appPrincipal } else { $a.principal }
            if (-not $principal) { throw 'the app identity is unknown (the app step did not run)' }
            if (-not $storageId) { $storageId = "$((Get-PimArmStorageAccount -SubscriptionId $plan.steps[0].sub -ResourceGroup $s.rg -Name $StorageAccountName).id)" }
            if (-not $storageId) { throw "storage account $StorageAccountName not found" }
            $have = @(Get-PimArmRoleAssignments -Scope $storageId -PrincipalId $principal -SubscriptionId $s.sub)
            if (-not @($have | Where-Object { "$($_.roleDefinitionName)" -eq $a.role }).Count) {
                [void](New-PimArmRoleAssignment -Scope $storageId -PrincipalId $principal -PrincipalType ServicePrincipal -Role $a.role -SubscriptionId $s.sub)
            }
        }
        'auth' {
            # Easy Auth only serves the Entra APPLICATION tokens on /api/v1 (the PIN portal and API keys work without it),
            # so a failure here is a warning with the next step, never a stopped deploy.
            # az containerapp auth update --unauthenticated-client-action AllowAnonymous --enabled true: authConfigs/current, read-modify-write
            try {
                [void](Set-PimArmAcaAuthConfig -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.app -Mutate {
                    param($p)
                    $pl = if ($p.PSObject.Properties['platform'] -and $p.platform) { $p.platform } else { [pscustomobject]@{} }
                    $pl | Add-Member -NotePropertyName enabled -NotePropertyValue $true -Force
                    $p | Add-Member -NotePropertyName platform -NotePropertyValue $pl -Force
                    $gv = if ($p.PSObject.Properties['globalValidation'] -and $p.globalValidation) { $p.globalValidation } else { [pscustomobject]@{} }
                    $gv | Add-Member -NotePropertyName unauthenticatedClientAction -NotePropertyValue 'AllowAnonymous' -Force
                    $p | Add-Member -NotePropertyName globalValidation -NotePropertyValue $gv -Force
                })
            }
            catch { Write-Warning "   Easy Auth could not be switched on yet ($($_.Exception.Message)) -- Entra application tokens are refused until it is; API keys and the portal work." }
            if ("$TenantId".Trim()) {
                $aa = @{ SubscriptionId = $s.sub; ResourceGroup = $s.rg; BrokerApp = $a.app; TenantId = $TenantId; ApiAppDisplayName = $ApiAppDisplayName; Apply = $true }
                try { & (Join-Path $PSScriptRoot 'Set-PimRfaBrokerApiAuth.ps1') @aa | Out-Host; $followUps.Add('api audience: registered') }
                catch { Write-Warning "   the API audience could not be registered: $($_.Exception.Message)"; $followUps.Add('api audience: FAILED -- re-run Set-PimRfaBrokerApiAuth.ps1 -Apply') }
            } else {
                Write-Host "   NEXT: Set-PimRfaBrokerApiAuth.ps1 -SubscriptionId $($s.sub) -ResourceGroup $($s.rg) -BrokerApp $($a.app) -TenantId <tenant>  (registers the API audience so Entra application tokens are accepted; plans unless -Apply)" -ForegroundColor Yellow
            }
        }
        'ip' {
            # az containerapp ingress access-restriction set --rule-name allow-<ip> --ip-address IP --action Allow (per IP):
            # one read-modify-write of the ingress; a rule of the same name is replaced, every other rule is kept.
            $allowIps = @($a.allow)
            [void](Set-PimArmAcaAppConfiguration -SubscriptionId $s.sub -ResourceGroup $s.rg -Name $a.app -Mutate {
                param($cfg)
                $ing = $cfg.ingress
                if (-not $ing) { throw "container app '$($a.app)' has no ingress" }
                $rules = @(@($ing.ipSecurityRestrictions) | Where-Object { $_ })
                foreach ($ip in $allowIps) {
                    $rn = "allow-" + ($ip -replace '[./]', '-')
                    $range = if ("$ip" -match '/') { "$ip" } else { "$ip/32" }
                    $rules = @($rules | Where-Object { "$($_.name)" -ne $rn }) + @([pscustomobject]@{ name = $rn; ipAddressRange = $range; action = 'Allow' })
                }
                $ing | Add-Member -NotePropertyName ipSecurityRestrictions -NotePropertyValue @($rules) -Force
            })
        }
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
