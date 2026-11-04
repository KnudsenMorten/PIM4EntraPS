#Requires -Version 5.1
<#
.SYNOPSIS
    The hosting-region checks every entry point runs BEFORE anything is created. THE CUSTOMER DECIDES THE REGION.

.DESCRIPTION
    REQUIREMENTS 100.62 (owner 2026-10-10, verbatim: "customer decide region") supersedes BUG-299's three-region allow-list
    and the France denial: data residency is the customer's decision. There is NO region list in this file or anywhere else.

    Two checks, both before anything is created:
      1. OFFLINE (pure): Test-PimSetupRegion -- the region NAME is a plausible Azure region name (lower-case letters and
         digits, no spaces, after normalising "Sweden Central" -> "swedencentral"). Read by _PimSetupShared.ps1
         (Assert-PimSetupRegion, Setup-PimContainers), _PimGuidedInstall.ps1 (Test-PimInstallConfig), Invoke-PimDeployAll.ps1
         and the multi-tenant build's config check (engine/msp/PIM-MspBuild.ps1).
      2. LIVE (capability preflight): does THIS subscription offer, in that region, every service PIM Manager creates --
         Container Apps managed environments + jobs, Azure SQL servers (+ the region open to the subscription and the
         Standard S0 database offered), Container Registry, Key Vault, Storage, Log Analytics, user-assigned managed
         identities? Test-PimRegionCapability is PURE (it takes the ARM answers and returns { ok; missing[]; suggestion });
         Invoke-PimRegionPreflight is the thin reader -- it makes no network call itself, the caller hands it a GET
         scriptblock over its own REST client (PIM-ArmSetup's Invoke-PimSetupArm, or the installer's Get-InstallRest).
         No az CLI, no PowerShell module.
      When something is missing the answer names EXACTLY which service(s) and suggests the nearest region (great-circle
      distance over the subscription's locations' latitude / longitude) where every service is offered and Azure SQL's
      capability is confirmed.
#>

function Test-PimSetupRegion {
    # PURE. '' when -Location is a plausible Azure region name, else the customer-language reason it is refused.
    # 100.62: syntax only -- WHICH region is the customer's choice; whether it has every service is the live preflight.
    param([AllowEmptyString()][string]$Location)
    $norm = ConvertTo-PimRegionKey $Location
    if (-not $norm) { return 'no Azure region was given -- choose the Azure region PIM Manager is installed in (for example swedencentral).' }
    if ($norm -notmatch '^[a-z][a-z0-9]{2,39}$') {
        return "'$Location' is not an Azure region name -- use the region's name, lower-case letters and digits (for example swedencentral or westeurope)."
    }
    return ''
}

function ConvertTo-PimRegionKey {
    # PURE. "Sweden Central" / "swedencentral" / " SwedenCentral " -> "swedencentral" (no lookup).
    param([AllowEmptyString()][AllowNull()][string]$Name)
    return ("$Name" -replace '\s', '').ToLowerInvariant()
}

function Get-PimRegionRequiredServices {
    # PURE. Every resource type PIM Manager creates in its hosting region (New-PimHostingPrerequisites + Setup-PimContainers).
    param([switch]$NoSql)
    $all = @(
        [pscustomobject]@{ Namespace = 'Microsoft.App';                 ResourceType = 'managedEnvironments';    Label = 'Azure Container Apps environments' }
        [pscustomobject]@{ Namespace = 'Microsoft.App';                 ResourceType = 'jobs';                   Label = 'Azure Container Apps jobs' }
        [pscustomobject]@{ Namespace = 'Microsoft.Sql';                 ResourceType = 'servers';                Label = 'Azure SQL Database servers' }
        [pscustomobject]@{ Namespace = 'Microsoft.ContainerRegistry';   ResourceType = 'registries';             Label = 'Azure Container Registry' }
        [pscustomobject]@{ Namespace = 'Microsoft.KeyVault';            ResourceType = 'vaults';                 Label = 'Azure Key Vault' }
        [pscustomobject]@{ Namespace = 'Microsoft.Storage';             ResourceType = 'storageAccounts';        Label = 'Azure Storage accounts' }
        [pscustomobject]@{ Namespace = 'Microsoft.OperationalInsights'; ResourceType = 'workspaces';             Label = 'Log Analytics workspaces' }
        [pscustomobject]@{ Namespace = 'Microsoft.ManagedIdentity';     ResourceType = 'userAssignedIdentities'; Label = 'user-assigned managed identities' }
    )
    if ($NoSql) { return @($all | Where-Object { $_.Namespace -ne 'Microsoft.Sql' }) }
    return $all
}

function Get-PimRegionLocationList {
    # PURE. The locations answer (GET /subscriptions/{sub}/locations: { value: [...] } or the array itself) -> its entries.
    param([object]$Locations)
    if ($null -eq $Locations) { return @() }
    if ($Locations.PSObject.Properties['value']) { return @($Locations.value | Where-Object { $_ }) }
    return @($Locations | Where-Object { $_ })
}

function Get-PimRegionNameMap {
    # PURE. normalised name / displayName / regionalDisplayName -> the region's name, from the subscription's locations list.
    param([object]$Locations)
    $m = @{}
    foreach ($l in @(Get-PimRegionLocationList $Locations)) {
        $n = ConvertTo-PimRegionKey "$($l.name)"
        if (-not $n) { continue }
        foreach ($cand in @("$($l.regionalDisplayName)", "$($l.displayName)", "$($l.name)")) { if ($cand) { $m[(ConvertTo-PimRegionKey $cand)] = $n } }
    }
    return $m
}

function ConvertTo-PimRegionName {
    # PURE. A region's display name ("Sweden Central") or name ("swedencentral") -> its name, using the subscription's
    # locations list (name / displayName / regionalDisplayName; or a prepared -Map). Not in the list -> the normalised key.
    param([AllowEmptyString()][AllowNull()][string]$Name, [object]$Locations, [hashtable]$Map)
    $k = ConvertTo-PimRegionKey $Name
    if (-not $k) { return '' }
    if ($null -eq $Map) { $Map = Get-PimRegionNameMap $Locations }
    if ($Map.ContainsKey($k)) { return $Map[$k] }
    return $k
}

function Get-PimRegionDisplayName {
    # PURE. "swedencentral" -> "Sweden Central" (from the locations list), else the name itself.
    param([string]$Name, [object]$Locations)
    $l = @(Get-PimRegionLocationList $Locations | Where-Object { (ConvertTo-PimRegionKey "$($_.name)") -eq (ConvertTo-PimRegionKey $Name) }) | Select-Object -First 1
    if ($l -and "$($l.displayName)") { return "$($l.displayName)" }
    return $Name
}

function Get-PimRegionDistanceKm {
    # PURE. Great-circle (haversine) distance in km between two latitude / longitude points (degrees).
    param([double]$Lat1, [double]$Lon1, [double]$Lat2, [double]$Lon2)
    $r = [Math]::PI / 180
    $dLat = ($Lat2 - $Lat1) * $r; $dLon = ($Lon2 - $Lon1) * $r
    $a = [Math]::Sin($dLat / 2) * [Math]::Sin($dLat / 2) + [Math]::Cos($Lat1 * $r) * [Math]::Cos($Lat2 * $r) * [Math]::Sin($dLon / 2) * [Math]::Sin($dLon / 2)
    return (2 * 6371.0 * [Math]::Atan2([Math]::Sqrt($a), [Math]::Sqrt(1 - $a)))
}

function Get-PimRegionProvider {
    # PURE. The provider answer for -Namespace out of -Providers (a hashtable namespace -> answer, or an array of answers).
    param([object]$Providers, [string]$Namespace)
    if ($null -eq $Providers) { return $null }
    if ($Providers -is [System.Collections.IDictionary]) {
        foreach ($k in @($Providers.Keys)) { if ("$k" -ieq $Namespace) { return $Providers[$k] } }
        return $null
    }
    return (@($Providers | Where-Object { $_ -and "$($_.namespace)" -ieq $Namespace }) | Select-Object -First 1)
}

function Get-PimRegionTypeLocations {
    # PURE. The region NAMES a provider offers -ResourceType in ($null when the provider answer or the type is absent).
    param([object]$Provider, [string]$ResourceType, [object]$Locations)
    if ($null -eq $Provider) { return $null }
    $t = @(@($Provider.resourceTypes) | Where-Object { $_ -and "$($_.resourceType)" -ieq $ResourceType }) | Select-Object -First 1
    if ($null -eq $t) { return $null }
    $map = Get-PimRegionNameMap $Locations
    # the unary comma keeps an EMPTY (or one-element) list a list: "offered nowhere" must not read as $null ("not read")
    return , @(@($t.locations) | Where-Object { "$_".Trim() } | ForEach-Object { ConvertTo-PimRegionName -Name "$_" -Map $map })
}

function Test-PimSqlRegionCapability {
    # PURE. '' when Azure SQL's capabilities answer (GET .../Microsoft.Sql/locations/{loc}/capabilities) says the region is
    # open to this subscription (status Available / Default) AND offers the Standard edition with the S0 objective, else the
    # missing piece in customer language. $null capabilities -> '?' (not read).
    param([object]$Capabilities, [string]$Location)
    if ($null -eq $Capabilities) { return '?' }
    $st = "$($Capabilities.status)"
    if ($st -notin @('Available', 'Default')) { return "Azure SQL Database (not open to this subscription in $Location -- status '$(if ($st) { $st } else { 'unknown' })')" }
    $s0 = $false
    foreach ($ver in @($Capabilities.supportedServerVersions)) {
        if (-not $ver -or "$($ver.status)" -eq 'Disabled') { continue }
        foreach ($ed in @($ver.supportedEditions)) {
            if (-not $ed -or "$($ed.name)" -ne 'Standard' -or "$($ed.status)" -eq 'Disabled') { continue }
            foreach ($slo in @($ed.supportedServiceLevelObjectives)) {
                if ($slo -and "$($slo.name)" -eq 'S0' -and "$($slo.status)" -ne 'Disabled') { $s0 = $true }
            }
        }
    }
    if (-not $s0) { return "Azure SQL Database Standard S0 (not offered in $Location)" }
    return ''
}

function Get-PimSqlNotRegisteredText {
    # PURE. BUG-300: the ONE customer sentence for "Azure SQL's capabilities cannot be read because the provider is not
    # registered yet" (the preflight message and the deploy's region line; tests assert it verbatim).
    return 'Microsoft.Sql is not registered yet -- setup registers it in the prerequisites step; the region check for SQL runs then.'
}

function Test-PimRegionProviderUnregistered {
    # PURE. BUG-300: $true when a provider answer (GET /subscriptions/{sub}/providers/{ns}) says it is NOT registered
    # (NotRegistered / Registering / Unregistered / Unregistering). An absent answer, or one without registrationState, is
    # $false: "could not read" stays unknown -- only a provider ARM itself reports as unregistered defers the check.
    param([object]$Provider)
    if ($null -eq $Provider) { return $false }
    $st = if ($Provider -is [System.Collections.IDictionary]) { "$($Provider['registrationState'])" } elseif ($Provider.PSObject.Properties['registrationState']) { "$($Provider.registrationState)" } else { '' }
    $st = $st.Trim()
    return [bool]($st -and $st -ne 'Registered')
}

function Test-PimSqlRegionAfterRegistration {
    <#
      PURE. BUG-300 -- the SQL half of the region check, run by the prerequisites step right AFTER it registered Microsoft.Sql
      and BEFORE it creates anything. -> { state = ok | failed | warning; message }.
        failed  : the capabilities answer says the region is closed to this subscription or has no Standard S0 (stop: nothing
                  has been created yet, choose another region)
        warning : the answer still cannot be read (the SQL server creation reports a refused region by name)
    #>
    param([object]$Capabilities, [Parameter(Mandatory)][string]$Location)
    $sq = Test-PimSqlRegionCapability -Capabilities $Capabilities -Location $Location
    if ($sq -eq '?') { return [pscustomobject]@{ state = 'warning'; message = "Microsoft.Sql is registered now, but Azure SQL's capabilities in $Location still cannot be read -- creating the SQL server will tell if the region refuses it" } }
    if ($sq) { return [pscustomobject]@{ state = 'failed'; message = "Azure SQL is not available for this subscription in $Location -- $sq. Nothing has been created yet: choose another region and run the installation again." } }
    return [pscustomobject]@{ state = 'ok'; message = "Azure SQL Database (Standard S0) is offered in $Location (checked after Microsoft.Sql was registered)" }
}

function Get-PimRegionCandidateOrder {
    # PURE. The regions (names) other than -Location where EVERY required resource type is offered, nearest first
    # (great-circle over the locations' latitude / longitude). Regions without coordinates, and canary / staging regions,
    # are never suggested. -Location without coordinates -> the same set in name order.
    param([string]$Location, [object]$Providers, [object]$Locations, [switch]$NoSql)
    $locs = @(Get-PimRegionLocationList $Locations)
    $me = ConvertTo-PimRegionName -Name $Location -Locations $Locations
    $sets = New-Object System.Collections.Generic.List[object]
    foreach ($svc in @(Get-PimRegionRequiredServices -NoSql:$NoSql)) {
        $tl = Get-PimRegionTypeLocations -Provider (Get-PimRegionProvider -Providers $Providers -Namespace $svc.Namespace) -ResourceType $svc.ResourceType -Locations $Locations
        if ($null -eq $tl) { return @() }       # a service's offer is unknown -> no suggestion can be proven
        $sets.Add([string[]]@($tl))
    }
    $here = @($locs | Where-Object { (ConvertTo-PimRegionKey "$($_.name)") -eq $me }) | Select-Object -First 1
    $hasXY = { param($l) "$($l.metadata.latitude)".Trim() -and "$($l.metadata.longitude)".Trim() }
    $out = foreach ($l in $locs) {
        $n = ConvertTo-PimRegionKey "$($l.name)"
        if (-not $n -or $n -eq $me -or $n -match '(euap|stage|stg)$') { continue }
        if ("$($l.metadata.regionType)" -and "$($l.metadata.regionType)" -ne 'Physical') { continue }
        if (-not (& $hasXY $l)) { continue }
        $all = $true
        foreach ($s in $sets) { if ($n -notin $s) { $all = $false; break } }
        if (-not $all) { continue }
        $d = if ($here -and (& $hasXY $here)) {
            Get-PimRegionDistanceKm -Lat1 ([double]"$($here.metadata.latitude)") -Lon1 ([double]"$($here.metadata.longitude)") -Lat2 ([double]"$($l.metadata.latitude)") -Lon2 ([double]"$($l.metadata.longitude)")
        } else { 0 }
        [pscustomobject]@{ name = $n; km = $d }
    }
    return @(@($out) | Sort-Object km, name | ForEach-Object { $_.name })
}

function Test-PimRegionCapability {
    <#
      PURE. Can PIM Manager be hosted in -Location for this subscription?
        -Providers                 : the provider answers (hashtable namespace -> GET /subscriptions/{sub}/providers/{ns}, or array)
        -Locations                 : GET /subscriptions/{sub}/locations (gives names, display names, latitude / longitude)
        -SqlCapabilities           : GET .../Microsoft.Sql/locations/{loc}/capabilities for -Location
        -CandidateSqlCapabilities  : hashtable region -> the same answer for suggested regions (a suggestion needs SQL confirmed)
        -NoSql                     : the environment uses a central store (no SQL server in this region)
      -> { ok; location; displayName; missing[] (customer-language service names); unknown[] (answers not read);
           deferred[] (checks that run later -- BUG-300: Azure SQL's capabilities while Microsoft.Sql is not registered yet);
           suggestion (region name or ''); suggestionDisplayName; candidates[]; message }
      ok = nothing is missing. An answer that could not be read is listed in unknown[], never as missing (the caller warns).
      A deferred check is NOT a warning: the prerequisites step registers the provider and runs it before anything is created.
    #>
    param(
        [AllowEmptyString()][string]$Location,
        [object]$Providers,
        [object]$Locations,
        [object]$SqlCapabilities,
        [hashtable]$CandidateSqlCapabilities = @{},
        [switch]$NoSql
    )
    $name = ConvertTo-PimRegionName -Name $Location -Locations $Locations
    $missing = New-Object System.Collections.Generic.List[string]
    $unknown = New-Object System.Collections.Generic.List[string]
    $locs = @(Get-PimRegionLocationList $Locations)
    if (-not $locs.Count) { $unknown.Add('the subscription''s Azure regions') }
    elseif (-not @($locs | Where-Object { (ConvertTo-PimRegionKey "$($_.name)") -eq $name }).Count) {
        $missing.Add("the region itself (this subscription does not offer '$Location')")
    }
    foreach ($svc in @(Get-PimRegionRequiredServices -NoSql:$NoSql)) {
        $tl = Get-PimRegionTypeLocations -Provider (Get-PimRegionProvider -Providers $Providers -Namespace $svc.Namespace) -ResourceType $svc.ResourceType -Locations $Locations
        if ($null -eq $tl) { $unknown.Add($svc.Label); continue }
        if ($name -notin @($tl)) { $missing.Add($svc.Label) }
    }
    # BUG-300: ARM refuses Microsoft.Sql/locations/{loc}/capabilities while the Microsoft.Sql provider is not registered --
    # on a FRESH subscription that is every first install, and the unread answer read as a scary "could not check". When the
    # provider answer says it is not registered (yet), the SQL capability check is DEFERRED to the prerequisites step (which
    # registers the provider and checks SQL again before it creates anything) -- never listed as unknown.
    $deferred = New-Object System.Collections.Generic.List[string]
    if (-not $NoSql) {
        $sq = Test-PimSqlRegionCapability -Capabilities $SqlCapabilities -Location $name
        if ($sq -eq '?') {
            if (Test-PimRegionProviderUnregistered -Provider (Get-PimRegionProvider -Providers $Providers -Namespace 'Microsoft.Sql')) { $deferred.Add((Get-PimSqlNotRegisteredText)) }
            else { $unknown.Add('Azure SQL Database capabilities') }
        }
        elseif ($sq -and -not ($missing -contains 'Azure SQL Database servers')) { $missing.Add($sq) }
    }
    $candidates = @()
    $suggestion = ''
    if ($missing.Count) {
        $candidates = @(Get-PimRegionCandidateOrder -Location $name -Providers $Providers -Locations $Locations -NoSql:$NoSql)
        foreach ($c in $candidates) {
            if ($NoSql) { $suggestion = $c; break }
            $cc = $null; foreach ($k in @($CandidateSqlCapabilities.Keys)) { if ((ConvertTo-PimRegionKey "$k") -eq $c) { $cc = $CandidateSqlCapabilities[$k] } }
            if ($null -ne $cc -and -not (Test-PimSqlRegionCapability -Capabilities $cc -Location $c)) { $suggestion = $c; break }
        }
    }
    $disp = Get-PimRegionDisplayName -Name $name -Locations $Locations
    $sugDisp = if ($suggestion) { Get-PimRegionDisplayName -Name $suggestion -Locations $Locations } else { '' }
    $msg = if (-not $missing.Count) {
        "every service PIM Manager needs is offered in $disp ('$name')" + $(if ($unknown.Count) { " -- could not check: $(@($unknown) -join ', ')" } else { '' }) +
            $(if ($deferred.Count) { " -- $(@($deferred) -join ' ')" } else { '' })
    } else {
        "PIM Manager cannot be installed in $disp ('$name') for this subscription -- not available there: $(@($missing) -join '; ')." +
            $(if ($suggestion) { " Nearest region that has every service: $sugDisp ('$suggestion') -- choose it, or another region." } else { ' Choose another region.' })
    }
    return [pscustomobject]@{
        ok = (-not $missing.Count); location = $name; displayName = $disp
        missing = @($missing); unknown = @($unknown); deferred = @($deferred)
        suggestion = $suggestion; suggestionDisplayName = $sugDisp; candidates = @($candidates); message = $msg
    }
}

# ---- REGION-ACCEPTS-NEW (framework installer rule 9, 2026-11-03) -------------------------------------------------------------
# A region can OFFER a service and still refuse NEW resources for this subscription ("the selected region is currently not
# accepting new customers", RequestDisallowedByAzure -- westeurope, proven live 2026-11-03). Provider locations do not show it;
# only an ARM deployment VALIDATE does (it creates nothing). The form is the one SI proved (duplicated here on purpose:
# solution isolation): the install's resource group exists -> validate in it; it does not -> a SUBSCRIPTION-scope validate whose
# template makes the group and a NESTED deployment holding the resources (a group alone answers 200 even in a refused region).
# The probe resources carry the REAL resources' settings (a customer's policy must judge what the install will create).
# RequestDisallowedByAzure stops; a policy refusal (RequestDisallowedByPolicy) or a 403 is NOT KNOWN -- said, never a stop; a
# mix (one Azure + one policy) stops.

function Get-PimRegionProbeResources {
    <#
      PURE. One minimal resource per Azure service PIM Manager creates, in -Region, with the install's own names (-Names:
      Get-PimInstallNames) and settings. The SQL server needs an Entra administrator: -AdminObjectId (else left out, checked
      when created). -> @{ Resources = @(); Covered = @(<label>); Left = @(<label>) }
    #>
    param([Parameter(Mandatory)][string]$Region, [Parameter(Mandatory)][object]$Names, [string]$TenantId = '', [string]$AdminObjectId = '',
          [string]$AdminType = 'User', [bool]$PrivateNetwork = $false, [switch]$NoSql)
    $tok = "$($Names.token)"
    $pna = $(if ($PrivateNetwork) { 'Disabled' } else { 'Enabled' })
    $res = New-Object System.Collections.Generic.List[object]; $covered = New-Object System.Collections.Generic.List[string]; $left = New-Object System.Collections.Generic.List[string]
    $res.Add([ordered]@{ type = 'Microsoft.ManagedIdentity/userAssignedIdentities'; apiVersion = '2023-01-31'; name = "id-pim-sql-$tok"; location = $Region }); $covered.Add('user-assigned managed identities')
    $st = [ordered]@{ supportsHttpsTrafficOnly = $true; allowBlobPublicAccess = $false; minimumTlsVersion = 'TLS1_2' }
    if ($PrivateNetwork) { $st['publicNetworkAccess'] = 'Disabled' }
    $res.Add([ordered]@{ type = 'Microsoft.Storage/storageAccounts'; apiVersion = '2023-01-01'; name = ("stpim$tok" -replace '[^a-z0-9]', '').ToLowerInvariant(); location = $Region; kind = 'StorageV2'; sku = [ordered]@{ name = 'Standard_LRS' }; properties = $st }); $covered.Add('Azure Storage accounts')
    $res.Add([ordered]@{ type = 'Microsoft.OperationalInsights/workspaces'; apiVersion = '2022-10-01'; name = "$($Names.logAnalytics)"; location = $Region; properties = [ordered]@{ sku = [ordered]@{ name = 'PerGB2018' } } }); $covered.Add('Log Analytics workspaces')
    $res.Add([ordered]@{ type = 'Microsoft.App/managedEnvironments'; apiVersion = '2024-03-01'; name = "$($Names.environment)"; location = $Region; properties = [ordered]@{} }); $covered.Add('Azure Container Apps environments')
    $acr = [ordered]@{ adminUserEnabled = $false }; if ($PrivateNetwork) { $acr['publicNetworkAccess'] = 'Disabled' }
    $res.Add([ordered]@{ type = 'Microsoft.ContainerRegistry/registries'; apiVersion = '2023-07-01'; name = "$($Names.acr)"; location = $Region; sku = [ordered]@{ name = $(if ($PrivateNetwork) { 'Premium' } else { 'Basic' }) }; properties = $acr }); $covered.Add('Azure Container Registry')
    if ($TenantId) {
        $kv = [ordered]@{ tenantId = $TenantId; sku = [ordered]@{ family = 'A'; name = 'standard' }; enableRbacAuthorization = $true; accessPolicies = @(); enableSoftDelete = $true; softDeleteRetentionInDays = 90; enablePurgeProtection = $true }
        # framework installer rule 11: a private install's vault is private from birth
        if ($PrivateNetwork) { $kv['publicNetworkAccess'] = 'Disabled'; $kv['networkAcls'] = [ordered]@{ defaultAction = 'Deny'; bypass = 'AzureServices'; ipRules = @(); virtualNetworkRules = @() } }
        $res.Add([ordered]@{ type = 'Microsoft.KeyVault/vaults'; apiVersion = '2023-07-01'; name = "$($Names.keyVault)"; location = $Region; properties = $kv }); $covered.Add('Azure Key Vault')
    } else { $left.Add('Azure Key Vault') }
    if (-not $NoSql) {
        if ($TenantId -and $AdminObjectId) {
            $res.Add([ordered]@{ type = 'Microsoft.Sql/servers'; apiVersion = '2021-11-01'; name = "$($Names.sqlServer)"; location = $Region
                properties = [ordered]@{ version = '12.0'; minimalTlsVersion = '1.2'; publicNetworkAccess = $pna
                    administrators = [ordered]@{ administratorType = 'ActiveDirectory'; azureADOnlyAuthentication = $true; login = 'PIM Manager installer'; sid = $AdminObjectId; tenantId = $TenantId
                        principalType = $(if ($AdminType -eq 'User') { 'User' } else { 'Application' }) } } }); $covered.Add('Azure SQL Database servers')
        } else { $left.Add('Azure SQL Database servers') }
    }
    return @{ Resources = $res.ToArray(); Covered = $covered.ToArray(); Left = $left.ToArray() }
}

function Get-PimRegionProbeRequest {
    <#
      PURE. The ARM deployment VALIDATE request (creates nothing, not even the group): -ResourceGroupExists -> POST in the group;
      else at SUBSCRIPTION scope, a template that makes the group and a NESTED deployment into it holding -Resources.
      -> @{ Path; Body (JSON string) }
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Region,
          [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Resources, [bool]$ResourceGroupExists, [string]$DeploymentName = 'pim-preflight-region')
    $inner = [ordered]@{ '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'; contentVersion = '1.0.0.0'; resources = @($Resources) }
    if ($ResourceGroupExists) {
        $path = '/subscriptions/{0}/resourcegroups/{1}/providers/Microsoft.Resources/deployments/{2}/validate?api-version=2021-04-01' -f $SubscriptionId, $ResourceGroup, $DeploymentName
        $body = [ordered]@{ properties = [ordered]@{ mode = 'Incremental'; template = $inner } }
    } else {
        $path = '/subscriptions/{0}/providers/Microsoft.Resources/deployments/{1}/validate?api-version=2021-04-01' -f $SubscriptionId, $DeploymentName
        $tpl = [ordered]@{ '$schema' = 'https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#'; contentVersion = '1.0.0.0'
            resources = @(
                [ordered]@{ type = 'Microsoft.Resources/resourceGroups'; apiVersion = '2021-04-01'; name = $ResourceGroup; location = $Region; properties = [ordered]@{} },
                [ordered]@{ type = 'Microsoft.Resources/deployments'; apiVersion = '2021-04-01'; name = ($DeploymentName + '-rg'); resourceGroup = $ResourceGroup
                    dependsOn = @(("[resourceId('Microsoft.Resources/resourceGroups', '{0}')]" -f $ResourceGroup))
                    properties = [ordered]@{ mode = 'Incremental'; template = $inner } }) }
        $body = [ordered]@{ location = $Region; properties = [ordered]@{ mode = 'Incremental'; template = $tpl } }
    }
    return @{ Path = $path; Body = (ConvertTo-Json -InputObject $body -Depth 30 -Compress) }
}

function ConvertFrom-PimRegionValidateAnswer {
    <#
      PURE. What the VALIDATE answered (-StatusCode, -Content = the body text): @{ State = ok | refused | unknown | other; Text }.
      200/201 ok. RequestDisallowedByAzure anywhere in error / details (nested deployments too) = refused -- also when another
      resource of the same answer is refused by a policy. RequestDisallowedByPolicy only, or 403 = unknown (named policy).
      Anything else (another error, 202, no answer) = other: never a stop, the create-time catch decides.
    #>
    param([int]$StatusCode, [AllowEmptyString()][AllowNull()][string]$Content)
    if ($StatusCode -in 200, 201) { return @{ State = 'ok'; Text = '' } }
    $c = "$Content"
    $obj = $null; try { if ($c.Trim()) { $obj = $c | ConvertFrom-Json } } catch { $obj = $null }
    $codes = New-Object System.Collections.Generic.List[string]; $msgs = New-Object System.Collections.Generic.List[string]; $policies = New-Object System.Collections.Generic.List[string]
    $get = { param($o, $n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { return $o[$n] }; $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    $walk = $null
    $walk = {
        param($e, $depth)
        if ($null -eq $e -or $depth -gt 12) { return }
        foreach ($x in @($e)) {
            if ($null -eq $x -or $x -is [string]) { continue }
            $cd = "$(& $get $x 'code')"; if ($cd) { $codes.Add($cd) }
            $mg = "$(& $get $x 'message')"; if ($mg) { $msgs.Add($mg) }
            foreach ($src in @($x) + @(@(& $get $x 'additionalInfo') | Where-Object { $_ } | ForEach-Object { & $get $_ 'info' })) {
                foreach ($pn in 'policyAssignmentDisplayName', 'policyDefinitionDisplayName') { $pv = "$(& $get $src $pn)"; if ($pv -and -not $policies.Contains($pv)) { $policies.Add($pv) } }
            }
            & $walk (& $get $x 'error') ($depth + 1)
            & $walk (& $get $x 'details') ($depth + 1)
        }
    }
    if ($obj) { & $walk $obj 0 }
    if ($codes -contains 'RequestDisallowedByAzure' -or $c -match 'RequestDisallowedByAzure') {
        $types = @([regex]::Matches(($msgs -join ' '), "(?i)type '([A-Za-z.]+/[A-Za-z/]+)'") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        return @{ State = 'refused'; Text = $(if ($types.Count) { "Azure is not accepting new resources there for this subscription ($($types -join ', '))" } else { 'Azure is not accepting new resources there for this subscription' }) }
    }
    if ($codes -contains 'RequestDisallowedByPolicy' -or $c -match 'RequestDisallowedByPolicy') {
        return @{ State = 'unknown'; Text = ('an Azure Policy in your subscription refuses the check''s test resources{0} -- the region could not be checked' -f $(if ($policies.Count) { ' (' + ($policies -join ', ') + ')' } else { '' })) }
    }
    if ($StatusCode -eq 403) { return @{ State = 'unknown'; Text = 'you may not run Azure''s deployment check in this subscription -- the region could not be checked' } }
    if ($StatusCode -eq 202) { return @{ State = 'other'; Text = 'Azure took the check but did not answer at once' } }
    $first = @($msgs | Select-Object -Last 1) | Select-Object -First 1
    return @{ State = 'other'; Text = $(if ($first) { "$first ($(@($codes | Select-Object -Unique) -join ', '))" } elseif ($c.Trim()) { $c.Trim() } else { "HTTP $StatusCode" }) }
}

function Test-PimRegionAcceptsNew {
    <#
      THIN. One VALIDATE in -Location; refused -> the same validate in the -Candidates (nearest first) until -Want accept, at most
      -MaxTries. -Post is param([string]$Path, [string]$Body) -> @{ StatusCode; Content } over the CALLER's ARM client (never
      throws here). -> @{ State = ok | refused | unknown | other; Text; Alternatives = @(); Left = @() }. Creates nothing.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$ResourceGroup,
          [bool]$ResourceGroupExists, [Parameter(Mandatory)][object]$Names, [Parameter(Mandatory)][scriptblock]$Post, [string]$TenantId = '',
          [string]$AdminObjectId = '', [string]$AdminType = 'User', [bool]$PrivateNetwork = $false, [switch]$NoSql, [string[]]$Candidates = @(),
          [int]$Want = 1, [int]$MaxTries = 4)
    $probe = {
        param([string]$Region)
        $p = Get-PimRegionProbeResources -Region $Region -Names $Names -TenantId $TenantId -AdminObjectId $AdminObjectId -AdminType $AdminType -PrivateNetwork $PrivateNetwork -NoSql:$NoSql
        $q = Get-PimRegionProbeRequest -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Region $Region -Resources $p.Resources -ResourceGroupExists $ResourceGroupExists
        $r = $null; try { $r = & $Post $q.Path $q.Body } catch { $r = @{ StatusCode = 0; Content = "$($_.Exception.Message)" } }
        $sc = 0; $ct = ''
        if ($r) { if ($r -is [System.Collections.IDictionary]) { $sc = [int]$r['StatusCode']; $ct = "$($r['Content'])" } else { $sc = [int]$r.StatusCode; $ct = "$($r.Content)" } }
        $a = ConvertFrom-PimRegionValidateAnswer -StatusCode $sc -Content $ct
        $a['Left'] = @($p.Left)
        $a
    }
    $a = & $probe $Location
    $a['Alternatives'] = @()
    if ($a.State -ne 'refused') { return $a }
    $alt = New-Object System.Collections.Generic.List[string]; $tries = 0
    foreach ($c in @($Candidates)) {
        if ($alt.Count -ge $Want -or $tries -ge $MaxTries) { break }
        $tries++
        if ((& $probe $c).State -eq 'ok') { $alt.Add($c) }
    }
    $a['Alternatives'] = $alt.ToArray()
    return $a
}

function Invoke-PimRegionPreflight {
    <#
      THIN. Reads the ARM answers Test-PimRegionCapability needs and returns its verdict. Makes NO network call itself:
      -Get is param([string]$Url) -> the parsed JSON or $null, over the CALLER's REST client (full https://management.azure.com
      URL with its api-version). Reads only -- nothing is created. Azure SQL's capabilities are read for the chosen region and,
      when something is missing, for up to -MaxSuggestionProbes nearest candidates (a suggestion must have SQL confirmed).
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][scriptblock]$Get,
        [switch]$NoSql,
        [int]$MaxSuggestionProbes = 6,
        # REGION-ACCEPTS-NEW (installer rule 9): with -Post (param([string]$Path, [string]$Body) -> @{ StatusCode; Content }) and
        # -ProbeNames (Get-PimInstallNames), a region whose services are offered is ALSO asked, by an ARM deployment VALIDATE,
        # whether it accepts NEW resources for this subscription. Without -Post: the reads only (unchanged).
        [scriptblock]$Post,
        [object]$ProbeNames,
        [string]$ResourceGroup = '',
        [bool]$ResourceGroupExists = $false,
        [string]$TenantId = '',
        [string]$AdminObjectId = '',
        [string]$AdminType = 'User',
        [bool]$PrivateNetwork = $false
    )
    $arm = "https://management.azure.com/subscriptions/$SubscriptionId"
    $read = { param($u) try { & $Get $u } catch { $null } }
    $locations = & $read "$arm/locations?api-version=2022-12-01"
    $providers = @{}
    foreach ($ns in @(Get-PimRegionRequiredServices -NoSql:$NoSql | ForEach-Object { $_.Namespace } | Select-Object -Unique)) {
        $p = & $read "$arm/providers/$ns`?api-version=2021-04-01"
        if ($null -ne $p) { $providers[$ns] = $p }
    }
    $name = ConvertTo-PimRegionName -Name $Location -Locations $locations
    $sqlCap = if ($NoSql) { $null } else { & $read "$arm/providers/Microsoft.Sql/locations/$name/capabilities?api-version=2021-11-01" }
    $v = Test-PimRegionCapability -Location $Location -Providers $providers -Locations $locations -SqlCapabilities $sqlCap -NoSql:$NoSql
    if (-not $v.ok -and -not $NoSql -and @($v.candidates).Count) {
        $cand = @{}
        foreach ($c in @($v.candidates | Select-Object -First $MaxSuggestionProbes)) {
            $cc = & $read "$arm/providers/Microsoft.Sql/locations/$c/capabilities?api-version=2021-11-01"
            if ($null -ne $cc) { $cand[$c] = $cc; if (-not (Test-PimSqlRegionCapability -Capabilities $cc -Location $c)) { break } }
        }
        $v = Test-PimRegionCapability -Location $Location -Providers $providers -Locations $locations -SqlCapabilities $sqlCap -CandidateSqlCapabilities $cand -NoSql:$NoSql
    }
    if ($v.ok -and $Post -and $null -ne $ProbeNames -and "$ResourceGroup".Trim()) {
        $cands = @(Get-PimRegionCandidateOrder -Location $name -Providers $providers -Locations $locations -NoSql:$NoSql)
        $an = Test-PimRegionAcceptsNew -SubscriptionId $SubscriptionId -Location $name -ResourceGroup "$ResourceGroup".Trim() -ResourceGroupExists $ResourceGroupExists `
            -Names $ProbeNames -Post $Post -TenantId $TenantId -AdminObjectId $AdminObjectId -AdminType $AdminType -PrivateNetwork $PrivateNetwork -NoSql:$NoSql -Candidates $cands
        $v = Merge-PimRegionAcceptsNew -Verdict $v -Answer $an -Locations $locations
    }
    return $v
}

function Merge-PimRegionAcceptsNew {
    <#
      PURE. The capability verdict (Test-PimRegionCapability) + the VALIDATE answer (Test-PimRegionAcceptsNew):
        refused -> ok = $false, the refusal named, the first alternative that validated is the suggestion;
        unknown -> the policy / 403 sentence joins unknown[] (a warning, never a stop);
        other   -> a note in unknown[] (the create-time catch decides); ok -> unchanged.
    #>
    param([Parameter(Mandatory)][object]$Verdict, [Parameter(Mandatory)][object]$Answer, [object]$Locations)
    $st = "$($Answer.State)"
    if ($st -eq 'ok') { return $Verdict }
    $unknown = @($Verdict.unknown)
    if ($st -in 'unknown', 'other') {
        $note = if ($st -eq 'unknown') { "$($Answer.Text)" } else { "Azure's deployment check could not confirm the region ($($Answer.Text)) -- each resource is checked when it is created" }
        $unknown += $note
        $msg = "$($Verdict.message)" + $(if (@($Verdict.unknown).Count) { "; $note" } else { " -- could not check: $note" })
        return [pscustomobject]@{ ok = $Verdict.ok; location = $Verdict.location; displayName = $Verdict.displayName; missing = @($Verdict.missing); unknown = $unknown
            deferred = @($Verdict.deferred); suggestion = $Verdict.suggestion; suggestionDisplayName = $Verdict.suggestionDisplayName; candidates = @($Verdict.candidates); message = $msg }
    }
    $sug = @($Answer.Alternatives | Where-Object { $_ }) | Select-Object -First 1
    $sugDisp = if ($sug) { Get-PimRegionDisplayName -Name $sug -Locations $Locations } else { '' }
    $msg = "PIM Manager cannot be installed in $($Verdict.displayName) ('$($Verdict.location)') for this subscription -- $($Answer.Text)." +
        $(if ($sug) { " Nearest region that accepts them: $sugDisp ('$sug') -- choose it, or another region." } else { ' Choose another region.' })
    return [pscustomobject]@{ ok = $false; location = $Verdict.location; displayName = $Verdict.displayName; missing = @(@($Verdict.missing) + "new resources ($($Answer.Text))"); unknown = $unknown
        deferred = @($Verdict.deferred); suggestion = "$sug"; suggestionDisplayName = $sugDisp; candidates = @($Answer.Alternatives); message = $msg }
}
