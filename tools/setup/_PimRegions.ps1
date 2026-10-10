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
        [int]$MaxSuggestionProbes = 6
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
    return $v
}
