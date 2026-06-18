#Requires -Version 5.1
<#
.SYNOPSIS
    Pure, offline registry-policy/plan BUILDER for the PIM Activator hybrid
    (on-prem / standalone) deploy. NO network, NO DC, NO admin, NO modules.

.DESCRIPTION
    This is the shared core behind Deploy-PimActivatorHybrid.ps1's three
    -Target modes (Json / DomainGpo / LocalGpo). It turns an MSP's
    multi-tenant Activator config into the EXACT same client-side managed
    configuration that Deploy-PimActivatorIntune.ps1 produces, expressed as
    plain HKLM registry policy values so the same plan drives:

      * LocalGpo  -- write the values straight into the local machine's
                     policy hive (HKLM\SOFTWARE\Policies\...), no domain.
      * DomainGpo -- feed the values to New-GPO / Set-GPRegistryValue.
      * Json      -- emit the managed-config JSON artifact for inspection.

    PARITY CONTRACT (must match Deploy-PimActivatorIntune.ps1):
    Per included browser (Edge and/or Chrome) the Intune deploy pushes FOUR
    client policies. Their on-device HKLM registry shapes are:

      1. ExtensionInstallForcelist  (REG_SZ list, numbered value names "1","2"..)
           key:   SOFTWARE\Policies\<vendor>\ExtensionInstallForcelist
           value: "<extId>;<updateUrl>"
      2. ExtensionInstallSources    (REG_SZ list)
           key:   SOFTWARE\Policies\<vendor>\ExtensionInstallSources
           value: "<sourcePattern>"
      3. ExtensionSettings          (REG_SZ, single JSON string)
           key:   SOFTWARE\Policies\<vendor>
           value name: ExtensionSettings
           value: { "<extId>": { installation_mode, update_url,
                                  runtime_allowed_hosts:["<all_urls>"] } }
      4. tenantCatalog              (REG_SZ, single JSON string) via the
         3rd-party extension policy path (the ADMX-backed Intune setting
         writes here)
           key:   SOFTWARE\Policies\<vendor>\3rdparty\extensions\<extId>\policy
           value name: tenantCatalog
           value: JSON array of tenant entries

    where <vendor> is:
       Edge   -> Microsoft\Edge
       Chrome -> Google\Chrome

    The ExtensionSettings JSON and the forcelist/source row formats are byte
    identical to those built in Deploy-PimActivatorIntune.ps1 so all targets
    (and Intune) converge on the same effective client configuration.

    PS 5.1-safe: no ?./??, no RSA.ImportFromPem, no .Contains(string,cmp);
    ConvertTo-Json forced to array shape via -InputObject @(...) (PS 5.1 drops
    the outer [] for a single-element array otherwise).

    Dot-source this file to get the pure functions with NO side effects:
       New-PaHybridConfig          -- validate + normalise a tenant config
       New-PaHybridExtensionSettingsJson
       New-PaHybridForcelistValue
       Get-PaHybridRegistryPlan    -- the full per-browser registry value plan
       ConvertTo-PaHybridManagedConfigObject  -- the -Target Json artifact
#>

# Vendor registry sub-paths under HKLM\SOFTWARE\Policies, keyed by our browser
# label. Mirrors the verify hints printed at the end of Deploy-PimActivatorIntune.ps1.
$script:PaHybridVendorPath = @{
    Edge   = 'Microsoft\Edge'
    Chrome = 'Google\Chrome'
}

function Get-PaEntryProp {
    <#
    .SYNOPSIS
        Read a named property from a tenant entry that may be a hashtable OR a
        PSCustomObject (ConvertFrom-Json). Returns $null when absent.
    .DESCRIPTION
        A plain function (not a scriptblock) on purpose -- see the note in
        New-PaHybridConfig: a `& {scriptblock}` would inherit the caller's
        $WhatIfPreference and PS would emit a "What if: Retrieve the value..."
        line per property read under -WhatIf.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][string]$Name)
    # Pure read -- never a confirmable op; pin WhatIf off so PSObject property
    # access doesn't surface "What if: Retrieve the value..." under -WhatIf.
    $WhatIfPreference = $false
    if ($Entry -is [System.Collections.IDictionary]) {
        if ($Entry.Contains($Name)) { return $Entry[$Name] }
        return $null
    }
    $p = $Entry.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function New-PaHybridConfig {
    <#
    .SYNOPSIS
        Validate + normalise an MSP multi-tenant Activator config (parsed JSON)
        into the catalog array the registry plan + JSON artifact consume.

    .DESCRIPTION
        Accepts EITHER:
          * a bare array of tenant entries  (the same shape the Intune
            -CatalogJsonPath / sample-tenant-catalog.json uses), OR
          * an object wrapper  { tenants: [ ... ] }  (a friendlier top-level
            shape for the hybrid UNC config so an MSP can add file-level
            metadata next to the array).

        Each tenant entry MUST carry: name, tenantId, clientId.
        Optional per-entry keys (passed through verbatim, mirroring the
        managed-schema.json tenantCatalog contract): defaultJustification,
        defaultDurationHours, prefix, entraPrefix, azurePrefix, groupNameFilter,
        entraGroupRegex, azureGroupRegex, bulkActivateConfirmThreshold.

        Throws a clear error on: empty set, >MaxTenants, missing required
        field, duplicate tenantId, or a non-GUID tenantId/clientId.

    .OUTPUTS
        [pscustomobject[]] normalised tenant catalog (always an array).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $InputObject,
        [int]$MaxTenants = 25
    )

    # Pure validation/normalisation -- makes no changes. Pin WhatIf off so a
    # caller running with -WhatIf doesn't turn benign property reads into
    # "What if:" noise.
    $WhatIfPreference = $false

    # Unwrap { tenants: [...] } if present; else treat as the array itself.
    $entries = $null
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains('tenants')) { $entries = $InputObject['tenants'] }
        else { throw "Hybrid config object has no 'tenants' property. Provide either a bare JSON array of tenant entries or an object { ""tenants"": [ ... ] }." }
    } elseif ($null -ne $InputObject -and $null -ne $InputObject.PSObject.Properties['tenants']) {
        $entries = $InputObject.tenants
    } else {
        $entries = $InputObject
    }

    $entries = @($entries)
    if ($entries.Count -eq 0) {
        throw "Tenant config is empty -- expected 1..$MaxTenants tenant entry/entries."
    }
    if ($entries.Count -gt $MaxTenants) {
        throw "Tenant config has $($entries.Count) entries which exceeds the supported maximum of $MaxTenants. Split into multiple deployments or raise -MaxTenants."
    }

    $guidRe = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $seenTenantIds = @{}
    $out = New-Object System.Collections.Generic.List[object]

    $idx = 0
    foreach ($e in $entries) {
        $idx++
        if ($null -eq $e) { throw "Tenant entry #$idx is null." }

        # Property accessor that works for both hashtables and PSCustomObjects.
        # NOTE: a plain function call (not a `& {scriptblock}`) -- a scriptblock
        # invoked here would inherit the CALLER's $WhatIfPreference and PS would
        # treat each PSObject property read as a confirmable "Retrieve the value"
        # operation, spamming "What if:" lines when the deploy runs with -WhatIf.
        $name     = [string](Get-PaEntryProp -Entry $e -Name 'name')
        $tenantId = [string](Get-PaEntryProp -Entry $e -Name 'tenantId')
        $clientId = [string](Get-PaEntryProp -Entry $e -Name 'clientId')

        if ([string]::IsNullOrWhiteSpace($name))     { throw "Tenant entry #$idx is missing 'name'." }
        if ([string]::IsNullOrWhiteSpace($tenantId)) { throw "Tenant entry '$name' (#$idx) is missing 'tenantId'." }
        if ([string]::IsNullOrWhiteSpace($clientId)) { throw "Tenant entry '$name' (#$idx) is missing 'clientId'." }
        if ($tenantId -notmatch $guidRe) { throw "Tenant entry '$name' (#$idx) has a malformed tenantId '$tenantId' (expected a GUID)." }
        if ($clientId -notmatch $guidRe) { throw "Tenant entry '$name' (#$idx) has a malformed clientId '$clientId' (expected a GUID)." }

        $tidKey = $tenantId.ToLowerInvariant()
        if ($seenTenantIds.ContainsKey($tidKey)) {
            throw "Duplicate tenantId '$tenantId' (entry '$name', #$idx) -- each tenant must appear once."
        }
        $seenTenantIds[$tidKey] = $true

        # Build a normalised, ordered entry. Required fields first, then any of
        # the known optional keys that are present (verbatim pass-through).
        $norm = [ordered]@{
            name     = $name
            tenantId = $tenantId
            clientId = $clientId
        }
        foreach ($opt in @('defaultJustification','defaultDurationHours','prefix','entraPrefix','azurePrefix','groupNameFilter','entraGroupRegex','azureGroupRegex','bulkActivateConfirmThreshold')) {
            $v = Get-PaEntryProp -Entry $e -Name $opt
            if ($null -ne $v) { $norm[$opt] = $v }
        }
        $out.Add([pscustomobject]$norm)
    }

    return $out.ToArray()
}

function ConvertTo-PaHybridCatalogJson {
    <#
    .SYNOPSIS
        Serialise the normalised catalog to the minified JSON string the
        extension reads as tenantCatalog (always emits a JSON array).
    .DESCRIPTION
        Matches Deploy-PimActivatorIntune.ps1's $minifiedCatalog:
        ConvertTo-Json -InputObject @($catalog) -Depth 10 -Compress, so PS 5.1
        never collapses a single-element catalog to a bare object.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Catalog)
    return (ConvertTo-Json -InputObject @($Catalog) -Depth 10 -Compress)
}

function New-PaHybridForcelistValue {
    <#
    .SYNOPSIS
        The single ExtensionInstallForcelist row: "<extId>;<updateUrl>".
        Identical to Deploy-PimActivatorIntune.ps1's $forcelistValue.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExtensionId,
        [Parameter(Mandatory)][string]$UpdateUrl
    )
    return ("{0};{1}" -f $ExtensionId, $UpdateUrl)
}

function New-PaHybridExtensionSettingsJson {
    <#
    .SYNOPSIS
        The ExtensionSettings policy value (single JSON string keyed by ext id).
    .DESCRIPTION
        Byte-identical to Deploy-PimActivatorIntune.ps1's $extSettingsJson:
        runtime_allowed_hosts=['<all_urls>'] pre-grants the broad scope so
        Chrome's permission-expansion gate skips the auto-update silent-disable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExtensionId,
        [Parameter(Mandatory)][string]$UpdateUrl
    )
    return (@{ $ExtensionId = @{
        installation_mode     = 'force_installed'
        update_url            = $UpdateUrl
        runtime_allowed_hosts = @('<all_urls>')
    }} | ConvertTo-Json -Depth 5 -Compress)
}

function Get-PaHybridRegistryPlan {
    <#
    .SYNOPSIS
        The full per-browser registry policy plan equivalent to the Intune
        client policies. Pure -- builds an in-memory plan, writes nothing.

    .PARAMETER Catalog
        Normalised tenant catalog (output of New-PaHybridConfig).

    .PARAMETER Browser
        'Both' (default), 'Edge', or 'Chrome' -- same set as the Intune deploy.

    .OUTPUTS
        [pscustomobject] with:
          CatalogJson       - the minified tenantCatalog string
          ForcelistValue    - "<extId>;<updateUrl>"
          ExtensionSettings - the ExtensionSettings JSON string
          Browsers          - the browser labels included
          Entries           - array of registry value entries, each:
              Browser   (Edge|Chrome)
              Policy    (Forcelist|Sources|Settings|Catalog)
              Hive      (always 'HKLM')
              Key       (e.g. SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist)
              ValueName (e.g. '1' for list rows, or 'ExtensionSettings'/'tenantCatalog')
              ValueKind (String|Dword)
              Value     (the data)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Catalog,
        [ValidateSet('Both','Edge','Chrome')][string]$Browser = 'Both',
        [Parameter(Mandatory)][string]$ExtensionId,
        [Parameter(Mandatory)][string]$UpdateUrl,
        [Parameter(Mandatory)][string]$SourcePattern
    )

    $WhatIfPreference = $false   # pure builder -- never a confirmable op

    $browsers = switch ($Browser) {
        'Both'   { @('Edge','Chrome') }
        'Edge'   { @('Edge') }
        'Chrome' { @('Chrome') }
    }

    $catalogJson  = ConvertTo-PaHybridCatalogJson -Catalog $Catalog
    $forcelistVal = New-PaHybridForcelistValue   -ExtensionId $ExtensionId -UpdateUrl $UpdateUrl
    $extSettings  = New-PaHybridExtensionSettingsJson -ExtensionId $ExtensionId -UpdateUrl $UpdateUrl

    $entries = New-Object System.Collections.Generic.List[object]

    foreach ($b in $browsers) {
        $vendor   = $script:PaHybridVendorPath[$b]
        $polKey   = "SOFTWARE\Policies\$vendor"
        $thirdKey = "SOFTWARE\Policies\$vendor\3rdparty\extensions\$ExtensionId\policy"

        # 1. ExtensionInstallForcelist -- numbered REG_SZ list (single row).
        $entries.Add([pscustomobject]@{
            Browser = $b; Policy = 'Forcelist'; Hive = 'HKLM'
            Key = "$polKey\ExtensionInstallForcelist"; ValueName = '1'
            ValueKind = 'String'; Value = $forcelistVal
        })

        # 2. ExtensionInstallSources -- numbered REG_SZ list (single row).
        $entries.Add([pscustomobject]@{
            Browser = $b; Policy = 'Sources'; Hive = 'HKLM'
            Key = "$polKey\ExtensionInstallSources"; ValueName = '1'
            ValueKind = 'String'; Value = $SourcePattern
        })

        # 3. ExtensionSettings -- single REG_SZ JSON string.
        $entries.Add([pscustomobject]@{
            Browser = $b; Policy = 'Settings'; Hive = 'HKLM'
            Key = $polKey; ValueName = 'ExtensionSettings'
            ValueKind = 'String'; Value = $extSettings
        })

        # 4. tenantCatalog -- single REG_SZ JSON string under the 3rd-party
        #    extension policy path (the ADMX-backed Intune setting writes here).
        $entries.Add([pscustomobject]@{
            Browser = $b; Policy = 'Catalog'; Hive = 'HKLM'
            Key = $thirdKey; ValueName = 'tenantCatalog'
            ValueKind = 'String'; Value = $catalogJson
        })

        # 4b. Any per-tenant bulkActivateConfirmThreshold is carried INSIDE the
        #     tenantCatalog JSON (per managed-schema.json). A tenant-wide DWORD
        #     bulkActivateConfirmThreshold is only emitted when a file-level
        #     value is supplied -- callers pass it via -BulkThreshold below; the
        #     base plan stays catalog-only to match the Intune client policies.
    }

    return [pscustomobject]@{
        CatalogJson       = $catalogJson
        ForcelistValue    = $forcelistVal
        ExtensionSettings = $extSettings
        Browsers          = $browsers
        Entries           = $entries.ToArray()
    }
}

function ConvertTo-PaHybridManagedConfigObject {
    <#
    .SYNOPSIS
        Build the -Target Json artifact: the managed-config object (per browser)
        for inspection / manual import.
    .DESCRIPTION
        Groups the registry plan into a browser-keyed object whose shape mirrors
        the effective chrome.storage.managed config + the install policies, so an
        operator can eyeball exactly what each browser will receive. This is a
        documentation/inspection artifact -- the registry plan (Get-PaHybridRegistryPlan)
        remains the single source of truth all three targets write from.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Plan)

    $out = [ordered]@{}
    foreach ($b in $Plan.Browsers) {
        $out[$b] = [ordered]@{
            ExtensionInstallForcelist = @($Plan.ForcelistValue)
            ExtensionInstallSources   = @(($Plan.Entries | Where-Object { $_.Browser -eq $b -and $_.Policy -eq 'Sources' } | Select-Object -First 1).Value)
            ExtensionSettings         = $Plan.ExtensionSettings
            managedConfig             = [ordered]@{ tenantCatalog = $Plan.CatalogJson }
        }
    }
    return [pscustomobject]$out
}
