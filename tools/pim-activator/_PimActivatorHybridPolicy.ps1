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
       Get-PaPolicyListPlan        -- WHERE our row goes in a Chromium list policy (BUG-182/220)
       Get-PaExtensionSettingsPlan -- MERGE our id into ExtensionSettings (BUG-182)
    plus two small registry helpers shared by the LOCAL writers
    (Deploy-PimActivatorClient.ps1 and Deploy-PimActivatorHybrid.ps1 -Target LocalGpo):
       Read-PaPolicyRegistryState  -- read-only snapshot of what is already there
       Invoke-PaPolicyRegistryOps  -- apply a plan's Set/Remove ops

    🔒 NEVER OVERWRITE AN ORGANISATION'S OWN EXTENSION POLICIES (BUG-182, 2026-09-18).
    The list policies (ExtensionInstallForcelist / Sources / Allowlist) are SHARED keys: the
    org's own force-installed extensions live in the same numbered values. Our row goes into
    the slot that ALREADY holds our id if there is one, else the LOWEST FREE numeric slot --
    never a hard-coded '1' (which replaced the org's first extension) and never a
    GetHashCode() slot (randomised per process on .NET Core, so re-runs piled up duplicates
    and -Uninstall removed nothing; BUG-220 -- measured on mgmt1 2026-09-18: FOUR rows for
    the released id at 1590 / 3077 / 5148 / 7772). Lowest-free also keeps the list in the
    documented contiguous '1','2',... form, and a removal refills the hole it leaves, so
    the list is valid whether or not a reader tolerates gaps (arbitrary value names do
    appear to be accepted in practice -- the hashed slots installed -- but that is not
    something to depend on).
    ExtensionSettings is ONE dictionary for the whole browser: the org's '*' defaults and
    their other extensions' entries are MERGED with ours, never replaced. Both local
    writers use this one layout, so they can no longer disagree.
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
        [Parameter(Mandatory)][string]$UpdateUrl,
        # 🔴 THE FLEET-WIDE UNSTICK LEVER. Optional and INERT when omitted, so every existing
        # assignment keeps emitting byte-identical JSON.
        # Measured 2026-09-04: no existing install anywhere had moved to 1.6.124 (published
        # 26 Jun). A laptop sat on 1.6.25 -- the 2026-06-10 build, i.e. the exact release the
        # comment below says froze the fleet -- while the TEST extension on the SAME browser was
        # current, because that one arrived as a FRESH INSTALL rather than an update. Fresh
        # installs work; updates were not landing.
        # `minimum_version_required` is Chrome's own answer to that: an install BELOW the minimum
        # is disabled and pushed to update, instead of quietly sitting on an old build forever.
        # It is the difference between "we hope the update check runs" and "a stale install cannot
        # keep running" -- and it ships as POLICY, so it reaches 10,000 machines without touching
        # one of them.
        # 🪤 Set it to a version you have ALREADY published and verified installable. Naming a
        # version that is not downloadable disables the extension fleet-wide with no way forward.
        [string]$MinimumVersion
    )
    $__cfg = New-PaExtensionSettingsEntry -UpdateUrl $UpdateUrl -MinimumVersion $MinimumVersion
    return (@{ $ExtensionId = $__cfg } | ConvertTo-Json -Depth 5 -Compress)
}

function New-PaExtensionSettingsEntry {
    <#
    .SYNOPSIS
        OUR per-extension ExtensionSettings dictionary (the inner value keyed by our id).
        The one definition New-PaHybridExtensionSettingsJson and the merge both use.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$UpdateUrl,
        [string]$MinimumVersion
    )
    $__cfg = @{
        installation_mode     = 'force_installed'
        update_url            = $UpdateUrl
        runtime_allowed_hosts = @('<all_urls>')
    }
    if ("$MinimumVersion".Trim()) { $__cfg['minimum_version_required'] = "$MinimumVersion".Trim() }
    return $__cfg
}

function New-PaRowMatcher {
    <#
    .SYNOPSIS
        A scriptblock ($data) -> bool that recognises OUR row in a list policy:
          -ExtensionId  a forcelist row "<id>;<url>" (any url) or an allowlist row "<id>"
          -Exact        a row equal to this value (case-insensitive), e.g. a source pattern
    .NOTES
        Built with [scriptblock]::Create on purpose, NOT .GetNewClosure(): a closure copies
        every variable of the calling scope, and on Windows PowerShell 5.1 that THROWS when
        the caller is a script with a validated parameter holding an out-of-range default
        (e.g. [ValidateRange(1,24)][int]$DefaultDurationHours = 0 when not passed).
    #>
    [CmdletBinding()]
    param([string]$ExtensionId, [string]$Exact)
    $WhatIfPreference = $false
    if ($ExtensionId) {
        if ($ExtensionId -notmatch '^[a-p]{32}$') { throw "New-PaRowMatcher: '$ExtensionId' is not a Chromium extension id." }
        return [scriptblock]::Create("param(`$d) (`"`$d`" -like '$ExtensionId;*') -or (`"`$d`" -ieq '$ExtensionId')")
    }
    $lit = "$Exact" -replace "'", "''"
    return [scriptblock]::Create("param(`$d) (`"`$d`" -ieq '$lit')")
}

function Test-PaNumericSlotName {
    # A list-policy value name Chromium treats as a list index: a positive integer.
    param([string]$Name)
    $n = 0
    return ([int]::TryParse("$Name", [ref]$n) -and $n -ge 1 -and "$n" -eq "$Name")
}

function Get-PaPolicyListPlan {
    <#
    .SYNOPSIS
        Pure. Plan where OUR row goes in a Chromium list policy (ExtensionInstallForcelist,
        ExtensionInstallSources, ExtensionInstallAllowlist) -- or how to take it out again --
        WITHOUT touching anybody else's rows (BUG-182 / BUG-220).

    .PARAMETER Existing
        What is already in the list key: value name -> data. $null/empty = nothing there.

    .PARAMETER Value
        The row we want present (e.g. "<id>;<updateUrl>").

    .PARAMETER IsOurs
        Scriptblock ($data) -> bool: which existing rows are OURS. Default: data equals
        -Value (case-insensitive). For the forcelist pass { $args[0] -like "$id;*" } so a
        row with an older update URL is recognised and updated in place.

    .PARAMETER ReservedNames
        Slot names used ELSEWHERE (another GPO, the effective machine policy) that we must
        not pick for a NEW row and must never modify.

    .PARAMETER Remove
        Take our row(s) out instead of putting one in.

    .PARAMETER KeepOnRemove
        Scriptblock ($data) -> bool, -Remove only: rows that look like ours but must stay
        (e.g. an install-source pattern another force-installed extension still needs).

    .OUTPUTS
        [pscustomobject] Slot (the name our row lands in, install only), Reused (bool),
        Ops (array of @{ Op = 'Set'|'Remove'; Name; Value }) -- the minimal diff to apply,
        and Final (the resulting name -> data map).

    .NOTES
        Install: our row lands in the LOWEST positive integer no other row uses; a row of
        ours already there is reused, any other row of ours (duplicates -- e.g. the legacy
        hashed 1000-9999 slots Deploy-PimActivatorClient.ps1 used to write) is removed.
        Every hole a removal
        opens inside a contiguous run is refilled by moving the LAST row of that run into
        it, so the org's rows after it stay visible to a reader that stops at a gap. Order
        inside these lists carries no meaning, so moving a row changes nothing else.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Existing,
        [Parameter(Mandatory)][string]$Value,
        [scriptblock]$IsOurs,
        [string[]]$ReservedNames = @(),
        [switch]$Remove,
        [scriptblock]$KeepOnRemove
    )
    $WhatIfPreference = $false   # pure builder -- never a confirmable op

    if (-not $IsOurs) { $IsOurs = New-PaRowMatcher -Exact $Value }

    # Working copy (case-insensitive names, like the registry).
    $orig = @{}
    if ($Existing) { foreach ($k in $Existing.Keys) { $orig["$k"] = "$($Existing[$k])" } }
    $work = @{}
    foreach ($k in $orig.Keys) { $work[$k] = $orig[$k] }

    $reserved = @{}
    foreach ($r in @($ReservedNames)) { if ("$r") { $reserved["$r"] = $true } }

    $ours = @($work.Keys | Where-Object { & $IsOurs $work[$_] })
    # Numeric slots first (lowest wins), then any non-numeric names, deterministically.
    $oursSorted = @($ours | Sort-Object @{ Expression = { if (Test-PaNumericSlotName $_) { [int]$_ } else { [int]::MaxValue } } }, @{ Expression = { "$_" } })

    $removed = New-Object System.Collections.Generic.List[string]
    $slot = $null; $reused = $false

    if ($Remove) {
        foreach ($n in $oursSorted) {
            if ($KeepOnRemove -and (& $KeepOnRemove $work[$n])) { continue }
            [void]$work.Remove($n); $removed.Add($n)
        }
    } else {
        # Our row belongs in the LOWEST slot not used by anybody else. If one of our
        # existing rows already sits exactly there, it is reused (idempotent re-run);
        # a row of ours stranded above a gap (e.g. the old hashed 1000-9999 slot) is
        # moved down into the documented contiguous form instead.
        $i = 1
        while (($work.ContainsKey("$i") -and -not ($oursSorted -contains "$i")) -or $reserved.ContainsKey("$i")) { $i++ }
        $slot = "$i"
        $reused = $oursSorted -contains $slot
        foreach ($n in $oursSorted) {
            if ($n -ne $slot) { [void]$work.Remove($n); $removed.Add($n) }
        }
        $work[$slot] = $Value
    }

    # Refill every hole a removal opened inside a contiguous run (see .NOTES).
    foreach ($r in @($removed | Where-Object { Test-PaNumericSlotName $_ } | Sort-Object { [int]$_ })) {
        if ($work.ContainsKey($r)) { continue }            # refilled already
        $next = [int]$r + 1
        if (-not $work.ContainsKey("$next")) { continue }   # hole at the end of a run: harmless
        $last = $next
        while ($work.ContainsKey("$($last + 1)")) { $last++ }
        $work[$r] = $work["$last"]
        [void]$work.Remove("$last")
    }

    # Minimal diff original -> work.
    $ops = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($orig.Keys | Sort-Object)) {
        if (-not $work.ContainsKey($k)) { $ops.Add([pscustomobject]@{ Op = 'Remove'; Name = $k; Value = $null }) }
    }
    foreach ($k in @($work.Keys | Sort-Object)) {
        if (-not $orig.ContainsKey($k) -or $orig[$k] -cne $work[$k]) {
            $ops.Add([pscustomobject]@{ Op = 'Set'; Name = $k; Value = $work[$k] })
        }
    }
    return [pscustomobject]@{
        Slot   = $slot
        Reused = $reused
        Ops    = $ops.ToArray()
        Final  = $work
    }
}

function Get-PaExtensionSettingsPlan {
    <#
    .SYNOPSIS
        Pure. MERGE our id into the ExtensionSettings policy -- or take it out -- keeping
        every other entry the organisation has there, including the '*' defaults (BUG-182).

    .DESCRIPTION
        Chromium reads ExtensionSettings on Windows from EITHER layout:
          Value  -- a REG_SZ named 'ExtensionSettings' under the policy root holding the
                    whole dictionary as JSON (the documented form; what the ADMX / Intune write)
          Subkey -- a key named 'ExtensionSettings' with one REG_SZ per extension id
                    (value name = id or '*', data = that id's JSON)
        and when BOTH exist the subkey wins for the whole policy. So:
          * the org already uses the Subkey layout (it holds any id other than ours)
              -> add/update ONLY our value inside it; the root value is shadowed anyway.
          * otherwise -> merge our entry into the root JSON (parsed, never replaced), and
              remove a leftover subkey value of ours (the old Deploy-PimActivatorClient.ps1
              layout) so the subkey cannot shadow the merged value.
        A root value that is not a JSON object is an ERROR, not an overwrite: we will not
        replace a policy we cannot read.

    .OUTPUTS
        [pscustomobject] Layout ('Value'|'Subkey'|'None'), Error (string or $null), and Ops:
        @{ Op = 'Set'|'Remove'|'RemoveKeyIfEmpty'; Location = 'Root'|'Subkey'; Name; Value }.
        Location Root = value 'ExtensionSettings' under the policy root; Subkey = value
        <Name> under <policy root>\ExtensionSettings.
    #>
    [CmdletBinding()]
    param(
        [string]$ExistingValue,
        [hashtable]$ExistingSubkey,
        [Parameter(Mandatory)][string]$ExtensionId,
        [hashtable]$Settings,
        [switch]$Remove
    )
    $WhatIfPreference = $false   # pure builder -- never a confirmable op

    $ops = New-Object System.Collections.Generic.List[object]
    $sub = @{}
    if ($ExistingSubkey) { foreach ($k in $ExistingSubkey.Keys) { $sub["$k"] = $ExistingSubkey[$k] } }
    $foreignSub = @($sub.Keys | Where-Object { $_ -ne $ExtensionId })
    $oursInSub  = $sub.ContainsKey($ExtensionId)

    # Parse the root value (if any). $rootObj = $null means "no root value".
    $rootObj = $null; $rootErr = $null
    if ("$ExistingValue".Trim()) {
        try { $rootObj = "$ExistingValue" | ConvertFrom-Json -ErrorAction Stop } catch { $rootErr = $_.Exception.Message }
        if (-not $rootErr -and -not ($rootObj -is [System.Management.Automation.PSCustomObject])) {
            $rootErr = 'it is not a JSON object'
        }
    }

    if ($Remove) {
        if ($oursInSub) {
            $ops.Add([pscustomobject]@{ Op = 'Remove'; Location = 'Subkey'; Name = $ExtensionId; Value = $null })
            if ($foreignSub.Count -eq 0) { $ops.Add([pscustomobject]@{ Op = 'RemoveKeyIfEmpty'; Location = 'Subkey'; Name = $null; Value = $null }) }
        }
        if ($rootObj -and $rootObj.PSObject.Properties[$ExtensionId]) {
            $rootObj.PSObject.Properties.Remove($ExtensionId)
            if (@($rootObj.PSObject.Properties).Count -eq 0) {
                $ops.Add([pscustomobject]@{ Op = 'Remove'; Location = 'Root'; Name = 'ExtensionSettings'; Value = $null })
            } else {
                $ops.Add([pscustomobject]@{ Op = 'Set'; Location = 'Root'; Name = 'ExtensionSettings'; Value = (ConvertTo-Json -InputObject $rootObj -Depth 20 -Compress) })
            }
        }
        $layout = if ($ops.Count -gt 0) { if ($oursInSub) { 'Subkey' } else { 'Value' } } else { 'None' }
        # An unreadable root value on uninstall is reported, not touched.
        return [pscustomobject]@{ Layout = $layout; Error = $(if ($rootErr) { "existing ExtensionSettings value left untouched: $rootErr" } else { $null }); Ops = $ops.ToArray() }
    }

    if (-not $Settings) { throw 'Get-PaExtensionSettingsPlan: -Settings is required unless -Remove.' }
    $ourJson = ConvertTo-Json -InputObject $Settings -Depth 10 -Compress

    if ($foreignSub.Count -gt 0) {
        # The org uses the per-id subkey layout: add ours next to theirs.
        if (-not $oursInSub -or "$($sub[$ExtensionId])" -cne $ourJson) {
            $ops.Add([pscustomobject]@{ Op = 'Set'; Location = 'Subkey'; Name = $ExtensionId; Value = $ourJson })
        }
        return [pscustomobject]@{ Layout = 'Subkey'; Error = $null; Ops = $ops.ToArray() }
    }

    if ($rootErr) {
        return [pscustomobject]@{
            Layout = 'None'
            Error  = "the existing ExtensionSettings policy value cannot be merged ($rootErr). Refusing to overwrite the organisation's ExtensionSettings -- fix or remove that value, then re-run."
            Ops    = @()
        }
    }

    if ($rootObj) {
        # MERGE: keep every other entry verbatim, set/replace only ours.
        if ($rootObj.PSObject.Properties[$ExtensionId]) { $rootObj.PSObject.Properties.Remove($ExtensionId) }
        $rootObj | Add-Member -NotePropertyName $ExtensionId -NotePropertyValue $Settings -Force
        $merged = ConvertTo-Json -InputObject $rootObj -Depth 20 -Compress
    } else {
        # Nothing there: exactly what the Intune deploy writes (byte-identical).
        $merged = (@{ $ExtensionId = $Settings } | ConvertTo-Json -Depth 5 -Compress)
    }
    if ("$ExistingValue" -cne $merged) {
        $ops.Add([pscustomobject]@{ Op = 'Set'; Location = 'Root'; Name = 'ExtensionSettings'; Value = $merged })
    }
    if ($oursInSub) {
        # Legacy Deploy-PimActivatorClient.ps1 layout: a subkey holding only our id would
        # SHADOW the merged root value. Take it out.
        $ops.Add([pscustomobject]@{ Op = 'Remove'; Location = 'Subkey'; Name = $ExtensionId; Value = $null })
        $ops.Add([pscustomobject]@{ Op = 'RemoveKeyIfEmpty'; Location = 'Subkey'; Name = $null; Value = $null })
    }
    return [pscustomobject]@{ Layout = 'Value'; Error = $null; Ops = $ops.ToArray() }
}

function Read-PaPolicyRegistryState {
    <#
    .SYNOPSIS
        Read-only snapshot of the extension policies already present under one browser
        policy root (e.g. HKLM:\SOFTWARE\Policies\Microsoft\Edge). Missing keys = empty.
    .OUTPUTS
        @{ Forcelist; Sources; Allowlist = name->data hashtables; SettingsValue = string or
           $null; SettingsSubkey = name->data hashtable }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PolicyRoot)
    $WhatIfPreference = $false
    function Read-PaKeyValues([string]$Path) {
        $h = @{}
        if (Test-Path -LiteralPath $Path) {
            $item = Get-Item -LiteralPath $Path
            foreach ($n in @($item.GetValueNames())) { if ("$n") { $h["$n"] = "$($item.GetValue($n))" } }
        }
        return $h
    }
    $settingsValue = $null
    if (Test-Path -LiteralPath $PolicyRoot) {
        $rootItem = Get-Item -LiteralPath $PolicyRoot
        if (@($rootItem.GetValueNames()) -contains 'ExtensionSettings') { $settingsValue = "$($rootItem.GetValue('ExtensionSettings'))" }
    }
    return @{
        Forcelist      = Read-PaKeyValues (Join-Path $PolicyRoot 'ExtensionInstallForcelist')
        Sources        = Read-PaKeyValues (Join-Path $PolicyRoot 'ExtensionInstallSources')
        Allowlist      = Read-PaKeyValues (Join-Path $PolicyRoot 'ExtensionInstallAllowlist')
        SettingsValue  = $settingsValue
        SettingsSubkey = Read-PaKeyValues (Join-Path $PolicyRoot 'ExtensionSettings')
    }
}

function Invoke-PaPolicyRegistryOps {
    <#
    .SYNOPSIS
        Apply plan entries (Key relative to the hive, ValueName, ValueKind, Value, Action =
        Set|Remove|RemoveKeyIfEmpty) to a local registry hive ('HKLM:' / 'HKCU:').
        Shared by Deploy-PimActivatorClient.ps1 and Deploy-PimActivatorHybrid.ps1 -Target
        LocalGpo so both write the same layout. Returns one line per op applied.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Hive,
        [Parameter(Mandatory)] $Entries
    )
    $done = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($Entries)) {
        $path = "$Hive\$($e.Key)"
        $action = if ($e.PSObject.Properties['Action'] -and $e.Action) { $e.Action } else { 'Set' }
        switch ($action) {
            'Set' {
                if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
                $kind = if ($e.ValueKind -eq 'Dword') { 'DWord' } else { 'String' }
                New-ItemProperty -LiteralPath $path -Name $e.ValueName -Value $e.Value -PropertyType $kind -Force | Out-Null
                $done.Add("set    $path\$($e.ValueName)")
            }
            'Remove' {
                # Remove-ItemProperty -Name takes WILDCARDS: never let a '*' (the org's
                # ExtensionSettings default entry) or '?' through as a name.
                if ("$($e.ValueName)" -match '[\*\?\[\]]') { throw "Refusing to remove registry value '$($e.ValueName)' under $path -- the name contains a wildcard character." }
                if ((Test-Path -LiteralPath $path) -and (@((Get-Item -LiteralPath $path).GetValueNames()) -contains $e.ValueName)) {
                    Remove-ItemProperty -LiteralPath $path -Name $e.ValueName -Force
                    $done.Add("remove $path\$($e.ValueName)")
                }
            }
            'RemoveKeyIfEmpty' {
                if (Test-Path -LiteralPath $path) {
                    $it = Get-Item -LiteralPath $path
                    if (@($it.GetValueNames() | Where-Object { "$_" }).Count -eq 0 -and $it.SubKeyCount -eq 0) {
                        Remove-Item -LiteralPath $path -Force
                        $done.Add("remove empty key $path")
                    }
                }
            }
        }
    }
    return $done.ToArray()
}

function Select-PaActivatorApp {
    <#
    .SYNOPSIS
        Pure. Pick THE PIM Activator app registration out of a Graph /applications
        result -- deterministically (BUG-220). Match by -ClientId when given, else by the
        EXACT display name; anything but exactly one match is an error, never a guess.
    .OUTPUTS
        [pscustomobject] App (the match or $null), Error (why not, or $null).
    #>
    [CmdletBinding()]
    param(
        $Apps,
        [string]$ClientId,
        [string]$DisplayName = 'PIM Activator'
    )
    $WhatIfPreference = $false
    $get = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o) { $o.$n } else { $null } }
    $all = @($Apps | Where-Object { $_ })
    if ($ClientId) {
        $m = @($all | Where-Object { "$(& $get $_ 'appId')" -ieq $ClientId })
        $what = "appId '$ClientId'"
    } else {
        $m = @($all | Where-Object { "$(& $get $_ 'displayName')" -ceq $DisplayName })
        $what = "the exact display name '$DisplayName'"
    }
    if ($m.Count -eq 1) { return [pscustomobject]@{ App = $m[0]; Error = $null } }
    if ($m.Count -eq 0) {
        return [pscustomobject]@{ App = $null; Error = "no app registration with $what (run Deploy-PimActivatorBackend.ps1, or pass -ClientId)" }
    }
    $ids = ($m | ForEach-Object { "$(& $get $_ 'appId')" }) -join ', '
    return [pscustomobject]@{ App = $null; Error = "$($m.Count) app registrations match $what ($ids) -- ambiguous; pass -ClientId <appId> to choose" }
}

function ConvertTo-PaPolicyEntries {
    <#
    .SYNOPSIS
        Turn list-plan / settings-plan ops into registry plan entries (the shape
        Get-PaHybridRegistryPlan emits and Invoke-PaPolicyRegistryOps applies).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Browser,
        [Parameter(Mandatory)][string]$Policy,
        [Parameter(Mandatory)][string]$PolicyKey,      # e.g. SOFTWARE\Policies\Microsoft\Edge
        [string]$ListKeyName,                          # e.g. ExtensionInstallForcelist (list ops)
        $ListOps,
        $SettingsOps
    )
    $WhatIfPreference = $false
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($o in @($ListOps)) {
        if (-not $o) { continue }
        $out.Add([pscustomobject]@{
            Browser = $Browser; Policy = $Policy; Hive = 'HKLM'
            Key = "$PolicyKey\$ListKeyName"; ValueName = "$($o.Name)"
            ValueKind = 'String'; Value = $(if ($o.Op -eq 'Set') { "$($o.Value)" } else { '' }); Action = $o.Op
        })
    }
    foreach ($o in @($SettingsOps)) {
        if (-not $o) { continue }
        $key = if ($o.Location -eq 'Subkey') { "$PolicyKey\ExtensionSettings" } else { $PolicyKey }
        $out.Add([pscustomobject]@{
            Browser = $Browser; Policy = $Policy; Hive = 'HKLM'
            Key = $key; ValueName = $(if ($o.Name) { "$($o.Name)" } else { '' })
            ValueKind = 'String'; Value = $(if ($o.Op -eq 'Set') { "$($o.Value)" } else { '' }); Action = $o.Op
        })
    }
    return $out.ToArray()
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
              Action    (Set|Remove|RemoveKeyIfEmpty)

    .PARAMETER ExistingState
        Optional. Browser label -> what is ALREADY in that browser's policy root, as
        Read-PaPolicyRegistryState returns it (+ optional ForcelistReserved /
        SourcesReserved: slot names taken elsewhere, e.g. by another GPO). With it, our
        rows go into the slot already holding our id or the lowest free one, and our
        ExtensionSettings entry is MERGED with the org's (BUG-182). Without it (the Json
        artifact) the plan assumes empty keys: slot '1', a fresh ExtensionSettings.

    .PARAMETER MinimumVersion
        Optional ExtensionSettings minimum_version_required (IMP-49 r -- was unreachable).

    .PARAMETER BulkThreshold
        Optional tenant-wide bulkActivateConfirmThreshold (1..100) written as a DWORD next
        to tenantCatalog (managed-schema.json). 0 = not written (IMP-49 r).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Catalog,
        [ValidateSet('Both','Edge','Chrome')][string]$Browser = 'Both',
        [Parameter(Mandatory)][string]$ExtensionId,
        [Parameter(Mandatory)][string]$UpdateUrl,
        [Parameter(Mandatory)][string]$SourcePattern,
        [hashtable]$ExistingState,
        [string]$MinimumVersion,
        [ValidateRange(0, 100)][int]$BulkThreshold = 0,
        # Per-DEVICE auto-activate cap (2026-09-23): autoActivateMaxGroups DWORD next to tenantCatalog.
        # -1 = not written (no limit); 0 = auto-activation off; N = at most N groups.
        [ValidateRange(-1, 100)][int]$AutoActivateMaxGroups = -1
    )

    $WhatIfPreference = $false   # pure builder -- never a confirmable op

    $browsers = switch ($Browser) {
        'Both'   { @('Edge','Chrome') }
        'Edge'   { @('Edge') }
        'Chrome' { @('Chrome') }
    }

    $catalogJson  = ConvertTo-PaHybridCatalogJson -Catalog $Catalog
    $forcelistVal = New-PaHybridForcelistValue   -ExtensionId $ExtensionId -UpdateUrl $UpdateUrl
    $extSettings  = New-PaHybridExtensionSettingsJson -ExtensionId $ExtensionId -UpdateUrl $UpdateUrl -MinimumVersion $MinimumVersion
    $ourSettings  = New-PaExtensionSettingsEntry -UpdateUrl $UpdateUrl -MinimumVersion $MinimumVersion
    $isOurForcelistRow = New-PaRowMatcher -ExtensionId $ExtensionId

    $entries = New-Object System.Collections.Generic.List[object]
    $slots   = [ordered]@{}

    foreach ($b in $browsers) {
        $vendor   = $script:PaHybridVendorPath[$b]
        $polKey   = "SOFTWARE\Policies\$vendor"
        $thirdKey = "SOFTWARE\Policies\$vendor\3rdparty\extensions\$ExtensionId\policy"
        $st = if ($ExistingState -and $ExistingState.ContainsKey($b)) { $ExistingState[$b] } else { @{} }
        $stGet = { param($k) if ($st -is [System.Collections.IDictionary] -and $st.Contains($k)) { $st[$k] } else { $null } }

        # 1. ExtensionInstallForcelist -- our row in the slot holding our id, else the
        #    lowest free slot. Never a hard-coded '1' (that replaced the org's first row).
        $fl = Get-PaPolicyListPlan -Existing (& $stGet 'Forcelist') -Value $forcelistVal `
                -IsOurs $isOurForcelistRow -ReservedNames @(& $stGet 'ForcelistReserved')
        foreach ($e in (ConvertTo-PaPolicyEntries -Browser $b -Policy 'Forcelist' -PolicyKey $polKey -ListKeyName 'ExtensionInstallForcelist' -ListOps $fl.Ops)) { $entries.Add($e) }

        # 2. ExtensionInstallSources -- same rule; a row with our exact pattern is reused.
        $sr = Get-PaPolicyListPlan -Existing (& $stGet 'Sources') -Value $SourcePattern `
                -ReservedNames @(& $stGet 'SourcesReserved')
        foreach ($e in (ConvertTo-PaPolicyEntries -Browser $b -Policy 'Sources' -PolicyKey $polKey -ListKeyName 'ExtensionInstallSources' -ListOps $sr.Ops)) { $entries.Add($e) }

        # 3. ExtensionSettings -- MERGED with the org's dictionary ('*' defaults and every
        #    other extension kept). A value we cannot parse stops the plan: fail closed.
        $es = Get-PaExtensionSettingsPlan -ExistingValue (& $stGet 'SettingsValue') -ExistingSubkey (& $stGet 'SettingsSubkey') `
                -ExtensionId $ExtensionId -Settings $ourSettings
        if ($es.Error) { throw "[$b] $($es.Error)" }
        foreach ($e in (ConvertTo-PaPolicyEntries -Browser $b -Policy 'Settings' -PolicyKey $polKey -SettingsOps $es.Ops)) { $entries.Add($e) }

        # 4. tenantCatalog -- single REG_SZ JSON string under the 3rd-party
        #    extension policy path (the ADMX-backed Intune setting writes here).
        #    This key is OURS alone (it carries our extension id), so it is simply set.
        $entries.Add([pscustomobject]@{
            Browser = $b; Policy = 'Catalog'; Hive = 'HKLM'
            Key = $thirdKey; ValueName = 'tenantCatalog'
            ValueKind = 'String'; Value = $catalogJson; Action = 'Set'
        })

        # 4b. Per-tenant bulkActivateConfirmThreshold travels INSIDE tenantCatalog (per
        #     managed-schema.json). The tenant-wide DWORD is emitted only when asked for.
        if ($BulkThreshold -gt 0) {
            $entries.Add([pscustomobject]@{
                Browser = $b; Policy = 'BulkThreshold'; Hive = 'HKLM'
                Key = $thirdKey; ValueName = 'bulkActivateConfirmThreshold'
                ValueKind = 'Dword'; Value = $BulkThreshold; Action = 'Set'
            })
        }

        # 4c. Per-device auto-activate cap -- device policy only, never inside tenantCatalog.
        if ($AutoActivateMaxGroups -ge 0) {
            $entries.Add([pscustomobject]@{
                Browser = $b; Policy = 'AutoActivateMax'; Hive = 'HKLM'
                Key = $thirdKey; ValueName = 'autoActivateMaxGroups'
                ValueKind = 'Dword'; Value = $AutoActivateMaxGroups; Action = 'Set'
            })
        }

        $slots[$b] = [pscustomobject]@{ Forcelist = $fl.Slot; ForcelistReused = $fl.Reused; Sources = $sr.Slot; SettingsLayout = $es.Layout }
    }

    return [pscustomobject]@{
        CatalogJson       = $catalogJson
        ForcelistValue    = $forcelistVal
        ExtensionSettings = $extSettings
        Browsers          = $browsers
        Entries           = $entries.ToArray()
        Slots             = $slots
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
        $managed = [ordered]@{ tenantCatalog = $Plan.CatalogJson }
        $bulk = @($Plan.Entries | Where-Object { $_.Browser -eq $b -and $_.Policy -eq 'BulkThreshold' } | Select-Object -First 1)
        if ($bulk.Count -gt 0) { $managed['bulkActivateConfirmThreshold'] = [int]$bulk[0].Value }
        $amx = @($Plan.Entries | Where-Object { $_.Browser -eq $b -and $_.Policy -eq 'AutoActivateMax' } | Select-Object -First 1)
        if ($amx.Count -gt 0) { $managed['autoActivateMaxGroups'] = [int]$amx[0].Value }
        $out[$b] = [ordered]@{
            ExtensionInstallForcelist = @($Plan.ForcelistValue)
            ExtensionInstallSources   = @(($Plan.Entries | Where-Object { $_.Browser -eq $b -and $_.Policy -eq 'Sources' } | Select-Object -First 1).Value)
            ExtensionSettings         = $Plan.ExtensionSettings
            managedConfig             = $managed
        }
    }
    return [pscustomobject]$out
}
