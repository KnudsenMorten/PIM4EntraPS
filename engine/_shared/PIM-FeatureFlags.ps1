# =============================================================================
# PIM-FeatureFlags.ps1 -- Manager feature-flag registry (REQUIREMENTS [GUI gradual rollout]).
#
# A declarative catalog of the Manager's toggleable GUI surfaces (the tabs /
# major panels) plus a PURE resolver that merges the shipped defaults with the
# operator's persisted on/off overrides (pim.Settings key 'FeatureFlags'). The
# operator turns features on one-by-one over time, so newer/advanced surfaces
# ship OFF by default and core surfaces ship ON.
#
# WHY a shared lib: the GUI nav/tab render AND any server-side gate must resolve
# the SAME effective flag set from the SAME persisted store -- GUI state ==
# actual behaviour (the CLAUDE.md invariant). This file holds NO I/O: it takes a
# raw stored value (whatever the single Get-/Set-PimManagerSetting store handed
# back) and returns a normalized, default-applied, always-on-guarded map. The
# Manager's Get-/Set-PimFeatureFlags wrappers do the persistence through that
# same chokepoint.
#
# PS 5.1 COMPATIBLE: no ?. / ??, no RSA.ImportFromPem, null-guarded property
# access (no $null.Prop NRE), IDictionary-vs-PSCustomObject dual reads (a value
# round-tripped in-process is a hashtable; one round-tripped through JSON is a
# PSCustomObject -- PSObject.Properties does NOT see dictionary keys).
# =============================================================================

# The flag catalog. `id` MUST equal the GUI's data-tab key so the nav/tab render
# can gate directly on it. `default` = shipped on/off (core ON, newer/advanced
# OFF for gradual rollout). `alwaysOn` = the operator can never disable it (e.g.
# Settings itself -- disabling it would lock the operator out of this very panel;
# Home is the landing tab and the audit trail must always be reachable).
$script:PimFeatureFlagCatalog = @(
    # ---- Core surfaces (default ON) -------------------------------------------
    [ordered]@{ id = 'home';        label = 'Home / Overview';          default = $true;  alwaysOn = $true  }
    [ordered]@{ id = 'map';         label = 'Delegation Map';           default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'authoring';   label = 'Authoring';                default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'save';        label = 'Review & Save';            default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'validate';    label = 'Validate';                 default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'cutover';     label = 'Cutover';                  default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'revoke';      label = 'Maintenance / Revoke';     default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'approvals';   label = 'Approvals';                default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'jobs';        label = 'Jobs';                     default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'governance';  label = 'Governance & Drift';       default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'roleperms';   label = 'Role Lookup';              default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'audit';       label = 'Audit';                    default = $true;  alwaysOn = $true  }
    [ordered]@{ id = 'support';     label = 'Support';                  default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'settings';    label = 'Settings';                 default = $true;  alwaysOn = $true  }
    # ---- Newer / advanced surfaces (default OFF -- enabled gradually) ----------
    [ordered]@{ id = 'new';         label = 'Create (delegation wizard)'; default = $false; alwaysOn = $false }
    [ordered]@{ id = 'onboarding';  label = 'Onboarding';               default = $false; alwaysOn = $false }
    [ordered]@{ id = 'grid';        label = 'Advanced View (grid)';     default = $false; alwaysOn = $false }
    [ordered]@{ id = 'accessreview';label = 'Access Review';            default = $false; alwaysOn = $false }
    [ordered]@{ id = 'reports';     label = 'Reports';                  default = $false; alwaysOn = $false }
    [ordered]@{ id = 'conformance'; label = 'Template Rollout';         default = $false; alwaysOn = $false }
)

function Get-PimFeatureFlagCatalog {
    # Return a fresh COPY of the catalog (ordered hashtables) so a caller can
    # never mutate the module-level definition.
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($f in $script:PimFeatureFlagCatalog) {
        $out.Add([ordered]@{
            id       = "$($f.id)"
            label    = "$($f.label)"
            default  = [bool]$f.default
            alwaysOn = [bool]$f.alwaysOn
        })
    }
    return @($out.ToArray())
}

function Get-PimFeatureFlagValue {
    # Null-safe property read across hashtable / IDictionary / PSCustomObject.
    # (Same dual-read pattern as PIM-OperationalPolicy.ps1: an in-process value is
    # a hashtable; a JSON-round-tripped value is a PSCustomObject.)
    param([object]$Object, [Parameter(Mandatory)][string]$Key)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Key)) { return $Object[$Key] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    return $null
}

function Resolve-PimFeatureFlags {
    # Take a raw stored overrides object (any shape, possibly partial / null /
    # JSON string) and return the EFFECTIVE flag map merged over the catalog
    # defaults, with the always-on guard applied:
    #   - start from each catalog flag's `default`
    #   - apply a persisted override ($true/$false) for a KNOWN flag id
    #   - an UNKNOWN flag id in the store is IGNORED (never invents a surface)
    #   - an always-on flag is forced ON regardless of the override (no lock-out)
    # Returns @{ flags=<ordered id->bool>; effective=<id->object>; warnings=<string[]> }.
    # `effective` carries per-flag id/label/enabled/default/alwaysOn for the GUI.
    param([object]$Raw)

    $warnings = New-Object System.Collections.Generic.List[string]
    $raw = $Raw
    if ($raw -is [string]) {
        $s = "$raw".Trim()
        if ($s) { try { $raw = $s | ConvertFrom-Json } catch { $raw = $null; $warnings.Add('FeatureFlags store value is not valid JSON; using defaults.') } }
        else { $raw = $null }
    }
    # The override map may be nested under a 'flags' key (the shape we persist) or
    # be a flat id->bool map (a hand-edited / partial value) -- accept both.
    $overrideContainer = $raw
    $flagsNode = Get-PimFeatureFlagValue -Object $raw -Key 'flags'
    if ($null -ne $flagsNode) { $overrideContainer = $flagsNode }

    # Set of known ids (for the unknown-flag-ignored rule + a warning so a typo is
    # surfaced rather than silently dropped).
    $catalog = Get-PimFeatureFlagCatalog
    $known = @{}
    foreach ($f in $catalog) { $known["$($f.id)"] = $true }

    # Surface unknown override ids (ignored, but reported).
    if ($null -ne $overrideContainer) {
        $overKeys = @()
        if ($overrideContainer -is [System.Collections.IDictionary]) { $overKeys = @($overrideContainer.Keys) }
        else { $overKeys = @($overrideContainer.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($k in $overKeys) {
            if ($k -eq 'flags') { continue }
            if (-not $known.ContainsKey("$k")) { $warnings.Add("Unknown feature flag '$k' in store; ignored.") }
        }
    }

    $flags = [ordered]@{}
    $effective = [ordered]@{}
    foreach ($f in $catalog) {
        $id = "$($f.id)"
        $enabled = [bool]$f.default
        $ov = Get-PimFeatureFlagValue -Object $overrideContainer -Key $id
        if ($null -ne $ov) { $enabled = [bool]$ov }
        # Always-on guard: a protected surface can never be turned off (lock-out).
        if ([bool]$f.alwaysOn) {
            if (-not $enabled) { $warnings.Add("Feature '$id' is always-on and cannot be disabled; forced on.") }
            $enabled = $true
        }
        $flags[$id] = $enabled
        $effective[$id] = [ordered]@{
            id       = $id
            label    = "$($f.label)"
            enabled  = $enabled
            default  = [bool]$f.default
            alwaysOn = [bool]$f.alwaysOn
        }
    }
    return @{ flags = $flags; effective = $effective; warnings = @($warnings.ToArray()) }
}

function ConvertTo-PimFeatureFlagOverrides {
    # Reduce a (possibly full effective) flag map down to the MINIMAL override set
    # we persist: only flags whose desired value DIFFERS from the catalog default,
    # EXCLUDING always-on flags (their value is fixed, never stored). Unknown ids
    # are dropped. This keeps pim.Settings small and means a future default change
    # flows through to any flag the operator never explicitly touched.
    # Returns an ordered id->bool map suitable for storing under { flags = ... }.
    param([object]$Raw)
    $resolved = Resolve-PimFeatureFlags -Raw $Raw
    $catalog = Get-PimFeatureFlagCatalog
    $defaults = @{}; $always = @{}
    foreach ($f in $catalog) { $defaults["$($f.id)"] = [bool]$f.default; $always["$($f.id)"] = [bool]$f.alwaysOn }
    $overrides = [ordered]@{}
    foreach ($id in $resolved.flags.Keys) {
        if ($always[$id]) { continue }
        if ([bool]$resolved.flags[$id] -ne [bool]$defaults[$id]) { $overrides[$id] = [bool]$resolved.flags[$id] }
    }
    return $overrides
}
