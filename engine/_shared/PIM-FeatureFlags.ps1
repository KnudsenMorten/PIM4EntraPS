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
    [ordered]@{ id = 'revoke';      label = 'Maintenance / Revoke';     default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'approvals';   label = 'Approvals';                default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'jobs';        label = 'Jobs';                     default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'governance';  label = 'Governance & Drift';       default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'roleperms';   label = 'Role Lookup';              default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'audit';       label = 'Audit';                    default = $true;  alwaysOn = $true  }
    [ordered]@{ id = 'support';     label = 'Support';                  default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'settings';    label = 'Settings';                 default = $true;  alwaysOn = $true  }
    # ---- Promoted to default ON (operator, 2026-08-31) -------------------------
    # 🔑 These four shipped OFF "for gradual rollout" and the rollout never happened. The
    # delegation wizard has existed since 2026-06-15 and was invisible in the operator's own
    # portal the entire time -- he asked "where is the wizard, as i dont see it in the portal",
    # and the answer was this line. A surface nobody can see is not a cautious rollout, it is a
    # feature that was built and then hidden; and the §35 complaint that authoring is cramped
    # was partly caused by the guided alternative being switched off.
    # Operator decision: "delegation wizard, onboarding, advanced view grid, reports must be on
    # by default." An operator who does not want one still turns it off in Settings -> Features.
    [ordered]@{ id = 'new';         label = 'Create (delegation wizard)'; default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'onboarding';  label = 'Onboarding';               default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'grid';        label = 'Advanced View (grid)';     default = $true;  alwaysOn = $false }
    [ordered]@{ id = 'reports';     label = 'Reports';                  default = $true;  alwaysOn = $false }
    # ---- Newer / advanced surfaces (default OFF -- enabled gradually) ----------
    # accessreview stays OFF: it was NOT named in the operator's decision, and promoting a
    # surface he did not ask for would be exactly the drift this catalog exists to prevent.
    [ordered]@{ id = 'accessreview';label = 'Access Review';            default = $false; alwaysOn = $false }
    [ordered]@{ id = 'conformance'; label = 'Template Rollout';         default = $false; alwaysOn = $false }
    # MSP-2 / control #1+#2. OFF by shipped default like every other advanced surface:
    # most deployments are single-tenant and have no managed relationships at all, so the
    # tab would render an empty view. An MSP turns it on deliberately.
    # 🔴 `requires` (operator 2026-09-20: "should not be possible to select in single domain setup"):
    # OFF-by-default was not enough -- on a SINGLE-tenant deployment the checkbox was still live, so the
    # operator could switch on a surface that has nothing behind it and no write of which is legal here.
    # A surface that needs a topology this tenant is NOT is not a choice: it is locked OFF with the
    # reason, exactly the way an always-on surface is locked ON.
    [ordered]@{ id = 'downlink';    label = 'MSP Downlink';             default = $false; alwaysOn = $false; requires = 'msp-master' })

# What each `requires` value means, in one phrase -- shown on the locked toggle and in the refusal.
$script:PimFeatureFlagRequirementText = @{
    'msp-master' = 'an MSP master (this deployment manages no other tenants)'
}

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
            requires = "$($f.requires)"
        })
    }
    return @($out.ToArray())
}

function Test-PimFeatureFlagTopologyAllowed {
    # PURE. May a surface with this `requires` value exist in a deployment with this topology?
    # A flag with NO requirement is always allowed. An UNKNOWN requirement fails CLOSED -- a
    # requirement we cannot evaluate must not silently become "no requirement".
    param([AllowNull()][string]$Requires, [bool]$IsMspMaster)
    $r = "$Requires".Trim().ToLowerInvariant()
    if (-not $r) { return $true }
    if ($r -eq 'msp-master') { return [bool]$IsMspMaster }
    return $false
}

function Get-PimFeatureFlagRequirementText {
    param([AllowNull()][string]$Requires)
    $r = "$Requires".Trim().ToLowerInvariant()
    if (-not $r) { return '' }
    if ($script:PimFeatureFlagRequirementText.ContainsKey($r)) { return "$($script:PimFeatureFlagRequirementText[$r])" }
    return "a deployment of type '$r'"
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
    #   - a flag whose `requires` this deployment does not satisfy is forced OFF and marked
    #     unavailable -- but ONLY when the caller tells us the topology (-IsMspMaster). A caller
    #     that does not know it passes nothing and gets exactly the old behaviour; the alternative,
    #     guessing, would hide an MSP master's own Downlink tab the moment a read failed.
    # Returns @{ flags=<ordered id->bool>; effective=<id->object>; warnings=<string[]> }.
    # `effective` carries per-flag id/label/enabled/default/alwaysOn/available/unavailableReason.
    param([object]$Raw, [AllowNull()][object]$IsMspMaster = $null)
    $topologyKnown = ($null -ne $IsMspMaster)
    $isMaster = [bool]$IsMspMaster

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
        # Topology guard: a surface this deployment cannot host is locked OFF, whatever is stored.
        $available = $true
        $unavailableReason = ''
        if ($topologyKnown -and "$($f.requires)".Trim()) {
            $available = Test-PimFeatureFlagTopologyAllowed -Requires "$($f.requires)" -IsMspMaster $isMaster
            if (-not $available) {
                $unavailableReason = "needs $(Get-PimFeatureFlagRequirementText -Requires "$($f.requires)")"
                if ($enabled) { $warnings.Add("Feature '$id' $unavailableReason; forced off.") }
                $enabled = $false
            }
        }
        $flags[$id] = $enabled
        $effective[$id] = [ordered]@{
            id       = $id
            label    = "$($f.label)"
            enabled  = $enabled
            default  = [bool]$f.default
            alwaysOn = [bool]$f.alwaysOn
            requires = "$($f.requires)"
            available = $available
            unavailableReason = $unavailableReason
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
    # With -IsMspMaster, a surface this deployment cannot host resolves OFF and therefore never
    # reaches the store as an ON override -- the refusal is here, not only in the GUI's disabled box.
    param([object]$Raw, [AllowNull()][object]$IsMspMaster = $null)
    $resolved = Resolve-PimFeatureFlags -Raw $Raw -IsMspMaster $IsMspMaster
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
