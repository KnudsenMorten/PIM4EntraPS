# =============================================================================
# PIM-GovernancePreview.ps1 -- "show the surface, safely OFF" preview gate for the
# two governance features (REQUIREMENTS s27 approval-gated offboarding + revoke,
# and s28 [L2] active-exemptions register on Template Rollout).
#
# WHY THIS EXISTS
# ---------------
# These two governance surfaces are SECURITY-SENSITIVE (automatic offboarding is
# operator-PROHIBITED -- 2026-06-15 mass-disable incident, REQUIREMENTS s13/s22).
# This gate lets the maintainer SEE both Manager surfaces in a *preview* state --
# rendered + reachable, but clearly marked "preview -- disabled in Settings" and
# INERT (no destructive endpoint may act) -- with each feature OFF BY DEFAULT.
#
# Unlike the feature-flag registry (PIM-FeatureFlags.ps1), which HIDES a disabled
# surface entirely, this preview gate keeps the surface VISIBLE so it can be
# reviewed, while neutering its action paths. The two are orthogonal: a surface is
# shown only if its feature flag is ON *and*, when in preview, it renders disabled.
#
# CONTRACT (the safety invariant)
# -------------------------------
#   * Default = OFF for BOTH (approvals + conformance preview). A no-op preview.
#   * While OFF, the GUI shows a "preview -- disabled in Settings" banner and the
#     server's mutating endpoints for that surface SHORT-CIRCUIT (return a
#     preview-disabled marker, do nothing). It NEVER changes the always-on safety
#     gates (DisableGuard breaker, break-glass exclusion, "automatic offboarding
#     prohibited") -- those stay enforced regardless of this flag.
#   * Turning a preview ON does NOT bypass any safety gate -- it only stops the
#     preview short-circuit, after which the EXISTING (already-delivered) maker/
#     checker + DisableGuard composite gates govern behaviour exactly as before.
#
# WHERE IT LIVES: persisted under pim.Settings key 'GovernancePreview' via the
# SAME Get-/Set-PimManagerSetting chokepoint every other Manager setting uses, so
# the GUI boot-injected value == the value the endpoint guard reads (GUI state ==
# actual behaviour -- the CLAUDE.md invariant). This file holds NO I/O: PURE
# resolver over a raw stored value, PS 5.1-safe (no ?./??, null-guarded,
# IDictionary-vs-PSCustomObject dual reads).
# =============================================================================

Set-StrictMode -Off

# The preview catalog. `id` is the persisted key; `surface` is the GUI data-tab it
# governs. `default` is the shipped state -- OFF for BOTH (the whole point of this
# gate is "show me the surface, safely off"). A NEW preview feature is added here.
$script:PimGovernancePreviewCatalog = @(
    [ordered]@{ id = 'approvalsPreview';   surface = 'approvals';   default = $false; label = 'Approval-gated offboarding + revoke (preview)' }
    [ordered]@{ id = 'conformancePreview'; surface = 'conformance'; default = $false; label = 'Active-exemptions register on Template Rollout (preview)' }
)

function Get-PimGovernancePreviewCatalog {
    # Defensive copy of the catalog (callers must not mutate the module state).
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($f in $script:PimGovernancePreviewCatalog) {
        $out.Add([ordered]@{ id = "$($f.id)"; surface = "$($f.surface)"; default = [bool]$f.default; label = "$($f.label)" })
    }
    return $out.ToArray()
}

function ConvertTo-PimPreviewBool {
    # Coerce a stored/over-the-wire value to a strict bool. $null -> $null (caller
    # decides the default). Accepts real bools, the JSON strings, and 0/1.
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return [bool]$Value }
    $s = "$Value".Trim().ToLowerInvariant()
    if ($s -eq '') { return $null }
    if ($s -in @('1','true','yes','y','on','enable','enabled'))  { return $true }
    if ($s -in @('0','false','no','n','off','disable','disabled')) { return $false }
    return $null
}

function Resolve-PimGovernancePreview {
    # PURE: merge the shipped defaults (OFF) with the operator's persisted overrides.
    # $Raw is whatever Get-PimManagerSetting handed back for 'GovernancePreview' --
    #   a hashtable (in-proc round-trip), a PSCustomObject (JSON round-trip), a JSON
    #   string, or $null/garbage. Unknown keys are ignored. A bad/absent value for a
    #   known key falls back to its default (OFF). Returns:
    #     @{ flags = <id->bool>; enabled = <id->bool, alias of flags>; catalog = <...>;
    #        anyEnabled = <bool>; warnings = <string[]> }
    [CmdletBinding()]
    param([object]$Raw)

    $warnings = New-Object System.Collections.Generic.List[string]

    # Normalize $Raw down to a property bag we can read by key.
    $bag = $null
    if ($null -ne $Raw) {
        if ($Raw -is [string]) {
            $t = $Raw.Trim()
            if ($t) {
                try { $bag = $t | ConvertFrom-Json } catch { $warnings.Add("GovernancePreview store value is not valid JSON -- using defaults (OFF).") | Out-Null; $bag = $null }
            }
        } else {
            $bag = $Raw
        }
    }
    # Accept a { flags: {...} } wrapper or a flat id->bool map.
    if ($null -ne $bag) {
        $inner = $null
        if ($bag -is [System.Collections.IDictionary]) {
            if ($bag.Contains('flags')) { $inner = $bag['flags'] }
        } else {
            $p = $bag.PSObject.Properties['flags']
            if ($p) { $inner = $p.Value }
        }
        if ($null -ne $inner) { $bag = $inner }
    }

    $readKey = {
        param($Bag, $Key)
        if ($null -eq $Bag) { return $null }
        if ($Bag -is [System.Collections.IDictionary]) {
            if ($Bag.Contains($Key)) { return $Bag[$Key] }
            return $null
        }
        $pp = $Bag.PSObject.Properties[$Key]
        if ($pp) { return $pp.Value }
        return $null
    }

    $flags = [ordered]@{}
    foreach ($f in $script:PimGovernancePreviewCatalog) {
        $id  = "$($f.id)"
        $def = [bool]$f.default
        $val = & $readKey $bag $id
        $b   = ConvertTo-PimPreviewBool -Value $val
        if ($null -eq $b) { $b = $def }
        $flags[$id] = [bool]$b
    }

    # Warn on any unknown key in the store (typo guard) -- ignored, not applied.
    if ($bag -is [System.Collections.IDictionary]) {
        foreach ($k in @($bag.Keys)) { if (-not ($flags.Contains("$k"))) { $warnings.Add("Unknown GovernancePreview flag '$k' ignored.") | Out-Null } }
    } elseif ($null -ne $bag) {
        foreach ($pp in @($bag.PSObject.Properties)) { if (-not ($flags.Contains("$($pp.Name)"))) { $warnings.Add("Unknown GovernancePreview flag '$($pp.Name)' ignored.") | Out-Null } }
    }

    $any = $false
    foreach ($k in $flags.Keys) { if ($flags[$k]) { $any = $true } }

    return [ordered]@{
        flags      = $flags
        enabled    = $flags
        catalog    = @(Get-PimGovernancePreviewCatalog)
        anyEnabled = [bool]$any
        warnings   = @($warnings.ToArray())
    }
}

function Test-PimGovernancePreviewEnabled {
    # PURE convenience: is a named preview feature ENABLED (not in preview-disabled
    # state)? $Resolved is the output of Resolve-PimGovernancePreview. An unknown id
    # is treated as NOT enabled (fail-safe: an unrecognised surface stays inert).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Resolved,
        [Parameter(Mandatory)][string]$Id
    )
    if ($null -eq $Resolved) { return $false }
    $flags = $null
    if ($Resolved -is [System.Collections.IDictionary]) {
        if ($Resolved.Contains('flags')) { $flags = $Resolved['flags'] }
    } else {
        $p = $Resolved.PSObject.Properties['flags']
        if ($p) { $flags = $p.Value }
    }
    if ($null -eq $flags) { return $false }
    if ($flags -is [System.Collections.IDictionary]) {
        if ($flags.Contains($Id)) { return [bool]$flags[$Id] }
        return $false
    }
    $pp = $flags.PSObject.Properties[$Id]
    if ($pp) { return [bool]$pp.Value }
    return $false
}

function ConvertTo-PimGovernancePreviewOverrides {
    # Reduce a (partial/full) flag map to the MINIMAL override set -- only keys that
    # differ from their shipped default. The store never holds redundant values, so
    # a fresh/default install persists {} (and stays OFF). PS 5.1-safe dual reads.
    [CmdletBinding()]
    param([object]$Raw)

    $bag = $Raw
    if ($Raw -is [string]) { try { $bag = $Raw | ConvertFrom-Json } catch { $bag = $null } }
    if ($bag -is [System.Collections.IDictionary] -and $bag.Contains('flags')) { $bag = $bag['flags'] }
    elseif ($bag -isnot [System.Collections.IDictionary] -and $null -ne $bag) {
        $p = $bag.PSObject.Properties['flags']; if ($p) { $bag = $p.Value }
    }

    $out = [ordered]@{}
    foreach ($f in $script:PimGovernancePreviewCatalog) {
        $id = "$($f.id)"; $def = [bool]$f.default
        $val = $null
        if ($bag -is [System.Collections.IDictionary]) { if ($bag.Contains($id)) { $val = $bag[$id] } }
        elseif ($null -ne $bag) { $pp = $bag.PSObject.Properties[$id]; if ($pp) { $val = $pp.Value } }
        $b = ConvertTo-PimPreviewBool -Value $val
        if ($null -ne $b -and [bool]$b -ne $def) { $out[$id] = [bool]$b }
    }
    return $out
}
