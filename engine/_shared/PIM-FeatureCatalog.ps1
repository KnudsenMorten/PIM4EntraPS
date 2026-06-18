# =============================================================================
# PIM-FeatureCatalog.ps1 -- the SINGLE source of truth for customizable
# capabilities + the gate functions (REQUIREMENTS s29 + s30).
#
# WHY this file exists (and how it relates to the two PRE-EXISTING layers):
#   * PIM-FeatureFlags.ps1  -- gates the Manager's GUI SURFACES (tabs/panels) for
#                              gradual rollout. Per-operator visibility, not behaviour.
#   * PIM-License.ps1       -- the offline signed-license Core/Pro EDITION model
#                              (Test-PimProFeature / Get-PimEdition). Commercial gate.
#   * PIM-FeatureCatalog.ps1 (this) -- the unified CAPABILITY catalog: every
#                              customizable engine/job/integration capability with a
#                              tier (core|advanced), a license tier (free|pro), a
#                              feature GROUP (chapter), a default-enabled flag, and
#                              dependsOn. It is the catalog the GUI renders, the
#                              engine + jobs gate on, and the classification TEST reads.
#
# This file BUILDS ON the others -- it does not replace them. The combined gate
# (Test-PimFeatureAvailable) = ENABLED (kill switch, this catalog's persisted
# state) AND LICENSED (this catalog's license tier vs the active edition, resolved
# through Get-PimEdition from PIM-License.ps1). CORE features are NEVER in the gate
# (always on, always free) -- only ADVANCED features are gateable.
#
# PURE-ish: the catalog itself + the resolver (Resolve-PimFeatureGate) are pure (no
# I/O), mirroring PIM-FeatureFlags.ps1. The gate FUNCTIONS read the persisted kill
# switch from the settings store; they do so through a small store-reader seam
# (Get-PimFeatureGateState) that prefers an already-hydrated in-process value
# ($global:PIM_NamingConventions['FeatureGates'] / $global:PIM_FeatureGates), then
# a Get-PimSetting bridge (Manager), then a direct SQL read against
# $global:PIM_EngineSqlCs (engine/jobs) -- so ONE persisted state drives the GUI,
# the engine and the scheduler identically.
#
# PS 5.1 COMPATIBLE: no ?. / ??, no .ToArray() on @()-wrapped List[object] of
# PSCustomObjects, null-guarded property access, IDictionary-vs-PSCustomObject
# dual reads (a value round-tripped in-process is a hashtable; one round-tripped
# through JSON is a PSCustomObject).
# =============================================================================

# pim.Settings key the persisted per-feature kill switch lives under (the same
# store the engine + jobs already read at runtime). Shape:
#   { gates: { '<featureKey>': $true|$false, ... } }   (only non-default overrides)
$script:PimFeatureGateSettingKey = 'FeatureGates'
# pim.Settings key the active edition lives under (license backend, s30). Shape:
#   { edition: 'Core'|'Pro'|'Pro-DesignPartner'; grantBasis: 'paid'|'design-partner'|''; note: '...' }
$script:PimEditionSettingKey = 'Edition'

# The recognised editions (s30). 'Pro' and 'Pro-DesignPartner' BOTH unlock every
# 'pro' feature; they differ only in the recorded commercial grant basis.
$script:PimEditionNames = @('Core', 'Pro', 'Pro-DesignPartner')

# ---------------------------------------------------------------------------
# THE CATALOG -- one declarative entry per CUSTOMIZABLE capability.
#   key            stable id (the kill-switch + license key; never renamed)
#   label          human/display name
#   group          feature GROUP / chapter heading the GUI renders under
#   tier           'core'      = essential surface, ALWAYS on, NOT gateable
#                  'advanced'  = optional/side-effecting, gateable (kill switch)
#   license        'free'      = available in every edition (incl. Core)
#                  'pro'       = requires a Pro / Pro-DesignPartner edition
#   defaultEnabled advanced features default OFF (opt-in; an upgrade never springs
#                  a new behaviour on a customer). Core is implicitly always-on.
#   dependsOn      other feature keys that must be available for this to function.
#   proFeature     (optional) the PIM-License.ps1 Pro-feature-catalog name this
#                  maps to, so the existing Test-PimProFeature gate stays in sync.
#   description    short operator-facing note (safe, generic).
#
# CORE entries are listed too (for the GUI to SHOW them, dimmed/locked-on), but
# they are never gated: the gate functions always return available for tier=core.
# ---------------------------------------------------------------------------
$script:PimFeatureCatalog = @(
    # ---- Core PIM surface (always on, free, NOT gateable) ---------------------
    [ordered]@{ key='engine.reconcile'; label='Engine reconcile';        group='Core PIM';     tier='core';     license='free'; defaultEnabled=$true;  dependsOn=@();                       proFeature='';                  description='Desired-vs-live reconcile of delegation (create/update). The essential engine; never disabled.' }
    [ordered]@{ key='delegation.read';  label='Delegation map (read)';   group='Core PIM';     tier='core';     license='free'; defaultEnabled=$true;  dependsOn=@();                       proFeature='';                  description='Read/search the delegation model. Always available.' }
    [ordered]@{ key='authoring';        label='Authoring / Review & Save';group='Core PIM';    tier='core';     license='free'; defaultEnabled=$true;  dependsOn=@();                       proFeature='';                  description='Author and commit delegation changes. Always available.' }

    # ---- Discovery (advanced) -------------------------------------------------
    [ordered]@{ key='discovery.sweep';  label='Discovery sweep';         group='Discovery';    tier='advanced'; license='free'; defaultEnabled=$false; dependsOn=@('engine.reconcile');     proFeature='AzureDiscovery';    description='End-of-run sweep that enumerates Azure scopes + Power BI workspaces and flags/auto-creates new resources. Off = no discovery, no auto-create.' }

    # ---- Notifications / Email (advanced) -------------------------------------
    [ordered]@{ key='alerting.email';   label='Email alerting';          group='Notifications';tier='advanced'; license='free'; defaultEnabled=$false; dependsOn=@();                       proFeature='';                  description='Email notifications for engine-failure / drift / expiring-access / break-glass and the daily/tier digests. Off = no mail is sent.' }
    [ordered]@{ key='alerting.webhook'; label='Teams / webhook alerting';group='Notifications';tier='advanced'; license='free'; defaultEnabled=$false; dependsOn=@('alerting.email');       proFeature='';                  description='Post alerts to a Microsoft Teams / generic webhook in addition to email. Off = no webhook POST.' }

    # ---- Workload connectors / integrations (advanced, Pro) -------------------
    [ordered]@{ key='connectors.workload'; label='Workload connectors (app-role)'; group='Integrations'; tier='advanced'; license='pro'; defaultEnabled=$false; dependsOn=@('engine.reconcile'); proFeature='WorkloadConnectors'; description='Enterprise-app app-role + workload-RBAC connectors (Defender XDR, Intune, generic app-role, Azure DevOps, Dataverse, Business Central, Power Platform). Off = these providers no-op.' }
    [ordered]@{ key='connectors.powerbi';  label='Power BI integration';            group='Integrations'; tier='advanced'; license='pro'; defaultEnabled=$false; dependsOn=@('discovery.sweep');   proFeature='WorkloadConnectors'; description='Power BI workspace discovery + role reconcile. Off = Power BI is skipped by the discovery sweep.' }
    [ordered]@{ key='connectors.exo';      label='Exchange Online integration';     group='Integrations'; tier='advanced'; license='pro'; defaultEnabled=$false; dependsOn=@('engine.reconcile');  proFeature='WorkloadConnectors'; description='Exchange Online role-group delegation (ManageAsApp). Off = EXO delegation is not applied.' }

    # ---- MSP (advanced, Pro) --------------------------------------------------
    [ordered]@{ key='msp.downlink';     label='MSP downlink / fan-out';  group='MSP';          tier='advanced'; license='pro';  defaultEnabled=$false; dependsOn=@('engine.reconcile');     proFeature='MspFanout';         description='Fan a central admin baseline out to managed customer tenants (pull-not-push). Off = no fan-out runs.' }

    # ---- Scheduler / automated jobs (advanced) --------------------------------
    [ordered]@{ key='scheduler.jobs';   label='Scheduled jobs';          group='Automation';   tier='advanced'; license='free'; defaultEnabled=$false; dependsOn=@();                       proFeature='';                  description='The in-container/VM scheduler that drives reminders, digests, discovery, queue-apply, tenant-cache and engine runs on a cadence. Off = no scheduled job runs (manual/commit triggers still work via their own gates).' }
)

function Get-PimFeatureCatalog {
    # Return a fresh COPY of the catalog so a caller can never mutate the module
    # definition. Each entry is a fresh [ordered] hashtable.
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($f in $script:PimFeatureCatalog) {
        $deps = @(); if ($f.dependsOn) { foreach ($d in @($f.dependsOn)) { if ("$d".Trim()) { $deps += "$d" } } }
        $out.Add([ordered]@{
            key            = "$($f.key)"
            label          = "$($f.label)"
            group          = "$($f.group)"
            tier           = "$($f.tier)"
            license        = "$($f.license)"
            defaultEnabled = [bool]$f.defaultEnabled
            dependsOn      = @($deps)
            proFeature     = "$($f.proFeature)"
            description    = "$($f.description)"
        })
    }
    # PS 5.1: .ToArray() not @()-wrap -- @(List[object] of hashtables) throws
    # ArgumentException (the List[object] @()-wrap trap).
    return $out.ToArray()
}

function Get-PimFeatureCatalogEntry {
    # The single catalog entry for a key, or $null. Case-insensitive on the key.
    param([Parameter(Mandatory)][string]$Key)
    foreach ($f in $script:PimFeatureCatalog) {
        if ("$($f.key)".ToLowerInvariant() -eq "$Key".Trim().ToLowerInvariant()) {
            return (Get-PimFeatureCatalog | Where-Object { "$($_.key)" -eq "$($f.key)" } | Select-Object -First 1)
        }
    }
    return $null
}

function Get-PimFeatureCatalogValue {
    # Null-safe property read across hashtable / IDictionary / PSCustomObject
    # (same dual-read as PIM-FeatureFlags.ps1).
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

# ---------------------------------------------------------------------------
# Pure resolver -- merge persisted kill-switch overrides over catalog defaults.
# Returns @{ gates=<key->bool ENABLED>; effective=<key->object>; warnings=<string[]> }.
# CORE features are always enabled (never gateable); ADVANCED features default OFF
# unless a persisted override or a different catalog default says otherwise.
# ---------------------------------------------------------------------------
function Resolve-PimFeatureGate {
    param([object]$Raw)

    $warnings = New-Object System.Collections.Generic.List[string]
    $raw = $Raw
    if ($raw -is [string]) {
        $s = "$raw".Trim()
        if ($s) { try { $raw = $s | ConvertFrom-Json } catch { $raw = $null; $warnings.Add('FeatureGates store value is not valid JSON; using defaults.') } }
        else { $raw = $null }
    }
    # Overrides may be nested under a 'gates' key (the shape we persist) or a flat
    # key->bool map (hand-edited / partial) -- accept both.
    $overrideContainer = $raw
    $gatesNode = Get-PimFeatureCatalogValue -Object $raw -Key 'gates'
    if ($null -ne $gatesNode) { $overrideContainer = $gatesNode }

    $catalog = Get-PimFeatureCatalog
    $known = @{}
    foreach ($f in $catalog) { $known["$($f.key)"] = $true }

    # Surface unknown override keys (ignored, but reported).
    if ($null -ne $overrideContainer) {
        $overKeys = @()
        if ($overrideContainer -is [System.Collections.IDictionary]) { $overKeys = @($overrideContainer.Keys) }
        else { $overKeys = @($overrideContainer.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($k in $overKeys) {
            if ($k -eq 'gates') { continue }
            if (-not $known.ContainsKey("$k")) { $warnings.Add("Unknown feature '$k' in FeatureGates store; ignored.") }
        }
    }

    $gates = [ordered]@{}
    $effective = [ordered]@{}
    foreach ($f in $catalog) {
        $key = "$($f.key)"
        $isCore = ("$($f.tier)" -eq 'core')
        $enabled = [bool]$f.defaultEnabled
        if ($isCore) {
            # Core is always on; an override can never turn it off.
            $ov = Get-PimFeatureCatalogValue -Object $overrideContainer -Key $key
            if ($null -ne $ov -and -not [bool]$ov) { $warnings.Add("Feature '$key' is core and cannot be disabled; forced on.") }
            $enabled = $true
        } else {
            $ov = Get-PimFeatureCatalogValue -Object $overrideContainer -Key $key
            if ($null -ne $ov) { $enabled = [bool]$ov }
        }
        $gates[$key] = $enabled
        $effective[$key] = [ordered]@{
            key            = $key
            label          = "$($f.label)"
            group          = "$($f.group)"
            tier           = "$($f.tier)"
            license        = "$($f.license)"
            defaultEnabled = [bool]$f.defaultEnabled
            dependsOn      = @($f.dependsOn)
            enabled        = $enabled
        }
    }
    return @{ gates = $gates; effective = $effective; warnings = @($warnings.ToArray()) }
}

function ConvertTo-PimFeatureGateOverrides {
    # Reduce a (possibly full) gate map to the MINIMAL override set we persist:
    # only ADVANCED features whose desired ENABLED value differs from the catalog
    # default. Core features are never stored (they are not gateable). Unknown
    # keys are dropped. Returns an ordered key->bool map for storing under { gates }.
    param([object]$Raw)
    $resolved = Resolve-PimFeatureGate -Raw $Raw
    $catalog = Get-PimFeatureCatalog
    $defaults = @{}; $isCore = @{}
    foreach ($f in $catalog) { $defaults["$($f.key)"] = [bool]$f.defaultEnabled; $isCore["$($f.key)"] = ("$($f.tier)" -eq 'core') }
    $overrides = [ordered]@{}
    foreach ($key in $resolved.gates.Keys) {
        if ($isCore[$key]) { continue }
        if ([bool]$resolved.gates[$key] -ne [bool]$defaults[$key]) { $overrides[$key] = [bool]$resolved.gates[$key] }
    }
    return $overrides
}

# ---------------------------------------------------------------------------
# Store-reader seam -- read the persisted FeatureGates / Edition state. ONE state
# drives GUI + engine + jobs. Prefers an already-hydrated in-process value, then a
# Get-PimSetting bridge (Manager), then a direct SQL read (engine/jobs). PS 5.1-safe.
# ---------------------------------------------------------------------------
function Get-PimFeatureStoreValue {
    # Internal: read a named pim.Settings value via the best available channel.
    param([Parameter(Mandatory)][string]$Name)
    # 1) In-process hydrated naming/conventions bag (Manager mirrors settings here).
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($Name)) {
        return $global:PIM_NamingConventions[$Name]
    }
    # 2) Manager bridge (Get-PimSetting -> Get-PimManagerSetting -> store).
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimSetting -Name $Name; if ($null -ne $v) { return $v } } catch {}
    }
    # 3) Direct SQL read (engine / scheduler process: no Manager bridge present).
    $cs = $null
    if ("$($global:PIM_EngineSqlCs)".Trim()) { $cs = $global:PIM_EngineSqlCs }
    elseif ("$($global:PIM_SqlConnectionString)".Trim()) { $cs = $global:PIM_SqlConnectionString }
    if ($cs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
        try { return (Get-PimSqlSetting -ConnectionString $cs -Name $Name) } catch {}
    }
    return $null
}

function Get-PimFeatureGateState {
    # The resolved gate map (defaults + persisted overrides). Cheap to call; reads
    # the store each time so a toggle takes effect on the next engine/job run.
    $raw = $null
    try { $raw = Get-PimFeatureStoreValue -Name $script:PimFeatureGateSettingKey } catch {}
    return (Resolve-PimFeatureGate -Raw $raw)
}

# ---------------------------------------------------------------------------
# Edition (license backend, s30). Persisted edition wins; falls back to the
# offline signed-license edition (Get-PimEdition from PIM-License.ps1) when no
# explicit edition is set; ultimate default is 'Core'.
# ---------------------------------------------------------------------------
function Resolve-PimEdition {
    # Normalise a raw stored Edition value to one of $script:PimEditionNames.
    # Returns @{ edition; grantBasis; note }.
    param([object]$Raw)
    $raw = $Raw
    if ($raw -is [string]) { $s = "$raw".Trim(); if ($s) { try { $raw = $s | ConvertFrom-Json } catch { $raw = $s } } else { $raw = $null } }
    $edition = $null; $grant = ''; $note = ''
    if ($raw -is [string]) { $edition = "$raw".Trim() }
    elseif ($null -ne $raw) {
        $e = Get-PimFeatureCatalogValue -Object $raw -Key 'edition'; if ($null -ne $e) { $edition = "$e".Trim() }
        $g = Get-PimFeatureCatalogValue -Object $raw -Key 'grantBasis'; if ($null -ne $g) { $grant = "$g".Trim() }
        $n = Get-PimFeatureCatalogValue -Object $raw -Key 'note'; if ($null -ne $n) { $note = "$n".Trim() }
    }
    # Match case-insensitively to a known edition; else Core.
    $resolved = 'Core'
    if ($edition) {
        foreach ($name in $script:PimEditionNames) { if ($name.ToLowerInvariant() -eq $edition.ToLowerInvariant()) { $resolved = $name; break } }
    }
    return @{ edition = $resolved; grantBasis = $grant; note = $note }
}

function Get-PimActiveEdition {
    # The active edition for this tenant: persisted Edition setting wins; else the
    # offline signed-license edition (Get-PimEdition, mapped Pro/Community); else Core.
    $raw = $null
    try { $raw = Get-PimFeatureStoreValue -Name $script:PimEditionSettingKey } catch {}
    if ($null -ne $raw -and "$raw".Trim() -ne '') {
        $r = Resolve-PimEdition -Raw $raw
        return $r.edition
    }
    # No explicit edition set -> honour the offline signed-license model if present.
    if (Get-Command Get-PimEdition -ErrorAction SilentlyContinue) {
        try {
            $e = Get-PimEdition
            if ("$e" -eq 'Pro') { return 'Pro' }
        } catch {}
    }
    return 'Core'
}

function Test-PimEditionCoversLicense {
    # Does the given edition cover a feature's license tier?
    #   license 'free' -> any edition (incl. Core)
    #   license 'pro'  -> 'Pro' or 'Pro-DesignPartner' only
    param([Parameter(Mandatory)][string]$License, [string]$Edition)
    $ed = if ("$Edition".Trim()) { "$Edition".Trim() } else { Get-PimActiveEdition }
    if ("$License".ToLowerInvariant() -eq 'free') { return $true }
    return ($ed -eq 'Pro' -or $ed -eq 'Pro-DesignPartner')
}

# ---------------------------------------------------------------------------
# THE GATE FUNCTIONS (the contract the engine + jobs + GUI call).
#   Test-PimFeatureEnabled   -- kill switch (catalog default + persisted override)
#   Test-PimFeatureLicensed  -- license tier vs active edition
#   Test-PimFeatureAvailable -- ENABLED *and* LICENSED (what side-effecting code gates on)
# CORE features always return $true (never gated). An UNKNOWN key returns $false
# from Available (fail-safe: a typo never silently enables a side effect) but logs.
# ---------------------------------------------------------------------------
function Test-PimFeatureEnabled {
    # $true if the feature's kill switch is ON (or it is a core feature). Reads the
    # persisted FeatureGates override merged over the catalog default.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Key)
    $entry = Get-PimFeatureCatalogEntry -Key $Key
    if (-not $entry) { return $false }
    if ("$($entry.tier)" -eq 'core') { return $true }
    $state = Get-PimFeatureGateState
    if ($state.gates.Contains("$($entry.key)")) { return [bool]$state.gates["$($entry.key)"] }
    return [bool]$entry.defaultEnabled
}

function Test-PimFeatureLicensed {
    # $true if the active edition covers the feature's license tier. Core/free
    # features are always licensed. -Edition overrides the resolved active edition
    # (for what-if / GUI preview).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Key, [string]$Edition)
    $entry = Get-PimFeatureCatalogEntry -Key $Key
    if (-not $entry) { return $false }
    if ("$($entry.tier)" -eq 'core') { return $true }
    return (Test-PimEditionCoversLicense -License "$($entry.license)" -Edition $Edition)
}

function Test-PimFeatureAvailable {
    # The combined gate side-effecting code calls: ENABLED *and* LICENSED. Core
    # features are always available. -SuperAdmin bypasses the LICENSE gate only
    # (never the kill switch -- a deliberately-off feature stays off even for an
    # admin, so a disabled integration performs no writes). -Quiet suppresses the
    # one-line "skipped" log. Returns $true = the feature may run.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Key, [string]$Edition, [switch]$SuperAdmin, [switch]$Quiet)
    $entry = Get-PimFeatureCatalogEntry -Key $Key
    if (-not $entry) {
        if (-not $Quiet) { Write-PimFeatureGateLog -Key $Key -Reason "unknown feature key" }
        return $false
    }
    if ("$($entry.tier)" -eq 'core') { return $true }

    $enabled = Test-PimFeatureEnabled -Key $Key
    if (-not $enabled) {
        if (-not $Quiet) { Write-PimFeatureGateLog -Key $Key -Reason 'disabled (kill switch off)' }
        return $false
    }
    $licensed = $SuperAdmin -or (Test-PimFeatureLicensed -Key $Key -Edition $Edition)
    if (-not $licensed) {
        if (-not $Quiet) { Write-PimFeatureGateLog -Key $Key -Reason "requires Pro (edition '$(if ("$Edition".Trim()) { $Edition } else { Get-PimActiveEdition })')" }
        return $false
    }
    return $true
}

function Write-PimFeatureGateLog {
    # Single-line "feature 'X' disabled -- skipped" log (matches the engine's tagged
    # output style). Best-effort: also records an audit event when available.
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$Reason)
    Write-Host ("[engine] feature '{0}' {1} -- skipped (no writes/sends)" -f $Key, $Reason) -ForegroundColor DarkYellow
    if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
        try { Write-PimAuditEvent -Action 'feature.skipped' -Target $Key -After @{ reason = $Reason } } catch {}
    }
}

# ---------------------------------------------------------------------------
# Dependency analysis (s29 cross-references) -- pure, for the GUI hints + tests.
# ---------------------------------------------------------------------------
function Get-PimFeatureDependencyIssues {
    # Given a resolved gate map, return per-feature warnings where an ENABLED
    # feature has a dependency that is NOT available (disabled or unlicensed).
    # Pure: takes the gate state + edition so the GUI can preview a what-if.
    param([object]$GateState, [string]$Edition)
    if (-not $GateState) { $GateState = Get-PimFeatureGateState }
    $ed = if ("$Edition".Trim()) { "$Edition".Trim() } else { Get-PimActiveEdition }
    $catalog = Get-PimFeatureCatalog
    $byKey = @{}; foreach ($f in $catalog) { $byKey["$($f.key)"] = $f }
    $avail = @{}
    foreach ($f in $catalog) {
        $key = "$($f.key)"
        if ("$($f.tier)" -eq 'core') { $avail[$key] = $true; continue }
        $en = if ($GateState.gates.Contains($key)) { [bool]$GateState.gates[$key] } else { [bool]$f.defaultEnabled }
        $lic = (Test-PimEditionCoversLicense -License "$($f.license)" -Edition $ed)
        $avail[$key] = ($en -and $lic)
    }
    $issues = New-Object System.Collections.Generic.List[object]
    foreach ($f in $catalog) {
        $key = "$($f.key)"
        if (-not $avail[$key]) { continue }   # only matters for enabled features
        foreach ($dep in @($f.dependsOn)) {
            if (-not $byKey.ContainsKey("$dep")) { continue }
            if (-not $avail["$dep"]) {
                $issues.Add([ordered]@{ feature = $key; dependsOn = "$dep"; message = "Feature '$($f.label)' is enabled but its prerequisite '$($byKey["$dep"].label)' is not available." })
            }
        }
    }
    return @($issues.ToArray())
}
