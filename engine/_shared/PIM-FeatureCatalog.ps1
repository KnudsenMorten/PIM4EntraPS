# IMP-03: the one visible way to swallow a non-fatal error (loaded defensively --
# this file is dot-sourced standalone by tests and by the Manager).
if (-not (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-Swallow.ps1') }
# REQ-Y: the hard Pro gate (Test-PimFeatureProLicence) verifies the licence with PIM-License.ps1 -- load it wherever the
# catalog is loaded, so no process can end up with the gate but without the verifier (which would read "not licensed").
if (-not (Get-Command Test-PimProLicence -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-License.ps1') }

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
#   scope          'single'    = acts on ONE tenant (this environment)
#                  'multi'     = the multi-tenant half (MSP master / managed tenants)
#                  REQ-Y (operator 2026-09-19: "single tenant must be sep in free and pro"): the edition is decided per
#                  entry by license x scope, and THIS catalog is the one authoritative list -- PIM-License.ps1's
#                  Get-PimProFeatureCatalog must equal Get-PimCatalogProFeatureNames (tests/Test-PimMspLicense.ps1).
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
    [ordered]@{ key='engine.reconcile'; label='Engine reconcile';        group='Core PIM';     tier='core';     license='free'; scope='single'; defaultEnabled=$true;  dependsOn=@();                       proFeature='';                  description='Desired-vs-live reconcile of delegation (create/update). The essential engine; never disabled.' }
    [ordered]@{ key='delegation.read';  label='Delegation map (read)';   group='Core PIM';     tier='core';     license='free'; scope='single'; defaultEnabled=$true;  dependsOn=@();                       proFeature='';                  description='Read/search the delegation model. Always available.' }
    [ordered]@{ key='authoring';        label='Authoring / Review & Save';group='Core PIM';    tier='core';     license='free'; scope='single'; defaultEnabled=$true;  dependsOn=@();                       proFeature='';                  description='Author and commit delegation changes. Always available.' }
    # 🔴 BUG-107. Second-approver (maker/checker) on sensitive changes. ADVANCED + defaultEnabled
    # =$false, because it requires TWO PEOPLE and shipped ON to deployments that have one.
    # A single-administrator tenant could not commit ANY privileged change: the 409 demands a
    # second administrator, self-approval is refused by design (maker != checker), and there is
    # no second administrator to ask. Reported as "i have not enabled this feature ... that
    # should not be standard".
    # 🪤 It MUST live in THIS catalog, not in PIM-FeatureFlags.ps1 (which drives GUI TAB
    # visibility). Test-PimAuthoringCommitAllowed calls Test-PimFeatureAvailable, which resolves
    # against Get-PimFeatureCatalogEntry HERE -- a key that is only in the tab list resolves as
    # "unknown feature key" and returns $false, which looks like the right answer (the gate is
    # off) for entirely the wrong reason: the operator could then never turn it ON.
    # tier='advanced' matters too -- a 'core' entry short-circuits to available and is
    # unswitchable, which would restore the exact bug this fixes.
    [ordered]@{ key='makerchecker';     label='Second-approver on sensitive changes'; group='Core PIM'; tier='advanced'; license='pro'; scope='single'; defaultEnabled=$false; dependsOn=@('authoring');            proFeature='MakerChecker';      description='Require a SECOND administrator to approve a change that touches privileged access before it can be committed (separation of duties). Needs at least two administrators -- with one, nothing privileged can ever be committed. Off = changes are still classified as sensitive and fully audited, they just do not need a second approver.' }

    # ---- Discovery (advanced) -------------------------------------------------
    [ordered]@{ key='discovery.sweep';  label='Discovery sweep';         group='Discovery';    tier='advanced'; license='pro';  scope='single'; defaultEnabled=$false; dependsOn=@('engine.reconcile');     proFeature='Discovery';         description='End-of-run sweep that enumerates Azure scopes + Power BI workspaces and flags/auto-creates new resources. Off = no discovery, no auto-create.' }

    # ---- Notifications / Email (advanced) -------------------------------------
    [ordered]@{ key='alerting.email';   label='Email alerting';          group='Notifications';tier='advanced'; license='free'; scope='single'; defaultEnabled=$false; dependsOn=@();                       proFeature='';                  description='Email notifications for engine-failure / drift / expiring-access / break-glass and the daily/tier digests. Off = no mail is sent.' }
    [ordered]@{ key='alerting.webhook'; label='Teams / webhook alerting';group='Notifications';tier='advanced'; license='free'; scope='single'; defaultEnabled=$false; dependsOn=@('alerting.email');       proFeature='';                  description='Post alerts to a Microsoft Teams / generic webhook in addition to email. Off = no webhook POST.' }

    # ---- Workload connectors / integrations (advanced, Pro) -------------------
    # 🔴 v1 PARITY: v1 applied workload bindings whenever its PIM-Assignments-Workloads file existed
    # (PIM-Baseline-Management-CSV.ps1 L1426-1436) -- there was no switch. Shipped v2 defaulted this OFF
    # and no deploy step turned it on, so a migrated customer's workload rows were imported and never
    # applied. autoEnableWhenData makes it EFFECTIVELY ON while any of these entities has rows, with no
    # deploy step and no GUI action; a deliberately stored `false` still wins (see Test-PimFeatureEnabled).
    # REQ-Y (operator 2026-09-19: "intune and defender is free"): the connectors are SPLIT. connectors.workload keeps its key
    # and its switch and is now FREE: Intune + Defender XDR (the IntuneRoles / DefenderXdrRoles providers, and the intune /
    # defender connector rows of PIM-Assignments-Workloads). Every other connector is connectors.apps (Pro): the generic
    # app-role provider and the WorkloadConnectors rows for Azure DevOps, Dataverse, Business Central, Power Platform, ...
    [ordered]@{ key='connectors.workload'; label='Workload connectors: Intune + Defender XDR'; group='Integrations'; tier='advanced'; license='free'; scope='single'; defaultEnabled=$false; dependsOn=@('engine.reconcile'); proFeature=''; autoEnableWhenData=@('PIM-Assignments-Workloads','PIM-Assignments-Defender','PIM-Assignments-Intune'); description='Intune and Defender XDR role delegation (free). On automatically while their assignment rows exist; off = these providers no-op.' }
    [ordered]@{ key='connectors.apps';     label='Workload connectors: app-role, Azure DevOps, Dataverse, Business Central, Power Platform'; group='Integrations'; tier='advanced'; license='pro'; scope='single'; defaultEnabled=$false; dependsOn=@('engine.reconcile'); proFeature='WorkloadConnectors'; autoEnableWhenData=@('PIM-Assignments-AppRole','PIM-Assignments-Workloads'); description='Enterprise-app app-role and the workload connectors other than Intune / Defender XDR (Pro). On automatically while their assignment rows exist; off or unlicensed = these connectors no-op.' }
    [ordered]@{ key='connectors.powerbi';  label='Power BI integration';            group='Integrations'; tier='advanced'; license='pro'; scope='single'; defaultEnabled=$false; dependsOn=@('discovery.sweep');   proFeature='WorkloadConnectors'; description='Power BI workspace discovery + role reconcile. Off = Power BI is skipped by the discovery sweep.' }
    # 🔴 REQ-Y (operator 2026-09-20: "fix req-y 3 items") -- 'connectors.exo' WAS REMOVED FROM THIS CATALOG.
    # It declared "Exchange Online role-group delegation (ManageAsApp)" as a Pro feature, and v2 has NO code that
    # applies it: no workloads\connectors\exchange-online.connector.json (the ten shipped manifests do not include
    # one), no provider, and not one gate site anywhere outside this file. The only Exchange in v2 is mail SENDING
    # (PIM-Notify.ps1, a per-mailbox Exchange RBAC assignment) -- a different thing entirely.
    # 🪤 A catalog entry is not documentation, it is the product surface: this one rendered a Settings toggle that
    # changed nothing, and -- being license='pro' -- told an unlicensed customer that a feature which does not exist
    # "requires a Pro licence". Selling an absent feature is worse than not listing it. It is now a ◻ backlog item in
    # docs\REQUIREMENTS.md; when EXO delegation is actually built, the entry comes back WITH its connector.
    # The Pro feature NAME 'WorkloadConnectors' is unaffected -- connectors.apps and connectors.powerbi still use it.

    # ---- Governance / reporting (Pro, single tenant; operator 2026-09-19 "i agree to your proposals") ---------------
    # tier='core' + license='pro': not a kill switch (nothing to turn on), but inert without a Pro licence -- the engine,
    # the jobs and the Manager refuse them with the licence reason (Test-PimFeatureProLicence).
    [ordered]@{ key='coverage.gaps';     label='Coverage & gaps';                     group='Governance';   tier='core'; license='pro'; scope='single'; defaultEnabled=$true; dependsOn=@(); proFeature='Coverage';       description='Which roles, scopes and groups have no delegation, and the proposals that close the gap. Computed by the coverage job.' }
    [ordered]@{ key='revoke.current';    label='Revoke current delegations';          group='Governance';   tier='core'; license='pro'; scope='single'; defaultEnabled=$true; dependsOn=@(); proFeature='Revoke';         description='Review current (standing) delegations and revoke them from the Manager.' }
    [ordered]@{ key='reviews.campaigns'; label='Access review campaigns';             group='Governance';   tier='core'; license='pro'; scope='single'; defaultEnabled=$true; dependsOn=@(); proFeature='AccessReviews';  description='Scheduled access reviews with the decisions recorded and enforced.' }
    [ordered]@{ key='access.delegated';  label='Delegated administration ceilings';   group='Governance';   tier='core'; license='pro'; scope='single'; defaultEnabled=$true; dependsOn=@(); proFeature='PortalAdmins';   description='Manager users limited by tier / level / service / scope with named capabilities.' }
    [ordered]@{ key='reports.tier';      label='Tier-impact report';                  group='Governance';   tier='core'; license='pro'; scope='single'; defaultEnabled=$true; dependsOn=@(); proFeature='TierReport';     description='Everyone who can reach tier 0, including through nested groups.' }
    [ordered]@{ key='reports.evidence';  label='Evidence / audit export';             group='Governance';   tier='core'; license='pro'; scope='single'; defaultEnabled=$true; dependsOn=@(); proFeature='EvidenceExport'; description='Who may hold what, who held it and who approved it -- the evidence report and its export.' }

    # ---- MSP (advanced, Pro) --------------------------------------------------
    [ordered]@{ key='msp.downlink';     label='MSP downlink / fan-out';  group='MSP';          tier='advanced'; license='pro';  scope='multi'; defaultEnabled=$false; dependsOn=@('engine.reconcile');     proFeature='MspFanout';         description='Fan a central admin baseline out to managed customer tenants (pull-not-push). Off = no fan-out runs.' }

    # ---- Scheduler / automated jobs (advanced) --------------------------------
    [ordered]@{ key='scheduler.jobs';   label='Scheduled jobs';          group='Automation';   tier='advanced'; license='free'; scope='single'; defaultEnabled=$false; dependsOn=@();                       proFeature='';                  description='The in-container/VM scheduler that drives reminders, digests, discovery, queue-apply, tenant-cache and engine runs on a cadence. Off = no scheduled job runs (manual/commit triggers still work via their own gates).' }
)

function Get-PimFeatureCatalog {
    # Return a fresh COPY of the catalog so a caller can never mutate the module
    # definition. Each entry is a fresh [ordered] hashtable.
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($f in $script:PimFeatureCatalog) {
        $deps = @(); if ($f.dependsOn) { foreach ($d in @($f.dependsOn)) { if ("$d".Trim()) { $deps += "$d" } } }
        $auto = @(); if ($f.Contains('autoEnableWhenData') -and $f.autoEnableWhenData) { foreach ($e in @($f.autoEnableWhenData)) { if ("$e".Trim()) { $auto += "$e" } } }
        $out.Add([ordered]@{
            key            = "$($f.key)"
            label          = "$($f.label)"
            group          = "$($f.group)"
            tier           = "$($f.tier)"
            license        = "$($f.license)"
            scope          = "$($f.scope)"
            defaultEnabled = [bool]$f.defaultEnabled
            dependsOn      = @($deps)
            proFeature     = "$($f.proFeature)"
            description    = "$($f.description)"
            # Entities whose rows switch this feature on when nothing is stored for it (v1 parity).
            autoEnableWhenData = @($auto)
        })
    }
    # PS 5.1: .ToArray() not @()-wrap -- @(List[object] of hashtables) throws
    # ArgumentException (the List[object] @()-wrap trap).
    return $out.ToArray()
}

function Get-PimCatalogProFeatureNames {
    <#
      REQ-Y. PURE. The Pro-feature names (PIM-License.ps1 vocabulary) that follow from THIS catalog: the distinct
      proFeature of every license='pro' entry, sorted. PIM-License.ps1's Get-PimProFeatureCatalog must equal this list
      (tests/Test-PimMspLicense.ps1 fails on any drift). -Scope narrows to 'single' or 'multi'.
    #>
    param([ValidateSet('', 'single', 'multi')][string]$Scope = '')
    $names = @()
    foreach ($f in $script:PimFeatureCatalog) {
        if ("$($f.license)" -ne 'pro') { continue }
        if ($Scope -and "$($f.scope)" -ne $Scope) { continue }
        $n = "$($f.proFeature)".Trim()
        if ($n -and $names -notcontains $n) { $names += $n }
    }
    return @($names | Sort-Object)
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
    # Which advanced features carry a STORED value (as opposed to riding the catalog default). Needed by
    # autoEnableWhenData: only a feature nobody decided about is switched on by the presence of data.
    $explicit = @{}
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
            if ($null -ne $ov) { $enabled = [bool]$ov; $explicit[$key] = $true }
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
    return @{ gates = $gates; effective = $effective; warnings = @($warnings.ToArray()); explicit = $explicit }
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
    #
    # IMP-03: a channel that THROWS is remembered, not reported immediately --
    # falling through to a channel that works is normal and must stay silent
    # (warning on it would be noise on every engine run without the Manager
    # bridge). It is only reported when the WHOLE chain yields nothing AFTER an
    # error, because that is the case where the caller silently proceeds on
    # defaults: the persisted state exists, we just could not read it, and GUI
    # state then no longer equals actual behaviour with no trace of why.
    param([Parameter(Mandatory)][string]$Name)
    $chainErr = $null
    # 1) In-process hydrated naming/conventions bag (Manager mirrors settings here).
    if ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($Name)) {
        return $global:PIM_NamingConventions[$Name]
    }
    # 2) Manager bridge (Get-PimSetting -> Get-PimManagerSetting -> store).
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimSetting -Name $Name; if ($null -ne $v) { return $v } } catch { $chainErr = $_ }
    }
    # 3) Direct SQL read (engine / scheduler process: no Manager bridge present).
    $cs = $null
    if ("$($global:PIM_EngineSqlCs)".Trim()) { $cs = $global:PIM_EngineSqlCs }
    elseif ("$($global:PIM_SqlConnectionString)".Trim()) { $cs = $global:PIM_SqlConnectionString }
    if ($cs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
        try { return (Get-PimSqlSetting -ConnectionString $cs -Name $Name) } catch { $chainErr = $_ }
    }
    if ($chainErr -and (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue)) {
        Write-PimSwallowed -Scope 'feature-store-read' -ErrorRecord $chainErr `
            -Consequence ("could not read setting '{0}' from any channel -- falling back to built-in defaults, so a persisted toggle/edition is NOT in effect this run" -f $Name)
    }
    return $null
}

function Get-PimFeatureGateState {
    # The resolved gate map (defaults + persisted overrides). Cheap to call; reads
    # the store each time so a toggle takes effect on the next engine/job run.
    $raw = $null
    # IMP-03: the reader below already reports a chain that failed outright; this
    # catch is the belt-and-braces one (it must never throw into a gate check).
    try { $raw = Get-PimFeatureStoreValue -Name $script:PimFeatureGateSettingKey }
    catch {
        if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
            Write-PimSwallowed -Scope 'feature-gate-read' -ErrorRecord $_ `
                -Consequence 'gate map resolved from DEFAULTS -- advanced features stay off regardless of what is persisted'
        }
    }
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
    try { $raw = Get-PimFeatureStoreValue -Name $script:PimEditionSettingKey }
    catch {
        if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
            Write-PimSwallowed -Scope 'edition-read' -ErrorRecord $_ `
                -Consequence 'active edition falls back to the signed license, then Core -- a persisted Pro edition is NOT in effect this run'
        }
    }
    if ($null -ne $raw -and "$raw".Trim() -ne '') {
        $r = Resolve-PimEdition -Raw $raw
        return $r.edition
    }
    # No explicit edition set -> honour the offline signed-license model if present.
    if (Get-Command Get-PimEdition -ErrorAction SilentlyContinue) {
        try {
            $e = Get-PimEdition
            if ("$e" -eq 'Pro') { return 'Pro' }
        } catch {
            if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
                Write-PimSwallowed -Scope 'edition-read' -ErrorRecord $_ `
                    -Consequence 'signed-license edition unreadable -- edition resolves to Core, so Pro capabilities are gated off'
            }
        }
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
    $k = "$($entry.key)"
    # v1 PARITY (autoEnableWhenData): a feature that nobody has stored a value for, and whose
    # entities hold rows, is ON -- the customer's data is the decision, exactly as v1's file was.
    # A STORED value always wins: `true` is on regardless, and a deliberately stored `false` (the
    # feature baseline's -Disable list, or a hand-set store) keeps it off even with rows present.
    # The Manager's save only ever stores values that DIFFER from the catalog default, so saving the
    # Features card with this toggle showing off never records a `false` that would defeat this.
    $isExplicit = ($state.explicit -is [hashtable]) -and $state.explicit.ContainsKey($k)
    if (-not $isExplicit -and @($entry.autoEnableWhenData).Count -gt 0) {
        if (Test-PimFeatureDataPresent -Entities @($entry.autoEnableWhenData)) { return $true }
    }
    if ($state.gates.Contains($k)) { return [bool]$state.gates[$k] }
    return [bool]$entry.defaultEnabled
}

function Test-PimFeatureDataPresent {
    <#
      Does ANY of these desired-state entities hold at least one row? The data half of
      autoEnableWhenData. Channels, first that can answer wins:
        1. $global:PIM_FeatureDataPresence  -- entity -> bool (tests; a host that already knows)
        2. SQL pim.Rows, one cheap TOP 1 query (engine / scheduler / Manager with a SQL store)
        3. $global:PIM_DesiredRows          -- the engine's in-memory desired seam (offline runs)
      Returns $false when nothing can answer: "cannot tell" must never switch a writer on. A SQL
      read that FAILS is reported (Write-PimSwallowed), because then persisted rows exist and the
      feature is off for a reason nobody would otherwise see.
    #>
    [CmdletBinding()]
    param([string[]]$Entities = @())
    $ents = @($Entities | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if (-not $ents.Count) { return $false }
    if ($global:PIM_FeatureDataPresence -is [System.Collections.IDictionary]) {
        foreach ($e in $ents) { if ($global:PIM_FeatureDataPresence.Contains($e) -and [bool]$global:PIM_FeatureDataPresence[$e]) { return $true } }
        return $false
    }
    $cs = $null
    if ("$($global:PIM_EngineSqlCs)".Trim()) { $cs = "$($global:PIM_EngineSqlCs)" }
    elseif ("$($global:PIM_SqlConnectionString)".Trim()) { $cs = "$($global:PIM_SqlConnectionString)" }
    if ($cs -and (Get-Command Invoke-PimSqlScalar -ErrorAction SilentlyContinue)) {
        try {
            $p = @{}; $names = @()
            for ($i = 0; $i -lt $ents.Count; $i++) { $p["e$i"] = $ents[$i]; $names += "@e$i" }
            $v = Invoke-PimSqlScalar -ConnectionString $cs -Sql ("SELECT TOP 1 1 FROM pim.Rows WHERE Entity IN ({0})" -f ($names -join ',')) -Parameters $p
            return ("$v" -eq '1')
        } catch {
            if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
                Write-PimSwallowed -Scope 'feature-data-presence' -ErrorRecord $_ `
                    -Consequence ("could not check whether {0} hold rows -- the features they switch on stay OFF this run" -f ($ents -join ', '))
            }
            return $false
        }
    }
    if ($global:PIM_DesiredRows -is [System.Collections.IDictionary]) {
        foreach ($e in $ents) { if ($global:PIM_DesiredRows.Contains($e) -and @(@($global:PIM_DesiredRows[$e]) | Where-Object { $null -ne $_ }).Count -gt 0) { return $true } }
    }
    return $false
}

function Test-PimLicenseGateActive {
    <#
      Is the Pro licence gate ACTUALLY enforced this session?

      🔒 THE POLICY, and it lives in PIM-License.ps1: Pro is FREE by default -- no nag,
      no block, no phone-home -- and only an internal verification harness turns
      enforcement on ($global:PIM_EnforceProLicense).

      ⚠️ THIS FILE USED TO IGNORE THAT ENTIRELY. Test-PimFeatureLicensed gated purely on
      EDITION, and Test-PimFeatureAvailable is "what side-effecting code gates on" -- so
      the ENGINE skipped Pro features on a Community edition and logged
      "requires Pro ... -- skipped", while PIM-License.ps1's own gate was returning
      "allowed, free" for the same feature. Two parallel licence gates disagreeing, with
      the restrictive one wired into the engine. Operator directive 2026-08-07:
      "no limitations ... full access default".

      Resolved here rather than at each call site so there is ONE answer. Falls back to
      NOT enforced if PIM-License.ps1 is not loaded -- the shipped default, and the
      direction that cannot lock anyone out of anything.
    #>
    if (Get-Command Test-PimProLicenseEnforced -ErrorAction SilentlyContinue) {
        try { return [bool](Test-PimProLicenseEnforced) } catch { return $false }
    }
    if ($null -ne $global:PIM_EnforceProLicense) { return [bool]$global:PIM_EnforceProLicense }
    return $false
}

function Test-PimFeatureLicensed {
    # $true if the active edition covers the feature's license tier. Core/free
    # features are always licensed. -Edition overrides the resolved active edition
    # (for what-if / GUI preview).
    #
    # When the licence gate is NOT enforced (the shipped default) EVERYTHING is
    # licensed -- see Test-PimLicenseGateActive above.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Key, [string]$Edition)
    $entry = Get-PimFeatureCatalogEntry -Key $Key
    if (-not $entry) { return $false }
    if ("$($entry.tier)" -eq 'core') { return $true }
    if (-not (Test-PimLicenseGateActive)) { return $true }
    return (Test-PimEditionCoversLicense -License "$($entry.license)" -Edition $Edition)
}

$script:PimFeatureProGraceWarned = @{}

function Test-PimFeatureProLicence {
    <#
      REQ-Y (operator 2026-09-19: "Hard, like MSP"). The HARD licence gate of ONE catalog feature, driven by the entry's
      license: a license='free' entry is never gated (required=$false, ok=$true); a license='pro' entry needs a Pro
      licence that covers its proFeature (or '*') for this tenant -- the same check the MSP jobs run
      (Test-PimProLicence, PIM-License.ps1). Independent of the global switch ($global:PIM_EnforceProLicense keeps
      meaning "the legacy edition gate"), and no SuperAdmin bypass: a licence is a fact about the environment.
      Returns the Test-PimProLicence result plus key / required. The tenant defaults to $global:PIM_TenantId.
      -PublicCertB64 / -LicenseText are the test seams Test-PimProLicence has.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Key, [string]$TenantId, [string]$SqlServer, [string]$PublicCertB64, [AllowEmptyString()][AllowNull()][string]$LicenseText)
    $entry = Get-PimFeatureCatalogEntry -Key $Key
    if (-not $entry -or "$($entry.license)" -ne 'pro') {
        return [pscustomobject]@{ key = $Key; required = $false; ok = $true; grace = $false; label = $(if ($entry) { "$($entry.label)" } else { $Key }); reason = 'free'; message = ''; contact = 'mok@mortenknudsen.net'; command = '' }
    }
    $tid = if ("$TenantId".Trim()) { "$TenantId".Trim() } elseif ("$($global:PIM_TenantId)".Trim()) { "$($global:PIM_TenantId)".Trim() } else { '' }
    $srv = if ("$SqlServer".Trim()) { "$SqlServer".Trim() } elseif ("$($global:PIM_SqlServer)".Trim()) { "$($global:PIM_SqlServer)".Trim() } else { '' }
    if (-not (Get-Command Test-PimProLicence -ErrorAction SilentlyContinue)) {
        # A process that loaded the catalog without PIM-License.ps1 cannot verify a licence: Pro stays off, and says why.
        $why = 'the licence verifier (PIM-License.ps1) is not loaded in this process'
        return [pscustomobject]@{ key = $Key; required = $true; ok = $false; grace = $false; label = "$($entry.label)"; reason = $why
            message = "$($entry.label) requires a PIM4EntraPS Pro licence -- $why. Contact mok@mortenknudsen.net for a licence."; contact = 'mok@mortenknudsen.net'; command = '' }
    }
    $a = @{ FeatureNames = @("$($entry.proFeature)"); Label = "$($entry.label)"; TenantId = $tid; SqlServer = $srv; UseCache = $true }
    if ($PublicCertB64) { $a['PublicCertB64'] = $PublicCertB64 }
    if ($PSBoundParameters.ContainsKey('LicenseText')) { $a['LicenseText'] = "$LicenseText" }
    $r = Test-PimProLicence @a
    $r | Add-Member -NotePropertyName key -NotePropertyValue $Key -Force
    $r | Add-Member -NotePropertyName required -NotePropertyValue $true -Force
    return $r
}

# REQ-Y (operator 2026-09-19: "intune and defender is free"): which catalog key licenses a PIM-Assignments-Workloads row,
# by its connector id (the row's Workload, lower-cased -- workloads/connectors/*.connector.json). Intune, Defender XDR,
# Azure RBAC and Entra roles are FREE; Power BI is connectors.powerbi; the other known connectors are connectors.apps.
# An id not listed here is not gated (its own "unknown connector" error must surface, not be hidden as a licence hold).
$script:PimWorkloadConnectorProKeys = @{
    'powerbi' = 'connectors.powerbi'; 'power-bi' = 'connectors.powerbi'
    'entra-approle' = 'connectors.apps'; 'approle' = 'connectors.apps'; 'azure-devops' = 'connectors.apps'
    'dataverse' = 'connectors.apps'; 'business-central' = 'connectors.apps'; 'power-platform' = 'connectors.apps'
}
$script:PimWorkloadLicenceWarned = @{}

function Get-PimWorkloadConnectorProKey {
    <# PURE. The Pro catalog key a workload connector id needs, or '' (free / not gated). #>
    param([AllowNull()][string]$Workload)
    $w = "$Workload".Trim().ToLowerInvariant()
    if ($w -and $script:PimWorkloadConnectorProKeys.ContainsKey($w)) { return "$($script:PimWorkloadConnectorProKeys[$w])" }
    return ''
}

function Select-PimWorkloadRowsLicensed {
    <#
      REQ-Y. The PIM-Assignments-Workloads rows the generic connector dispatcher may act on: every row of a FREE connector,
      and a Pro connector's rows only with a Pro licence (the hard gate, Test-PimFeatureProLicence -- never the kill
      switch, which the provider's own feature already is). Held rows (assign AND remove -- inert, both ways) are named
      ONCE per process in a scope warning with the licence line. -Warnings: the engine's per-scope warning list.
    #>
    param([object[]]$Rows = @(), [object]$Warnings)
    $keep = New-Object System.Collections.Generic.List[object]
    $held = @{}
    $verdict = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $w = if ($r -is [System.Collections.IDictionary]) { "$($r['Workload'])" } else { $pp = $r.PSObject.Properties['Workload']; if ($pp) { "$($pp.Value)" } else { '' } }
        $k = Get-PimWorkloadConnectorProKey -Workload $w
        if (-not $k) { $keep.Add($r); continue }
        if (-not $verdict.ContainsKey($k)) { $verdict[$k] = Test-PimFeatureProLicence -Key $k }
        if ($verdict[$k].ok) { $keep.Add($r); continue }
        $id = "$w".Trim().ToLowerInvariant()
        if (-not $held.ContainsKey($id)) { $held[$id] = 0 }
        $held[$id]++
    }
    foreach ($id in @($held.Keys | Sort-Object)) {
        $k = Get-PimWorkloadConnectorProKey -Workload $id
        $line = ("{0} row(s) for the '{1}' connector are held -- {2}" -f $held[$id], $id, $verdict[$k].message)
        # $null -ne, not truthiness: an EMPTY warning list is falsy, and it is exactly the one the engine passes in.
        if ($null -ne $Warnings -and ($Warnings -is [System.Collections.IList])) { [void]$Warnings.Add($line) }
        if (-not $script:PimWorkloadLicenceWarned[$id]) { $script:PimWorkloadLicenceWarned[$id] = $true; Write-Warning ("  [WorkloadConnectors] " + $line) }
    }
    return @($keep.ToArray())
}

function Get-PimProFeatureStates {
    <#
      REQ-Y. Every license='pro' catalog entry with its hard-gate verdict, for GET /api/license and the GUI's
      "Pro -- contact" notices: key -> @{ label; scope; ok; grace; state (ok|grace|locked); reason; message }.
    #>
    [CmdletBinding()] param([string]$TenantId, [string]$SqlServer, [string]$PublicCertB64)
    $out = [ordered]@{}
    foreach ($f in $script:PimFeatureCatalog) {
        if ("$($f.license)" -ne 'pro') { continue }
        $a = @{ Key = "$($f.key)"; TenantId = $TenantId; SqlServer = $SqlServer }
        if ($PublicCertB64) { $a['PublicCertB64'] = $PublicCertB64 }
        $r = Test-PimFeatureProLicence @a
        $out["$($f.key)"] = [ordered]@{ label = "$($f.label)"; scope = "$($f.scope)"; description = "$($f.description)"; proFeature = "$($f.proFeature)"; ok = [bool]$r.ok; grace = [bool]$r.grace
            state = $(if (-not $r.ok) { 'locked' } elseif ($r.grace) { 'grace' } else { 'ok' }); reason = "$($r.reason)"; message = "$($r.message)" }
    }
    return $out
}

function Test-PimFeatureAvailable {
    # The combined gate side-effecting code calls: ENABLED *and* LICENSED. Core
    # features are always available. -SuperAdmin bypasses the LICENSE gate only
    # (never the kill switch -- a deliberately-off feature stays off even for an
    # admin, so a disabled integration performs no writes). -Quiet suppresses the
    # one-line "skipped" log. Returns $true = the feature may run.
    # REQ-Y: a license='pro' entry ALSO needs a Pro licence (Test-PimFeatureProLicence) -- checked FIRST, for every tier,
    # with no SuperAdmin bypass. So every engine scope, job and sweep that already asks this gate is inert without one.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Key, [string]$Edition, [switch]$SuperAdmin, [switch]$Quiet)
    $entry = Get-PimFeatureCatalogEntry -Key $Key
    if (-not $entry) {
        if (-not $Quiet) { Write-PimFeatureGateLog -Key $Key -Reason "unknown feature key" }
        return $false
    }
    if ("$($entry.license)" -eq 'pro') {
        $pl = Test-PimFeatureProLicence -Key $Key
        if (-not $pl.ok) {
            if (-not $Quiet) { Write-PimFeatureGateLog -Key $Key -Reason ("is Pro -- " + $pl.message) }
            return $false
        }
        if ($pl.grace -and -not $script:PimFeatureProGraceWarned[$Key]) {
            $script:PimFeatureProGraceWarned[$Key] = $true
            Write-Warning ("[licence] " + $pl.message)
        }
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
        try { Write-PimAuditEvent -Action 'feature.skipped' -Target $Key -After @{ reason = $Reason } }
        catch {
            # IMP-03: the console line above already ran, so the skip is not invisible --
            # but the audit record of WHY work was skipped is what an operator reads later.
            if (Get-Command Write-PimSwallowed -ErrorAction SilentlyContinue) {
                Write-PimSwallowed -Scope 'feature-skip-audit' -ErrorRecord $_ `
                    -Consequence ("the 'feature {0} skipped' audit event was not recorded" -f $Key)
            }
        }
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
        # Same rule as Test-PimFeatureLicensed: unenforced => licensed. Otherwise the
        # dependency report would invent "prerequisite not available" warnings about
        # features that run perfectly well.
        $lic = (-not (Test-PimLicenseGateActive)) -or (Test-PimEditionCoversLicense -License "$($f.license)" -Edition $ed)
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
