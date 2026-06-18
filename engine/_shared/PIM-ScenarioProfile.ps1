# =============================================================================
# PIM-ScenarioProfile.ps1 -- the SINGLE source of truth for the supported
# deployment TOPOLOGIES (REQUIREMENTS s31): the {tenancy} x {edition} x
# {update-source} x {license} x {hosting + sync-file location} x {SPN model}
# combinations PIM must explicitly support.
#
# WHY this file exists
#   Operator directive 2026-06-17: PIM must support six concrete topologies
#   (S1-S6). The GUI, engine, update/sync routines and deploy/install scripts
#   all need to branch on "which topology is this install?". Rather than scatter
#   that branching, this file declares ONE descriptor per scenario and resolves
#   it into the EXISTING knobs the rest of the solution already reads:
#     * edition / license      -> PIM-FeatureCatalog.ps1 (Get-PimActiveEdition,
#                                 Test-PimFeatureAvailable) + PIM-License.ps1
#     * update source          -> PIM-UpdateLifecycle.ps1 (Get-PimUpdateSourceProfile)
#     * MSP downlink / rings   -> Setup-PimMsp.ps1 / Invoke-PimMspFanout.ps1 +
#                                 $global:PIM_ConfigVariant / $global:PIM_Ring
#     * SQL/web hosting        -> PIM-SqlStore.ps1 (Get-PimSqlConnectionString)
#     * SPN model              -> Invoke-PimEngineCore.ps1 cert-SPN auth
#   This module does NOT introduce new primitives -- it MAPS a scenario onto the
#   ones above so a single descriptor drives the whole install.
#
# REUSE (solution-agnostic): the SHAPE of the descriptor is generic so SI / CEH
#   can adopt the same model later. Get-PimGenericScenarioDimensions returns the
#   dimension contract with NO PIM specifics; Get-PimScenarioCatalog returns the
#   PIM bindings. A sibling solution copies the dimension contract + this resolver
#   pattern and supplies its own catalog. The descriptor dimensions are:
#     role           single | msp-master | msp-managed
#     edition        internal-automateit | community   (DISTRIBUTION edition --
#                    branding + where updates come from; NOT the license tier)
#     updateSource   internal-automateit | github | from-master-by-rings
#     hostingLocation in-tenant | central-msp | local-slave
#     syncFileLocation none | central-msp | local-slave
#     spnModel       local-spn | multi-tenant-spn
#     syncModel      none | master-to-slave-admins-permissions
#     licenseTier    Pro-DesignPartner | Community | Pro
#
# PS 5.1 COMPATIBLE: no ?. / ??, no RSA.ImportFromPem, null-guarded property
# access, IDictionary-vs-PSCustomObject dual reads, InvariantCulture-safe string
# compares. Pure (no I/O) except the optional store-resolve helper.
# =============================================================================

# pim.Settings key the active scenario id lives under (so the GUI + engine + jobs
# all read ONE persisted topology). Shape: { scenario: 'S1'..'S6' }  (or a bare id).
$script:PimScenarioSettingKey = 'Scenario'

# The recognised distribution editions (s31). DISTINCT from the license tier in
# PIM-FeatureCatalog.ps1 (Core/Pro/Pro-DesignPartner). 'internal-automateit' =
# the operator's own AutomateIT build (updates from the internal source);
# 'community' = the public/community build (updates from GitHub).
$script:PimDistributionEditions = @('internal-automateit', 'community')

# ---------------------------------------------------------------------------
# Generic, SOLUTION-AGNOSTIC dimension contract. Other solutions (SI/CEH) lift
# THIS verbatim and supply their own catalog. No PIM specifics here.
# ---------------------------------------------------------------------------
function Get-PimGenericScenarioDimensions {
    # The reusable descriptor contract: each dimension + its allowed values + what
    # it means. Returns an ordered map dimension -> @{ values; description }.
    return [ordered]@{
        role             = @{ values = @('single', 'msp-master', 'msp-managed'); description = 'Tenancy role of this install.' }
        edition          = @{ values = @('internal-automateit', 'community');     description = 'Distribution edition / branding + update origin (NOT the license tier).' }
        updateSource     = @{ values = @('internal-automateit', 'github', 'from-master-by-rings'); description = 'Where code updates are pulled from.' }
        hostingLocation  = @{ values = @('in-tenant', 'central-msp', 'local-slave'); description = 'Where the GUI (web) + SQL store live.' }
        syncFileLocation = @{ values = @('none', 'central-msp', 'local-slave');     description = 'Where master->managed sync files are staged on the automation server.' }
        spnModel         = @{ values = @('local-spn', 'multi-tenant-spn');          description = 'Service-principal model for tenant auth.' }
        syncModel        = @{ values = @('none', 'master-to-slave-admins-permissions'); description = 'Whether admins+permissions are synced from the MSP master.' }
        licenseTier      = @{ values = @('Pro-DesignPartner', 'Community', 'Pro');  description = 'Commercial license tier required.' }
    }
}

# ---------------------------------------------------------------------------
# THE PIM SCENARIO CATALOG -- one descriptor per supported topology (S1-S6).
# Each entry is a complete generic descriptor (the dimensions above) PLUS the
# concrete PIM bindings the resolver maps onto.
# ---------------------------------------------------------------------------
function Get-PimScenarioCatalog {
    # Returns the array of scenario descriptors. Each is a [pscustomobject] so it
    # round-trips cleanly through the GUI/JSON. 'bindings' carries the PIM-specific
    # resolution (which existing knob each dimension drives).
    $catalog = @(
        [pscustomobject]@{
            id               = 'S1'
            label            = 'Single tenant -- Internal/AutomateIT edition'
            role             = 'single'
            edition          = 'internal-automateit'
            updateSource     = 'internal-automateit'
            hostingLocation  = 'in-tenant'
            syncFileLocation = 'none'
            spnModel         = 'local-spn'
            syncModel        = 'none'
            licenseTier      = 'Pro-DesignPartner'
            summary          = "Operator's own customer. GUI + SQL hosted in that tenant. Updates from the internal AutomateIT source. Pro (Design Partner) license."
            bindings         = [pscustomobject]@{ configVariant = 'local'; updateSourceProfile = 'sync-automateit'; ringGated = $false; activeEdition = 'Pro-DesignPartner'; grantBasis = 'design-partner' }
        },
        [pscustomobject]@{
            id               = 'S2'
            label            = 'Single tenant -- Community edition'
            role             = 'single'
            edition          = 'community'
            updateSource     = 'github'
            hostingLocation  = 'in-tenant'
            syncFileLocation = 'none'
            spnModel         = 'local-spn'
            syncModel        = 'none'
            licenseTier      = 'Community'
            summary          = 'Community install. GUI + SQL hosted in that tenant. Updates from GitHub (public mirror). Community license (Core features; advanced need Pro).'
            bindings         = [pscustomobject]@{ configVariant = 'local'; updateSourceProfile = 'git-pull'; ringGated = $false; activeEdition = 'Core'; grantBasis = '' }
        },
        [pscustomobject]@{
            id               = 'S3'
            label            = 'MSP master tenant -- Internal/AutomateIT edition'
            role             = 'msp-master'
            edition          = 'internal-automateit'
            updateSource     = 'internal-automateit'
            hostingLocation  = 'in-tenant'
            syncFileLocation = 'central-msp'
            spnModel         = 'local-spn'
            syncModel        = 'none'
            licenseTier      = 'Pro-DesignPartner'
            summary          = "MSP master. GUI + SQL hosted in the master tenant. Updates from the internal AutomateIT source. Operator's customers. Pro (Design Partner) license."
            bindings         = [pscustomobject]@{ configVariant = 'msp'; updateSourceProfile = 'sync-automateit'; ringGated = $false; activeEdition = 'Pro-DesignPartner'; grantBasis = 'design-partner' }
        },
        [pscustomobject]@{
            id               = 'S4'
            label            = 'MSP master tenant -- Community edition'
            role             = 'msp-master'
            edition          = 'community'
            updateSource     = 'github'
            hostingLocation  = 'in-tenant'
            syncFileLocation = 'central-msp'
            spnModel         = 'local-spn'
            syncModel        = 'none'
            licenseTier      = 'Pro'
            summary          = 'MSP master, Community build. GUI + SQL hosted in the master tenant. Updates from GitHub. MSP/master features require a Pro license.'
            bindings         = [pscustomobject]@{ configVariant = 'msp'; updateSourceProfile = 'git-pull'; ringGated = $false; activeEdition = 'Pro'; grantBasis = 'paid' }
        },
        [pscustomobject]@{
            id               = 'S5'
            label            = 'MSP managed/slave tenant -- CENTRAL hosted (multi-tenant SPN)'
            role             = 'msp-managed'
            edition          = 'internal-automateit'
            updateSource     = 'from-master-by-rings'
            hostingLocation  = 'central-msp'
            syncFileLocation = 'central-msp'
            spnModel         = 'multi-tenant-spn'
            syncModel        = 'master-to-slave-admins-permissions'
            licenseTier      = 'Pro-DesignPartner'
            summary          = 'Managed/slave tenant, CENTRAL hosted. Updates pulled from the master, ring-gated. Syncs admins+permissions from the master so MSP admins are created in the managed tenant. SQL + web stored separately in the MSP (central) tenant. Sync files central, in separate per-tenant folders on the MSP automation server. Multi-tenant SPN in the managed tenant.'
            bindings         = [pscustomobject]@{ configVariant = 'msp'; updateSourceProfile = 'from-master'; ringGated = $true; activeEdition = 'Pro-DesignPartner'; grantBasis = 'design-partner' }
        },
        [pscustomobject]@{
            id               = 'S6'
            label            = 'MSP managed/slave tenant -- LOCAL hosted (local SPN)'
            role             = 'msp-managed'
            edition          = 'internal-automateit'
            updateSource     = 'from-master-by-rings'
            hostingLocation  = 'local-slave'
            syncFileLocation = 'local-slave'
            spnModel         = 'local-spn'
            syncModel        = 'master-to-slave-admins-permissions'
            licenseTier      = 'Pro-DesignPartner'
            summary          = 'Managed/slave tenant, LOCAL hosted. Local SPN in the managed/slave tenant. Updates from the master, ring-gated. Syncs admins+permissions from the master so MSP admins are created in the managed tenant. SQL + web stored LOCALLY in the managed/slave tenant. Sync files stored LOCALLY in folders on the managed tenant automation server.'
            bindings         = [pscustomobject]@{ configVariant = 'msp'; updateSourceProfile = 'from-master'; ringGated = $true; activeEdition = 'Pro-DesignPartner'; grantBasis = 'design-partner' }
        }
    )
    return $catalog
}

# ---------------------------------------------------------------------------
# Small null-safe property reader (IDictionary OR PSCustomObject) -- mirrors
# Get-PimFeatureCatalogValue so this module stands alone if dot-sourced first.
# ---------------------------------------------------------------------------
function Get-PimScenarioValue {
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

function Get-PimScenario {
    # Return the descriptor for a scenario id ('S1'..'S6'), case-insensitive.
    # $null if unknown (fail-safe -- the caller must handle).
    param([Parameter(Mandatory)][string]$Id)
    $want = "$Id".Trim().ToUpperInvariant()
    foreach ($s in (Get-PimScenarioCatalog)) {
        if ("$($s.id)".ToUpperInvariant() -eq $want) { return $s }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Resolve the active scenario from the persisted store (or an explicit override).
# Mirrors Get-PimFeatureStoreValue's channel order so ONE persisted topology
# drives GUI + engine + jobs. Falls back to S1 (single, internal) only when
# NOTHING is set -- the safest single-tenant default (no MSP, no ring pull).
# ---------------------------------------------------------------------------
function Get-PimActiveScenario {
    param([string]$Override)
    if ("$Override".Trim()) {
        $s = Get-PimScenario -Id $Override
        if ($s) { return $s }
    }
    # in-process hydrated bag (Manager mirrors settings here)
    $raw = $null
    if ($global:PIM_ActiveScenario) { $raw = $global:PIM_ActiveScenario }
    elseif ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains($script:PimScenarioSettingKey)) {
        $raw = $global:PIM_NamingConventions[$script:PimScenarioSettingKey]
    } elseif (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $raw = Get-PimSetting -Name $script:PimScenarioSettingKey } catch {}
    }
    if ($null -ne $raw) {
        $id = $null
        if ($raw -is [string]) {
            $t = "$raw".Trim()
            if ($t.StartsWith('{')) { try { $j = $t | ConvertFrom-Json; $id = "$(Get-PimScenarioValue -Object $j -Key 'scenario')" } catch { $id = $t } }
            else { $id = $t }
        } else {
            $id = "$(Get-PimScenarioValue -Object $raw -Key 'scenario')"
        }
        if ("$id".Trim()) {
            $s = Get-PimScenario -Id $id
            if ($s) { return $s }
        }
    }
    # Safest default: single tenant, internal edition, no MSP, no ring pull.
    return (Get-PimScenario -Id 'S1')
}

# ---------------------------------------------------------------------------
# Resolve a scenario into the concrete runtime knobs the rest of the solution
# reads. This is the bridge function the engine/GUI/deploy call. PURE: it does
# NOT mutate globals -- it RETURNS the resolution; the caller applies it
# (Set-PimScenarioContext) so the mapping is testable without side effects.
# ---------------------------------------------------------------------------
function Resolve-PimScenarioContext {
    param([Parameter(Mandatory)][object]$Scenario)
    $s = $Scenario
    if ($s -is [string]) { $s = Get-PimScenario -Id $s }
    if (-not $s) { throw 'Resolve-PimScenarioContext: unknown scenario.' }
    $b = $s.bindings
    return [pscustomobject]@{
        id                  = "$($s.id)"
        role                = "$($s.role)"
        # ConfigVariant: 'msp' uses config-msp/ (central-authoritative admins);
        # 'local' uses config-local/ (local-tenant-owned). $global:PIM_ConfigVariant.
        configVariant       = "$(Get-PimScenarioValue -Object $b -Key 'configVariant')"
        # Update source profile fed to Invoke-PimUpdate / Get-PimUpdateSourceProfile.
        # 'from-master' is the ring-gated MSP downlink (managed pulls from master).
        updateSourceProfile = "$(Get-PimScenarioValue -Object $b -Key 'updateSourceProfile')"
        # Ring gating: TRUE for managed/slave (S5/S6) -- they pull only their ring.
        ringGated           = [bool](Get-PimScenarioValue -Object $b -Key 'ringGated')
        # Active LICENSE edition (Core/Pro/Pro-DesignPartner) the feature catalog gates on.
        activeEdition       = "$(Get-PimScenarioValue -Object $b -Key 'activeEdition')"
        grantBasis          = "$(Get-PimScenarioValue -Object $b -Key 'grantBasis')"
        # Hosting: where SQL + web live. 'central-msp' (S5) | 'local-slave' (S6) | 'in-tenant'.
        hostingLocation     = "$($s.hostingLocation)"
        # Sync-file staging location for master->managed sync files.
        syncFileLocation    = "$($s.syncFileLocation)"
        # SPN model: 'multi-tenant-spn' (S5) vs 'local-spn'.
        spnModel            = "$($s.spnModel)"
        # Whether master->managed admin+permission sync runs.
        syncAdminsPermissions = ("$($s.syncModel)" -eq 'master-to-slave-admins-permissions')
        distributionEdition = "$($s.edition)"
    }
}

# ---------------------------------------------------------------------------
# Map a scenario onto the CONCRETE knobs the deploy/update ENTRY POINTS consume.
# This is the Phase-1 (s31.3) bridge: the entry-point scripts (Invoke-PimUpdate,
# Invoke-PimDeployAll, Build-PimManagerImage, Setup-PimMsp, sync/schedule) call THIS
# to learn exactly which existing knob each takes, instead of branching on the
# scenario themselves. PURE: no az / SQL / HTTP / file I/O / global mutation -- it
# only RETURNS the resolved settings object; callers consume it. Built ON
# Resolve-PimScenarioContext (does not re-derive what that already resolves).
#
# Returns a [pscustomobject] with everything an entry point needs:
#   id, role, distributionEdition
#   updateSource         git-pull | sync-automateit | from-master  (the value fed to
#                        Get-PimUpdateSourceProfile / Invoke-PimUpdate -Source)
#   managedHosting       central | local  (only meaningful when updateSource=from-master;
#                        S5=central, S6=local; '' otherwise -- fed to -ManagedHosting)
#   configVariant        msp | local
#   ringGated            $true for S5/S6
#   hostingLocation      in-tenant | central-msp | local-slave
#   spnModel             local-spn | multi-tenant-spn
#   syncFileLocation     none | central-msp | local-slave
#   syncAdminsPermissions $true for S5/S6
#   activeEdition        Core | Pro | Pro-DesignPartner  (the license tier the s30 gate reads)
#   grantBasis           '' | paid | design-partner
#   editionPayload       @{ edition; grantBasis; note } -- persist under the 'Edition'
#                        setting key so Get-PimActiveEdition / Test-PimFeatureAvailable
#                        gate on the scenario's tier (S2=Core hides advanced; S4=Pro
#                        unlocks MSP/master; S1/S3/S5/S6=Pro-DesignPartner unlock all).
#   mspFeaturesRequirePro $true when MSP/master features must be Pro-gated (S4 only:
#                        Community distribution but the master features need Pro).
# ---------------------------------------------------------------------------
function Get-PimScenarioEntryPlan {
    param([Parameter(Mandatory)][object]$Scenario)
    $ctx = Resolve-PimScenarioContext -Scenario $Scenario
    # central vs local managed hosting (only for the from-master downlink, S5/S6).
    $managedHosting = ''
    if ($ctx.updateSourceProfile -eq 'from-master') {
        $managedHosting = if ($ctx.hostingLocation -eq 'central-msp') { 'central' } else { 'local' }
    }
    # Edition payload (the exact shape Resolve-PimEdition reads under the 'Edition' key).
    $note = "set by deployment scenario $($ctx.id) ($($ctx.role), $($ctx.distributionEdition))"
    $editionPayload = @{ edition = "$($ctx.activeEdition)"; grantBasis = "$($ctx.grantBasis)"; note = $note }
    # S4 is the ONLY Community-distribution scenario whose MSP/master features still
    # require a Pro license -- so the gate must be pro even though the build is community.
    $mspFeaturesRequirePro = ("$($ctx.distributionEdition)" -eq 'community' -and "$($ctx.role)" -eq 'msp-master')
    return [pscustomobject]@{
        id                    = "$($ctx.id)"
        role                  = "$($ctx.role)"
        distributionEdition   = "$($ctx.distributionEdition)"
        updateSource          = "$($ctx.updateSourceProfile)"
        managedHosting        = "$managedHosting"
        configVariant         = "$($ctx.configVariant)"
        ringGated             = [bool]$ctx.ringGated
        hostingLocation       = "$($ctx.hostingLocation)"
        spnModel              = "$($ctx.spnModel)"
        syncFileLocation      = "$($ctx.syncFileLocation)"
        syncAdminsPermissions = [bool]$ctx.syncAdminsPermissions
        activeEdition         = "$($ctx.activeEdition)"
        grantBasis            = "$($ctx.grantBasis)"
        editionPayload        = $editionPayload
        mspFeaturesRequirePro = [bool]$mspFeaturesRequirePro
    }
}

# ---------------------------------------------------------------------------
# §31.3 RUNTIME RESOLUTION — three pure decision functions that turn the resolved
# scenario knobs (hostingLocation / spnModel / syncFileLocation) into the concrete
# values the runtime areas consume. PURE: no SQL / HTTP / az / file I/O / global
# mutation — each RETURNS its decision; the area wiring applies it. They are the
# bridge for the four §31.3 ◻ items so the engine/Manager/sync pick the store /
# tenant-to-auth-against / staging-root from the SCENARIO, not only ambient signals.
# Default behaviour is UNCHANGED when no scenario knob applies (in-tenant / local-spn
# / none all fall through to the existing ambient resolution).
# ---------------------------------------------------------------------------

# HOSTING RESOLUTION (s31.3 ◻ "Hosting resolution per scenario"). Pick which SQL
# store the resolved hostingLocation implies:
#   central-msp (S5) -> the central MSP Azure SQL (server from -CentralServer /
#                       $env:PIM_SqlServerCentral); 'azure' kind, hosted web.
#   local-slave (S6) -> the local SQL in the managed tenant (server from
#                       -LocalServer / $env:PIM_SqlServerLocal, default .\SQLEXPRESS).
#   in-tenant   (S1-S4) -> the single-tenant in-tenant store; '' server (let the
#                       existing ambient resolution in Get-PimSqlConnectionString win).
# Returns @{ source; server; kind; reason } — server='' means "no scenario override,
# use ambient". `kind` = azure | local | ambient. PURE.
function Resolve-PimScenarioHostingStore {
    param(
        [Parameter(Mandatory)][object]$Scenario,
        [string]$CentralServer = $env:PIM_SqlServerCentral,
        [string]$LocalServer   = $env:PIM_SqlServerLocal
    )
    $ctx = Resolve-PimScenarioContext -Scenario $Scenario
    $loc = "$($ctx.hostingLocation)".Trim().ToLowerInvariant()
    if ($loc -eq 'central-msp') {
        $srv = "$CentralServer".Trim()
        if (-not $srv) { return @{ source = 'central-msp'; server = ''; kind = 'azure'; reason = 'central MSP store but no central server supplied (set $env:PIM_SqlServerCentral) -- fall back to ambient' } }
        return @{ source = 'central-msp'; server = $srv; kind = 'azure'; reason = "central MSP Azure SQL store '$srv' (hostingLocation=central-msp)" }
    }
    if ($loc -eq 'local-slave') {
        $srv = "$LocalServer".Trim(); if (-not $srv) { $srv = '.\SQLEXPRESS' }
        return @{ source = 'local-slave'; server = $srv; kind = 'local'; reason = "local managed-tenant SQL store '$srv' (hostingLocation=local-slave)" }
    }
    # in-tenant (S1-S4) -- no scenario override; the existing ambient resolution wins.
    return @{ source = 'in-tenant'; server = ''; kind = 'ambient'; reason = 'in-tenant single store -- use ambient connection resolution (no scenario override)' }
}

# SPN MODEL RESOLUTION (s31.3 ◻ "SPN model resolution"). The engine cert-SPN auth
# branches on the resolved spnModel:
#   multi-tenant-spn (S5) -> the SAME multi-tenant engine app authenticates AGAINST
#                            the MANAGED tenant id (the central host reaches into the
#                            slave). tenantId = the managed tenant; multiTenant=$true.
#   local-spn (S1-S4/S6)  -> a local single-tenant SPN against the local tenant id;
#                            multiTenant=$false; tenantId = the ambient local tenant.
# Returns @{ spnModel; multiTenant; tenantId; reason } — tenantId='' means "use the
# ambient $global:PIM_TenantId" (no override). PURE: never mutates globals.
function Resolve-PimScenarioSpnAuth {
    param(
        [Parameter(Mandatory)][object]$Scenario,
        [string]$ManagedTenantId = $env:PIM_ManagedTenantId,
        [string]$LocalTenantId
    )
    $ctx = Resolve-PimScenarioContext -Scenario $Scenario
    $model = "$($ctx.spnModel)".Trim().ToLowerInvariant()
    if ($model -eq 'multi-tenant-spn') {
        $tid = "$ManagedTenantId".Trim()
        if (-not $tid) { return @{ spnModel = 'multi-tenant-spn'; multiTenant = $true; tenantId = ''; reason = 'multi-tenant SPN but no managed tenant id supplied (set $env:PIM_ManagedTenantId) -- fall back to ambient tenant' } }
        return @{ spnModel = 'multi-tenant-spn'; multiTenant = $true; tenantId = $tid; reason = "multi-tenant engine SPN authenticates against the MANAGED tenant '$tid' (spnModel=multi-tenant-spn)" }
    }
    # local single-tenant SPN -- authenticate against the local tenant (ambient unless given).
    $lt = "$LocalTenantId".Trim()
    return @{ spnModel = 'local-spn'; multiTenant = $false; tenantId = $lt; reason = $(if ($lt) { "local single-tenant SPN against '$lt'" } else { 'local single-tenant SPN against the ambient tenant (no scenario override)' }) }
}

# SYNC-FILE STAGING-ROOT RESOLUTION (s31.3 ◻ "Sync-file path resolution"). Resolve
# JUST the staging ROOT for the resolved syncFileLocation, honouring the env defaults
# ($env:PIM_SyncRootCentral / $env:PIM_SyncRootLocal) -- the thin scenario-aware
# convenience over PIM-Downlink's Resolve-PimDownlinkSyncPath (which still does the
# per-tenant folder + file layout). Lets callers resolve the root from the SCENARIO
# without passing syncFileLocation + both roots by hand.
#   central-msp (S5) -> -CentralRoot / $env:PIM_SyncRootCentral
#   local-slave (S6) -> -LocalRoot   / $env:PIM_SyncRootLocal
#   none        (S1-S4) -> stage=$false (single/non-managed stages nothing)
# Returns @{ syncFileLocation; stage; root; reason }. PURE.
function Resolve-PimScenarioSyncRoot {
    param(
        [Parameter(Mandatory)][object]$Scenario,
        [string]$CentralRoot = $env:PIM_SyncRootCentral,
        [string]$LocalRoot   = $env:PIM_SyncRootLocal
    )
    $ctx = Resolve-PimScenarioContext -Scenario $Scenario
    $loc = "$($ctx.syncFileLocation)".Trim().ToLowerInvariant()
    if ($loc -eq 'none' -or -not $loc) {
        return @{ syncFileLocation = 'none'; stage = $false; root = ''; reason = 'scenario stages no sync files (syncFileLocation=none)' }
    }
    $root = ''
    if ($loc -eq 'central-msp') { $root = "$CentralRoot".Trim() }
    elseif ($loc -eq 'local-slave') { $root = "$LocalRoot".Trim() }
    else { return @{ syncFileLocation = $loc; stage = $false; root = ''; reason = "unknown syncFileLocation '$($ctx.syncFileLocation)'" } }
    if (-not $root) {
        $envName = if ($loc -eq 'central-msp') { '$env:PIM_SyncRootCentral' } else { '$env:PIM_SyncRootLocal' }
        return @{ syncFileLocation = $loc; stage = $true; root = ''; reason = "syncFileLocation=$loc but no staging root supplied (set $envName)" }
    }
    return @{ syncFileLocation = $loc; stage = $true; root = $root; reason = "stage sync files under root '$root' (syncFileLocation=$loc)" }
}

# ---------------------------------------------------------------------------
# License/edition gate driven by the resolved scenario (s31.3 "License-tier gating
# per scenario"). PURE decision: given the scenario's activeEdition and whether the
# caller is a super-admin, decide if a Pro/advanced feature may run. Super-admins are
# NEVER locked out (mirrors Test-PimProFeature / Test-PimFeatureAvailable -SuperAdmin).
#   * Core/free features (no proFeature requirement) always pass.
#   * Pro features pass only when the scenario edition is Pro or Pro-DesignPartner.
# This is the pure core; the GUI/engine call Test-PimFeatureAvailable -Edition <tier>
# (which this mirrors) so ONE edition value drives both. Returns $true = allowed.
# ---------------------------------------------------------------------------
function Test-PimScenarioFeatureAllowed {
    param(
        [Parameter(Mandatory)][object]$Scenario,
        [switch]$RequiresPro,
        [switch]$SuperAdmin
    )
    if ($SuperAdmin) { return $true }
    if (-not $RequiresPro) { return $true }
    $ctx = Resolve-PimScenarioContext -Scenario $Scenario
    return ("$($ctx.activeEdition)" -eq 'Pro' -or "$($ctx.activeEdition)" -eq 'Pro-DesignPartner')
}

# ---------------------------------------------------------------------------
# Apply a resolved scenario to the runtime globals the engine/GUI already read.
# This is the ONLY side-effecting function -- it sets the existing knobs; it does
# NOT invent new behaviour. Returns the resolution it applied (for logging).
# ---------------------------------------------------------------------------
function Set-PimScenarioContext {
    param(
        [Parameter(Mandatory)][object]$Scenario,
        [switch]$Quiet
    )
    $ctx = Resolve-PimScenarioContext -Scenario $Scenario
    # ConfigVariant drives config-msp/ vs config-local/ (existing engine knob).
    $global:PIM_ConfigVariant = $ctx.configVariant
    # Ring gating flag for the managed downlink pull (existing MSP pull reads PIM_Ring).
    $global:PIM_ScenarioRingGated = $ctx.ringGated
    # The active scenario id (so subsequent Get-PimActiveScenario is stable in-process).
    $global:PIM_ActiveScenario = "$($ctx.id)"
    # Distribution edition (branding + update origin).
    $global:PIM_DistributionEdition = $ctx.distributionEdition
    # Hosting + SPN model + sync-file location so the runtime (SQL/web resolution,
    # cert-SPN auth, sync-file staging) reflects the scenario. These are the existing
    # knobs the per-area wiring (s31.3 hosting/SPN/sync-file resolution) reads.
    $global:PIM_HostingLocation       = $ctx.hostingLocation
    $global:PIM_SpnModel              = $ctx.spnModel
    $global:PIM_SyncFileLocation      = $ctx.syncFileLocation
    $global:PIM_SyncAdminsPermissions = [bool]$ctx.syncAdminsPermissions
    if (-not $Quiet) {
        Write-Host ("[scenario] {0} ({1}) -- configVariant={2} updateSource={3} ringGated={4} edition={5} hosting={6} spn={7}" -f `
            $ctx.id, $ctx.role, $ctx.configVariant, $ctx.updateSourceProfile, $ctx.ringGated, $ctx.activeEdition, $ctx.hostingLocation, $ctx.spnModel) -ForegroundColor Cyan
    }
    return $ctx
}

# ---------------------------------------------------------------------------
# Validate a scenario descriptor against the generic dimension contract -- every
# dimension present + a recognised value, and the cross-field invariants hold
# (managed => ring-gated + multi-... only for S5; master/single never ring-gated).
# Returns @{ ok; errors=string[] }. Used by the classification test + GUI guard.
# ---------------------------------------------------------------------------
function Test-PimScenarioDescriptor {
    param([Parameter(Mandatory)][object]$Scenario)
    $errors = New-Object System.Collections.Generic.List[string]
    $dims = Get-PimGenericScenarioDimensions
    foreach ($dim in $dims.Keys) {
        $val = "$(Get-PimScenarioValue -Object $Scenario -Key $dim)"
        if (-not $val.Trim()) { $errors.Add("$($Scenario.id): missing dimension '$dim'"); continue }
        $allowed = $dims[$dim].values
        if ($val -notin $allowed) { $errors.Add("$($Scenario.id): dimension '$dim'='$val' not in [$($allowed -join ', ')]") }
    }
    # Cross-field invariants.
    $role = "$($Scenario.role)"
    $us   = "$($Scenario.updateSource)"
    $sm   = "$($Scenario.syncModel)"
    $spn  = "$($Scenario.spnModel)"
    if ($role -eq 'msp-managed') {
        if ($us -ne 'from-master-by-rings') { $errors.Add("$($Scenario.id): managed tenant must update from-master-by-rings") }
        if ($sm -ne 'master-to-slave-admins-permissions') { $errors.Add("$($Scenario.id): managed tenant must sync admins+permissions from master") }
    } else {
        if ($us -eq 'from-master-by-rings') { $errors.Add("$($Scenario.id): only a managed tenant updates from-master-by-rings") }
        if ($sm -ne 'none') { $errors.Add("$($Scenario.id): only a managed tenant syncs admins+permissions from master") }
    }
    # multi-tenant SPN only makes sense for a centrally-hosted managed tenant (S5).
    if ($spn -eq 'multi-tenant-spn' -and -not ($role -eq 'msp-managed' -and "$($Scenario.hostingLocation)" -eq 'central-msp')) {
        $errors.Add("$($Scenario.id): multi-tenant-spn is only for a central-hosted managed tenant")
    }
    return @{ ok = ($errors.Count -eq 0); errors = @($errors.ToArray()) }
}

# ---------------------------------------------------------------------------
# §31.3 Phase-2 downlink + scenario runner. Dot-source the downlink core/runner
# at the tail so any consumer that loads THIS scenario module (engine, GUI, jobs,
# the live scenario matrix verifier) also gets Invoke-PimManagedDownlink /
# Sync-PimMasterToSlave / Invoke-PimScenarioSync (the master->managed admin sync)
# and Invoke-PimScenarioDeploy (the scenario-bound engine runner). Idempotent.
# ---------------------------------------------------------------------------
if ($PSScriptRoot -and -not (Get-Command Invoke-PimManagedDownlink -ErrorAction SilentlyContinue)) {
    $__pimDownlink = Join-Path $PSScriptRoot 'PIM-Downlink.ps1'
    if (Test-Path -LiteralPath $__pimDownlink) { . $__pimDownlink }
}
