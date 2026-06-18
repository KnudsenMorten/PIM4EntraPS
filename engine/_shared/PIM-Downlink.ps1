# =============================================================================
# PIM-Downlink.ps1 -- the PURE, offline-testable decision brain for the §31.3
# master->managed (slave) admin/permission SYNC (downlink) + the scenario-bound
# engine runner. Phase 2 of the §31 hosting/edition scenario matrix (S1-S6).
#
# WHAT this delivers (the §31.3 wiring gap the live matrix asserts):
#   * a ring-gated master->managed admin/permission downlink: PULL the master's
#     SIGNED baseline (RSA-SHA256, same trust model as .pimlicense -- verify with
#     the embedded PUBLIC cert, refuse on bad sig / expiry / rollback), FILTER the
#     admin set to admin.Ring <= slave.Ring, STAGE per-tenant sync files in the
#     resolved folder (central-msp vs local-slave), and APPLY into the slave by
#     composing the EXISTING Invoke-PimMspFanout (pull-not-push: the MASTER never
#     writes into a managed tenant; the central/managed engine applies the synced
#     rows into the slave via ITS OWN per-tenant SPN).
#   * a scenario-bound runner: resolve the scenario, and for single/master run the
#     engine apply; for managed run the downlink-sync THEN the engine apply.
#
# DESIGN TENETS (non-negotiable, mirror the rest of PIM4EntraPS):
#   * PURE core here: NO az / Graph / SQL / HTTP / file I/O / global mutation in
#     the decision functions -- they take FACTS, return PLANS/decisions. The thin
#     live wrappers (setup/Invoke-PimDownlinkSync.ps1 + setup/Invoke-PimScenarioRun.ps1)
#     gather the facts (pull the signed bundle, read the registry, write files, run
#     the fan-out/engine) and ACT on these plans. That keeps every risky decision --
#     "does this signature verify?", "which admins does this ring reach?", "where do
#     the sync files go?", "is the second pass a no-op?", "which topology branch?" --
#     unit-testable in real PS 5.1 with NO live tenant.
#   * pull-not-push + ring-gated + guardrails: the downlink only ever PULLS the
#     ring's approved baseline; an admin above the slave's ring is never synced; the
#     apply composes the engine's mass-disable guard (empty desired never prunes).
#   * idempotent: a second pass produces zero changes (find-or-create fan-out +
#     anti-rollback baseline marker + stable sync-file content hash).
#
# PS 5.1 COMPATIBLE: no ?. / ??, no RSA.ImportFromPem, no ternary, Set-StrictMode
#   -Off, null-guarded property access, .ToArray() not @() on List[object].
#
# REUSE (does not reinvent): Resolve-PimScenarioContext / Get-PimScenarioEntryPlan
#   (PIM-ScenarioProfile.ps1), Test-PimBaselineDoc / Get-PimBaselineBundle
#   (PIM-Baseline.ps1), Invoke-PimMspFanout.ps1 (the real admin-creation engine),
#   Invoke-PimEngineCore.ps1 (engine apply). This file MAPS + ORCHESTRATES them.
# =============================================================================

Set-StrictMode -Off

# Idempotent dot-source of the scenario resolver + the baseline verifier so this
# module stands alone if loaded first. (PIM-ScenarioProfile.ps1 dot-sources THIS
# file at its tail so the live matrix -- which loads PIM-ScenarioProfile.ps1 --
# resolves Invoke-PimManagedDownlink / Invoke-PimScenarioDeploy via Get-Command.)
if ($PSScriptRoot) {
    if (-not (Get-Command Resolve-PimScenarioContext -ErrorAction SilentlyContinue)) {
        $__sp = Join-Path $PSScriptRoot 'PIM-ScenarioProfile.ps1'
        if (Test-Path -LiteralPath $__sp) { . $__sp }
    }
    if (-not (Get-Command Test-PimBaselineDoc -ErrorAction SilentlyContinue)) {
        $__bl = Join-Path $PSScriptRoot 'PIM-Baseline.ps1'
        if (Test-Path -LiteralPath $__bl) { . $__bl }
    }
}

# ---------------------------------------------------------------------------
# Small null-safe property reader (IDictionary OR PSCustomObject). Mirrors
# Get-PimScenarioValue so this file is self-contained.
# ---------------------------------------------------------------------------
function Get-PimDownlinkValue {
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
# RING FILTER (pure). Which baseline admins does THIS slave receive?
#   Engine ring semantics (matches pim.vw_AdminTenantTargets `a.Ring <= t.Ring`
#   and the seeder's Get-ExpectedAdminsForSlave): a ring-0 admin is BROAD and
#   reaches every slave; a ring-2 admin only reaches ring>=2 (test) slaves.
#   => an admin reaches the slave when admin.Ring <= slave.Ring.
# Input rows may be hashtables OR PSCustomObjects (UserName + Ring). Returns the
# filtered subset (same shape) sorted by Ring then UserName for determinism.
# ---------------------------------------------------------------------------
function Select-PimDownlinkAdmins {
    param(
        [object[]]$Admins = @(),
        [Parameter(Mandatory)][int]$SlaveRing
    )
    $keep = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($Admins)) {
        if ($null -eq $a) { continue }
        $ringRaw = Get-PimDownlinkValue -Object $a -Key 'Ring'
        if ($null -eq $ringRaw -or "$ringRaw".Trim() -eq '') { continue }   # no ring => not eligible (fail-safe)
        $ring = [int]$ringRaw
        if ($ring -le $SlaveRing) { $keep.Add($a) | Out-Null }
    }
    $sorted = @($keep.ToArray() | Sort-Object `
        @{ Expression = { [int](Get-PimDownlinkValue -Object $_ -Key 'Ring') } }, `
        @{ Expression = { "$(Get-PimDownlinkValue -Object $_ -Key 'UserName')".ToLowerInvariant() } })
    # Return as a plain array. NB: do NOT `return ,$sorted` -- the unary comma wraps
    # the already-array $sorted into a 1-element array-of-array, which @() at the call
    # site only unwraps one level (leaving a single Object[] element). Plain return +
    # @() wrap at the call site is the PS 5.1-safe contract.
    return $sorted
}

# ---------------------------------------------------------------------------
# SIGNATURE / VALIDITY VERIFY (pure). Verify a signed baseline document with a
# CALLER-SUPPLIED public key (the real key never leaves mgmt1; tests pass an
# EPHEMERAL test key). Mirrors Test-PimBaselineDoc but lets a test inject the
# verifying RSA so we can prove valid / tampered / wrong-key WITHOUT the prod key
# and WITHOUT RSA.ImportFromPem (PS 5.1).
#
# -Doc           : @{ payloadB64; signature; keyThumbprint } (the signed bundle).
# -PublicKey     : an [RSA] (or an X509Certificate2) to verify with. When omitted,
#                  falls back to the embedded PIM4EntraPS-Baseline public cert (via
#                  Test-PimBaselineDoc) so production verification is unchanged.
# -AllowedKind   : accepted payload.kind values (default 'baseline').
# -NowUtc        : clock injection for expiry tests (default [datetime]::UtcNow).
# -LastVersion   : anti-rollback floor (default 0; payload.version must be >=).
# Returns @{ ok; reason; payload } -- ok=$false on any failure (never throws on a
# bad sig/expiry/rollback; throws only on a structurally-broken doc).
# ---------------------------------------------------------------------------
function Test-PimDownlinkBaseline {
    param(
        [Parameter(Mandatory)][object]$Doc,
        [object]$PublicKey,
        [string[]]$AllowedKind = @('baseline'),
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0
    )
    $payloadB64 = "$(Get-PimDownlinkValue -Object $Doc -Key 'payloadB64')"
    $sigB64     = "$(Get-PimDownlinkValue -Object $Doc -Key 'signature')"
    if (-not $payloadB64.Trim() -or -not $sigB64.Trim()) {
        return @{ ok = $false; reason = 'not a signed bundle (payloadB64/signature missing)'; payload = $null }
    }

    $payloadBytes = $null; $sigBytes = $null
    try {
        $payloadBytes = [Convert]::FromBase64String($payloadB64)
        $sigBytes     = [Convert]::FromBase64String($sigB64)
    } catch {
        return @{ ok = $false; reason = "base64 decode failed: $($_.Exception.Message)"; payload = $null }
    }

    # Resolve the verifying RSA public key.
    $rsa = $null
    if ($null -ne $PublicKey) {
        if ($PublicKey -is [System.Security.Cryptography.RSA]) { $rsa = $PublicKey }
        elseif ($PublicKey -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($PublicKey)
        } else {
            return @{ ok = $false; reason = 'unsupported -PublicKey type (need [RSA] or X509Certificate2)'; payload = $null }
        }
    }

    $ok = $false
    if ($rsa) {
        try {
            $ok = $rsa.VerifyData($payloadBytes, $sigBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } catch {
            return @{ ok = $false; reason = "signature verify threw: $($_.Exception.Message)"; payload = $null }
        }
        if (-not $ok) { return @{ ok = $false; reason = 'SIGNATURE INVALID -- bundle tampered or signed by the wrong key'; payload = $null } }
    } else {
        # No explicit key: defer to the embedded prod public cert via Test-PimBaselineDoc.
        if (-not (Get-Command Test-PimBaselineDoc -ErrorAction SilentlyContinue)) {
            return @{ ok = $false; reason = 'no -PublicKey and Test-PimBaselineDoc (embedded cert) not loaded'; payload = $null }
        }
        try {
            $p = Test-PimBaselineDoc -Doc $Doc -AllowedKind $AllowedKind
            # Test-PimBaselineDoc already enforced product/kind. Continue with expiry/rollback below.
            $payloadObj = $p
            return (Test-PimDownlinkBaselineFinish -PayloadObject $payloadObj -AllowedKind $AllowedKind -NowUtc $NowUtc -LastVersion $LastVersion)
        } catch {
            return @{ ok = $false; reason = "embedded-cert verify failed: $($_.Exception.Message)"; payload = $null }
        }
    }

    # Parse the now-trusted payload and run the shape/expiry/rollback gates.
    $payloadObj = $null
    try { $payloadObj = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json }
    catch { return @{ ok = $false; reason = "payload JSON parse failed: $($_.Exception.Message)"; payload = $null } }
    return (Test-PimDownlinkBaselineFinish -PayloadObject $payloadObj -AllowedKind $AllowedKind -NowUtc $NowUtc -LastVersion $LastVersion)
}

# Shared post-signature gates (product/kind/expiry/anti-rollback). Pure.
function Test-PimDownlinkBaselineFinish {
    param(
        [Parameter(Mandatory)][object]$PayloadObject,
        [string[]]$AllowedKind = @('baseline'),
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0
    )
    $p = $PayloadObject
    if ("$(Get-PimDownlinkValue -Object $p -Key 'product')" -ne 'PIM4EntraPS') {
        return @{ ok = $false; reason = "unexpected bundle product '$(Get-PimDownlinkValue -Object $p -Key 'product')'"; payload = $null }
    }
    $kind = "$(Get-PimDownlinkValue -Object $p -Key 'kind')"
    if (@($AllowedKind) -notcontains $kind) {
        return @{ ok = $false; reason = "unexpected bundle kind '$kind' (allowed: $($AllowedKind -join ', '))"; payload = $null }
    }
    $validTo = "$(Get-PimDownlinkValue -Object $p -Key 'validToUtc')"
    if ($validTo.Trim()) {
        $vt = $null
        try { $vt = [datetime]::Parse($validTo, [System.Globalization.CultureInfo]::InvariantCulture) } catch {}
        if ($vt -and $NowUtc.ToUniversalTime() -gt $vt.ToUniversalTime()) {
            return @{ ok = $false; reason = "baseline bundle expired ($validTo)"; payload = $null }
        }
    }
    $ver = 0
    $verRaw = Get-PimDownlinkValue -Object $p -Key 'version'
    if ($null -ne $verRaw -and "$verRaw".Trim()) { try { $ver = [int64]$verRaw } catch { $ver = 0 } }
    if ($ver -lt [int64]$LastVersion) {
        return @{ ok = $false; reason = "baseline rollback refused: bundle version $ver < last-applied $LastVersion"; payload = $null }
    }
    return @{ ok = $true; reason = "verified (version $ver, kind $kind)"; payload = $p }
}

# ---------------------------------------------------------------------------
# SYNC-FILE PATH RESOLUTION (pure). Where does the downlink stage the per-tenant
# sync files for THIS scenario? The matrix reads:
#     central (S5): $env:PIM_SyncRootCentral / <tenantId> / *.json
#     local   (S6): $env:PIM_SyncRootLocal   / <tenantId> / *.json
# Resolution rule (mirrors Get-PimScenarioEntryPlan .syncFileLocation):
#     syncFileLocation = 'central-msp'  -> root = -CentralRoot   (per-tenant subfolder)
#     syncFileLocation = 'local-slave'  -> root = -LocalRoot
#     syncFileLocation = 'none'         -> no staging (single/non-managed)
# Returns @{ stage; root; tenantFolder; files=@{name->relpath} } -- stage=$false
# when the scenario stages nothing (none). PURE: builds paths, writes nothing.
# ---------------------------------------------------------------------------
function Resolve-PimDownlinkSyncPath {
    param(
        [Parameter(Mandatory)][string]$SyncFileLocation,   # none | central-msp | local-slave
        [Parameter(Mandatory)][string]$TenantId,
        [string]$CentralRoot,
        [string]$LocalRoot
    )
    $loc = "$SyncFileLocation".Trim().ToLowerInvariant()
    if ($loc -eq 'none' -or -not $loc) {
        return @{ stage = $false; root = ''; tenantFolder = ''; reason = 'scenario stages no sync files (syncFileLocation=none)'; files = @{} }
    }
    $root = $null
    if ($loc -eq 'central-msp') { $root = $CentralRoot }
    elseif ($loc -eq 'local-slave') { $root = $LocalRoot }
    else { return @{ stage = $false; root = ''; tenantFolder = ''; reason = "unknown syncFileLocation '$SyncFileLocation'"; files = @{} } }

    if (-not "$root".Trim()) {
        return @{ stage = $true; root = ''; tenantFolder = ''; reason = "syncFileLocation=$loc but no staging root supplied"; files = @{} }
    }
    $tenantFolder = Join-Path $root "$TenantId"
    return @{
        stage        = $true
        root         = "$root"
        tenantFolder = $tenantFolder
        reason       = "stage per-tenant sync files under $tenantFolder"
        files        = @{
            admins   = (Join-Path $tenantFolder 'admins.sync.json')
            manifest = (Join-Path $tenantFolder 'manifest.sync.json')
        }
    }
}

# ---------------------------------------------------------------------------
# SYNC-FILE CONTENT (pure). Build the deterministic per-tenant sync payloads from
# the ring-filtered admin set + the verified baseline meta. Stable JSON (sorted
# keys, fixed order) so re-staging identical input yields byte-identical files
# (the idempotency contract for the file layer). Returns @{ admins; manifest }.
# ---------------------------------------------------------------------------
function New-PimDownlinkSyncContent {
    param(
        [object[]]$Admins = @(),
        [Parameter(Mandatory)][string]$TenantId,
        [int]$SlaveRing = 2,
        [int64]$BaselineVersion = 0,
        [string]$Scope = 'fleet'
    )
    $adminRows = @(@($Admins) | ForEach-Object {
        [ordered]@{
            UserName    = "$(Get-PimDownlinkValue -Object $_ -Key 'UserName')"
            DisplayName = "$(Get-PimDownlinkValue -Object $_ -Key 'DisplayName')"
            Ring        = [int](Get-PimDownlinkValue -Object $_ -Key 'Ring')
            Template    = "$(Get-PimDownlinkValue -Object $_ -Key 'Template')"
        }
    } | Sort-Object @{ e = { $_.Ring } }, @{ e = { "$($_.UserName)".ToLowerInvariant() } })

    $adminsDoc = [ordered]@{
        product   = 'PIM4EntraPS'
        kind      = 'downlink-admins'
        tenantId  = "$TenantId"
        slaveRing = [int]$SlaveRing
        version   = [int64]$BaselineVersion
        scope     = "$Scope"
        admins    = $adminRows
    }
    $manifestDoc = [ordered]@{
        product       = 'PIM4EntraPS'
        kind          = 'downlink-manifest'
        tenantId      = "$TenantId"
        slaveRing     = [int]$SlaveRing
        version       = [int64]$BaselineVersion
        adminCount    = $adminRows.Count
        adminUserNames = @($adminRows | ForEach-Object { $_.UserName })
    }
    return @{
        admins   = ($adminsDoc   | ConvertTo-Json -Depth 8)
        manifest = ($manifestDoc | ConvertTo-Json -Depth 8)
    }
}

# ---------------------------------------------------------------------------
# DOWNLINK DECISION PLAN (pure). The end-to-end ring-gated downlink decision for
# ONE managed tenant, built from FACTS the live wrapper gathers:
#   -Scenario        : S5 | S6 (or a descriptor) -- resolved for hosting/sync loc.
#   -Doc             : the pulled signed baseline document (verified here).
#   -PublicKey       : verifying RSA/cert (tests inject an ephemeral key; prod omits
#                      to use the embedded cert).
#   -BaselineAdmins  : the admin rows carried by the verified baseline payload
#                      (UserName+Ring+Template+DisplayName). When omitted, taken
#                      from the verified payload.rows.
#   -TenantId/-SlaveRing : the managed tenant + its registry ring.
#   -CentralRoot/-LocalRoot : sync-file staging roots (per syncFileLocation).
#   -NowUtc/-LastVersion : expiry + anti-rollback inputs.
# Returns a decision object the wrapper executes:
#   { ok; reason; scenarioId; ring; sync=<Resolve-PimDownlinkSyncPath>;
#     admins=<ring-filtered set>; content=<New-PimDownlinkSyncContent>;
#     baselineVersion; verify=<Test-PimDownlinkBaseline meta> }.
# ok=$false (with reason) when verification fails -> the wrapper REFUSES to stage
# or apply (bad sig / expired / rollback). NO I/O, NO globals.
# ---------------------------------------------------------------------------
function Get-PimDownlinkPlan {
    param(
        [Parameter(Mandatory)][object]$Scenario,
        [Parameter(Mandatory)][object]$Doc,
        [object]$PublicKey,
        [object[]]$BaselineAdmins,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][int]$SlaveRing,
        [string]$CentralRoot,
        [string]$LocalRoot,
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0,
        [string]$Scope = 'fleet'
    )
    $ctx = Resolve-PimScenarioContext -Scenario $Scenario
    if (-not [bool]$ctx.syncAdminsPermissions) {
        return @{ ok = $false; reason = "scenario $($ctx.id) is not a managed/sync scenario (syncAdminsPermissions=false)"; scenarioId = "$($ctx.id)"; admins = @(); sync = $null; content = $null; baselineVersion = 0; verify = $null }
    }

    # 1) verify the pulled baseline (sig + product/kind + expiry + anti-rollback).
    $verify = Test-PimDownlinkBaseline -Doc $Doc -PublicKey $PublicKey -AllowedKind @('baseline') -NowUtc $NowUtc -LastVersion $LastVersion
    if (-not $verify.ok) {
        return @{ ok = $false; reason = "baseline verify failed: $($verify.reason)"; scenarioId = "$($ctx.id)"; ring = $SlaveRing; admins = @(); sync = $null; content = $null; baselineVersion = 0; verify = $verify }
    }
    $payload = $verify.payload
    $blVersion = 0
    $vr = Get-PimDownlinkValue -Object $payload -Key 'version'
    if ($null -ne $vr -and "$vr".Trim()) { try { $blVersion = [int64]$vr } catch { $blVersion = 0 } }

    # 2) the admin set to consider = explicit -BaselineAdmins, else payload.rows.
    $src = @()
    if ($PSBoundParameters.ContainsKey('BaselineAdmins') -and $null -ne $BaselineAdmins) { $src = @($BaselineAdmins) }
    else { $src = @(Get-PimDownlinkValue -Object $payload -Key 'rows') }

    # 3) ring-gate to admin.Ring <= slave.Ring.
    $admins = @(Select-PimDownlinkAdmins -Admins $src -SlaveRing $SlaveRing)

    # 4) resolve the sync-file staging path for this scenario.
    $sync = Resolve-PimDownlinkSyncPath -SyncFileLocation "$($ctx.syncFileLocation)" -TenantId $TenantId -CentralRoot $CentralRoot -LocalRoot $LocalRoot

    # 5) build the deterministic per-tenant sync content.
    $content = New-PimDownlinkSyncContent -Admins $admins -TenantId $TenantId -SlaveRing $SlaveRing -BaselineVersion $blVersion -Scope $Scope

    return @{
        ok              = $true
        reason          = "downlink plan for $($ctx.id): $($admins.Count) admin(s) reach slave ring $SlaveRing from baseline v$blVersion"
        scenarioId      = "$($ctx.id)"
        ring            = $SlaveRing
        sync            = $sync
        admins          = $admins
        content         = $content
        baselineVersion = $blVersion
        verify          = $verify
    }
}

# ---------------------------------------------------------------------------
# IDEMPOTENCY DECISION (pure). Given the freshly-computed sync content + what is
# ALREADY staged on disk (the wrapper reads the existing files' text), decide
# whether the second pass is a no-op. Compares the stable JSON byte-for-byte.
# Returns @{ changed; changedFiles=@(...); detail }. changed=$false => idempotent.
# ---------------------------------------------------------------------------
function Test-PimDownlinkIdempotent {
    param(
        [Parameter(Mandatory)][hashtable]$NewContent,    # @{ admins; manifest } (strings)
        [hashtable]$ExistingContent = @{}                # @{ admins; manifest } current on-disk text (missing = '')
    )
    $changed = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($NewContent.Keys)) {
        $new = "$($NewContent[$k])"
        $old = ''
        if ($ExistingContent.ContainsKey($k)) { $old = "$($ExistingContent[$k])" }
        # normalise line endings so a CRLF/LF round-trip on disk isn't a false change.
        $newN = $new -replace "`r`n", "`n"
        $oldN = $old -replace "`r`n", "`n"
        if ($newN -ne $oldN) { $changed.Add($k) | Out-Null }
    }
    $arr = @($changed.ToArray())
    return @{
        changed      = ($arr.Count -gt 0)
        changedFiles = $arr
        detail       = $(if ($arr.Count) { "would rewrite: $($arr -join ', ')" } else { 'all sync files identical (idempotent no-op)' })
    }
}

# ---------------------------------------------------------------------------
# SCENARIO RUNNER PLAN (pure). The topology branch for the scenario-bound runner:
#   single  (S1/S2)        -> engine apply only.
#   master  (S3/S4)        -> engine apply only (master hosts its own estate).
#   managed (S5/S6)        -> downlink-sync THEN engine apply.
# Returns @{ scenarioId; role; steps=@('downlink-sync'?, 'engine-apply'); runDownlink; runEngine; reason }.
# PURE: decides the ordered step list; the live runner executes each step.
# ---------------------------------------------------------------------------
function Get-PimScenarioRunPlan {
    param([Parameter(Mandatory)][object]$Scenario)
    $ctx = Resolve-PimScenarioContext -Scenario $Scenario
    $role = "$($ctx.role)"
    $runDownlink = [bool]$ctx.syncAdminsPermissions   # true only for managed (S5/S6)
    $steps = New-Object System.Collections.Generic.List[string]
    if ($runDownlink) { $steps.Add('downlink-sync') | Out-Null }
    $steps.Add('engine-apply') | Out-Null
    $reason = if ($runDownlink) {
        "managed scenario $($ctx.id) ($role): ring pull -> master->slave sync -> engine apply"
    } else {
        "$role scenario $($ctx.id): engine apply only (no downlink)"
    }
    return @{
        scenarioId  = "$($ctx.id)"
        role        = $role
        runDownlink = $runDownlink
        runEngine   = $true
        steps       = @($steps.ToArray())
        reason      = $reason
    }
}

# =============================================================================
# THIN LIVE ORCHESTRATORS (named to satisfy the live matrix's capability probe).
# These compose the pure cores above with the EXISTING live engines. They DO
# touch the world (verify+stage files, run the fan-out + engine) -- but ONLY when
# explicitly invoked by the live wrappers / main session. The matrix's
# Test-SyncWiringBuilt only needs these to be DEFINED (Get-Command), which is the
# §31.3 "wiring exists + is invokable" contract; the live outcome (admins created
# in the slave) is proven by running them against the real tenants.
#
# IMPORTANT (pull-not-push): the MASTER never writes into a managed tenant. The
# central/managed engine host runs Invoke-PimManagedDownlink, which applies the
# synced rows into the slave via the SLAVE's OWN per-tenant SPN (Invoke-PimMspFanout
# authenticates per-tenant from pim.CentralAdmins + platform.TenantApps and creates
# the admins IN the slave). The downlink only stages the ring's signed baseline.
# =============================================================================

# Invoke-PimManagedDownlink -- the ring-gated master->managed admin/permission
# downlink for ONE managed tenant. Verifies + stages the sync files (pure plan),
# then (unless -WhatIfMode) applies into the slave by composing Invoke-PimMspFanout.
#   -Scenario        : S5 | S6 (or descriptor).
#   -Doc             : the pulled signed baseline document.
#   -PublicKey       : verifying key (omit in prod -> embedded cert).
#   -TenantId/-SlaveRing : the managed tenant + ring.
#   -CentralRoot/-LocalRoot : sync-file staging roots.
#   -SqlServer/-SqlDatabase : the registry the fan-out reads (slave creation).
#   -WhatIfMode      : default ON (verify + stage files + PLAN the fan-out only).
# Returns the decision/plan object + a `staged` list + the fan-out result (live).
function Invoke-PimManagedDownlink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Scenario,
        [Parameter(Mandatory)][object]$Doc,
        [object]$PublicKey,
        [object[]]$BaselineAdmins,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][int]$SlaveRing,
        [string]$CentralRoot = $env:PIM_SyncRootCentral,
        [string]$LocalRoot   = $env:PIM_SyncRootLocal,
        [string]$SqlServer,
        [string]$SqlDatabase,
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0,
        [switch]$WhatIfMode = $true
    )
    # 1) PURE plan: verify + ring-filter + resolve paths + build content.
    $plan = Get-PimDownlinkPlan -Scenario $Scenario -Doc $Doc -PublicKey $PublicKey `
        -BaselineAdmins $BaselineAdmins -TenantId $TenantId -SlaveRing $SlaveRing `
        -CentralRoot $CentralRoot -LocalRoot $LocalRoot -NowUtc $NowUtc -LastVersion $LastVersion
    if (-not $plan.ok) {
        Write-Host "[downlink] REFUSED: $($plan.reason)" -ForegroundColor Red
        return ([pscustomobject]@{ ok = $false; reason = $plan.reason; plan = $plan; staged = @(); fanout = $null })
    }
    Write-Host "[downlink] $($plan.reason)" -ForegroundColor Cyan

    # 2) STAGE the per-tenant sync files (idempotent: only rewrite on change).
    $staged = New-Object System.Collections.Generic.List[object]
    $sync = $plan.sync
    if ($sync -and [bool]$sync.stage -and "$($sync.tenantFolder)".Trim()) {
        if (-not (Test-Path -LiteralPath $sync.tenantFolder)) { New-Item -ItemType Directory -Force -Path $sync.tenantFolder | Out-Null }
        $existing = @{}
        foreach ($k in @($plan.content.Keys)) {
            $fp = $sync.files[$k]
            if ($fp -and (Test-Path -LiteralPath $fp)) { try { $existing[$k] = [System.IO.File]::ReadAllText($fp) } catch {} }
        }
        $idem = Test-PimDownlinkIdempotent -NewContent $plan.content -ExistingContent $existing
        foreach ($k in @($plan.content.Keys)) {
            $fp = $sync.files[$k]
            if (-not $fp) { continue }
            if ($idem.changedFiles -contains $k -or -not (Test-Path -LiteralPath $fp)) {
                [System.IO.File]::WriteAllText($fp, "$($plan.content[$k])", (New-Object System.Text.UTF8Encoding($false)))
                $staged.Add([pscustomobject]@{ file = $fp; action = 'written' }) | Out-Null
            } else {
                $staged.Add([pscustomobject]@{ file = $fp; action = 'unchanged' }) | Out-Null
            }
        }
        Write-Host "[downlink] sync files: $($idem.detail) ($($sync.tenantFolder))" -ForegroundColor DarkGray
    } else {
        Write-Host "[downlink] no sync-file staging for this scenario ($($sync.reason))" -ForegroundColor DarkGray
    }

    # 3) APPLY into the slave by composing Invoke-PimMspFanout (creates the admins
    #    IN the slave via its OWN per-tenant SPN). pull-not-push: the master host
    #    runs the fan-out; the slave's SPN does the write. The fan-out is ring-aware
    #    (pim.vw_AdminTenantTargets) so it materializes exactly the ring-reached set.
    $fanout = $null
    $fanoutScript = Join-Path (Split-Path -Parent $PSScriptRoot) '..\setup\Invoke-PimMspFanout.ps1'
    $fanoutScript = (Resolve-Path -LiteralPath $fanoutScript -ErrorAction SilentlyContinue)
    if ($fanoutScript) {
        $srv = if ("$SqlServer".Trim()) { $SqlServer } elseif ($global:PIM_SqlServer) { "$($global:PIM_SqlServer)" } else { '.\SQLEXPRESS' }
        $db  = if ("$SqlDatabase".Trim()) { $SqlDatabase } elseif ($global:PIM_SqlDatabase) { "$($global:PIM_SqlDatabase)" } else { 'PimPlatform' }
        try {
            $fanout = & $fanoutScript -ServerInstance $srv -Database $db -WhatIfMode:$WhatIfMode
        } catch {
            Write-Host "[downlink] fan-out apply failed: $($_.Exception.Message)" -ForegroundColor Red
            return ([pscustomobject]@{ ok = $false; reason = "fan-out failed: $($_.Exception.Message)"; plan = $plan; staged = @($staged.ToArray()); fanout = $null })
        }
    } else {
        Write-Host "[downlink] Invoke-PimMspFanout.ps1 not found -- staged sync files only (no apply)." -ForegroundColor Yellow
    }

    return ([pscustomobject]@{ ok = $true; reason = $plan.reason; plan = $plan; staged = @($staged.ToArray()); fanout = $fanout })
}

# Sync-PimMasterToSlave -- alias-style entry the matrix also probes for. Thin
# pass-through to Invoke-PimManagedDownlink (one orchestrator, two recognised names).
function Sync-PimMasterToSlave {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][object]$Scenario,
        [Parameter(Mandatory)][object]$Doc,
        [object]$PublicKey,
        [object[]]$BaselineAdmins,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][int]$SlaveRing,
        [string]$CentralRoot = $env:PIM_SyncRootCentral,
        [string]$LocalRoot   = $env:PIM_SyncRootLocal,
        [string]$SqlServer, [string]$SqlDatabase,
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0,
        [switch]$WhatIfMode = $true
    )
    Invoke-PimManagedDownlink @PSBoundParameters
}

# Invoke-PimScenarioDeploy / Invoke-PimScenarioSync -- the scenario-bound RUNNER
# the matrix probes for (scenario-runner-triggers-engine + idempotent-second-pass).
# Resolves the scenario, then per topology: single/master -> engine apply; managed
# -> downlink-sync THEN engine apply. Returns the run-plan + per-step results.
#   -Scenario : S1..S6 (or descriptor).
#   -EngineScope/-EngineMode : forwarded to Invoke-PimEngineCore (default All/Delta).
#   -Doc/-PublicKey/-TenantId/-SlaveRing/... : forwarded to the downlink (managed only).
#   -WhatIfMode : default ON (plan/preview; no live writes).
function Invoke-PimScenarioDeploy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Scenario,
        [string]$EngineScope = 'All',
        [ValidateSet('Full','Delta')][string]$EngineMode = 'Delta',
        # downlink inputs (managed scenarios only)
        [object]$Doc,
        [object]$PublicKey,
        [object[]]$BaselineAdmins,
        [string]$TenantId,
        [int]$SlaveRing = 2,
        [string]$CentralRoot = $env:PIM_SyncRootCentral,
        [string]$LocalRoot   = $env:PIM_SyncRootLocal,
        [string]$SqlServer, [string]$SqlDatabase,
        [datetime]$NowUtc = ([datetime]::UtcNow),
        [int64]$LastVersion = 0,
        [switch]$WhatIfMode = $true
    )
    $run = Get-PimScenarioRunPlan -Scenario $Scenario
    Write-Host "[scenario-run] $($run.reason)" -ForegroundColor Cyan
    $results = New-Object System.Collections.Generic.List[object]

    # 1) managed: downlink-sync first.
    if ($run.runDownlink) {
        if (-not ($Doc -and "$TenantId".Trim())) {
            Write-Host "[scenario-run] managed scenario but no -Doc/-TenantId supplied -- skipping downlink step." -ForegroundColor Yellow
            $results.Add([pscustomobject]@{ step = 'downlink-sync'; ok = $false; detail = 'no baseline doc / tenant id supplied' }) | Out-Null
        } else {
            $dl = Invoke-PimManagedDownlink -Scenario $Scenario -Doc $Doc -PublicKey $PublicKey `
                -BaselineAdmins $BaselineAdmins -TenantId $TenantId -SlaveRing $SlaveRing `
                -CentralRoot $CentralRoot -LocalRoot $LocalRoot -SqlServer $SqlServer -SqlDatabase $SqlDatabase `
                -NowUtc $NowUtc -LastVersion $LastVersion -WhatIfMode:$WhatIfMode
            $results.Add([pscustomobject]@{ step = 'downlink-sync'; ok = [bool]$dl.ok; detail = "$($dl.reason)"; result = $dl }) | Out-Null
            if (-not $dl.ok) {
                return ([pscustomobject]@{ ok = $false; scenarioId = $run.scenarioId; plan = $run; steps = @($results.ToArray()) })
            }
        }
    }

    # 2) engine apply (all scenarios). Composes Invoke-PimEngineCore (which honours
    #    the mass-disable guard + empty-desired-never-prunes).
    $engine = $null
    $engineScript = Join-Path (Split-Path -Parent $PSScriptRoot) '..\tools\pim-engine\Invoke-PimEngineCore.ps1'
    $engineScript = (Resolve-Path -LiteralPath $engineScript -ErrorAction SilentlyContinue)
    if ($engineScript) {
        try {
            $engineArgs = @{ Scope = $EngineScope; Mode = $EngineMode }
            if ($WhatIfMode) { $engineArgs.WhatIf = $true }
            $engine = & $engineScript @engineArgs
            # The engine entry emits a tagged summary object (kind='pim-engine-summary')
            # carrying the REAL create/update/remove counts. Extract it so the caller (the
            # live matrix's idempotent-second-pass step) can assert zero changes on pass 2.
            $summary = $null
            foreach ($o in @($engine)) {
                if ($o -and ($o.PSObject.Properties['kind']) -and "$($o.kind)" -eq 'pim-engine-summary') { $summary = $o }
            }
            $cu = if ($summary) { [int]$summary.create } else { -1 }
            $uu = if ($summary) { [int]$summary.update } else { -1 }
            $ru = if ($summary) { [int]$summary.remove } else { -1 }
            $eu = if ($summary) { [int]$summary.errors } else { -1 }
            $okEngine = if ($summary) { ($eu -eq 0) } else { $true }
            $det = if ($summary) { "engine ran ($EngineScope/$EngineMode$(if($WhatIfMode){' whatif'})): create=$cu update=$uu remove=$ru errors=$eu" }
                   else { "engine ran ($EngineScope/$EngineMode$(if($WhatIfMode){' whatif'})) -- no structured summary returned" }
            $results.Add([pscustomobject]@{ step = 'engine-apply'; ok = $okEngine; detail = $det; result = $engine; changeSummary = $summary }) | Out-Null
            if (-not $okEngine) {
                return ([pscustomobject]@{ ok = $false; scenarioId = $run.scenarioId; plan = $run; steps = @($results.ToArray()); changeSummary = $summary })
            }
        } catch {
            Write-Host "[scenario-run] engine apply failed: $($_.Exception.Message)" -ForegroundColor Red
            $results.Add([pscustomobject]@{ step = 'engine-apply'; ok = $false; detail = "$($_.Exception.Message)" }) | Out-Null
            return ([pscustomobject]@{ ok = $false; scenarioId = $run.scenarioId; plan = $run; steps = @($results.ToArray()) })
        }
    } else {
        Write-Host "[scenario-run] Invoke-PimEngineCore.ps1 not found -- engine step skipped." -ForegroundColor Yellow
        $results.Add([pscustomobject]@{ step = 'engine-apply'; ok = $false; detail = 'engine entry not found' }) | Out-Null
    }

    $okAll = -not (@($results.ToArray()) | Where-Object { -not $_.ok })
    # Surface the engine change summary at the top level so the live matrix can assert
    # idempotency (create+update+remove == 0 on a second pass) without re-digging the steps.
    $cs = $null
    foreach ($st in @($results.ToArray())) { if ($st.step -eq 'engine-apply' -and $st.changeSummary) { $cs = $st.changeSummary } }
    return ([pscustomobject]@{ ok = [bool]$okAll; scenarioId = $run.scenarioId; plan = $run; steps = @($results.ToArray()); changeSummary = $cs })
}

# alias name the matrix also probes for.
function Invoke-PimScenarioSync {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][object]$Scenario,
        [string]$EngineScope = 'All',
        [ValidateSet('Full','Delta')][string]$EngineMode = 'Delta',
        [object]$Doc, [object]$PublicKey, [object[]]$BaselineAdmins,
        [string]$TenantId, [int]$SlaveRing = 2,
        [string]$CentralRoot = $env:PIM_SyncRootCentral, [string]$LocalRoot = $env:PIM_SyncRootLocal,
        [string]$SqlServer, [string]$SqlDatabase,
        [datetime]$NowUtc = ([datetime]::UtcNow), [int64]$LastVersion = 0,
        [switch]$WhatIfMode = $true
    )
    Invoke-PimScenarioDeploy @PSBoundParameters
}
