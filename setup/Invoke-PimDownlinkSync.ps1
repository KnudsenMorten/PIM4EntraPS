#Requires -Version 5.1
<#
.SYNOPSIS
    §31.3 Phase-2 -- the ring-gated master->managed (slave) admin/permission SYNC
    (downlink) live wrapper. Thin orchestrator over the PURE core in
    engine/_shared/PIM-Downlink.ps1 (Invoke-PimManagedDownlink).

.DESCRIPTION
    For ONE managed/slave tenant (S5 central-hosted | S6 local-hosted):

      1. PULL the master's SIGNED baseline bundle (HTTPS GET from private-endpoint
         blob storage, OAuth bearer over REST) -- the SAME bundle New-PimBaselineBundle
         publishes. -BaselineDocPath lets the main session feed a locally-pulled
         bundle instead (e.g. when the seeder produced it).
      2. VERIFY it offline (RSA-SHA256 against the embedded PUBLIC baseline cert;
         refuse on bad signature / expiry / anti-rollback) -- pull-not-push trust
         model identical to the offline .pimlicense.
      3. RING-GATE the admin set to admin.Ring <= slave.Ring.
      4. STAGE the per-tenant sync files in the resolved folder (central-msp via
         -CentralRoot / $env:PIM_SyncRootCentral, local-slave via -LocalRoot /
         $env:PIM_SyncRootLocal). Idempotent: only rewrites on content change.
      5. PROVIDE THE ACCOUNTS, by the route the topology dictates (IMP-12):
           * S5 (central-hosted): compose Invoke-PimMspFanout, which authenticates
             per-tenant with the SLAVE's OWN SPN + certificate and creates the accounts.
           * S6 (local-hosted): stage them as desired rows in the slave's own store
             (Invoke-PimDownlinkAdminApply) and let the slave's engine create them on its
             next tick -- pull, not push. Needs -SlaveSqlServer and a slave default domain.
         Either way the MASTER never writes into the managed tenant.

    PURE decisions live in engine/_shared/PIM-Downlink.ps1 (offline-tested in
    tests/Test-PimDownlink.ps1). This wrapper only gathers facts (pull + read
    registry) and acts. PS 5.1-safe; SPN + certificate only (never interactive,
    never a secret, never device-code).

.PARAMETER Scenario
    'S5' (central-hosted managed) or 'S6' (local-hosted managed).

.PARAMETER TenantId / SlaveRing
    The managed tenant id + its registry ring (default 2 = test).

.PARAMETER BaselineUrl
    HTTPS URL of the master's signed baseline bundle (baseline-latest.json).
    Mutually exclusive with -BaselineDocPath.

.PARAMETER BaselineAccessToken
    Storage bearer token for the pull (minted by the caller over REST/MI).

.PARAMETER BaselineDocPath
    Local path to an already-pulled signed bundle JSON (skips the HTTPS pull).

.PARAMETER CentralRoot / LocalRoot
    Sync-file staging roots (per syncFileLocation). Default from
    $env:PIM_SyncRootCentral / $env:PIM_SyncRootLocal.

.PARAMETER SqlServer / SqlDatabase
    The platform registry the fan-out reads. Default .\SQLEXPRESS / PimPlatform.

.PARAMETER WhatIfMode
    Default ON: verify + stage files + PLAN the fan-out only. -WhatIfMode:$false applies.

.EXAMPLE
    # MAIN SESSION (creds from kv-automatit-dev), S6 local-hosted managed (2linkit):
    $env:PIM_SyncRootLocal = 'C:\ProgramData\PIM4EntraPS\sync'
    .\Invoke-PimDownlinkSync.ps1 -Scenario S6 -TenantId <tenant-id-2linkit> -SlaveRing 2 `
        -BaselineDocPath C:\TMP\baseline-latest.json -WhatIfMode:$false
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario,
    [Parameter(Mandatory)][string]$TenantId,
    [ValidateRange(0,2)][int]$SlaveRing = 2,

    [string]$BaselineUrl,
    [string]$BaselineAccessToken,
    [string]$BaselineDocPath,

    [string]$CentralRoot = $env:PIM_SyncRootCentral,
    [string]$LocalRoot   = $env:PIM_SyncRootLocal,

    [string]$SqlServer   = $env:PIM_SqlServer,
    [string]$SqlDatabase = $env:PIM_SqlDatabase,

    [int64]$LastVersion = 0,

    # --- BUG-29: the master's TEMPLATE ring map (RING-1 plane 2) ---------------
    # The master's answer to "which baseline VERSION may this managed tenant pull?".
    # See config/template-ring-map.sample.json.
    # 🔒 OPT-IN AND INERT WITHOUT IT. Omit both and this script behaves exactly as it
    # did when S5/S6 were VERIFIED -- no version restriction, ring used only to filter
    # the admin set. That mirrors the framework's own `default: null` non-breaking rule.
    [string]$TemplateRingMapPath,
    [string]$TemplateRingMapUrl,
    [string]$TemplateName = 'Baseline',
    # ⚠️ 'managed', NOT plane 1's 'internal'. Plane 1's channels say where the CODE
    # comes from; plane 2's say what the MSP relationship is. Get-PimTemplateRingPlan
    # defaults the same way so the two planes cannot be confused by copy-paste.
    [string]$TemplateChannel = 'managed',

    # --- MSP-2 / control #2: reflect the master admins' ROLES into the slave -----
    # The projection itself always runs (it is carried by the signed bundle); these
    # decide whether it is APPLIED. The slave's DESIRED store is a different database
    # from the master's platform registry above, and this script cannot infer it --
    # so it is explicit. Without it the run still stages the assignments file and
    # says, in yellow, that it projected N roles and applied none.
    [string]$SlaveSqlServer,
    [string]$SlaveSqlDatabase,
    # IMP-12: the managed tenant's default verified domain. On S6 the synced admins are
    # staged into the slave's OWN store as <UserName>@<this domain> and its engine creates
    # them. Omit it when this runs inside the managed tenant and the domain can be read from
    # the ambient token; it is never guessed, so without either the admins are not staged.
    [string]$SlaveDefaultDomain,
    # TAP intent for the synced admins (operator decision 2026-08-13 -- ON by default, because a
    # synced admin who cannot sign in is not a delivered admin). Per-admin values from the
    # master's registry win; these apply only where the bundle carries none.
    # 🪤 -DefaultManagerEmail is not optional in practice: with no manager address the TAP is
    # minted and mailed nowhere, and the code cannot be recovered afterwards.
    [ValidateSet('TRUE','FALSE')][string]$CreateTapDefault = 'TRUE',
    [int]$TapLifetimeHoursDefault = 8,
    [string]$DefaultManagerEmail = '',
    # The decouple switch: withdraw previously-synced roles even when the master
    # currently projects none. Off by default -- see the mass-revoke guard.
    [switch]$AllowFullPrune,

    [switch]$WhatIfMode = $true
)

$ErrorActionPreference = 'Stop'
$shared = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared'
# 🔴 PIM-Rest FIRST, and PIM-SqlStore right after it. This script reads and writes the
# SLAVE's Azure SQL store, and that needs an access token -- but nothing in the chain below
# dot-sources the token provider, so in THIS script's scope $script:PimRestResources and
# $script:PimTokenCache were both $null. A dot-sourced function's $script: binds to the
# scope it is CALLED from, not the file it came from, so `Get-Command Get-PimRestToken`
# answered TRUE (the caller had it) while every token attempt threw "You cannot call a
# method on a null-valued expression" -- and New-PimSqlConnection then handed SQL no
# credential at all. The visible symptom is Azure SQL's `Login failed for user ''`, which
# reads like a permissions problem and is not one. Measured against HOGYM 2026-08-13.
. (Join-Path $shared 'PIM-Rest.ps1')
. (Join-Path $shared 'PIM-SqlStore.ps1')
. (Join-Path $shared 'PIM-ScenarioProfile.ps1')   # also dot-sources PIM-Downlink.ps1
. (Join-Path $shared 'PIM-Baseline.ps1')
# BUG-29: the vendored platform ring core. ⚠️ Until this line, PIM-RingGate.ps1 was
# dot-sourced by NOTHING except its own test -- so the version gate was not merely
# "called by nobody", its functions were not even DEFINED in any runtime process.
. (Join-Path $shared 'PIM-RingGate.ps1')

if (-not $SqlServer)   { $SqlServer = '.\SQLEXPRESS' }
if (-not $SqlDatabase) { $SqlDatabase = 'PimPlatform' }
$global:PIM_SqlServer   = $SqlServer
$global:PIM_SqlDatabase = $SqlDatabase
$global:PIM_UseGraphSdk = $false

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " PIM4EntraPS §31.3 downlink-sync ($Scenario, tenant $TenantId, ring $SlaveRing) $(if ($WhatIfMode) { '(WHATIF)' } else { '(LIVE)' })" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan

# 1) obtain the signed baseline bundle (local file OR HTTPS pull).
$doc = $null
if ("$BaselineDocPath".Trim()) {
    if (-not (Test-Path -LiteralPath $BaselineDocPath)) { throw "baseline doc not found: $BaselineDocPath" }
    $raw = Get-Content -LiteralPath $BaselineDocPath -Raw
    $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }
    $doc = $raw | ConvertFrom-Json
    Write-Host "  baseline: loaded from $BaselineDocPath" -ForegroundColor DarkGray
} elseif ("$BaselineUrl".Trim()) {
    $headers = @{ 'x-ms-version' = '2021-08-06' }
    if ("$BaselineAccessToken".Trim()) { $headers['Authorization'] = "Bearer $BaselineAccessToken" }
    $raw = Invoke-RestMethod -Method GET -Uri $BaselineUrl -Headers $headers -ErrorAction Stop
    if ($raw -is [string]) { $br = $raw.IndexOf('{'); if ($br -gt 0) { $raw = $raw.Substring($br) }; $doc = $raw | ConvertFrom-Json }
    else { $doc = $raw }
    Write-Host "  baseline: pulled from $BaselineUrl" -ForegroundColor DarkGray
} else {
    throw 'supply -BaselineDocPath (local) or -BaselineUrl (HTTPS pull) for the signed baseline.'
}

# 1b) BUG-29: build the TEMPLATE ring plan, if the master published a map.
# The decision comes from the VENDORED PLATFORM CORE (Get-PimTemplateRingPlan, itself
# composed from the vendored plane-1 parts), never from PIM-private hold/allow logic --
# PIM consumes the AutomateIT design here rather than reimplementing it.
$ringPlan = $null
$ringMap  = $null
if ("$TemplateRingMapPath".Trim()) {
    if (-not (Test-Path -LiteralPath $TemplateRingMapPath)) { throw "template ring map not found: $TemplateRingMapPath" }
    # Assign first, then use -- never @(pipeline). See BUG-26.
    $rawMap = Get-Content -LiteralPath $TemplateRingMapPath -Raw
    $ringMap = $rawMap | ConvertFrom-Json
    Write-Host "  ring map: loaded from $TemplateRingMapPath" -ForegroundColor DarkGray
} elseif ("$TemplateRingMapUrl".Trim()) {
    $mapHeaders = @{ 'x-ms-version' = '2021-08-06' }
    if ("$BaselineAccessToken".Trim()) { $mapHeaders['Authorization'] = "Bearer $BaselineAccessToken" }
    $rawMap = Invoke-RestMethod -Method GET -Uri $TemplateRingMapUrl -Headers $mapHeaders -ErrorAction Stop
    if ($rawMap -is [string]) { $bm = $rawMap.IndexOf('{'); if ($bm -gt 0) { $rawMap = $rawMap.Substring($bm) }; $ringMap = $rawMap | ConvertFrom-Json }
    else { $ringMap = $rawMap }
    Write-Host "  ring map: pulled from $TemplateRingMapUrl" -ForegroundColor DarkGray
}
if ($ringMap) {
    $ringPlan = Get-PimTemplateRingPlan -Template $TemplateName -TenantId $TenantId `
        -Assignments $ringMap.assignments -Promotions $ringMap.promotions `
        -Channel $TemplateChannel -DefaultRing $ringMap.default
    Write-Host ("  ring plan: {0} -> {1}{2}{3}" -f $TemplateName, $ringPlan.Action,
        $(if ($null -ne $ringPlan.Ring)    { " (ring $($ringPlan.Ring))" } else { '' }),
        $(if ("$($ringPlan.Version)".Trim()){ " approves v$($ringPlan.Version)" } else { '' })) -ForegroundColor Cyan
    if ($ringPlan.Reason) { Write-Host "             $($ringPlan.Reason)" -ForegroundColor DarkGray }
} else {
    # Say so explicitly. A silent absence is how BUG-29 survived for months: the gate
    # was DOCUMENTED as active while no code path implemented it.
    Write-Host "  ring map: none supplied -- version gate INERT (pulls whatever version the master published)" -ForegroundColor DarkYellow
}

# 2-5) verify + ring-filter + stage + apply via the orchestrator (prod cert path:
# no -PublicKey -> Invoke-PimManagedDownlink uses the embedded baseline cert).
# Splat -RingPlan only when there is one, so the gate stays inert without a map.
$dlArgs = @{}
if ($null -ne $ringPlan) { $dlArgs['RingPlan'] = $ringPlan }

# --- MSP-2 / control #2 inputs ------------------------------------------------
# The relationship's role-projection policy is AUTHORED in the master's platform registry
# (pim.TenantRoleProjection) and DELIVERED inside the signed bundle, keyed by tenant id.
#
# 🪤 It cannot be read from the registry here, and that is structural, not laziness: a process
# holds ONE ambient identity and Get-PimSqlConnectionString mints its Azure SQL token from it,
# so the same run cannot read the MASTER's registry and write the SLAVE's store -- different
# tenants, different credentials. In S6 the downlink runs inside the slave, which has no
# credential for the master's SQL at all. An earlier revision read it here and would have been
# unreachable on exactly the topology IMP-11 says we must use.
#
# So the bundle is the source, and the ESTATE-14 lesson still holds -- a policy that cannot be
# read must never silently become "no policy". Here it CAN always be read (it is in the payload
# we already verified), and a missing key genuinely means "no rules for this relationship".
$bundlePolicy = $null
try {
    # Decoded only to REPORT what will apply. The plan re-reads it from the payload it
    # verified itself, so this display copy is never what the decision is made on.
    $__payload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("$($doc.payloadB64)")) | ConvertFrom-Json
    $__map = $__payload.projectionPolicy
    if ($__map) {
        $__k = @($__map.PSObject.Properties | Where-Object { "$($_.Name)".Trim().ToLowerInvariant() -eq "$TenantId".Trim().ToLowerInvariant() } | Select-Object -First 1)
        if ($__k) { $bundlePolicy = @($__k.Value) }
    }
} catch { Write-Host "  [warn] could not read the bundle's projection policy: $($_.Exception.Message)" -ForegroundColor Yellow }
if ($bundlePolicy -and @($bundlePolicy).Count) {
    Write-Host "  role policy: $(@($bundlePolicy).Count) rule(s) carried in the SIGNED bundle ($((@($bundlePolicy) | ForEach-Object { "$($_.Mode):$($_.GroupTag)" }) -join ', '))" -ForegroundColor DarkGray
} else {
    Write-Host "  role policy: none for this relationship -- ALL of the master's roles project (add pim.TenantRoleProjection rows on the MASTER to narrow)" -ForegroundColor DarkGray
}

if ("$SlaveSqlServer".Trim()) {
    if (-not "$SlaveSqlDatabase".Trim()) { $SlaveSqlDatabase = 'PimPlatform' }
    $slaveCs = Get-PimSqlConnectionString -Server $SlaveSqlServer -Database $SlaveSqlDatabase
    $dlArgs['SlaveStoreConnectionString'] = $slaveCs
    if ($AllowFullPrune) { $dlArgs['AllowFullPrune'] = $true }
    # Which group tags actually EXIST in the slave. A projected tag with no group
    # there cannot be granted, and is reported instead of staged to fail at apply.
    try {
        # BUG-60: read every entity a group definition can live in. Reading only
        # 'PIM-Definitions' reported a tenant with a full delegation model as having NONE,
        # so its own groups looked absent and the sync offered to create duplicates of them.
        # 🔴 BUG-65 -- EXCLUDE THE ROWS THIS SYNC ITSELF OWNS. "SlaveGroupTags" answers exactly one
        # question: which tags does the CUSTOMER already have, so we defer to them instead of
        # creating our own? A group we planted on a previous run carries Owner='MSP' and is NOT the
        # customer's. Counting it made the second sync disown its own output: every group flipped
        # to "a group with this tag already exists -- the customer owns it", create dropped to 0,
        # the nestings and role bindings were withheld as writes-into-a-customer-group, and the
        # apply then offered to PRUNE the 7 rows it had just been told the master no longer
        # publishes. Measured live against HOGYM on the second run, minutes after the first.
        # An UNSTAMPED row still counts as the customer's -- absent provenance fails safe to Local,
        # exactly as the apply's prune scoping does.
        $tags = @()
        foreach ($__e in @('PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization','PIM-Definitions-Tasks','PIM-Definitions')) {
            $tags += @(Get-PimSqlRows -ConnectionString $slaveCs -Entity $__e |
                        Where-Object { "$($_.Owner)" -ne 'MSP' } |
                        ForEach-Object { "$($_.GroupTag)" } | Where-Object { $_ })
        }
        $tags = @($tags | Select-Object -Unique)
        if ($tags.Count) {
            $dlArgs['SlaveGroupTags'] = $tags
            Write-Host "  slave store: $SlaveSqlServer/$SlaveSqlDatabase ($($tags.Count) group tag(s) available)" -ForegroundColor DarkGray
        } else {
            # Loud: this is the state EFIF/RIDE are in today, and it means control #2
            # can create desired rows that the engine can never resolve.
            Write-Host "  [warn] the slave store has NO PIM-Definitions groups -- every projected role will be UNRESOLVED until its delegation model exists." -ForegroundColor Yellow
        }
    } catch { Write-Host "  [warn] could not read the slave's group tags: $($_.Exception.Message)" -ForegroundColor Yellow }
}
if ("$SlaveDefaultDomain".Trim()) { $dlArgs['SlaveDefaultDomain'] = "$SlaveDefaultDomain".Trim() }
$dlArgs['CreateTapDefault']       = $CreateTapDefault
$dlArgs['TapLifetimeHoursDefault'] = $TapLifetimeHoursDefault
if ("$DefaultManagerEmail".Trim()) { $dlArgs['DefaultManagerEmail'] = "$DefaultManagerEmail".Trim() }
$result = Invoke-PimManagedDownlink -Scenario $Scenario -Doc $doc `
    -TenantId $TenantId -SlaveRing $SlaveRing `
    -CentralRoot $CentralRoot -LocalRoot $LocalRoot `
    -SqlServer $SqlServer -SqlDatabase $SqlDatabase `
    -LastVersion $LastVersion -WhatIfMode:$WhatIfMode @dlArgs

Write-Host ""
if ($result.ok) {
    Write-Host "DOWNLINK $(if ($WhatIfMode) { 'PLANNED' } else { 'APPLIED' }): $($result.reason)" -ForegroundColor Green
    Write-Host ("  staged files: {0}" -f (@($result.staged | ForEach-Object { "$($_.action):$([System.IO.Path]::GetFileName($_.file))" }) -join ', ')) -ForegroundColor DarkGray
    if ($result.assignments) { Write-Host ("  roles: {0}" -f $result.assignments.detail) -ForegroundColor DarkGray }
} else {
    Write-Host "DOWNLINK FAILED: $($result.reason)" -ForegroundColor Red
}
$result
if (-not $result.ok) { exit 1 }
