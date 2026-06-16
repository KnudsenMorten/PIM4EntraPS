#Requires -Version 5.1
<#
.SYNOPSIS
    MSP shared substrate + multiple sync models + signed-baseline kill-switch
    (REQUIREMENTS.md § 4 / DESIGN.md § 13). Pure, offline-testable contracts that
    keep the MSP "vary the edges, never the core" rule:

      * Shared substrate (§ 4 "Shared platform/data model with TenantManager"):
        the platform registry is keyed by `Product` (`platform.Tenants` /
        `platform.TenantApps`), so TenantManager is just another Product value on
        the same tables. Resolve-PimSubstrateContext / Get-PimProductTenantQuery
        give every Product the same tenant/app/cert lookup without forking.

      * Multiple sync models (§ 4 "Support multiple MSP/sync models"): the
        deployment is NOT forced into one model. Resolve-PimSyncModel validates a
        requested model against the supported set; Get-PimSyncModelPlan returns the
        invariants (direction, who-writes, what-crosses) so a setup/scheduler can
        wire the right job. EVERY model still obeys the hard invariants: the MSP
        never writes to a customer tenant, and customer data never leaves it.

      * Signed-baseline kill-switch (§ 4 "Signed baseline + revoke kill-switch"):
        Test-PimBaselineSignerAllowed lets the local consumer reject a bundle
        signed by a REVOKED key thumbprint (kill-switch = revoke the cert), and
        Resolve-PimCentralKill verifies a SIGNED central-kill manifest (CISO
        KV-secret) that disables an admin / a whole product across all tenants by
        emitting AccountStatus flips the existing engine kill-switch pipeline
        already enforces (Invoke-PimAccountStatusChange). No new write path: the
        kill manifest is just signed desired-state the local engine applies.

    PS 5.1-safe: no ImportFromPem / ?. / ?? ; signature verify reuses the public
    cert + RSACertificateExtensions pattern from PIM-Baseline.ps1.
#>

# ---------------------------------------------------------------------------
# 1. Shared substrate -- Product-keyed platform registry (TenantManager reuse)
# ---------------------------------------------------------------------------

# The Products that ride the SAME substrate (platform.Tenants/TenantApps keyed by
# Product). Adding a Product here is the ONLY change needed for a new tool to
# share the registry, the auth/storage profiles, the signed courier + Owner tag.
$script:PimSubstrateProducts = @('PIM', 'TenantManager')

function Get-PimSubstrateProducts {
    <# Known Product values that share the registry substrate. #>
    [CmdletBinding()] param()
    @($script:PimSubstrateProducts)
}

function Test-PimSubstrateProduct {
    <# Is $Product one of the substrate-sharing products? #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Product)
    [bool]($script:PimSubstrateProducts -contains "$Product")
}

function Get-PimProductTenantQuery {
    <#
    .SYNOPSIS
        Build the Product-keyed tenant/app lookup for ANY substrate Product.
    .DESCRIPTION
        Returns a parameter-free, read-only T-SQL string that resolves the
        per-tenant app (AppId + cert thumbprint + auth mode) for the requested
        Product from the shared registry. PIM and TenantManager differ ONLY in
        this Product value -- same tables, same shape -- which is what "shared
        substrate" means. $Product is validated against the known set and
        single-quote-escaped so the literal is injection-safe.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Product,
        [string]$TenantId
    )
    if (-not (Test-PimSubstrateProduct -Product $Product)) {
        throw "Unknown substrate Product '$Product' -- expected one of: $($script:PimSubstrateProducts -join ', ')"
    }
    $p = "$Product".Replace("'", "''")
    $sql = @"
SELECT t.TenantId, t.DisplayName, t.Ring, t.Enabled,
       a.Product, a.AppId, a.CertificateThumbprint, a.AuthMode, a.SecretName
FROM platform.Tenants t
JOIN platform.TenantApps a ON a.TenantId = t.TenantId
WHERE a.Product = '$p'
"@
    if ($TenantId) {
        $tid = "$TenantId".Replace("'", "''")
        $sql += "  AND t.TenantId = '$tid'`n"
    }
    $sql += "ORDER BY t.Ring, t.DisplayName"
    $sql
}

function Resolve-PimSubstrateContext {
    <#
    .SYNOPSIS
        Normalize a registry row into a uniform per-tenant substrate context.
    .DESCRIPTION
        The SAME shape for every Product, so the core never branches on which
        tool it serves. Returns { Product, TenantId, DisplayName, Ring, AppId,
        CertificateThumbprint, AuthMode, SecretName, AuthProfile }. AuthProfile
        is the pluggable-edge selector ('cert' | 'secretref') -- the core only
        ever asks the profile for "a token for tenant X".
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Row)
    $product = "$($Row.Product)"
    if ($product -and -not (Test-PimSubstrateProduct -Product $product)) {
        throw "row Product '$product' is not a substrate Product"
    }
    $authMode = if ($Row.PSObject.Properties.Name -contains 'AuthMode' -and $Row.AuthMode) { "$($Row.AuthMode)" } else { 'Certificate' }
    [pscustomobject]@{
        Product               = $product
        TenantId              = "$($Row.TenantId)"
        DisplayName           = "$($Row.DisplayName)"
        Ring                  = if ($Row.PSObject.Properties.Name -contains 'Ring' -and "$($Row.Ring)" -ne '') { [int]$Row.Ring } else { 2 }
        AppId                 = "$($Row.AppId)"
        CertificateThumbprint = "$($Row.CertificateThumbprint)"
        AuthMode              = $authMode
        SecretName            = if ($Row.PSObject.Properties.Name -contains 'SecretName') { "$($Row.SecretName)" } else { '' }
        AuthProfile           = if ($authMode -eq 'SecretRef') { 'secretref' } else { 'cert' }
    }
}

# ---------------------------------------------------------------------------
# 2. Multiple sync models (don't force one)
# ---------------------------------------------------------------------------

# Each model is described by its INVARIANTS, not its plumbing. The hard rules
# (MSP never writes to a customer tenant; customer data never leaves the tenant;
# the local engine is the only writer into Entra/Azure) hold for ALL of them --
# the difference is only the direction of the (signed) artifact copy and which
# side initiates it. A model that violates an invariant is rejected (no fork).
$script:PimSyncModels = @{
    'pull-baseline' = @{   # default -- local PULLS the signed MSP baseline
        Direction      = 'msp-to-local'
        Initiator      = 'local'
        Crosses        = 'signed-baseline'
        MspWritesLocal = $false
        DataLeaves     = $false
        Description    = 'Local engine pulls the signed baseline bundle from the MSP and merges it with local rows.'
    }
    'template-pull' = @{   # per-customer template pull by ring (Setup-PimMsp)
        Direction      = 'msp-to-local'
        Initiator      = 'local'
        Crosses        = 'template-rows'
        MspWritesLocal = $false
        DataLeaves     = $false
        Description    = 'Customer scheduler pulls the ring template version from the MSP template DB into the local DB.'
    }
    'local-reads-msp' = @{ # local reads the MSP template store directly (read-only)
        Direction      = 'msp-to-local'
        Initiator      = 'local'
        Crosses        = 'template-rows'
        MspWritesLocal = $false
        DataLeaves     = $false
        Description    = 'Local engine reads the MSP template store read-only at run time; nothing is copied or pushed.'
    }
    'sync-out-status' = @{ # local emits a signed status summary (Flow C)
        Direction      = 'local-to-msp'
        Initiator      = 'local'
        Crosses        = 'signed-status-summary'
        MspWritesLocal = $false
        DataLeaves     = $false   # counts/compliance only, no raw privileged data
        Description    = 'Local engine emits a signed status summary (counts only) to the customer-owned sink the MSP reads.'
    }
    'msp-delegates-local' = @{ # MSP hands the customer authority; pure local autonomy
        Direction      = 'none'
        Initiator      = 'local'
        Crosses        = 'none'
        MspWritesLocal = $false
        DataLeaves     = $false
        Description    = 'MSP delegates fully to local IT; the local plane is autonomous with no standing MSP artifact exchange.'
    }
}

function Get-PimSupportedSyncModels {
    <# The supported sync-model ids. #>
    [CmdletBinding()] param()
    @($script:PimSyncModels.Keys | Sort-Object)
}

function Resolve-PimSyncModel {
    <#
    .SYNOPSIS
        Validate a requested sync model and return its invariant plan.
    .DESCRIPTION
        Throws on an unknown model OR a model whose declared invariants would
        break the MSP rules -- so a misconfigured deployment fails closed instead
        of silently pushing into a customer or exfiltrating data.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Model)
    $key = "$Model".Trim().ToLowerInvariant()
    if (-not $script:PimSyncModels.ContainsKey($key)) {
        throw "Unsupported sync model '$Model' -- supported: $((Get-PimSupportedSyncModels) -join ', ')"
    }
    $m = $script:PimSyncModels[$key]
    if ($m.MspWritesLocal) { throw "sync model '$key' violates the invariant: MSP must never write to a customer tenant" }
    if ($m.DataLeaves)     { throw "sync model '$key' violates the invariant: customer data must never leave the tenant" }
    [pscustomobject]@{
        Model          = $key
        Direction      = $m.Direction
        Initiator      = $m.Initiator
        Crosses        = $m.Crosses
        MspWritesLocal = $m.MspWritesLocal
        DataLeaves     = $m.DataLeaves
        Description    = $m.Description
    }
}

function Get-PimSyncModelPlan {
    <#
    .SYNOPSIS
        Resolve a sync model AND the scheduler job(s) that implement it.
    .DESCRIPTION
        Maps the model to the concrete scheduler job tokens a setup script wires
        on the LOCAL scheduler (PIM_SCHED_JOBS). All jobs are local-initiated --
        consistent with pull-not-push.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Model)
    $plan = Resolve-PimSyncModel -Model $Model
    $jobs = switch ($plan.Model) {
        'pull-baseline'       { @('baseline-pull') }
        'template-pull'       { @('template-pull') }
        'local-reads-msp'     { @() }                 # no copy job; engine reads at run time
        'sync-out-status'     { @('status-rollup') }
        'msp-delegates-local' { @() }                 # autonomous; no MSP exchange job
        default               { @() }
    }
    $plan | Add-Member -NotePropertyName SchedulerJobs -NotePropertyValue (@($jobs)) -PassThru
}

# ---------------------------------------------------------------------------
# 3. Signed-baseline kill-switch (revocation + central kill)
# ---------------------------------------------------------------------------

function Get-PimRevokedSignerFile {
    <# Local marker of revoked baseline-signer thumbprints (kill-switch state). #>
    [CmdletBinding()] param()
    $dir = if (Get-Command Get-PimBaselineStateFile -ErrorAction SilentlyContinue) {
        try { Split-Path -Parent (Get-PimBaselineStateFile) } catch { $null }
    } else { $null }
    if (-not $dir) { $dir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'output\state' }
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    Join-Path $dir 'baseline-revoked-signers.json'
}

function Get-PimRevokedSigners {
    <# The set of revoked baseline-signer thumbprints (upper-cased, no separators). #>
    [CmdletBinding()] param([string]$StateFile)
    if (-not $StateFile) { $StateFile = Get-PimRevokedSignerFile }
    if (-not (Test-Path $StateFile)) { return @() }
    try {
        $j = Get-Content $StateFile -Raw | ConvertFrom-Json
        , @(@($j.thumbprints) | ForEach-Object { ("$_" -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() } | Where-Object { $_ })
    } catch { @() }
}

function Set-PimRevokedSigners {
    <#
    .SYNOPSIS
        Record the revoked baseline-signer thumbprints (the kill-switch).
    .DESCRIPTION
        Revoking the signer thumbprint is the baseline kill-switch: once a
        thumbprint is here, Test-PimBaselineSignerAllowed (and thus the consumer)
        rejects every bundle signed by it. Normalizes to upper-hex, de-dups.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Thumbprints, [string]$StateFile)
    if (-not $StateFile) { $StateFile = Get-PimRevokedSignerFile }
    $clean = @($Thumbprints | ForEach-Object { ("$_" -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() } | Where-Object { $_ } | Select-Object -Unique)
    @{ thumbprints = $clean; updatedAtUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') } |
        ConvertTo-Json | Set-Content -LiteralPath $StateFile -Encoding UTF8
    , @($clean)
}

function Test-PimBaselineSignerAllowed {
    <#
    .SYNOPSIS
        Is a baseline bundle's signer thumbprint allowed (not revoked)?
    .DESCRIPTION
        The kill-switch check. $true unless the signer thumbprint is on the
        local revoked-signers list. Thumbprint comparison is separator- and
        case-insensitive. Used by the consumer BEFORE trusting a verified bundle.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Thumbprint,
        [string[]]$Revoked,
        [string]$StateFile
    )
    if (-not $PSBoundParameters.ContainsKey('Revoked')) { $Revoked = Get-PimRevokedSigners -StateFile $StateFile }
    # normalize BOTH sides (caller-supplied lists may carry colons / spaces / case)
    $norm = @($Revoked | ForEach-Object { ("$_" -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() } | Where-Object { $_ })
    $t = ("$Thumbprint" -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if (-not $t) { return $false }   # no signer thumbprint at all -> not allowed
    -not (@($norm) -contains $t)
}

function Resolve-PimCentralKill {
    <#
    .SYNOPSIS
        Verify a SIGNED central-kill manifest and emit the AccountStatus flips.
    .DESCRIPTION
        MSP-wide central kill (REQUIREMENTS.md § 4): a CISO-held KV secret /
        signed manifest disables or revokes an admin (or a whole product) across
        ALL tenants. This is NOT a new write path -- it is signed DESIRED state:
        the manifest is verified exactly like a baseline bundle (same public key,
        Test-PimBaselineDoc, kind='central-kill'), then translated into the
        AccountStatus=Disabled|Revoked + StatusChangeCode rows the EXISTING
        engine kill-switch pipeline (Invoke-PimAccountStatusChange) already
        authorizes + applies locally. The local engine remains the only writer
        into the tenant.

        The manifest payload shape:
          { product:'PIM4EntraPS', kind:'central-kill', version:<int>,
            validToUtc:<iso>, kills:[ { upn|userName, status:'Disabled'|'Revoked',
            statusChangeCode:<code>, reason:<text> } ] }

        Returns one row per kill: { UserPrincipalName, UserName, AccountStatus,
        StatusChangeCode, Reason }. Throws on a bad signature / wrong kind /
        expired manifest -- a forged kill can't disable anyone.
    .PARAMETER Doc
        The signed manifest document (payloadB64/signature/keyThumbprint).
    .PARAMETER Revoked
        Optional revoked-signer override (defaults to the local list) -- a kill
        manifest signed by a revoked key is itself refused.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Doc,
        [string[]]$Revoked,
        [string]$StateFile
    )
    if (-not (Get-Command Test-PimBaselineDoc -ErrorAction SilentlyContinue)) {
        throw "Test-PimBaselineDoc not loaded -- PIM-Baseline.ps1 must be dot-sourced before PIM-Substrate.ps1"
    }
    # signer kill-switch: refuse a manifest signed by a revoked key
    if (-not $PSBoundParameters.ContainsKey('Revoked')) { $Revoked = Get-PimRevokedSigners -StateFile $StateFile }
    if (-not (Test-PimBaselineSignerAllowed -Thumbprint "$($Doc.keyThumbprint)" -Revoked $Revoked)) {
        throw "central-kill manifest refused: signer $($Doc.keyThumbprint) is revoked (kill-switch)"
    }
    # verify signature + shape (reuses the baseline crypto + public key); the
    # kind gate inside Test-PimBaselineDoc rejects anything but a kill manifest.
    $payload = Test-PimBaselineDoc -Doc $Doc -AllowedKind 'central-kill' -ErrorAction Stop
    if ($payload.validToUtc) {
        $validTo = [datetime]::Parse("$($payload.validToUtc)", [System.Globalization.CultureInfo]::InvariantCulture)
        if ([datetime]::UtcNow -gt $validTo.ToUniversalTime()) { throw "central-kill manifest expired ($($payload.validToUtc))" }
    }
    $out = foreach ($k in @($payload.kills)) {
        $status = "$($k.status)"
        if ($status -notin @('Disabled', 'Revoked')) { throw "central-kill entry has invalid status '$status' (expected Disabled|Revoked)" }
        [pscustomobject]@{
            UserPrincipalName = "$($k.upn)"
            UserName          = "$($k.userName)"
            AccountStatus     = $status
            StatusChangeCode  = "$($k.statusChangeCode)"
            Reason            = "$($k.reason)"
        }
    }
    , @($out)
}

# ---------------------------------------------------------------------------
# 4. az acr import -- mirror the engine image MSP central ACR -> customer ACR
# ---------------------------------------------------------------------------

function Get-PimAcrImportArgs {
    <#
    .SYNOPSIS
        Build the `az acr import` argument list to mirror the engine image from
        the MSP central registry into the CUSTOMER's registry.
    .DESCRIPTION
        REQUIREMENTS.md § 4: the image is built ONCE centrally and IMPORTED to
        the customer ACR (no per-customer build); MI/SQL/license/config stay
        local. `az acr import` is server-side -- the blobs copy registry-to-
        registry, the customer never pulls/pushes through a local host, and the
        engine image carries NO secrets/customer data (already enforced by
        .dockerignore). Pure builder so the arg list is unit-tested offline.

        Cross-tenant note: when the source MSP ACR lives in a DIFFERENT tenant
        than the `az login` context (the normal MSP case), `az acr import` needs
        explicit source credentials (a token/identity that can pull the source)
        -- passed as -SourceToken (used as --password with --username '00000000-
        0000-0000-0000-000000000000', the ACR token convention) OR the source
        registry is referenced by its full resource id (--registry) for same-AAD
        cross-sub imports. We emit the token form when -SourceToken is supplied,
        else the --registry form when -SourceRegistryResourceId is supplied, else
        a same-tenant import by login server.
    .PARAMETER TargetAcrName
        The CUSTOMER's ACR (the import destination; the `-n/--name` of az acr import).
    .PARAMETER SourceLoginServer
        The MSP central ACR login server, e.g. 'mymspacr.azurecr.io'.
    .PARAMETER Repository
        Image repository, e.g. 'pim4entraps/engine'.
    .PARAMETER Tag
        Image tag to mirror, e.g. '1.1.4'.
    .PARAMETER SourceToken
        Optional ACR pull token for the source registry (cross-tenant). Treated
        as a SECRET by the caller -- never logged.
    .PARAMETER SourceRegistryResourceId
        Optional ARM resource id of the source ACR (same-AAD cross-sub form).
    .PARAMETER Force
        Overwrite an existing tag in the target (re-import a moved tag).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetAcrName,
        [Parameter(Mandatory)][string]$SourceLoginServer,
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$Tag,
        [string]$SourceToken,
        [string]$SourceRegistryResourceId,
        [switch]$Force
    )
    $sourceRef = "{0}/{1}:{2}" -f $SourceLoginServer.TrimEnd('/'), $Repository.Trim('/'), $Tag
    $args = @('acr', 'import',
        '--name', $TargetAcrName,
        '--source', $sourceRef,
        '--image', ("{0}:{1}" -f $Repository.Trim('/'), $Tag))
    if ($SourceRegistryResourceId) {
        $args += @('--registry', $SourceRegistryResourceId)
    }
    if ($SourceToken) {
        # ACR token convention: username is the all-zero GUID, password is the token.
        $args += @('--username', '00000000-0000-0000-0000-000000000000', '--password', $SourceToken)
    }
    if ($Force) { $args += '--force' }
    $args += @('--output', 'none')
    , @($args)
}

function Invoke-PimAcrImport {
    <#
    .SYNOPSIS
        Mirror the engine image into the customer ACR via `az acr import`.
    .DESCRIPTION
        Thin wrapper over Get-PimAcrImportArgs + the az CLI. Honours -WhatIf:
        prints the plan (token redacted) and runs nothing. The actual `az` call
        is only made on a real run -- the arg-building is what the offline tests
        cover. Returns $true on success.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$TargetAcrName,
        [Parameter(Mandatory)][string]$SourceLoginServer,
        [Parameter(Mandatory)][string]$Repository,
        [Parameter(Mandatory)][string]$Tag,
        [string]$SourceToken,
        [string]$SourceRegistryResourceId,
        [switch]$Force
    )
    $argList = Get-PimAcrImportArgs -TargetAcrName $TargetAcrName -SourceLoginServer $SourceLoginServer `
        -Repository $Repository -Tag $Tag -SourceToken $SourceToken `
        -SourceRegistryResourceId $SourceRegistryResourceId -Force:$Force
    $redacted = @($argList | ForEach-Object { if ($_ -eq $SourceToken -and $SourceToken) { '***' } else { $_ } })
    $target = "{0}/{1}:{2} -> {3}" -f $SourceLoginServer, $Repository, $Tag, $TargetAcrName
    if (-not $PSCmdlet.ShouldProcess($target, 'az acr import')) {
        Write-Host "  [whatif] az $($redacted -join ' ')" -ForegroundColor Yellow
        return $true
    }
    Write-Host "  az $($redacted -join ' ')" -ForegroundColor Gray
    & az @argList
    if ($LASTEXITCODE -ne 0) { throw "az acr import failed (exit $LASTEXITCODE) for $target" }
    $true
}
