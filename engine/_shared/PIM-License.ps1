#Requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS offline license verification (Core + Pro split).

.DESCRIPTION
    PIM4EntraPS Core is free. Pro features (MSP fan-out, workload connectors,
    external intake, access reviews, self-service, contacts routing) require a
    customer license file: config/<name>.pimlicense.

    The license is FULLY OFFLINE -- no online activation, no call-home, no
    public endpoint. It is a JSON payload signed with the maintainer's private
    RSA key (machine cert store on the management host, never distributed);
    this file embeds only the PUBLIC certificate and verifies the signature
    locally (RSA-SHA256). Customers on locked-down automation servers need
    nothing but the file.

    File format (issued by the internal-only New-PimLicense.ps1 -- NOT shipped):
      { "product": "PIM4EntraPS", "payloadB64": "<b64 of payload JSON>", "signature": "<b64 RSA sig>" }
    Payload:
      { licenseId, customer, sku, features[], tenantIds[], validFrom, validTo, graceDays }

    Semantics:
      * Signature is verified over the EXACT payloadB64 bytes (no JSON
        canonicalization pitfalls).
      * tenantIds [] / missing = any tenant; non-empty = the connected tenant
        must be listed (binding is the Entra tenant GUID).
      * features may contain '*' (all Pro features) or explicit names.
      * After validTo, a grace window (graceDays, default 30) keeps Pro
        features working with a warning; after grace they disable. Core is
        NEVER affected by license state.

    PS 5.1 note: certificate is loaded from raw bytes (X509Certificate2), and
    RSA comes via RSACertificateExtensions -- no ImportFromPem (PS 7-only).
#>

# Public certificate of the licensing key (CN=PIM4EntraPS-Licensing).
# The PRIVATE key never leaves the maintainer's machine store.
$script:PimLicensePublicCertB64 = 'MIID+zCCAmOgAwIBAgIQZi8bo4EYqJ9PSvrXsI3orTANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVQSU00RW50cmFQUy1MaWNlbnNpbmcwHhcNMjYwNjEyMTY1MzM4WhcNNDEwNjEyMTcwMzM0WjAgMR4wHAYDVQQDDBVQSU00RW50cmFQUy1MaWNlbnNpbmcwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQD+YFgQSxRJNuwpv/lc9z6ClbFgEc+9/hpM/TXPg7f3Q40TQfyWf54EgaKzC8Y04JkdS2lNv69NWZ5MJgwyHkwTuyngDx/giBF0aVBbnbW9dLixSY0YaN435uylMgrL9irYB79c+rN+NAWyRZTzFdw3LFLR7zhl4Wor3OexsI7tYHgH/WXegzmbl4R8amVHR2QsAr3ZHBg5WEW3C3DeomDeAuVIny4xMZp/nq6i1VXTqrBx76Cxdms6RJS0cwtystrFQFdCB4e06jqdttuj5m8CCvQbUILEzAhNnzHnFtMXJC/wWWu2vfOqqY/Wy7ORjZCWaI/a/c7bfXWpdiI5H3E4pcZCezSH7lg1VdvSGrq/bbQxOUO4a5FQ5JI5fXZuzQksjm7t0u5AAmdLpvtac86vMQmM8LCTsUoNs9GAhVvNmV+pJtReWyubfqLgzaRmMP4qMp7a6DoR3RKeuYjmSzhjFn5S4lcDmAz35Qc/LO0sEPDr3LL30fQxhX8uSqlFAEkCAwEAAaMxMC8wDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBS2n3cmD8taKDsdy2debDNeQkv7qzANBgkqhkiG9w0BAQsFAAOCAYEArrFYyp4BQzH803d4htpcqtWbkTgg10tFrdQndJ35tv+ZDGcq7AIHohI7egzH4pDPgbXOGf7GuisIzj8MEJkH63+xqB4wHHBPn+pl9YGYk02XiWY9H0blP+TIlYjderzr/XH/mLn67z2VAm9dGAw1X2xw1zMtc36aPVU7i7bRIZwfxIA5Y1sVJ9bpMRkXDawMhegA39a0inLVriBWcvfku3zz84MtHtB4WLfwUI97QLvDObHPdkQ68w+0+0tmIz33z5Fgu9dtIUf6RROkFhjoc2rC+GcI023SLeDPjHrUHg1RjUeoPJkPQiX8N8lSnX335dJddiHIDAn43OhQn13lITovtz5EHiaJJSXr/DwsaZzyv6UC067KpFeKLc4heYiM0A0Orj7UH/B5f/qEu8MPsl+XdBGl7v0lecn2DbG2bXlOxEucP8JNzIeOnLg609XaneGRdu93dFLUGSsNtUMnrhrSWGjqAwXteWhhGy+aJ/WfUdfUGJ+rf/D9hVOBIpsk'

# Editions: COMMUNITY (free) and PRO (licensed). One engine/manager/activator; Pro
# unlocks the advanced capabilities below. (The free tier was historically called
# 'Core'; it is surfaced as 'Community' now -- a license sku of 'Core' still maps
# to Pro for back-compat.)
$script:PimCommunityEditionName = 'Community'
$script:PimProEditionName       = 'Pro'

# Catalog of gateable Pro features. SQL data store is deliberately NOT here --
# operator decision 2026-06-12: SQL is part of the free (Community) edition.
$script:PimProFeatureCatalog = @(
    'MspFanout', 'WorkloadConnectors', 'Intake', 'AccessReviews', 'SelfService', 'ContactsRouting',
    # advanced capabilities added in the admin-interface epic (v2.4.187+):
    'Conformance', 'Rings', 'ApproverMatrix', 'PawPolicy', 'Lifecycle', 'AzureDiscovery',
    'DefinitionImport', 'PortalAdmins', 'PermissionWizard'
)

$script:PimLicenseCache = $null
$script:PimLicenseWarned = @{}

Function Get-PimProFeatureCatalog {
    # The gateable Pro feature names. The SQL data store is deliberately ABSENT
    # (SQL is part of the free edition -- operator decision 2026-06-12).
    @($script:PimProFeatureCatalog)
}

# --- Distribution policy (internal) ----------------------------------------
# Pro is distributed to customers free of charge. The license MECHANISM
# (offline signed-license verification + per-feature gate) is retained for
# internal/audit use, but the default POLICY is "Pro granted to everyone, for
# free, with no nag". So by default Test-PimProFeature passes silently for any
# feature regardless of license state -- and emits NO operator-facing message
# and NO customer-facing nag. Set $global:PIM_EnforceProLicense = $true ONLY in
# internal verification harnesses to exercise the gate.
#
# Invariants that hold REGARDLESS of this switch:
#   * Core behaviour is NEVER gated.
#   * Super-admins are NEVER locked out (the -SuperAdmin bypass always wins).
#   * Verification NEVER blocks startup -- a bad/missing license can never break
#     a tenant; the worst case is "edition reads Community".
Function Test-PimProLicenseEnforced {
    # Internal: is the Pro gate actively enforced this session? Defaults to OFF
    # (customers get Pro free). Honour the global if an internal harness set it.
    if ($null -ne $global:PIM_EnforceProLicense) { return [bool]$global:PIM_EnforceProLicense }
    $false
}

Function Get-PimLicenseSearchDir {
    if (Get-Command Get-PimConfigDir -ErrorAction SilentlyContinue) {
        try { $d = Get-PimConfigDir; if ($d) { return $d } } catch { }
    }
    # _shared -> engine -> solution root -> config
    Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'config'
}

Function Test-PimLicenseSignature {
    <#
    .SYNOPSIS
        Pure RSA-SHA256 PKCS#1 signature verify over raw bytes, against a
        base64-DER public certificate. Returns $true/$false; never throws.
    .DESCRIPTION
        Isolated so the verification path can be unit-tested with valid /
        invalid / tampered fixtures using an ephemeral test keypair, without
        the maintainer's private key (which only ever exists on mgmt1).
        PS 5.1-safe: X509Certificate2 from raw bytes + RSACertificateExtensions
        -- NO RSA.ImportFromPem (PS 7 / .NET Core 3.0+ only).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$PayloadBytes,
        [Parameter(Mandatory)][byte[]]$SignatureBytes,
        [Parameter(Mandatory)][string]$PublicCertB64
    )
    try {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($PublicCertB64))
        $rsa  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
        if (-not $rsa) { return $false }
        return [bool]$rsa.VerifyData($PayloadBytes, $SignatureBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch {
        return $false
    }
}

Function Get-PimLicense {
    <#
    .SYNOPSIS
        Load + verify the customer's .pimlicense (offline). Cached per session.
    .PARAMETER PublicCertB64
        Internal/testing override of the trusted public certificate. When
        omitted, the embedded production licensing cert is used. Tests pass an
        ephemeral test cert here to exercise valid/invalid/tampered fixtures.
    .PARAMETER Path
        Internal/testing override of the license file to load (bypasses the
        config-dir scan).
    #>
    [CmdletBinding()]
    param(
        [switch]$Refresh,
        [string]$PublicCertB64,
        [string]$Path
    )

    # An override (test) load is never cached -- it must not poison the real
    # session cache, and must always re-evaluate against the supplied inputs.
    $useOverride = $PublicCertB64 -or $Path
    if ($script:PimLicenseCache -and -not $Refresh -and -not $useOverride) { return $script:PimLicenseCache }

    $trustedCertB64 = if ($PublicCertB64) { $PublicCertB64 } else { $script:PimLicensePublicCertB64 }

    $result = [pscustomobject]@{
        Status     = 'Missing'      # Missing | Invalid | NotYetValid | Expired | Grace | Valid
        Reason     = 'no .pimlicense file found'
        Customer   = ''
        Sku        = 'Core'
        Features   = @()
        TenantIds  = @()
        ValidFrom  = $null
        ValidTo    = $null
        GraceUntil = $null
        LicenseId  = ''
        Path       = $null
    }

    $licPath = $null
    if ($Path) {
        if (Test-Path -LiteralPath $Path) { $licPath = $Path }
    } else {
        $dir = Get-PimLicenseSearchDir
        if ($dir -and (Test-Path -LiteralPath $dir)) {
            $file = Get-ChildItem -LiteralPath $dir -Filter '*.pimlicense' -File -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -First 1
            if ($file) { $licPath = $file.FullName }
        }
    }
    if (-not $licPath) { if (-not $useOverride) { $script:PimLicenseCache = $result }; return $result }
    $result.Path = $licPath

    try {
        $doc = Get-Content -LiteralPath $licPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $doc.payloadB64 -or -not $doc.signature) { throw "file is not a PIM4EntraPS license (payloadB64/signature missing)" }

        $payloadBytes = [Convert]::FromBase64String($doc.payloadB64)
        $sigBytes     = [Convert]::FromBase64String($doc.signature)

        $ok = Test-PimLicenseSignature -PayloadBytes $payloadBytes -SignatureBytes $sigBytes -PublicCertB64 $trustedCertB64
        if (-not $ok) { $result.Status = 'Invalid'; $result.Reason = 'signature verification FAILED (file tampered or not issued by the PIM4EntraPS licensing key)'; if (-not $useOverride) { $script:PimLicenseCache = $result }; return $result }

        $p = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json
        $result.Customer  = "$($p.customer)"
        $result.Sku       = "$($p.sku)"
        $result.LicenseId = "$($p.licenseId)"
        $result.Features  = @($p.features | Where-Object { $_ })
        $result.TenantIds = @($p.tenantIds | Where-Object { $_ })
        $result.ValidFrom = [datetime]::Parse("$($p.validFrom)", [System.Globalization.CultureInfo]::InvariantCulture).Date
        $result.ValidTo   = [datetime]::Parse("$($p.validTo)",   [System.Globalization.CultureInfo]::InvariantCulture).Date
        $graceDays = 30; if ($p.PSObject.Properties.Name -contains 'graceDays' -and "$($p.graceDays)" -match '^\d+$') { $graceDays = [int]$p.graceDays }
        $result.GraceUntil = $result.ValidTo.AddDays($graceDays)

        $today = (Get-Date).Date
        if     ($today -lt $result.ValidFrom)  { $result.Status = 'NotYetValid'; $result.Reason = "license starts $($result.ValidFrom.ToString('yyyy-MM-dd'))" }
        elseif ($today -le $result.ValidTo)    { $result.Status = 'Valid';       $result.Reason = "valid until $($result.ValidTo.ToString('yyyy-MM-dd'))" }
        elseif ($today -le $result.GraceUntil) { $result.Status = 'Grace';       $result.Reason = "EXPIRED $($result.ValidTo.ToString('yyyy-MM-dd')) -- grace until $($result.GraceUntil.ToString('yyyy-MM-dd')), renew now" }
        else                                   { $result.Status = 'Expired';     $result.Reason = "expired $($result.ValidTo.ToString('yyyy-MM-dd')) (grace ended $($result.GraceUntil.ToString('yyyy-MM-dd')))" }
    } catch {
        $result.Status = 'Invalid'
        $result.Reason = "license could not be read: $($_.Exception.Message)"
    }

    if (-not $useOverride) { $script:PimLicenseCache = $result }
    return $result
}

Function Test-PimProFeature {
    <#
    .SYNOPSIS
        Gate for a Pro feature. $true = allowed. Core behavior is NEVER gated.
    .PARAMETER Feature
        Name from the Pro feature catalog (e.g. 'MspFanout').
    .PARAMETER TenantId
        Tenant to check the license binding against. When omitted, the
        connected Graph context's tenant is used if resolvable; if no tenant
        can be resolved, the tenant binding is not evaluated here (per-tenant
        call sites pass it explicitly).
    .PARAMETER SuperAdmin
        The caller is acting as a super-admin. Super-admins are NEVER locked
        out -- the gate always returns $true for them, no matter the license
        state or enforcement policy.
    .PARAMETER Quiet
        Suppress the operator-facing block message.
    .NOTES
        By default Pro is granted free (Test-PimProLicenseEnforced = $false), so
        this returns $true silently with NO nag. The gate only actually blocks
        when an internal harness sets $global:PIM_EnforceProLicense = $true.
        Core behaviour is never routed through this gate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Feature,
        [string]$TenantId,
        [switch]$SuperAdmin,
        [switch]$Quiet
    )

    # Super-admins are never locked out.
    if ($SuperAdmin) { return $true }

    # Default policy: customers get Pro free, with no nag. The verification
    # mechanism still ran (so Get-PimEdition / audit can report it), but the
    # gate does not block and emits nothing customer-facing.
    if (-not (Test-PimProLicenseEnforced)) { return $true }

    $lic = Get-PimLicense
    $blockReason = $null

    if ($lic.Status -notin @('Valid', 'Grace')) {
        $blockReason = $lic.Reason
    } elseif (-not (($lic.Features -contains '*') -or ($lic.Features -contains $Feature))) {
        $blockReason = "license for '$($lic.Customer)' does not include feature '$Feature' (features: $($lic.Features -join ', '))"
    } else {
        if (-not $TenantId) {
            try { $ctx = Get-MgContext -ErrorAction SilentlyContinue; if ($ctx -and $ctx.TenantId) { $TenantId = $ctx.TenantId } } catch { }
        }
        if ($TenantId -and @($lic.TenantIds).Count -gt 0 -and ($lic.TenantIds -notcontains $TenantId)) {
            $blockReason = "license for '$($lic.Customer)' is not valid for tenant $TenantId"
        }
    }

    if ($blockReason) {
        if (-not $Quiet -and -not $script:PimLicenseWarned["$Feature|$TenantId"]) {
            $script:PimLicenseWarned["$Feature|$TenantId"] = $true
            Write-Host "[Pro] '$Feature' requires a PIM4EntraPS Pro license -- $blockReason. Core features continue to work normally." -ForegroundColor Yellow
        }
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) {
            Write-PimAuditEvent -Action 'license.blocked' -Target $Feature -After @{ reason = $blockReason; tenantId = "$TenantId" }
        }
        return $false
    }

    if ($lic.Status -eq 'Grace' -and -not $Quiet -and -not $script:PimLicenseWarned['__grace__']) {
        $script:PimLicenseWarned['__grace__'] = $true
        Write-Host "[Pro] license $($lic.Reason)" -ForegroundColor Yellow
    }
    return $true
}

Function Get-PimEdition {
    # The active EDITION: 'Pro' when a valid (or in-grace) license is present,
    # else 'Community' (free). Drives feature gating + the manager edition badge.
    $lic = Get-PimLicense
    if ($lic.Status -in @('Valid', 'Grace')) { return $script:PimProEditionName }
    return $script:PimCommunityEditionName
}

Function Get-PimLicenseStatusText {
    # One-line status for banners / the Manager Governance panel.
    $lic = Get-PimLicense
    switch ($lic.Status) {
        'Missing' { 'Community (free) -- no Pro license installed' }
        'Valid'   { "Pro -- $($lic.Customer) -- $($lic.Reason)" }
        'Grace'   { "Pro (GRACE) -- $($lic.Customer) -- $($lic.Reason)" }
        default   { "Community (free) -- license $($lic.Status): $($lic.Reason)" }
    }
}
