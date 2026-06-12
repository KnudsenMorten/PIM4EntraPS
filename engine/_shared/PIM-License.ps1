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

# Catalog of gateable Pro features. SQL data store is deliberately NOT here --
# operator decision 2026-06-12: SQL is part of Core.
$script:PimProFeatureCatalog = @('MspFanout', 'WorkloadConnectors', 'Intake', 'AccessReviews', 'SelfService', 'ContactsRouting')

$script:PimLicenseCache = $null
$script:PimLicenseWarned = @{}

Function Get-PimLicenseSearchDir {
    if (Get-Command Get-PimConfigDir -ErrorAction SilentlyContinue) {
        try { $d = Get-PimConfigDir; if ($d) { return $d } } catch { }
    }
    # _shared -> engine -> solution root -> config
    Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'config'
}

Function Get-PimLicense {
    <#
    .SYNOPSIS
        Load + verify the customer's .pimlicense (offline). Cached per session.
    #>
    [CmdletBinding()]
    param([switch]$Refresh)

    if ($script:PimLicenseCache -and -not $Refresh) { return $script:PimLicenseCache }

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

    $dir = Get-PimLicenseSearchDir
    $file = $null
    if ($dir -and (Test-Path -LiteralPath $dir)) {
        $file = Get-ChildItem -LiteralPath $dir -Filter '*.pimlicense' -File -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -First 1
    }
    if (-not $file) { $script:PimLicenseCache = $result; return $result }
    $result.Path = $file.FullName

    try {
        $doc = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $doc.payloadB64 -or -not $doc.signature) { throw "file is not a PIM4EntraPS license (payloadB64/signature missing)" }

        $payloadBytes = [Convert]::FromBase64String($doc.payloadB64)
        $sigBytes     = [Convert]::FromBase64String($doc.signature)

        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($script:PimLicensePublicCertB64))
        $rsa  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
        $ok   = $rsa.VerifyData($payloadBytes, $sigBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        if (-not $ok) { $result.Status = 'Invalid'; $result.Reason = 'signature verification FAILED (file tampered or not issued by the PIM4EntraPS licensing key)'; $script:PimLicenseCache = $result; return $result }

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

    $script:PimLicenseCache = $result
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
    .PARAMETER Quiet
        Suppress the operator-facing block message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Feature,
        [string]$TenantId,
        [switch]$Quiet
    )

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

Function Get-PimLicenseStatusText {
    # One-line status for banners / the Manager Governance panel.
    $lic = Get-PimLicense
    switch ($lic.Status) {
        'Missing' { 'Core (free) -- no Pro license installed' }
        'Valid'   { "Pro -- $($lic.Customer) -- $($lic.Reason)" }
        'Grace'   { "Pro (GRACE) -- $($lic.Customer) -- $($lic.Reason)" }
        default   { "Core (free) -- license $($lic.Status): $($lic.Reason)" }
    }
}
