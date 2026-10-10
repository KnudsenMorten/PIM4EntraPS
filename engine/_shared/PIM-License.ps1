#Requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS offline license verification (Core + Pro split).

.DESCRIPTION
    PIM4EntraPS Community is free for a single tenant. Pro (the licensed single-tenant features, and the
    multi-tenant half: managing tenant / managed tenants) requires a customer licence: the issued signed document,
    stored in SQL pim.Settings[License] (IMP-42 -- no file). REQ-Y: a managing tenant / slave is refused without one.

    The license is FULLY OFFLINE -- no online activation, no call-home, no
    public endpoint. It is a JSON payload signed with the maintainer's private
    RSA key (machine cert store on the management host, never distributed);
    this file embeds only the PUBLIC certificate and verifies the signature
    locally (RSA-SHA256). Customers on locked-down automation servers need
    nothing but the stored document.

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
# LIC-1 (2026-08-11) -- AutomateIT framework licensing signer, CN=AutomateIT-Licensing-Service.
# PIM now accepts BOTH this and its own legacy key below, so licences issued by the framework
# tool (TOOLS/New-AitLicense.ps1) verify here with no cutover and no reissue.
#
# 🔴 WHY THE MIGRATION IS URGENT, not cosmetic: the legacy CN=PIM4EntraPS-Licensing key is marked
# NON-EXPORTABLE, so backup-job-certificates-automation SKIPS it on every run -- verified absent
# from all recent backups. If mgmt1 were lost, no further PIM licence could EVER be issued (already
# issued ones keep verifying, since only the public half ships). The cert is valid to 2041, which
# makes it look safe; exportability is the thing that actually matters and is invisible unless
# checked. This key IS backed up.
$script:AitLicensePublicCertB64 = 'MIIFFzCCAv+gAwIBAgIQNY8l3/KZOoxF7K1nXIXwazANBgkqhkiG9w0BAQsFADAnMSUwIwYDVQQDDBxBdXRvbWF0ZUlULUxpY2Vuc2luZy1TZXJ2aWNlMB4XDTI2MDgxMTEzMDY0NloXDTQ2MDgxMTEzMTE0NlowJzElMCMGA1UEAwwcQXV0b21hdGVJVC1MaWNlbnNpbmctU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALuth8WywLfudbaoZ6eR570apvs5LXzOeGfl5Z14z6Nl6DQgvwMLXG/8lZEHOCKsHWVtEnjZOZigsh4c16owJVhuW67OgY0Iy6OjmfeXzu+kcTICSdZ+Qj3ecsGp1Cz6Xo1AjYbgIORdqUBncy4BAuA1bxH0E+V+1zT+ltEk840xpLdWde+m7W8q7BrG9klh+xQl8xJTjeliyV0JN2mvBjI0JwB9t9vL2/luMWWtHp752/ZG4Icd9u6HyqSR/xEmlZIjkZwI7LEPLTICXV1iA3c3nFUEHkLhLlpDW6EQn3cip0Sijr7SVWEBH1fCA8vCo+PxIEgJc3RXaeRhqD4UOwPJIziHtrpy8+9L15zrhXnhIGZv2mUAHKiamUIOmKl9vj31vFp/vJx1chE0XA358T09HGu0jKgSbbC4afKQPKf3v+BHPU42T/xIOPMxDJWuFqKvr4anL7P5PEkTjycBRCkXnIPC5PlrXR/ZZz4oit4WKhbdzONYwb8CKnsF2Z9IVL9yviVJxAIr7kiGqRme9+H0t5A+hzAydxdFMQnop+R8Q02a0sei9WrdtCbwLempVVrXIS6N4hh5kvLqMouDi62b0h645UNk2cWahDIZWTKd/MYdlcdrtRt5muy2LOasHByVxUrZKwH7IetCmv+Kkm1BfMF6Fvi1Jh2Qgz4bo5XJAgMBAAGjPzA9MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBT+IiWP1iqSIwaRLiV1somJAQ+ELjANBgkqhkiG9w0BAQsFAAOCAgEAFiDfl7nhDNIywkCZgu9iw0RtJUyJqiq8y+fXomucqowAQZKPhkpuHftZZjtDe09WM35TqjRgL7hqmJiEgqPlRrAv78FjE41RwMcANN2PVCrdcMcuDVdRbS40rObpp0B6+uVUiWY4+8MW6G8Wv+7CIBUEP8ypo3BhxQJZLpyJDKLNiPqnTVKOmYXe7BivfVz63F2Pg2dNXic1poQ7S6JTi/8FM4AV2Ge/zVQF+LaiIuBDJX3JjHnKXxNf1Zhk8PF6DeWaVSNyXtjESlaUfsz0U2Ue87UUZ8ELIuqjHTpG66HPInblBZme6VvR13n5QxmnvjPXdtmXAJzDzCf+76labSGQu9fMFxUoKwjAwT9vHrdFw8JEStappW7urXj+Oafp1wVafJOXzjd9utr8WT3AhaPeqMx3FYH20e2b7QNCI3owtm0ogHRg36neahe78PikiMe15AUpD3+BD6pKeLV7tsExeXZjxDxhFUSpScD0TrCOUEJdKL2Cfx8rM3ceISSiTTYmuJmU7fznQ122A6GNW58mpSk8miPYb3MzbLW0JFPRrEDiyT8dW1M9s98DL+7VR0z2QxgxhNMKyrVgBM7YgQtbtPLz26NBqAQsqG50rOdn7XmprzvnTmnb+r2PUQuqb6rCTAQFTJ3MjH7BviP3GkwJyvzMZ+S6OnUAGB2Fn3Y='

$script:PimLicensePublicCertB64 = 'MIID+zCCAmOgAwIBAgIQZi8bo4EYqJ9PSvrXsI3orTANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVQSU00RW50cmFQUy1MaWNlbnNpbmcwHhcNMjYwNjEyMTY1MzM4WhcNNDEwNjEyMTcwMzM0WjAgMR4wHAYDVQQDDBVQSU00RW50cmFQUy1MaWNlbnNpbmcwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQD+YFgQSxRJNuwpv/lc9z6ClbFgEc+9/hpM/TXPg7f3Q40TQfyWf54EgaKzC8Y04JkdS2lNv69NWZ5MJgwyHkwTuyngDx/giBF0aVBbnbW9dLixSY0YaN435uylMgrL9irYB79c+rN+NAWyRZTzFdw3LFLR7zhl4Wor3OexsI7tYHgH/WXegzmbl4R8amVHR2QsAr3ZHBg5WEW3C3DeomDeAuVIny4xMZp/nq6i1VXTqrBx76Cxdms6RJS0cwtystrFQFdCB4e06jqdttuj5m8CCvQbUILEzAhNnzHnFtMXJC/wWWu2vfOqqY/Wy7ORjZCWaI/a/c7bfXWpdiI5H3E4pcZCezSH7lg1VdvSGrq/bbQxOUO4a5FQ5JI5fXZuzQksjm7t0u5AAmdLpvtac86vMQmM8LCTsUoNs9GAhVvNmV+pJtReWyubfqLgzaRmMP4qMp7a6DoR3RKeuYjmSzhjFn5S4lcDmAz35Qc/LO0sEPDr3LL30fQxhX8uSqlFAEkCAwEAAaMxMC8wDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBS2n3cmD8taKDsdy2debDNeQkv7qzANBgkqhkiG9w0BAQsFAAOCAYEArrFYyp4BQzH803d4htpcqtWbkTgg10tFrdQndJ35tv+ZDGcq7AIHohI7egzH4pDPgbXOGf7GuisIzj8MEJkH63+xqB4wHHBPn+pl9YGYk02XiWY9H0blP+TIlYjderzr/XH/mLn67z2VAm9dGAw1X2xw1zMtc36aPVU7i7bRIZwfxIA5Y1sVJ9bpMRkXDawMhegA39a0inLVriBWcvfku3zz84MtHtB4WLfwUI97QLvDObHPdkQ68w+0+0tmIz33z5Fgu9dtIUf6RROkFhjoc2rC+GcI023SLeDPjHrUHg1RjUeoPJkPQiX8N8lSnX335dJddiHIDAn43OhQn13lITovtz5EHiaJJSXr/DwsaZzyv6UC067KpFeKLc4heYiM0A0Orj7UH/B5f/qEu8MPsl+XdBGl7v0lecn2DbG2bXlOxEucP8JNzIeOnLg609XaneGRdu93dFLUGSsNtUMnrhrSWGjqAwXteWhhGy+aJ/WfUdfUGJ+rf/D9hVOBIpsk'

# LIC-4 (operator 2026-10-03): the Invardia licence signer, CN=Invardia-Licensing (BA65E6AA62128EBE89A743722E404980F6D2878D).
# Trusted ALONGSIDE the two signers above, never instead: Invardia switches to it only after this release is rolled out.
# Byte-identical to sync/_AitLicense.ps1 $script:AitLicenseInvardiaCertB64 (tests/Test-PimLicensing.ps1 pins it).
$script:InvardiaLicensePublicCertB64 = 'MIIFQDCCAyigAwIBAgIQXXs1IY0ZQE2MwtugYutXwDANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDExJJbnZhcmRpYS1MaWNlbnNpbmcwHhcNMjYxMDAzMTY1NDMxWhcNMzYxMDAzMTcwNDMxWjAdMRswGQYDVQQDExJJbnZhcmRpYS1MaWNlbnNpbmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCn9X21WYLer9r3ojq9lCP3eGV5YK8UMHoyyGT/q8carwQK+ztBRweKAgHyg8rr67utZ1zZBDRei64T/63nXGZpC666efzNZjIU+Og7vtO0bTNjQm/yVD/Q4KFZachYbE5orU+99HQcgRrcwnmmltyazyun2MV2CTk2nUDeMX5IIFD/1yIT8SLNFa6b6Gy4Ms/TIlc4u3lEH3zjbTSF+phSrbv7J6ytz5Eq1ahRkKHWcdBoF9GJo2ynWP0vTGHWvvjNdeVpXP1rkGnLt9MAQj2Us/2XiTgZzf26QLNiXX9YeJeUA9IVdPWczJav+YYkcICyG4ynwhPCudI6S2iDeu8jyL54gfVT871/+RFebzKHq9teY2vB0aGsbaW9VOmV5dDQ2mVfQLFTkNd1ByeZKv9tR0vPfaiZCza+DedApF2LfoAa7Y34pb9WHGRJFAPVmG2WMSsTY90Y0VBYrktF4g4q712W2ZdQc+QIxtvP5nsz6bk1QBvJ1Hcsr/euiysxmkFxcl3NH7WM1EKzdzUaYDJpysoE9e0jkjdJpb9bNNmSE7V9IMTk7r/XOiYJ+8qOALTgwUIEyOLi/hfOihJDRn31aJ6aPvzCEYikueJV5oALrDxquiXbPi8z10aMuXLL4hfi6B7U0qo2kOTPQ9Qh/cJFVkV9pEXjtY+NwwI9EtxgaQIDAQABo3wwejAOBgNVHQ8BAf8EBAMCB4AwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYDVR0jBBgwFoAUuZzWkYh3hkE0oJH42LneYVKXIzowHQYDVR0OBBYEFLmc1pGId4ZBNKCR+Ni53mFSlyM6MA0GCSqGSIb3DQEBCwUAA4ICAQCluVZnotzEyS5ux+4hMuz9mOfpSJCNg5nkS8XxIHySiE2AEjVT4ZFEyykZUFoROv5clLBkO5icvDDRBitkeKHvioZruRPtVGy0fs0VxJ4VMcOU/i5cVdJXBQeyUFE8o//4+7FXZp10ToVNv/drjdO7adcNHRVjsddm2mXPNyHmE07ErV6eInPj+r0/1dogPBW1knF+T53RTwT2O0Ppe5qK0QEdBfo5sf4nvjg7ONNXYlW38SzXGLsXy6TZphRWqxLq7u31HAwujQGy9syO+TPIzusH1WHkCsvjDDRXNI8iYhKcS2wq/P/O6O4Ebt/PFN0hxyzyuYx4kreXKKhqrfsEMDxzMUQNnUEjFgU4/4atLVJpBvoDmb/MuQDIzlhxz8obAJi5BuxyjyemR9jg6XMIE2IAhe1v+MN0ZY58tbZR3t5rF30tp541NRaJfn4DBpqNmAIFyDQMdM2FogkFoOV+Mo0IBmGzV/jyv/2z+sre1P5MncLP2qZhfFmu595gWnNoOsMdUZmEWMkbISMGvGzfpPRF3IBan+fymCZSsKNB00E3W50Sh/t2sopEYc3eSwpu6bhvPUgB2ZKU6KN49Al4Pf41uldHVY0aVVp+kpLmRntDFzkTNXUG4OWOwF5gHuGY8jIrwDR7pCPSNzDWrUf857O6DyWEsHXERWg5OPLNUg=='

# Editions: COMMUNITY (free) and PRO (licensed). One engine/manager/activator; Pro
# unlocks the advanced capabilities below. (The free tier was historically called
# 'Core'; it is surfaced as 'Community' now. A licence SKU of 'Core' is NOT Pro --
# REQ-Y 2026-09-20; see the sku match in Test-PimProLicence for why that changed.)
$script:PimCommunityEditionName = 'Community'
$script:PimProEditionName       = 'Pro'

# Catalog of gateable Pro features. SQL data store is deliberately NOT here --
# operator decision 2026-06-12: SQL is part of the free (Community) edition.
# 🔒 REQ-Y (operator 2026-09-19: "single tenant must be sep in free and pro"): the feature catalog
# (engine/_shared/PIM-FeatureCatalog.ps1, license x scope per entry) is the ONE authoritative list. This list is the
# gate's copy (this file is also loaded standalone, without the catalog) and must EQUAL Get-PimCatalogProFeatureNames:
# tests/Test-PimMspLicense.ps1 fails on any drift. The single-tenant Pro set was decided 2026-09-19 ("i agree to your
# proposals"): coverage + discovery, the connectors other than Intune / Defender XDR, revoke, access review campaigns,
# the second approver, delegated administration ceilings, the tier-impact report and the evidence export. Dropped then
# (free, and never gated by production code): Intake, SelfService, ContactsRouting, Conformance, Rings, ApproverMatrix,
# PawPolicy, Lifecycle, AzureDiscovery (now 'Discovery'), DefinitionImport, PermissionWizard.
$script:PimProFeatureCatalog = @('AccessReviews', 'BrokerApi', 'ConsultantLifecycle', 'Coverage', 'Discovery', 'EvidenceExport', 'HybridAd', 'MakerChecker', 'McpServer', 'MspFanout',
    'PortalAdmins', 'Revoke', 'Rfa', 'TierReport', 'WorkloadConnectors')
# PRO-FEATURES-MISSING (PIM REQUIREMENTS §100.32, owner 2026-10-09: "i cannot use any of the features" on a Pro licence issued
# before ConsultantLifecycle / Rfa / BrokerApi / McpServer existed). The SINGLE-TENANT Pro features: the catalog's scope='single'
# Pro names (Get-PimCatalogProFeatureNames -Scope single). Framework §12.6a LICENCE-FEATURES (owner 2026-10-09): the licence
# names the EDITION, the product maps edition -> features, no re-signing for a new feature ever. Every Pro licence -- Pro
# Enterprise AND Pro Business (Business differs only by its signed `limits`, §12.6) -- grants every one of these, current and
# future, whatever its features[] list says. MSP (scope='multi', MspFanout) is never in this list: it is the Pro MSP edition
# (sku Pro-MSP, or a licence naming MspFanout / '*' as every MSP licence issued so far does). Must equal the catalog's
# single-tenant list (tests/Test-PimProEnterpriseFeatures.ps1).
$script:PimProSingleTenantFeatures = @('AccessReviews', 'BrokerApi', 'ConsultantLifecycle', 'Coverage', 'Discovery', 'EvidenceExport', 'HybridAd', 'MakerChecker', 'McpServer',
    'PortalAdmins', 'Revoke', 'Rfa', 'TierReport', 'WorkloadConnectors')

$script:PimLicenseCache = $null
$script:PimLicenseWarned = @{}

Function Get-PimProFeatureCatalog {
    # The gateable Pro feature names. The SQL data store is deliberately ABSENT
    # (SQL is part of the free edition -- operator decision 2026-06-12).
    @($script:PimProFeatureCatalog)
}

Function Get-PimProSingleTenantFeatures {
    # The single-tenant Pro feature names every Pro licence grants without listing them (§100.32, framework §12.6a).
    @($script:PimProSingleTenantFeatures)
}

Function Get-PimLicenceFeatureGrant {
    <#
      PURE. §100.32 / framework §12.6a -- does the licence's EDITION cover -FeatureNames, and why? Status, sku-is-Pro and
      tenant are NOT judged here (Test-PimProLicence does that around it); -License is a Get-PimLicense result, so everything
      read is from the SIGNED payload (Sku, Features, Limits) -- nothing unsigned can widen it.
        enterprise -- every name is a single-tenant Pro feature, no signed `limits`  -> covers ("included in Pro Enterprise")
        business   -- every name is a single-tenant Pro feature, signed `limits`     -> covers ("included in Pro Business (limits apply)")
        msp        -- an MSP name, and the licence is the MSP edition: sku Pro-MSP, or features[] names MspFanout / msp.downlink /
                      Msp / '*' (every MSP licence issued so far)                    -> covers ("included in Pro MSP")
        needs-msp  -- an MSP name on a licence that is not the MSP edition           -> not covered ("needs the MSP licence")
        listed     -- any other name (an explicit add-on) that features[] names or '*' -> covers ("listed in the licence")
        not-listed -- any other name the list lacks                                  -> not covered
      The features[] list is NEVER the gate for an edition feature (single-tenant Pro, MSP): it only identifies an MSP licence
      issued before the Pro-MSP sku, and names explicit add-ons. Returns @{ covers; basis; text }.
    #>
    param($License, [string[]]$FeatureNames)
    $features = @(@($(if ($License) { $License.Features } else { @() })) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $names = @(@($FeatureNames) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $isBusiness = [bool]($License -and $License.PSObject.Properties['Limits'] -and $null -ne $License.Limits)
    $sku = if ($License) { "$($License.Sku)".Trim() } else { '' }
    $isMsp = ($sku -match '^(?i)pro-msp$') -or ($features -contains '*') -or (@($features | Where-Object { $script:PimMspLicenseFeatures -contains $_ }).Count -gt 0)
    if ($names.Count -gt 0 -and @($names | Where-Object { $script:PimProSingleTenantFeatures -notcontains $_ }).Count -eq 0) {
        if ($isBusiness) { return [pscustomobject]@{ covers = $true; basis = 'business'; text = 'included in Pro Business (limits apply)' } }
        return [pscustomobject]@{ covers = $true; basis = 'enterprise'; text = 'included in Pro Enterprise' }
    }
    if (@($names | Where-Object { $script:PimMspLicenseFeatures -contains $_ }).Count -gt 0) {
        if ($isMsp) { return [pscustomobject]@{ covers = $true; basis = 'msp'; text = 'included in Pro MSP' } }
        return [pscustomobject]@{ covers = $false; basis = 'needs-msp'; text = 'needs the MSP licence' }
    }
    if ($features -contains '*') { return [pscustomobject]@{ covers = $true; basis = 'listed'; text = 'listed in the licence (all Pro features)' } }
    foreach ($n in $names) { if ($features -contains $n) { return [pscustomobject]@{ covers = $true; basis = 'listed'; text = 'listed in the licence' } } }
    return [pscustomobject]@{ covers = $false; basis = 'not-listed'; text = 'not listed in the licence' }
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

Function Get-PimLicenseFromStore {
    # IMP-42: the stored licence document. Returns @{ ok; text; error }. ok=$false = a store that exists but
    # could not be read (never read as "no licence"). No store wired = ok with no text (Core, as before).
    $v = $null
    try {
        if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { $v = Get-PimSetting -Name 'License' }
        elseif ((Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue) -and "$($global:PIM_SqlConnectionString)".Trim()) { $v = Get-PimSqlSetting -ConnectionString "$($global:PIM_SqlConnectionString)" -Name 'License' }
        # REQ-Y: the engine / jobs hold their store as $global:PIM_EngineSqlCs (the same store the feature gates read).
        elseif ((Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue) -and "$($global:PIM_EngineSqlCs)".Trim()) { $v = Get-PimSqlSetting -ConnectionString "$($global:PIM_EngineSqlCs)" -Name 'License' }
        else { return [pscustomobject]@{ ok = $true; text = ''; error = '' } }
    } catch { return [pscustomobject]@{ ok = $false; text = ''; error = "$($_.Exception.Message)" } }
    if ($null -eq $v) { return [pscustomobject]@{ ok = $true; text = ''; error = '' } }
    $t = if ($v -is [string]) { $v } else { ConvertTo-Json -InputObject $v -Depth 6 -Compress }
    return [pscustomobject]@{ ok = $true; text = $t; error = '' }
}

Function Set-PimLicense {
    <#
      IMP-42: store an issued licence in pim.Settings['License'] -- ONLY after it verifies (a tampered or
      foreign document is refused, never stored). -LicenseText is the issued file's content. Returns the
      verified licence object. THROWS on a failed verify or a failed write.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LicenseText, [string]$PublicCertB64, [string]$TenantId = $(if ("$($global:PIM_TenantId)".Trim()) { "$($global:PIM_TenantId)" } else { "$env:PIM_TenantId" }))
    $chk = if ($PublicCertB64) { Get-PimLicense -LicenseText $LicenseText -PublicCertB64 $PublicCertB64 } else { Get-PimLicense -LicenseText $LicenseText }
    if ($chk.Status -in @('Invalid','Missing')) { throw "licence NOT stored: $($chk.Reason)" }
    # BUG-278: a licence that can never make THIS environment Pro is refused at the door, not discovered later per feature.
    if ("$($chk.Sku)".Trim() -notmatch '^(?i)pro(-.+)?$') { throw "licence NOT stored: it is a '$("$($chk.Sku)".Trim())' licence, not Pro" }
    $bind = Test-PimLicenseTenantBinding -License $chk -TenantId $TenantId
    if (-not $bind.ok) { throw "licence NOT stored: $($bind.reason)" }
    if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { throw 'licence NOT stored: no SQL settings store (Set-PimSetting) is wired -- PIM v2 keeps the licence in SQL only' }
    # BUG-277: was this environment Community until now? Then record the conversion. A Community install has no in-cloud
    # updater by design; the ring gate reads this marker so the install keeps updating as before until the upgrade step
    # (tools\setup\Upgrade-PimToPro.ps1) gives it the Pro updater and its ring.
    $wasPro = $false
    try { $prev = Get-PimLicense -Refresh; $wasPro = [bool](Test-PimLicenseIsProForTenant -License $prev -TenantId $TenantId).pro } catch { $wasPro = $false }
    Set-PimSetting -Name 'License' -Value $LicenseText
    $script:PimLicenseCache = $null
    if (-not $wasPro) {
        try {
            Set-PimSetting -Name 'EditionUpgrade' -Value ([pscustomobject][ordered]@{ fromEdition = 'community'; toEdition = 'pro'; licensedUtc = [datetime]::UtcNow.ToString('o'); customer = "$($chk.Customer)"; licenseId = "$($chk.LicenseId)" }) | Out-Null
        } catch { Write-Warning "[licence] the Community -> Pro conversion could not be recorded ($($_.Exception.Message)) -- run tools\setup\Upgrade-PimToPro.ps1 before the next update." }
    }
    return $chk
}

Function Get-PimEditionUpgradeState {
    <#
      PURE. BUG-277: is this environment a Community install that registered a Pro licence and has NOT been given the Pro
      updater yet? -Marker = pim.Settings['EditionUpgrade'], -UpdateState = pim.Settings['UpdateState'] (written by the
      in-cloud updater on every run). Pending while the marker exists and no updater run is recorded after it.
      Returns @{ pending; since; reason; command }.
    #>
    param($Marker, $UpdateState)
    $m = $Marker; if ($m -is [string]) { try { $m = $m | ConvertFrom-Json } catch { $m = $null } }
    $cmd = '.\tools\setup\Upgrade-PimToPro.ps1 -SourceUrlTemplate ''<the Pro update feed you received with your licence>'' -Apply'
    if (-not $m -or "$($m.toEdition)" -ne 'pro') { return [pscustomobject]@{ pending = $false; since = ''; reason = ''; command = $cmd } }
    $since = "$($m.licensedUtc)"
    $u = $UpdateState; if ($u -is [string]) { try { $u = $u | ConvertFrom-Json } catch { $u = $null } }
    $last = ''; foreach ($n in 'lastRunUtc', 'finishedUtc', 'startedUtc', 'updatedUtc', 'utc') { if ($u -and $u.PSObject.Properties[$n] -and "$($u.$n)") { $last = "$($u.$n)"; break } }
    $pending = $true
    if ($last -and $since) {
        try {
            $ls = [datetime]::Parse($last, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal')
            $ss = [datetime]::Parse($since, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal')
            if ($ls -gt $ss) { $pending = $false }
        } catch { }
    }
    return [pscustomobject]@{ pending = $pending; since = $since
        reason = $(if ($pending) { 'the Pro licence is registered; this install still updates like the Community edition until the Pro updater is installed' } else { 'the Pro updater runs (it has reported since the licence was registered)' })
        command = $cmd }
}

Function Get-PimLicense {
    <#
    .SYNOPSIS
        Load + verify the customer's licence from pim.Settings[License] (offline). Cached per session.
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
        [string]$Path,
        # IMP-42: the licence DOCUMENT itself (JSON with payloadB64 + signature) -- what pim.Settings['License'] holds.
        [string]$LicenseText
    )

    # An override (test) load is never cached -- it must not poison the real
    # session cache, and must always re-evaluate against the supplied inputs.
    $useOverride = $PublicCertB64 -or $Path -or $LicenseText
    # REQ-Y: the hard Pro gates read this cache on hot paths, so it lives 5 minutes -- a licence registered while a
    # long-running process (the Manager, the tick) is up takes effect without a restart. A cache set with no stamp (a
    # test seeding it directly) is honoured as fresh.
    if ($script:PimLicenseCache -and -not $Refresh -and -not $useOverride) {
        if (-not $script:PimLicenseCacheUtc -or (([datetime]::UtcNow - $script:PimLicenseCacheUtc).TotalMinutes -lt 5)) { return $script:PimLicenseCache }
    }
    if (-not $useOverride) { $script:PimLicenseCacheUtc = [datetime]::UtcNow }

    # LIC-1 / LIC-4 -- accept ANY trusted signer (AutomateIT, the legacy PIM key, Invardia). AutomateIT first (the going-forward framework key), then the
    # legacy PIM key so anything already issued keeps verifying. An explicit -PublicCertB64 still
    # wins, which is what the negative tests rely on.
    $trustedCerts = if ($PublicCertB64) { @($PublicCertB64) }
                    else { @($script:AitLicensePublicCertB64, $script:PimLicensePublicCertB64, $script:InvardiaLicensePublicCertB64) }

    $result = [pscustomobject]@{
        Status     = 'Missing'      # Missing | Invalid | NotYetValid | Expired | Grace | Valid
        Reason     = 'no licence is stored (pim.Settings[''License'']) -- import the issued licence with tools/setup/Set-PimLicense.ps1'
        Customer   = ''
        Sku        = 'Core'
        Features   = @()
        TenantIds  = @()
        ValidFrom  = $null
        ValidTo    = $null
        GraceUntil = $null
        LicenseId  = ''
        Path       = $null
        # Framework §12.6 LICENCE-DIMENSION: the SIGNED payload's optional `limits` object ($null = none = Pro Enterprise).
        Limits     = $null
    }

    # 🔴 IMP-42 (§33.28) -- THE LICENCE LIVES IN SQL, NOT IN A FILE. It used to be found by scanning config/ for
    # *.pimlicense / *.aitlicense -- a directory the container image EXCLUDES, so every hosted environment read
    # "Missing" whatever had been issued. The signed document (payloadB64 + signature, byte-identical to the issued
    # file) is now pim.Settings['License'] (Set-PimLicense stores it after verifying it). -Path / -LicenseText stay
    # as EXPLICIT inputs (verify a file before importing it; the tests) -- they are never scanned for.
    $docText = $null
    if ($LicenseText) { $docText = "$LicenseText"; $result.Path = '(supplied text)' }
    elseif ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { $result.Reason = "no licence file at '$Path'"; return $result }
        $docText = Get-Content -LiteralPath $Path -Raw -Encoding UTF8; $result.Path = $Path
    } else {
        $st = Get-PimLicenseFromStore
        if (-not $st.ok) { $result.Status = 'Invalid'; $result.Reason = "the licence could not be read from the store: $($st.error)"; $script:PimLicenseCache = $result; return $result }
        if (-not "$($st.text)".Trim()) { $script:PimLicenseCache = $result; return $result }
        $docText = "$($st.text)"; $result.Path = "pim.Settings['License']"
    }

    try {
        $doc = $docText | ConvertFrom-Json
        if (-not $doc.payloadB64 -or -not $doc.signature) { throw "file is not a PIM4EntraPS license (payloadB64/signature missing)" }

        $payloadBytes = [Convert]::FromBase64String($doc.payloadB64)
        $sigBytes     = [Convert]::FromBase64String($doc.signature)

        $ok = $false
        foreach ($__tc in @($trustedCerts | Where-Object { $_ })) {
            if (Test-PimLicenseSignature -PayloadBytes $payloadBytes -SignatureBytes $sigBytes -PublicCertB64 $__tc) { $ok = $true; break }
        }
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
        # §12.6: read ONLY from the verified payload bytes ($p) -- a `limits` on the outer document ($doc) is unsigned and
        # never read. Absent = Pro Enterprise (every licence issued before §12.6 is byte-identical and stays uncapped).
        if ($p.PSObject.Properties.Name -contains 'limits') { $result.Limits = ConvertTo-PimLicenceLimits -Value $p.limits }

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

    # REQ-Y: a feature that is not in the Pro list is free -- never gated, even when a harness enforces the switch.
    # The list follows the feature catalog (see $script:PimProFeatureCatalog), so the list and the gate cannot disagree.
    if (@(Get-PimProFeatureCatalog) -notcontains $Feature) { return $true }

    $lic = Get-PimLicense
    $blockReason = $null

    if ($lic.Status -notin @('Valid', 'Grace')) {
        $blockReason = $lic.Reason
    } elseif (-not ($grant = Get-PimLicenceFeatureGrant -License $lic -FeatureNames @($Feature)).covers) {   # §100.32 / §12.6a: every Pro licence = every single-tenant Pro feature
        $blockReason = "license for '$($lic.Customer)' does not include feature '$Feature' -- $($grant.text) (features: $($lic.Features -join ', '))"
    } else {
        # §100.42: no Graph-SDK context fallback -- Resolve-PimLicenseTenantId takes the PIM-Rest tenant (MI home tenant /
        # $global:PIM_TenantId) when -TenantId is empty.
        $bind = Test-PimLicenseTenantBinding -License $lic -TenantId $TenantId
        if (-not $bind.ok) { $blockReason = "license for '$($lic.Customer)': $($bind.reason)" }
    }

    if ($blockReason) {
        if (-not $Quiet -and -not $script:PimLicenseWarned["$Feature|$TenantId"]) {
            $script:PimLicenseWarned["$Feature|$TenantId"] = $true
            Write-Host "[Pro] '$Feature' requires a PIM Manager Pro license -- $blockReason. Core features continue to work normally." -ForegroundColor Yellow
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

Function Resolve-PimLicenseTenantId {
    <#
      LIC anti-copy (2026-10-03). The tenant a licence is checked against: the MANAGED IDENTITY's home tenant when this
      process has minted a managed-identity token (PIM-Rest.ps1 records its tid in $global:PIM_ManagedIdentityTenantId --
      a managed identity's token always comes from its home tenant, so editing PIM_TenantId cannot change it); otherwise
      the configured -TenantId (operator tools that run as a certificate SPN or the signed-in user).
    #>
    param([string]$TenantId)
    $mi = "$($global:PIM_ManagedIdentityTenantId)".Trim().ToLowerInvariant()
    if ($mi) { return $mi }
    # SPN / signed-in: a token is requested FOR the configured tenant and issued BY it, so pointing the configuration at a
    # licensed tenant makes the process really operate there -- the configured tenant is honest without a managed identity.
    foreach ($c in @($TenantId, $global:PIM_TenantId, $env:PIM_TenantId)) { if ("$c".Trim()) { return "$c".Trim().ToLowerInvariant() } }
    return ''
}

Function Test-PimLicenseTenantBinding {
    <#
      PURE (given $global:PIM_ManagedIdentityTenantId). LIC anti-copy (operator 2026-10-03: "validate license against the
      tenant so license can not be copied to other tenants"). Returns @{ ok; reason; tenantId }.
        * a licence that names NO tenant is refused -- every licence is issued for the tenant(s) it was bought for;
        * the tenant is Resolve-PimLicenseTenantId (the managed identity's home tenant when known);
        * an unknown tenant is refused (fail closed); a tenant not in the licence is refused.
    #>
    param($License, [string]$TenantId)
    $bound = @(@($License.TenantIds) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    $tid = Resolve-PimLicenseTenantId -TenantId $TenantId
    if (-not $bound.Count) { return [pscustomobject]@{ ok = $false; tenantId = $tid; reason = 'the licence names no tenant -- a licence is only valid for the tenant it was issued for; ask for a licence bound to this tenant' } }
    if (-not $tid) { return [pscustomobject]@{ ok = $false; tenantId = $tid; reason = "the licence is bound to tenant $($bound -join ', '), and this environment's tenant id is not known" } }
    if ($bound -notcontains $tid) {
        $cfg = "$TenantId".Trim().ToLowerInvariant()
        $why = if ($cfg -and $cfg -ne $tid) { "; this environment runs in tenant $tid (its managed identity), although it is configured as $cfg" } else { "; this tenant is $tid" }
        return [pscustomobject]@{ ok = $false; tenantId = $tid; reason = "the licence is for another tenant (bound to $($bound -join ', ')$why)" }
    }
    return [pscustomobject]@{ ok = $true; tenantId = $tid; reason = '' }
}

Function Test-PimLicenseIsProForTenant {
    <#
      PURE. BUG-278 (2026-10-01): THE edition verdict -- the same rule the hard gate (Test-PimProLicence) applies, minus the
      per-feature check: Status Valid or Grace, sku Pro / Pro-<variant> (never Community, never 'Core'), and a tenant
      binding that includes -TenantId (or no binding). The badge, GET /api/license, the updater's edition read and the
      import all use it, so the header can no longer say Pro while every Pro feature is locked.
      Returns @{ pro; reason }. A bound licence with an UNKNOWN tenant is not Pro (fail closed, as the gate).
    #>
    param($License, [string]$TenantId)
    if (-not $License) { return [pscustomobject]@{ pro = $false; reason = 'no Pro licence is installed' } }
    $st = "$($License.Status)"
    if ($st -notin @('Valid', 'Grace')) { return [pscustomobject]@{ pro = $false; reason = $(if ($st -eq 'Missing') { 'no Pro licence is installed' } else { "the licence is $st ($($License.Reason))" }) } }
    $sku = "$($License.Sku)".Trim()
    if ($sku -notmatch '^(?i)pro(-.+)?$') { return [pscustomobject]@{ pro = $false; reason = "the licence is a '$sku' licence, not Pro" } }
    $bind = Test-PimLicenseTenantBinding -License $License -TenantId $TenantId
    if (-not $bind.ok) { return [pscustomobject]@{ pro = $false; reason = $bind.reason } }
    return [pscustomobject]@{ pro = $true; reason = $(if ($st -eq 'Grace') { "Pro licence in its grace period ($($License.Reason))" } else { "Pro licence for '$($License.Customer)'" }) }
}

Function Get-PimEdition {
    # The active EDITION: 'Pro' when a valid (or in-grace) PRO licence for THIS tenant is present, else 'Community' (free).
    # Drives the manager edition badge. BUG-278: was "any Valid licence" -- a Community-sku or another tenant's licence
    # showed Pro while the hard gate (which checks both) kept every Pro feature locked.
    param([string]$TenantId = $(if ("$($global:PIM_TenantId)".Trim()) { "$($global:PIM_TenantId)" } else { "$env:PIM_TenantId" }))
    $lic = Get-PimLicense
    if ((Test-PimLicenseIsProForTenant -License $lic -TenantId $TenantId).pro) { return $script:PimProEditionName }
    return $script:PimCommunityEditionName
}

# =====================================================================================================================
# Framework DOCS/REQUIREMENTS.md §12.6 LICENCE-DIMENSION (owner 2026-10-08) -- PIM's half; PIM docs/REQUIREMENTS.md §95.2d.
# Pro has two dimensions, decided by the SIGNED licence: Pro Business = the payload carries a `limits` object (PIM reads
# `admins`: the number of managed admin accounts it covers); Pro Enterprise = no `limits`. Community and MSP unchanged.
# Enforcement is a WARNING, never a stop: from 90% a banner; at/over the cap only a NEW managed admin account is refused
# (Manager commit + staging + MCP -- the page only mirrors it). Nothing existing is disabled or touched, and the ENGINE
# never reads the limit at all.
# =====================================================================================================================
$script:PimLicenceDimensionBusiness   = 'Pro Business'
$script:PimLicenceDimensionEnterprise = 'Pro Enterprise'
$script:PimLicenceUpgradeUrl          = 'invardia.com'
# An admin row in one of these states is not counted: it is off, removed from PIM or deleted (the row only keeps it so).
$script:PimAdminNotCountedStatuses    = @('disabled', 'removed', 'deleted', 'revoked')

Function ConvertTo-PimLicenceLimits {
    <#
      PURE. The payload's `limits` value -> an ordered map name (lower-case) -> non-negative int, or $null when the value is
      not an object (absent / null / a string / a number = no limits = Pro Enterprise). A key whose value is not a whole
      number is dropped (never guessed); an empty object stays an (empty) map -- the licence IS Business, with no PIM cap.
    #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    $pairs = @()
    if ($Value -is [System.Collections.IDictionary]) { foreach ($k in @($Value.Keys)) { $pairs += ,@("$k", $Value[$k]) } }
    # 🪤 not `-is [pscustomobject]`: that is [psobject], true for a PSObject-WRAPPED string too, whose properties (Length)
    # would read as a limit. The JSON object type itself is the only object accepted.
    elseif ($Value.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') { foreach ($pp in @($Value.PSObject.Properties)) { $pairs += ,@("$($pp.Name)", $pp.Value) } }
    else { return $null }
    $out = [ordered]@{}
    foreach ($pr in $pairs) {
        $n = "$($pr[0])".Trim().ToLowerInvariant(); $v = "$($pr[1])".Trim()
        if ($n -and $v -match '^\d{1,9}$') { $out[$n] = [int]$v }
    }
    return $out
}

Function Get-PimLicenceDimension {
    <#
      PURE. 'Community' | 'Pro Business' | 'Pro Enterprise' for -License as THIS tenant sees it: not Pro here (the same verdict
      as the badge, Test-PimLicenseIsProForTenant) = Community; Pro with a signed `limits` object = Pro Business; Pro without
      = Pro Enterprise (every licence issued before §12.6, MSP included).
    #>
    param($License, [string]$TenantId)
    if (-not $License -or -not (Test-PimLicenseIsProForTenant -License $License -TenantId $TenantId).pro) { return $script:PimCommunityEditionName }
    $lim = $null; if ($License.PSObject.Properties['Limits']) { $lim = $License.Limits }
    if ($null -ne $lim) { return $script:PimLicenceDimensionBusiness }
    return $script:PimLicenceDimensionEnterprise
}

Function Get-PimLicenceAdminCap {
    # PURE. The licence's managed-admin cap (int), or $null = no cap (Enterprise, Community, or a Business licence without `admins`).
    param($License)
    if (-not $License -or -not $License.PSObject.Properties['Limits'] -or $null -eq $License.Limits) { return $null }
    $l = $License.Limits
    if ($l -is [System.Collections.IDictionary] -and $l.Contains('admins')) { return [int]$l['admins'] }
    return $null
}

Function Get-PimLicenceDimensionText {
    # PURE. The one label every surface shows: "Pro Enterprise", "Pro Business (5 admins)", "Pro Business", "Community".
    param($License, [string]$TenantId)
    $d = Get-PimLicenceDimension -License $License -TenantId $TenantId
    if ($d -ne $script:PimLicenceDimensionBusiness) { return $d }
    $cap = Get-PimLicenceAdminCap -License $License
    if ($null -ne $cap) { return ('{0} ({1} admin{2})' -f $d, $cap, $(if ($cap -eq 1) { '' } else { 's' })) }
    return $d
}

Function Get-PimManagedAdminIdentities {
    <#
      PURE. The managed admin ACCOUNTS -- Account-Definitions-Admins rows -- that count against the cap, each counted once:
      the identity is the UPN (lower-case), else the UserName. A row whose AccountStatus is Disabled / Removed / Deleted /
      Revoked is not counted (it is off, or the row only keeps it gone). -All counts every row whatever its state (the "is
      this account NEW" test). Returns a sorted, distinct string array.
    #>
    param([AllowNull()][object[]]$Rows, [switch]$All)
    $seen = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $get = { param($n) if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { "$($r[$n])" } else { '' } } elseif ($r.PSObject.Properties[$n]) { "$($r.$n)" } else { '' } }
        $id = (& $get 'UserPrincipalName').Trim().ToLowerInvariant()
        if (-not $id) { $id = (& $get 'UserName').Trim().ToLowerInvariant() }
        if (-not $id) { continue }
        if (-not $All -and ($script:PimAdminNotCountedStatuses -contains (& $get 'AccountStatus').Trim().ToLowerInvariant())) { continue }
        $seen[$id] = $true
    }
    return @($seen.Keys | Sort-Object)
}

Function Get-PimAdminLicenceUsage {
    <#
      PURE. The admin usage against the licence, for /api/license, the banners and the refusal:
        @{ dimension; dimensionText; cap ($null = none); count ($null when -Rows was not given); percent; state; message }
        state: none (no cap, or the count is unknown) | ok (< 90%) | warn (>= 90%, below the cap) | at (= cap) | over (> cap)
      message is the plain sentence the banner shows ('' for none/ok).
    #>
    param($License, [string]$TenantId, [AllowNull()][object[]]$Rows, [switch]$RowsKnown)
    $dim = Get-PimLicenceDimension -License $License -TenantId $TenantId
    $cap = if ($dim -eq $script:PimLicenceDimensionBusiness) { Get-PimLicenceAdminCap -License $License } else { $null }
    $known = $RowsKnown -or $PSBoundParameters.ContainsKey('Rows')
    $count = if ($known) { @(Get-PimManagedAdminIdentities -Rows $Rows).Count } else { $null }
    $out = [ordered]@{ dimension = $dim; dimensionText = (Get-PimLicenceDimensionText -License $License -TenantId $TenantId); cap = $cap; count = $count; percent = $null; state = 'none'; message = '' }
    if ($null -eq $cap -or $null -eq $count) { return $out }
    $pct = if ($cap -gt 0) { [int][math]::Floor(100.0 * $count / $cap) } else { 100 }
    $out.percent = $pct
    $covers = "Your Pro Business licence covers $cap admin account$(if ($cap -eq 1) { '' } else { 's' })"
    if ($count -gt $cap) {
        $out.state = 'over'
        $out.message = "$covers and $count are managed. Nothing is switched off, but a new admin account is refused -- upgrade to Pro Enterprise at $script:PimLicenceUpgradeUrl, or remove one."
    } elseif ($count -eq $cap) {
        $out.state = 'at'
        $out.message = "$covers and all $count are in use. A new admin account is refused -- upgrade to Pro Enterprise at $script:PimLicenceUpgradeUrl, or remove one."
    } elseif ($cap -gt 0 -and ($count * 10) -ge ($cap * 9)) {
        $out.state = 'warn'
        $out.message = "$covers and $count are in use ($pct%). Upgrade to Pro Enterprise at $script:PimLicenceUpgradeUrl before you add more."
    } else {
        $out.state = 'ok'
    }
    return $out
}

Function Test-PimAdminLicenceLimit {
    <#
      PURE. The server-side cap check for a change to Account-Definitions-Admins (the commit, staging, MCP).
        -Before = the rows as they are; -After = the rows the change would leave.
      Refused ONLY when the change brings in a NEW admin account (an identity in no -Before row, in any state) that is
      counted, and the counted total afterwards exceeds the cap. Editing, disabling, removing or re-enabling an existing
      account is never refused, and nothing already there is touched. No cap (Enterprise / Community / no `admins`) = ok.
      Returns @{ ok; refused; cap; count; before; added[]; dimension; message }.
    #>
    param($License, [string]$TenantId, [AllowNull()][object[]]$Before, [AllowNull()][object[]]$After)
    $u = Get-PimAdminLicenceUsage -License $License -TenantId $TenantId -Rows @($After) -RowsKnown
    $res = [ordered]@{ ok = $true; refused = $false; cap = $u.cap; count = $u.count; before = @(Get-PimManagedAdminIdentities -Rows @($Before)).Count; added = @(); dimension = $u.dimension; message = '' }
    if ($null -eq $u.cap) { return [pscustomobject]$res }
    $known = @{}; foreach ($i in @(Get-PimManagedAdminIdentities -Rows @($Before) -All)) { $known[$i] = $true }
    $added = @(@(Get-PimManagedAdminIdentities -Rows @($After)) | Where-Object { -not $known.ContainsKey($_) })
    $res.added = @($added)
    if ($added.Count -gt 0 -and $u.count -gt $u.cap) {
        $res.ok = $false; $res.refused = $true
        # 🪤 the list is built first: inside a -f argument list the comma binds tighter than +, so "(a) + b" there splits
        # the array and the format string loses its arguments.
        $names = (@($added | Select-Object -First 5) -join ', ')
        if ($added.Count -gt 5) { $names += ', ...' }
        $res.message = ("Your Pro Business licence covers {0} admin account{1} -- upgrade to Pro Enterprise at {2}, or remove one. Not saved: {3} new admin account{4} ({5}) would make {6}. Existing admin accounts are not changed." -f
            $u.cap, $(if ($u.cap -eq 1) { '' } else { 's' }), $script:PimLicenceUpgradeUrl, $added.Count, $(if ($added.Count -eq 1) { '' } else { 's' }), $names, $u.count)
    }
    return [pscustomobject]$res
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

# =====================================================================================================================
# REQ-Y (operator 2026-09-19: "managing tenant slave require license pro" / "enforce in code" / "write text to contact
# mok@mortenknudsen.net for license" / "msp license is req now"). A TARGETED enforcement: an environment that runs as an
# MANAGING TENANT (publishes the signed baseline) or an MSP SLAVE (pulls it) needs a Pro licence bound to its tenant.
#   * It does NOT read Test-PimProLicenseEnforced. The global switch stays OFF, so every OTHER Pro feature stays free.
#   * Valid = run. Grace (the licence's own graceDays after validTo) = run, with a warning. Anything else = refuse.
#   * No introduction grace: the requirement is immediate (operator 2026-09-19, "msp license is req now").
# The MSP jobs (tools/pim-engine/publish-job-entry.ps1, downlink-job-entry.ps1) refuse through Invoke-PimMspLicenseGate;
# the Manager serves the same verdict on GET /api/license (Get-PimLicenseApiBody) for the Settings > Licence section and
# the MSP-page banners.
# =====================================================================================================================
$script:PimLicenseContact = 'info@invardia.com'
# Operator 2026-10-01: "https://invardia.com ... is the website for buying pro version. it is also the support page
# (portal.invardia.com) for support to paid licenses".
$script:PimProBuyUrlDefault  = 'https://invardia.com'
$script:PimProSupportUrl     = 'https://portal.invardia.com'
# The licence feature names that cover MSP: the Pro catalog's MspFanout, the feature catalog key msp.downlink, and 'Msp'.
# '*' (all Pro features) covers it too.
$script:PimMspLicenseFeatures = @('MspFanout', 'msp.downlink', 'Msp')

Function Get-PimLicenseContact { "$script:PimLicenseContact" }

Function Get-PimLicenseRegisterCommand {
    <#
      PURE. The supported way to register an issued licence file (tools/setup/Set-PimLicense.ps1), with this environment's
      store server and tenant filled in when known; placeholders otherwise. Never carries a secret -- and never a certificate (97.1, owner 2026-10-08: "we dont support certificates"): it signs in as the az account in that window (a member of the store's SQL admin group, or the Invardia Support app session).
    #>
    param([string]$SqlServer, [string]$TenantId)
    $srv = "$SqlServer".Trim(); if (-not $srv) { $srv = '<server>.database.windows.net' }
    $tid = "$TenantId".Trim();  if (-not $tid) { $tid = '<tenant>' }
    return ("pwsh -File tools\setup\Set-PimLicense.ps1 -LicensePath <file> -SqlServer {0} -TenantId {1} -UseSignedInAccount" -f $srv, $tid)
}

Function ConvertFrom-PimLicenseSettingRaw {
    <#
      PURE. pim.Settings['License'] as the raw ValueJson column -> the licence DOCUMENT text Get-PimLicense verifies.
      Set-PimLicense stores the issued text through Set-PimSetting, i.e. as a JSON string literal; a document stored as a
      JSON object is accepted too (same rule as Get-PimLicenseFromStore). '' = nothing stored.
    #>
    param([AllowNull()][object]$Raw)
    if ($null -eq $Raw -or $Raw -is [System.DBNull]) { return '' }
    $t = "$Raw".Trim()
    if (-not $t) { return '' }
    try { $v = $t | ConvertFrom-Json } catch { return $t }
    if ($null -eq $v) { return '' }
    if ($v -is [string]) { return "$v" }
    return (ConvertTo-Json -InputObject $v -Depth 6 -Compress)
}

Function Test-PimProLicence {
    <#
    .SYNOPSIS
        REQ-Y. The ONE hard licence check: does this environment hold a Pro licence that covers -FeatureNames for its
        tenant? Used by the MSP jobs (Test-PimMspLicense) and by every Pro feature of the catalog
        (Test-PimFeatureProLicence in PIM-FeatureCatalog.ps1). Independent of the global switch.
    .DESCRIPTION
        Returns @{ ok; status; grace; customer; sku; validTo; graceUntil; tenantIds; tenantId; label; reason; message;
        contact; command }.
          ok     = licence Status Valid or Grace, sku Pro or Pro-<variant> (nothing else -- 'Core' is refused), features '*' or one of
                   -FeatureNames, and a tenant binding that includes -TenantId (or no binding at all).
          grace  = ok, but in the licence's grace window: run, and say so.
          reason = plain words ("no Pro licence is installed", "the licence expired 2027-09-19 ...", "the licence is for
                   another tenant ...").
          message= the one line a job logs, an API refusal carries and the GUI shows:
                   "<Label> requires a PIM Manager Pro licence -- <reason>. Contact <contact> for a licence; register it with: <command>"
        It NEVER consults Test-PimProLicenseEnforced.
    .PARAMETER LicenseText
        The stored document (pim.Settings['License'] as text). When BOUND it is used as-is (empty = nothing stored). When
        not bound, Get-PimLicense reads the store itself (-UseCache: its short-lived session cache, for hot paths).
    .PARAMETER StoreError
        The caller could not read the store: the licence cannot be verified, so the check is not ok (never "no licence").
    .PARAMETER PublicCertB64
        Test seam only (the same one Get-PimLicense has): the trusted licensing certificate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$FeatureNames,
        [Parameter(Mandatory)][string]$Label,
        [string]$FeatureWord,
        [string]$TenantId,
        [AllowEmptyString()][AllowNull()][string]$LicenseText,
        [string]$StoreError,
        [string]$SqlServer,
        [string]$PublicCertB64,
        [switch]$UseCache
    )
    $tid = "$TenantId".Trim().ToLowerInvariant()
    $word = if ("$FeatureWord".Trim()) { "$FeatureWord".Trim() } else { $Label }
    $out = [ordered]@{
        ok = $false; status = 'Missing'; grace = $false; customer = ''; sku = ''; validTo = ''; graceUntil = ''
        tenantIds = @(); tenantId = $tid; label = "$Label"; reason = ''; message = ''
        # §100.32: WHY the feature is (or is not) licensed -- enterprise | business | msp | needs-msp | listed | not-listed, or
        # 'licence' when the licence itself (missing, expired, another tenant, not Pro) decides; basisText says it in words.
        basis = ''; basisText = ''
        contact = "$script:PimLicenseContact"; command = (Get-PimLicenseRegisterCommand -SqlServer $SqlServer -TenantId $TenantId)
    }
    $lic = $null
    if ("$StoreError".Trim()) {
        $out.status = 'Invalid'
        $out.reason = "the licence could not be read from the store ($("$StoreError".Trim()))"
    } else {
        $a = @{}
        if (-not $UseCache) { $a['Refresh'] = $true }
        if ($PublicCertB64) { $a['PublicCertB64'] = $PublicCertB64 }
        if ($PSBoundParameters.ContainsKey('LicenseText')) {
            if ("$LicenseText".Trim()) { $a['LicenseText'] = "$LicenseText" } else { $a = $null }
        }
        if ($null -ne $a) { $lic = Get-PimLicense @a }
    }
    if ($lic) {
        $out.status   = "$($lic.Status)"
        $out.customer = "$($lic.Customer)"
        $out.sku      = "$($lic.Sku)"
        $out.validTo    = $(if ($lic.ValidTo) { $lic.ValidTo.ToString('yyyy-MM-dd') } else { '' })
        $out.graceUntil = $(if ($lic.GraceUntil) { $lic.GraceUntil.ToString('yyyy-MM-dd') } else { '' })
        $out.tenantIds  = @($lic.TenantIds | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
        $features = @($lic.Features | ForEach-Object { "$_".Trim() })
        # §100.32 / framework §12.6a (owner 2026-10-09): the licence names the EDITION. Every Pro licence (Enterprise and
        # Business alike) covers every single-tenant Pro feature, current and future; MSP needs the Pro MSP edition; the
        # features[] list only names add-ons. The verdict reads only the verified payload (Sku, Features, Limits).
        $grant = Get-PimLicenceFeatureGrant -License $lic -FeatureNames $FeatureNames
        $covers = [bool]$grant.covers
        switch ("$($lic.Status)") {
            'Missing'     { $out.reason = 'no Pro licence is installed' }
            'Invalid'     { $out.reason = "the stored licence is not valid ($($lic.Reason))" }
            'NotYetValid' { $out.reason = "the licence only starts $($lic.ValidFrom.ToString('yyyy-MM-dd'))" }
            'Expired'     { $out.reason = "the licence expired $($out.validTo) (its grace period ended $($out.graceUntil))" }
            default {
                # Pro, Pro-<variant> (Pro-DesignPartner). Anything else -- Community, or the old 'Core' -- is NOT Pro.
                # 🔴 REQ-Y (operator 2026-09-20: "fix req-y 3 items") -- 'Core' NO LONGER UNLOCKS PRO.
                # It was accepted as "documented back-compat", and that back-compat protected nothing: the ONLY issuer
                # is TOOLS\New-AitLicense.ps1, whose -Sku is [ValidateSet('Pro','Community')], so no signing run can
                # ever have produced a 'Core' licence -- and none exists (every issued licence, checked 2026-09-20,
                # decodes to sku 'Pro'). What the clause DID do was make the word most likely to be typed by hand for
                # the FREE tier -- 'Core' is this product's own historical name for it, still the internal edition name
                # in PIM-FeatureCatalog.ps1 -- unlock every Pro feature instead of none of them. A licence that grants
                # MORE the more it looks free is the wrong direction for a gate with no grace.
                # 🪤 The EDITION 'Core' (Get-PimActiveEdition / $script:PimEditionNames) is a different thing and is
                # unchanged: that is the free edition's internal name, not a licence sku.
                if ("$($lic.Sku)".Trim() -notmatch '^(?i)pro(-.+)?$') {
                    $out.reason = "the licence is a '$("$($lic.Sku)".Trim())' licence, not Pro"
                } elseif (-not $covers) {
                    $out.reason = switch ("$($grant.basis)") {
                        'needs-msp' { "the licence does not include $word -- it needs the MSP licence (features: $(($features -join ', ')))" }
                        default     { "the licence does not include $word (features: $(($features -join ', ')))" }
                    }
                    $out.basis = "$($grant.basis)"; $out.basisText = "$($grant.text)"
                } elseif (-not ($bind = Test-PimLicenseTenantBinding -License $lic -TenantId $TenantId).ok) {
                    $out.reason = $bind.reason
                } else {
                    $out.ok = $true
                    $out.basis = "$($grant.basis)"; $out.basisText = "$($grant.text)"
                    if ("$($lic.Status)" -eq 'Grace') {
                        $out.grace = $true
                        $out.reason = "the licence expired $($out.validTo), grace until $($out.graceUntil)"
                    } else {
                        $out.reason = "Pro licence for '$($out.customer)', valid until $($out.validTo)"
                    }
                }
            }
        }
    } elseif (-not $out.reason) {
        $out.reason = 'no Pro licence is installed'
    }
    if (-not $out.basis) { $out.basis = 'licence'; $out.basisText = "$($out.reason)" }
    if (-not $out.ok) {
        $out.message = ("{0} requires a PIM Manager Pro licence -- {1}. Contact {2} for a licence; register it with: {3}" -f $Label, $out.reason, $out.contact, $out.command)
    } elseif ($out.grace) {
        $out.message = ("{0}: licence expired {1}, grace until {2} -- contact {3} to renew" -f $Label, $out.validTo, $out.graceUntil, $out.contact)
    } else {
        $out.message = ("{0}: {1}" -f $Label, $out.reason)
    }
    return [pscustomobject]$out
}

Function Test-PimMspLicense {
    <#
    .SYNOPSIS
        REQ-Y. Does this managing tenant / slave hold a Pro licence that covers MSP for its tenant? (Test-PimProLicence with
        the MSP feature names, labelled "managing tenant" / "MSP slave".) The result also carries role = master | slave.
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [ValidateSet('Master', 'Slave')][string]$Role = 'Master',
        [AllowEmptyString()][AllowNull()][string]$LicenseText,
        [string]$StoreError,
        [string]$SqlServer,
        [string]$PublicCertB64
    )
    $roleWord = if ($Role -eq 'Slave') { 'slave' } else { 'master' }
    # §85 (operator 2026-10-01: "slave is not nice"): the WORDS are "managing tenant" / "managed tenant"; the role field the
    # API and the jobs read stays master | slave.
    $roleLabel = if ($Role -eq 'Slave') { 'Managed tenant (MSP)' } else { 'Managing tenant (MSP)' }
    $a = @{ FeatureNames = $script:PimMspLicenseFeatures; Label = $roleLabel; FeatureWord = 'MSP'; TenantId = $TenantId; StoreError = $StoreError; SqlServer = $SqlServer }
    if ($PublicCertB64) { $a['PublicCertB64'] = $PublicCertB64 }
    if ($PSBoundParameters.ContainsKey('LicenseText')) { $a['LicenseText'] = "$LicenseText" }
    $r = Test-PimProLicence @a
    $r | Add-Member -NotePropertyName role -NotePropertyValue $roleWord -Force
    return $r
}
Function Invoke-PimMspLicenseGate {
    <#
      REQ-Y. The MSP jobs' gate: runs Test-PimMspLicense and logs ONE line through -Log (param($message, $level)):
        not ok -> ERROR  "MSP <role> requires a PIM Manager Pro licence -- <reason>. Contact ... ; register it with: ..."
        grace  -> WARN   "MSP <role>: licence expired <date>, grace until <date> -- contact ... to renew"
        ok     -> INFO   "MSP <role>: Pro licence for '<customer>', valid until <date>"
      Returns the Test-PimMspLicense result; the caller refuses (exit non-zero, nothing published / pulled) when not ok.
      A check that THROWS is not ok (a gate that cannot decide never runs the MSP pipeline).
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('Master', 'Slave')][string]$Role,
        [string]$TenantId,
        [AllowEmptyString()][AllowNull()][string]$LicenseText,
        [string]$StoreError,
        [string]$SqlServer,
        [scriptblock]$Log
    )
    $a = @{ Role = $Role; TenantId = $TenantId; StoreError = $StoreError; SqlServer = $SqlServer }
    if ($PSBoundParameters.ContainsKey('LicenseText')) { $a['LicenseText'] = "$LicenseText" }
    try { $r = Test-PimMspLicense @a }
    catch {
        $roleWord = if ($Role -eq 'Slave') { 'slave' } else { 'master' }
        $cmd = Get-PimLicenseRegisterCommand -SqlServer $SqlServer -TenantId $TenantId
        $r = [pscustomobject]@{ ok = $false; status = 'Invalid'; grace = $false; customer = ''; sku = ''; validTo = ''; graceUntil = ''; tenantIds = @(); tenantId = "$TenantId"; role = $roleWord
            reason = "the licence check failed ($($_.Exception.Message))"; contact = "$script:PimLicenseContact"; command = $cmd
            message = ("{0} requires a PIM Manager Pro licence -- the licence check failed ({1}). Contact {2} for a licence; register it with: {3}" -f $(if ($Role -eq 'Slave') { 'Managed tenant (MSP)' } else { 'Managing tenant (MSP)' }), $_.Exception.Message, $script:PimLicenseContact, $cmd) }
    }
    $lvl = if (-not $r.ok) { 'ERROR' } elseif ($r.grace) { 'WARN' } else { 'INFO' }
    if ($Log) { & $Log $r.message $lvl }
    return $r
}

Function Get-PimLicenseApiBody {
    <#
      REQ-Y. The body of the Manager's GET /api/license: the licence status in plain words, plus the MSP verdict for THIS
      environment. -MspRole '' = single (non-MSP): mspRequired false and the GUI shows no MSP banner. Read-only.
      mspState: none (single) | ok | grace | refused.
    #>
    param([ValidateSet('', 'Master', 'Slave')][string]$MspRole = '', [string]$TenantId, [string]$SqlServer, [string]$PublicCertB64,
          # §12.6: the stored Account-Definitions-Admins rows, for the admin usage (count / cap / state). Not given = count unknown.
          [AllowNull()][object[]]$AdminRows, [string]$LicenseText)
    $la = @{ Refresh = $true }; if ($PublicCertB64) { $la['PublicCertB64'] = $PublicCertB64 }
    if ($PSBoundParameters.ContainsKey('LicenseText') -and "$LicenseText".Trim()) { $la['LicenseText'] = "$LicenseText" }
    $lic = Get-PimLicense @la
    $ua = @{ License = $lic; TenantId = $TenantId }; if ($PSBoundParameters.ContainsKey('AdminRows')) { $ua['Rows'] = @($AdminRows); $ua['RowsKnown'] = $true }
    $usage = Get-PimAdminLicenceUsage @ua
    $ma = @{ Role = $(if ($MspRole) { $MspRole } else { 'Master' }); TenantId = $TenantId; SqlServer = $SqlServer }
    if ($la.ContainsKey('LicenseText')) { $ma['LicenseText'] = $la['LicenseText'] }
    if ($PublicCertB64) { $ma['PublicCertB64'] = $PublicCertB64 }
    $m = Test-PimMspLicense @ma
    $pro = [bool](Test-PimLicenseIsProForTenant -License $lic -TenantId $TenantId).pro   # BUG-278: sku + tenant, as the gate
    $statusText = switch ("$($lic.Status)") {
        'Missing' { 'Community (free) -- no Pro licence installed' }
        'Valid'   { "Pro -- $($lic.Customer) -- valid until $($m.validTo)" }
        'Grace'   { "Pro (grace) -- $($lic.Customer) -- expired $($m.validTo), grace until $($m.graceUntil)" }
        default   { "Community (free) -- licence $($lic.Status): $($lic.Reason)" }
    }
    $state = 'none'
    if ($MspRole) { $state = if (-not $m.ok) { 'refused' } elseif ($m.grace) { 'grace' } else { 'ok' } }
    return [ordered]@{
        status       = "$($lic.Status)"
        statusText   = $statusText
        edition      = $(if ($pro) { $script:PimProEditionName } else { $script:PimCommunityEditionName })
        # Framework §12.6: Pro Business (signed `limits`) | Pro Enterprise | Community; the limits as signed; the admin usage.
        dimension     = "$($usage.dimension)"
        dimensionText = "$($usage.dimensionText)"
        limits        = $(if ($pro -and $null -ne $lic.Limits) { $lic.Limits } else { $null })
        usage         = [ordered]@{ admins = [ordered]@{ cap = $usage.cap; count = $usage.count; percent = $usage.percent; state = $usage.state; message = $usage.message } }
        customer     = "$($lic.Customer)"
        sku          = "$($lic.Sku)"
        features     = @($lic.Features)
        tenantIds    = @($lic.TenantIds)
        boundTenant  = $(if (@($lic.TenantIds).Count) { (@($lic.TenantIds) -join ', ') } else { '' })
        tenantId     = "$TenantId".Trim()
        validTo      = $(if ($lic.ValidTo) { $lic.ValidTo.ToString('yyyy-MM-dd') } else { '' })
        graceUntil   = $(if ($lic.GraceUntil) { $lic.GraceUntil.ToString('yyyy-MM-dd') } else { '' })
        reason       = "$($lic.Reason)"
        mspRequired  = [bool]$MspRole
        mspRole      = $(if ($MspRole -eq 'Slave') { 'slave' } elseif ($MspRole) { 'master' } else { '' })
        mspOk        = $(if ($MspRole) { [bool]$m.ok } else { $true })
        mspState     = $state
        mspReason    = $(if ($MspRole) { "$($m.reason)" } else { '' })
        mspMessage   = $(if ($MspRole) { "$($m.message)" } else { '' })
        contact      = "$script:PimLicenseContact"
        # Free edition (operator 2026-09-26): where "Buy Pro" goes. An https URL from PIM_PRO_BUY_URL (env or global) --
        # anything else is ignored and the page mails the contact instead.
        buyUrl       = $(foreach ($u in @("$($global:PIM_ProBuyUrl)", "$env:PIM_PRO_BUY_URL", "$script:PimProBuyUrlDefault")) { if ("$u".Trim() -match '^https://[^\s"''<>]+$') { "$u".Trim(); break } })
        supportUrl   = "$script:PimProSupportUrl"   # support for paid licences (shown once the environment is Pro)
        command      = "$($m.command)"
        # BUG-277: a Community install that registered a Pro licence and has not got the Pro updater yet -> the page says how.
        upgrade      = $(try { $mk = $null; $us = $null; if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { $mk = Get-PimSetting -Name 'EditionUpgrade'; $us = Get-PimSetting -Name 'UpdateState' }; $ug = Get-PimEditionUpgradeState -Marker $mk -UpdateState $us; [ordered]@{ pending = [bool]($pro -and $ug.pending); since = $ug.since; reason = $ug.reason; command = $ug.command } } catch { [ordered]@{ pending = $false; since = ''; reason = ''; command = '' } })
        editionLine  = "Free: the community edition for a single tenant. Pro: the licensed features for a single tenant, and the multi-tenant half (managing tenant / managed tenants). Contact $script:PimLicenseContact."
        # key -> { label; scope; ok; grace; state ok|grace|locked; reason; message } for every Pro feature of the catalog
        # (the GUI's "Pro -- contact" notices). Empty when the catalog is not loaded in this process.
        pro          = $(if (Get-Command Get-PimProFeatureStates -ErrorAction SilentlyContinue) { $pa = @{ TenantId = $TenantId; SqlServer = $SqlServer }; if ($PublicCertB64) { $pa['PublicCertB64'] = $PublicCertB64 }; Get-PimProFeatureStates @pa } else { [ordered]@{} })
    }
}
