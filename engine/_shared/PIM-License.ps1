#Requires -Version 5.1
<#
.SYNOPSIS
    PIM4EntraPS offline license verification (Core + Pro split).

.DESCRIPTION
    PIM4EntraPS Community is free for a single tenant. Pro (the licensed single-tenant features, and the
    multi-tenant half: MSP master / managed tenants) requires a customer licence: the issued signed document,
    stored in SQL pim.Settings[License] (IMP-42 -- no file). REQ-Y: an MSP master / slave is refused without one.

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
$script:PimProFeatureCatalog = @('AccessReviews', 'Coverage', 'Discovery', 'EvidenceExport', 'MakerChecker', 'MspFanout',
    'PortalAdmins', 'Revoke', 'TierReport', 'WorkloadConnectors')

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
    param([Parameter(Mandatory)][string]$LicenseText, [string]$PublicCertB64)
    $chk = if ($PublicCertB64) { Get-PimLicense -LicenseText $LicenseText -PublicCertB64 $PublicCertB64 } else { Get-PimLicense -LicenseText $LicenseText }
    if ($chk.Status -in @('Invalid','Missing')) { throw "licence NOT stored: $($chk.Reason)" }
    if (-not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { throw 'licence NOT stored: no SQL settings store (Set-PimSetting) is wired -- PIM v2 keeps the licence in SQL only' }
    Set-PimSetting -Name 'License' -Value $LicenseText
    $script:PimLicenseCache = $null
    return $chk
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

    # LIC-1 -- accept EITHER signer. AutomateIT first (the going-forward framework key), then the
    # legacy PIM key so anything already issued keeps verifying. An explicit -PublicCertB64 still
    # wins, which is what the negative tests rely on.
    $trustedCerts = if ($PublicCertB64) { @($PublicCertB64) }
                    else { @($script:AitLicensePublicCertB64, $script:PimLicensePublicCertB64) }

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

# =====================================================================================================================
# REQ-Y (operator 2026-09-19: "msp master slave require license pro" / "enforce in code" / "write text to contact
# mok@mortenknudsen.net for license" / "msp license is req now"). A TARGETED enforcement: an environment that runs as an
# MSP MASTER (publishes the signed baseline) or an MSP SLAVE (pulls it) needs a Pro licence bound to its tenant.
#   * It does NOT read Test-PimProLicenseEnforced. The global switch stays OFF, so every OTHER Pro feature stays free.
#   * Valid = run. Grace (the licence's own graceDays after validTo) = run, with a warning. Anything else = refuse.
#   * No introduction grace: the requirement is immediate (operator 2026-09-19, "msp license is req now").
# The MSP jobs (tools/pim-engine/publish-job-entry.ps1, downlink-job-entry.ps1) refuse through Invoke-PimMspLicenseGate;
# the Manager serves the same verdict on GET /api/license (Get-PimLicenseApiBody) for the Settings > Licence section and
# the MSP-page banners.
# =====================================================================================================================
$script:PimLicenseContact = 'mok@mortenknudsen.net'
# The licence feature names that cover MSP: the Pro catalog's MspFanout, the feature catalog key msp.downlink, and 'Msp'.
# '*' (all Pro features) covers it too.
$script:PimMspLicenseFeatures = @('MspFanout', 'msp.downlink', 'Msp')

Function Get-PimLicenseContact { "$script:PimLicenseContact" }

Function Get-PimLicenseRegisterCommand {
    <#
      PURE. The supported way to register an issued licence file (tools/setup/Set-PimLicense.ps1), with this environment's
      store server and tenant filled in when known; placeholders otherwise. Never carries a secret.
    #>
    param([string]$SqlServer, [string]$TenantId)
    $srv = "$SqlServer".Trim(); if (-not $srv) { $srv = '<server>.database.windows.net' }
    $tid = "$TenantId".Trim();  if (-not $tid) { $tid = '<tenant>' }
    return ("pwsh -File tools\setup\Set-PimLicense.ps1 -LicensePath <file> -SqlServer {0} -TenantId {1} -AdminAppId <app id> -AdminCertThumbprint <thumbprint>" -f $srv, $tid)
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
                   "<Label> requires a PIM4EntraPS Pro licence -- <reason>. Contact <contact> for a licence; register it with: <command>"
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
        $covers = ($features -contains '*')
        foreach ($f in @($FeatureNames)) { if ("$f".Trim() -and ($features -contains "$f".Trim())) { $covers = $true } }
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
                    $out.reason = "the licence does not include $word (features: $(($features -join ', ')))"
                } elseif (@($out.tenantIds).Count -gt 0 -and -not $tid) {
                    $out.reason = "the licence is bound to tenant $(($out.tenantIds -join ', ')), and this environment's tenant id is not known"
                } elseif (@($out.tenantIds).Count -gt 0 -and ($out.tenantIds -notcontains $tid)) {
                    $out.reason = "the licence is for another tenant (bound to $(($out.tenantIds -join ', ')); this tenant is $tid)"
                } else {
                    $out.ok = $true
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
    if (-not $out.ok) {
        $out.message = ("{0} requires a PIM4EntraPS Pro licence -- {1}. Contact {2} for a licence; register it with: {3}" -f $Label, $out.reason, $out.contact, $out.command)
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
        REQ-Y. Does this MSP master / slave hold a Pro licence that covers MSP for its tenant? (Test-PimProLicence with
        the MSP feature names, labelled "MSP master" / "MSP slave".) The result also carries role = master | slave.
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
    $a = @{ FeatureNames = $script:PimMspLicenseFeatures; Label = "MSP $roleWord"; FeatureWord = 'MSP'; TenantId = $TenantId; StoreError = $StoreError; SqlServer = $SqlServer }
    if ($PublicCertB64) { $a['PublicCertB64'] = $PublicCertB64 }
    if ($PSBoundParameters.ContainsKey('LicenseText')) { $a['LicenseText'] = "$LicenseText" }
    $r = Test-PimProLicence @a
    $r | Add-Member -NotePropertyName role -NotePropertyValue $roleWord -Force
    return $r
}
Function Invoke-PimMspLicenseGate {
    <#
      REQ-Y. The MSP jobs' gate: runs Test-PimMspLicense and logs ONE line through -Log (param($message, $level)):
        not ok -> ERROR  "MSP <role> requires a PIM4EntraPS Pro licence -- <reason>. Contact ... ; register it with: ..."
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
            message = ("MSP {0} requires a PIM4EntraPS Pro licence -- the licence check failed ({1}). Contact {2} for a licence; register it with: {3}" -f $roleWord, $_.Exception.Message, $script:PimLicenseContact, $cmd) }
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
    param([ValidateSet('', 'Master', 'Slave')][string]$MspRole = '', [string]$TenantId, [string]$SqlServer, [string]$PublicCertB64)
    $la = @{ Refresh = $true }; if ($PublicCertB64) { $la['PublicCertB64'] = $PublicCertB64 }
    $lic = Get-PimLicense @la
    $ma = @{ Role = $(if ($MspRole) { $MspRole } else { 'Master' }); TenantId = $TenantId; SqlServer = $SqlServer }
    if ($PublicCertB64) { $ma['PublicCertB64'] = $PublicCertB64 }
    $m = Test-PimMspLicense @ma
    $pro = ("$($lic.Status)" -in @('Valid', 'Grace'))
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
        buyUrl       = $(foreach ($u in @("$($global:PIM_ProBuyUrl)", "$env:PIM_PRO_BUY_URL")) { if ("$u".Trim() -match '^https://[^\s"''<>]+$') { "$u".Trim(); break } })
        command      = "$($m.command)"
        editionLine  = "Free: the community edition for a single tenant. Pro: the licensed features for a single tenant, and the multi-tenant half (MSP master / managed tenants). Contact $script:PimLicenseContact."
        # key -> { label; scope; ok; grace; state ok|grace|locked; reason; message } for every Pro feature of the catalog
        # (the GUI's "Pro -- contact" notices). Empty when the catalog is not loaded in this process.
        pro          = $(if (Get-Command Get-PimProFeatureStates -ErrorAction SilentlyContinue) { $pa = @{ TenantId = $TenantId; SqlServer = $SqlServer }; if ($PublicCertB64) { $pa['PublicCertB64'] = $PublicCertB64 }; Get-PimProFeatureStates @pa } else { [ordered]@{} })
    }
}
