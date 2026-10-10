#Requires -Version 5.1
<#
.SYNOPSIS
    UPLINK-ENROL (framework DOCS/REQUIREMENTS.md 8.6, block "LIVE on invardia.com 2026-10-08"; PIM docs/REQUIREMENTS.md 99) --
    PIM Manager's half of SELF-SERVICE MANAGED TENANTS: a managed tenant is built with an ENROLLMENT KEY its managing company
    got from Invardia, and nobody has to register it, licence it or open the bundle store for it by hand.

.DESCRIPTION
    THE CALLS (base https://invardia.com, overridable; every call behind an -Http seam the tests mock):

      CLAIM    (managed tenant build, step 'enroll', first)        no sign-in
               POST /api/enrollments/claim { enrollmentKey, tenantId, subscriptionId, product: 'pim-manager' }
               -> 201 first / 200 again { environmentHandle, installKey: 'inv-...',
                    licence: { status: 'signing', licenceId: null, pollAfterSeconds, hint }
                           | { status: 'ready', licenceId, fileName, sha256, contentBase64, validFrom, validUntil },
                    managing: { bundleStorage, container, signingKeyIds } (or nulls), uplink {...}, updates {...} }
               Licence signing is ASYNC: the build claims again after pollAfterSeconds (bounded) until 'ready', checks the
               SHA-256 and decodes the file. EVERY CLAIM ISSUES A NEW INSTALL KEY (the old one stops working), so only the
               key of the LAST claim is kept, and the licence step that stores it always runs after a claim.
      MANAGING (managed tenant, when the claim returned null facts)  header X-Invardia-Install-Key = its own key
               GET /api/enrollments/managing -> { managingTenantId, managing: { bundleStorage, container, signingKeyIds } }
               | 404 notEnrolled
      FACTS    (both roles; writes the CALLER's own environment)    header X-Invardia-Install-Key = its own key
               PUT /api/enrollments/facts
                   managing tenant: { product, bundleStorage, container, signingKeyIds[] }
                   managed tenant : { product, pullSubnetIds[] }        (only the fields given change)
      TENANTS  (managing tenant job 'enrolled-tenants')             header X-Invardia-Install-Key = its own key
               GET /api/enrollments/tenants -> { managingTenantId, product,
                   tenants: [ { tenantId, environmentHandle, subscriptionId, pullSubnetIds[], claimedAt } ] }
               Each pull subnet is allowed on the bundle store; the job never removes a rule it did not add itself.

    SINGLE-TENANT enrollment (framework 8.6 "SINGLE-TENANT enrollment too", owner 2026-10-08): the same CLAIM from a single
    (non-MSP) install -- Invoke-PimDeployAll -EnrollmentKey and Install-PimManager's 'enrollmentKey' call
    Invoke-PimEnrollmentSingleClaim: managing must be null (a managing block = an MSP key = refused), the licence is polled
    the same way, and the licence + install key go to the licence step as files (Save-PimEnrollmentClaimFiles, shared with the
    managed-tenant build). Until Invardia issues kind 'single' it answers 409 managingTenant / noMspLicence: said plainly.

    RULE: the enrollment key (ek-...) is a bearer secret that mints licences. It is used for the claim only: never printed
          (only masked), never written to a file, the store, the plan, a step's arguments or telemetry.
    RULE: Invardia's error text is never shown; its 'error' code picks one plain sentence.
#>

$script:PimEnrollmentProduct = 'pim-manager'
$script:PimEnrollmentDefaultBase = 'https://invardia.com'
$script:PimEnrollmentGuid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
$script:PimEnrollmentSubnet = '^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\.Network/virtualNetworks/[^/]+/subnets/[^/]+$'
$script:PimEnrollmentSettingFacts = 'MspBundleFacts'
$script:PimEnrollmentSettingSubnet = 'MspPullSubnetId'
$script:PimEnrollmentSettingState = 'EnrolledTenantsState'

function Resolve-PimEnrollmentBaseUrl {
    # PURE. The Invardia base address: an explicit value, else https://invardia.com. https only (http is refused).
    param([string]$BaseUrl)
    $b = "$BaseUrl".Trim().TrimEnd('/')
    if (-not $b) { return $script:PimEnrollmentDefaultBase }
    if ($b -notmatch '^https://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~\-/]*)?$') { throw "the Invardia address '$b' is not an https:// address" }
    return $b
}

function Test-PimEnrollmentKeyFormat {
    # PURE. An Invardia enrollment key: 'ek-' + 43 characters of base64url. Refuses a paste accident before anything is sent.
    param([string]$Key)
    return [bool]("$Key" -cmatch '^ek-[A-Za-z0-9_-]{43}$')
}

function Get-PimEnrollmentKeyMask {
    # PURE. What may be SHOWN of an enrollment key: its length and last four characters. Never more.
    param([string]$Key)
    $k = "$Key".Trim()
    if (-not $k) { return '(none)' }
    $tail = if ($k.Length -ge 12) { $k.Substring($k.Length - 4) } else { '' }
    return ('ek-****{0} ({1} characters)' -f $tail, $k.Length)
}

function New-PimEnrollmentClaimBody {
    # PURE. The claim body, exactly as the contract names it. Tenant and subscription lower-cased.
    param([Parameter(Mandatory)][string]$EnrollmentKey, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId)
    return [ordered]@{
        enrollmentKey  = "$EnrollmentKey".Trim()
        tenantId       = "$TenantId".Trim().ToLowerInvariant()
        subscriptionId = "$SubscriptionId".Trim().ToLowerInvariant()
        product        = $script:PimEnrollmentProduct
    }
}

function Get-PimEnrollmentErrorCode {
    # PURE. Invardia's error CODE from an answer body ('error', else 'code'); '' when none.
    param([AllowNull()][object]$Body)
    if (-not $Body) { return '' }
    foreach ($n in 'error', 'code') { if ($Body.PSObject.Properties[$n] -and "$($Body.$n)".Trim()) { return "$($Body.$n)".Trim() } }
    return ''
}

function Get-PimEnrollmentRefusalMessage {
    <#
      PURE. A refused / failed claim -> ONE plain sentence for the customer. Invardia's own text is NOT echoed (it can carry
      internal ids); only its status + error CODE pick the sentence (live contract 2026-10-08):
        401 key | 403 keyRevoked, keyExpired | 422 invalid, productMismatch |
        409 managingTenant, tenantBelongsToAnotherCompany, noMspLicence, keyLimit, tenantLimit
      -Kind Single (a SINGLE-tenant install, framework 8.6 "SINGLE-TENANT enrollment too"): the same codes in the words of a
      customer installing its own tenant (no managing company), and 409 managingTenant | noMspLicence -- what Invardia answers
      a single key until it issues kind 'single' -- says so: "Invardia does not issue single-tenant enrollment yet".
    #>
    param([int]$Status, [AllowNull()][object]$Body, [ValidateSet('Managed', 'Single')][string]$Kind = 'Managed')
    $code = Get-PimEnrollmentErrorCode -Body $Body
    if ($Kind -eq 'Single') { return (Get-PimEnrollmentSingleRefusalMessage -Status $Status -Code $code) }
    switch -Regex ($code) {
        '^(?i)keyRevoked$'                    { return 'this enrollment key has been revoked. Ask your managing company for a new one. Nothing was created.' }
        '^(?i)keyExpired$'                    { return 'this enrollment key has expired. Ask your managing company for a new one. Nothing was created.' }
        '^(?i)productMismatch$'               { return 'this enrollment key is not for PIM Manager. Ask your managing company for a PIM Manager enrollment key.' }
        '^(?i)invalid$'                       { return 'Invardia refused the request as incomplete. Check the tenant id and subscription id in the build config, then run the build again.' }
        '^(?i)managingTenant$'                { return 'this tenant is your managing company''s own managing tenant. An enrollment key enrols a MANAGED tenant; build this one as the managing tenant instead.' }
        '^(?i)tenantBelongsToAnotherCompany$' { return 'this tenant is already registered to another company at Invardia. Contact Invardia support (support@invardia.com); nothing was created.' }
        '^(?i)noMspLicence$'                  { return 'your managing company has no active managed-service (Pro) licence at Invardia, so it cannot enrol tenants. Ask it to renew the licence; nothing was created.' }
        '^(?i)keyLimit$'                      { return 'this enrollment key has already enrolled as many tenants as it allows. Ask your managing company for a new key; nothing was created.' }
        '^(?i)tenantLimit$'                   { return 'your managing company has enrolled as many tenants as its licence covers. It can raise the limit with Invardia; nothing was created.' }
        '^(?i)key$'                           { return 'the enrollment key was not accepted. Check that it was copied completely, or ask your managing company for a new one.' }
    }
    switch ($Status) {
        401 { return 'the enrollment key was not accepted. Check that it was copied completely, or ask your managing company for a new one.' }
        403 { return 'Invardia refused this enrollment key. Ask your managing company for a new one. Nothing was created.' }
        404 { return 'Invardia''s enrollment service did not answer. Try again later, or build this tenant with its master block and licence file instead.' }
        409 { return 'Invardia cannot enrol this tenant with this key. Ask your managing company to check its enrollment key and licence; nothing was created.' }
        422 { return 'Invardia refused the request as incomplete. Check the tenant id and subscription id in the build config, then run the build again.' }
        429 { return 'Invardia is limiting enrollment requests right now. Wait a few minutes, then run the build again.' }
        0   { return 'Invardia could not be reached. Check that this machine can open https://invardia.com, then run the build again.' }
    }
    if ($Status -ge 500) { return "Invardia could not complete the enrollment right now (HTTP $Status). Run the build again later; nothing was created here." }
    return "Invardia did not accept the enrollment (HTTP $Status). Ask your managing company to check its enrollment key."
}

$script:PimEnrollmentAlreadyInstalled = 'this tenant is already installed with this enrollment key -- re-run the install with its existing configuration (or Install-PimManager -Resume). The install key it already has is kept.'
$script:PimEnrollmentSingleNotYet ='Invardia does not issue single-tenant enrollment yet -- use the licence file (it comes with your installation from invardia.com). Nothing was installed.'
$script:PimEnrollmentSingleManaged = 'this key is for a managed tenant -- use the MSP managed-tenant install (tools/setup/Invoke-PimMspBuild.ps1 -Role Slave -EnrollmentKey ...). Nothing was installed here.'

function Get-PimEnrollmentSingleRefusalMessage {
    # PURE. A refused SINGLE-tenant claim -> ONE plain sentence (status + Invardia's error CODE only; its text is never shown).
    param([int]$Status, [string]$Code = '')
    switch -Regex ("$Code".Trim()) {
        '^(?i)(managingTenant|noMspLicence)$'  { return $script:PimEnrollmentSingleNotYet }
        '^(?i)keyRevoked$'                    { return 'this enrollment key has been revoked. Get a new one at invardia.com; nothing was installed.' }
        '^(?i)keyExpired$'                    { return 'this enrollment key has expired. Get a new one at invardia.com; nothing was installed.' }
        '^(?i)productMismatch$'               { return 'this enrollment key is not for PIM Manager. Use a PIM Manager enrollment key from invardia.com.' }
        '^(?i)invalid$'                       { return 'Invardia refused the request as incomplete. Check the tenant id and subscription id, then run the installation again.' }
        '^(?i)tenantBelongsToAnotherCompany$' { return 'this tenant is already registered to another company at Invardia. Contact Invardia support (support@invardia.com); nothing was installed.' }
        '^(?i)keyLimit$'                      { return 'this enrollment key has already been used for as many tenants as it allows. Get a new key at invardia.com; nothing was installed.' }
        '^(?i)tenantLimit$'                   { return 'your Invardia licence covers no more tenants. Raise the limit at invardia.com; nothing was installed.' }
        '^(?i)key$'                           { return 'the enrollment key was not accepted. Check that it was copied completely, or get a new one at invardia.com.' }
    }
    switch ($Status) {
        401 { return 'the enrollment key was not accepted. Check that it was copied completely, or get a new one at invardia.com.' }
        403 { return 'Invardia refused this enrollment key. Get a new one at invardia.com; nothing was installed.' }
        404 { return 'Invardia''s enrollment service did not answer. Try again later, or install with the licence file instead.' }
        409 { return 'Invardia cannot enrol this tenant with this key. Check the key at invardia.com, or install with the licence file; nothing was installed.' }
        422 { return 'Invardia refused the request as incomplete. Check the tenant id and subscription id, then run the installation again.' }
        429 { return 'Invardia is limiting enrollment requests right now. Wait a few minutes, then run the installation again.' }
        0   { return 'Invardia could not be reached. Check that this machine can open https://invardia.com, then run the installation again.' }
    }
    if ($Status -ge 500) { return "Invardia could not complete the enrollment right now (HTTP $Status). Run the installation again later; nothing was installed." }
    return "Invardia did not accept the enrollment (HTTP $Status). Check the enrollment key at invardia.com."
}

function Get-PimEnrollmentSha256Hex {
    # PURE. Lower-case hex SHA-256 of a byte array.
    param([byte[]]$Bytes)
    $h = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() } finally { $h.Dispose() }
}

function ConvertFrom-PimEnrollmentManaging {
    # PURE. A 'managing' block -> @{ storageAccount; container; signingKeyIds; tenantId } or $null when it carries no facts
    # (the managing tenant has not reported yet: every value null). A PRESENT but malformed value refuses (@{ bad = reason }).
    param([AllowNull()][object]$Managing, [string]$ManagingTenantId = '')
    if (-not $Managing) { return $null }
    $st = "$($Managing.bundleStorage)".Trim().ToLowerInvariant()
    $pins = @(@($Managing.signingKeyIds) | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if (-not $st -and -not $pins.Count) { return $null }
    if ($st -notmatch '^[a-z0-9]{3,24}$') { return @{ bad = 'the bundle storage account is not valid' } }
    if (-not $pins.Count) { return @{ bad = 'no signing key id' } }
    foreach ($p in $pins) { if ($p -cnotmatch '^[A-Za-z0-9_-]{43}$') { return @{ bad = 'a signing key id is not valid' } } }
    $ct = "$($Managing.container)".Trim().ToLowerInvariant(); if (-not $ct) { $ct = 'baselines' }
    if ($ct -notmatch '^[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]$') { return @{ bad = 'the container name is not valid' } }
    $mt = "$ManagingTenantId".Trim(); if (-not $mt -and $Managing.PSObject.Properties['tenantId']) { $mt = "$($Managing.tenantId)".Trim() }
    if ($mt -notmatch $script:PimEnrollmentGuid) { $mt = '' }
    return @{ storageAccount = $st; container = $ct; signingKeyIds = $pins; tenantId = $mt.ToLowerInvariant() }
}

function ConvertFrom-PimEnrollmentClaimResponse {
    <#
      PURE. Validate a 200/201 claim answer. Returns
        @{ ok; reason; pending; pollAfterSeconds; environmentHandle; installKey; licenceText; licence = @{ licenceId; fileName;
           validFrom; validUntil }; managing = <ConvertFrom-PimEnrollmentManaging or $null>; uplink; updates }
      pending = $true while Invardia is still signing the licence (status 'signing'): the caller claims again later.
      A 'ready' licence must carry contentBase64 whose SHA-256 equals 'sha256' and that decodes to a signed document.
    #>
    param([AllowNull()][object]$Body)
    $bad = { param($m) @{ ok = $false; reason = "Invardia's enrollment answer is incomplete ($m). Nothing was stored; run the build again, or contact Invardia support." } }
    if (-not $Body) { return (& $bad 'empty') }
    $h = "$($Body.environmentHandle)".Trim()
    if ($h -notmatch '^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$') { return (& $bad 'no environment handle') }
    $ik = "$($Body.installKey)".Trim()
    if ($ik -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') { return (& $bad 'no install key') }
    $l = $Body.licence
    if (-not $l -or -not $l.PSObject.Properties['status']) { return (& $bad 'no licence status') }
    $res = @{ ok = $true; reason = ''; pending = $false; pollAfterSeconds = 0; environmentHandle = $h; installKey = $ik; licenceText = ''
              licence = @{}; managing = $null; uplink = $Body.uplink; updates = $Body.updates }
    $m = ConvertFrom-PimEnrollmentManaging -Managing $Body.managing
    if ($m -and $m.ContainsKey('bad')) { return (& $bad $m.bad) }
    $res.managing = $m
    switch ("$($l.status)".Trim().ToLowerInvariant()) {
        'signing' {
            $res.pending = $true
            $s = 0; if (-not [int]::TryParse("$($l.pollAfterSeconds)", [ref]$s) -or $s -lt 1) { $s = 30 }
            $res.pollAfterSeconds = $s
            return $res
        }
        'ready' {
            $b64 = "$($l.contentBase64)".Trim()
            $want = "$($l.sha256)".Trim().ToLowerInvariant()
            if (-not $b64) { return (& $bad 'no licence content') }
            if ($want -notmatch '^[0-9a-f]{64}$') { return (& $bad 'no licence checksum') }
            $bytes = $null; try { $bytes = [Convert]::FromBase64String($b64) } catch { return (& $bad 'the licence content is not base64') }
            if ((Get-PimEnrollmentSha256Hex -Bytes $bytes) -ne $want) { return @{ ok = $false; reason = 'the licence Invardia returned does not match its checksum (it may have been damaged on the way). Nothing was stored; run the build again.' } }
            $text = ([Text.Encoding]::UTF8.GetString($bytes)).TrimStart([char]0xFEFF).Trim()
            if ($text -notmatch 'payloadB64' -or $text -notmatch 'signature') { return (& $bad 'the licence file is not a signed licence') }
            $res.licenceText = $text
            $res.licence = @{ licenceId = "$($l.licenceId)"; fileName = "$($l.fileName)"; validFrom = "$($l.validFrom)"; validUntil = "$($l.validUntil)" }
            return $res
        }
    }
    return (& $bad "unknown licence status '$($l.status)'")
}

function Invoke-PimEnrollmentHttp {
    <#
      The REAL HTTP seam: @{ status; body; error }. PowerShell 7 and Windows PowerShell 5.1; a non-2xx answer is read from the
      exception (its JSON body parsed for the error code), never thrown. JSON in and out, 30 s timeout. The request BODY is
      never part of an error text.
    #>
    param([string]$Method, [string]$Url, $Body, [hashtable]$Headers)
    $a = @{ Method = $Method; Uri = $Url; Headers = $(if ($Headers) { $Headers } else { @{} }); ContentType = 'application/json'; TimeoutSec = 30; UseBasicParsing = $true }
    if ($null -ne $Body) { $a['Body'] = (ConvertTo-Json -InputObject $Body -Depth 6 -Compress) }
    try {
        $r = Invoke-WebRequest @a -ErrorAction Stop
        $b = $null; if ("$($r.Content)".Trim()) { try { $b = "$($r.Content)" | ConvertFrom-Json } catch { } }
        return @{ status = [int]$r.StatusCode; body = $b }
    } catch {
        $resp = $_.Exception.Response
        $code = 0; if ($resp) { try { $code = [int]$resp.StatusCode } catch { } }
        $b = $null
        try { if ($_.ErrorDetails -and "$($_.ErrorDetails.Message)".Trim()) { $b = "$($_.ErrorDetails.Message)" | ConvertFrom-Json } } catch { $b = $null }
        return @{ status = $code; body = $b; error = $(if ($code) { "HTTP $code" } else { 'no answer' }) }
    }
}

function Invoke-PimEnrollmentClaim {
    <#
      ONE claim, seams injected. Returns @{ ok; status; reason; claim } -- 'claim' is ConvertFrom-PimEnrollmentClaimResponse's
      result (it may be pending). The key goes into the request body and NOWHERE else: no field of the result carries it.
      -Kind Single: a single-tenant install. Refusals use the single-tenant sentences, and an answer that carries a
      'managing' block at all (even one of nulls: an MSP key whose managing tenant has not reported) is REFUSED -- a single
      key answers managing: null. The install key of such an answer is dropped, never returned.
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][string]$EnrollmentKey,
          [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId,
          [ValidateSet('Managed', 'Single')][string]$Kind = 'Managed')
    if (-not (Test-PimEnrollmentKeyFormat -Key $EnrollmentKey)) {
        $from = if ($Kind -eq 'Single') { 'from invardia.com' } else { 'from your managing company' }
        return @{ ok = $false; status = 0; reason = "the enrollment key is not in the expected form (ek- followed by 43 letters, digits, - or _). Copy it again $from."; claim = $null }
    }
    if ("$TenantId".Trim() -notmatch $script:PimEnrollmentGuid -or "$SubscriptionId".Trim() -notmatch $script:PimEnrollmentGuid) {
        return @{ ok = $false; status = 0; reason = 'the tenant id and subscription id must be GUIDs'; claim = $null }
    }
    $base = Resolve-PimEnrollmentBaseUrl -BaseUrl $BaseUrl
    $r = $null
    try { $r = & $Http 'POST' "$base/api/enrollments/claim" (New-PimEnrollmentClaimBody -EnrollmentKey $EnrollmentKey -TenantId $TenantId -SubscriptionId $SubscriptionId) @{} }
    catch { $r = @{ status = 0; body = $null } }
    $st = 0; try { $st = [int]$r.status } catch { $st = 0 }
    if ($st -ne 200 -and $st -ne 201) { return @{ ok = $false; status = $st; reason = (Get-PimEnrollmentRefusalMessage -Status $st -Body $r.body -Kind $Kind); claim = $null } }
    # Owner 2026-10-08 (via Invardia): a key may be claimed again while the tenant's install has NOT succeeded (a fresh install
    # key each time); once it has, Invardia answers installKey: null + alreadyInstalled: true and rotates nothing. Never a key
    # to store -- the caller keeps the install key it already has and goes on without the enrollment where it can.
    if ($r.body -and $r.body.PSObject.Properties['alreadyInstalled'] -and [bool]$r.body.alreadyInstalled -and -not "$($r.body.installKey)".Trim()) {
        $am = $null; if ($Kind -ne 'Single') { $am = ConvertFrom-PimEnrollmentManaging -Managing $r.body.managing; if ($am -and $am.ContainsKey('bad')) { $am = $null } }
        return @{ ok = $false; status = $st; alreadyInstalled = $true; claim = $null; managing = $am; environmentHandle = "$($r.body.environmentHandle)".Trim()
                  reason = $script:PimEnrollmentAlreadyInstalled }
    }
    if ($Kind -eq 'Single' -and $r.body -and $r.body.PSObject.Properties['managing'] -and $null -ne $r.body.managing) {
        return @{ ok = $false; status = $st; reason = $script:PimEnrollmentSingleManaged; claim = $null; managedKey = $true }
    }
    $c = ConvertFrom-PimEnrollmentClaimResponse -Body $r.body
    if (-not $c.ok) { return @{ ok = $false; status = $st; reason = $c.reason; claim = $null } }
    return @{ ok = $true; status = $st; reason = "enrolled as $($c.environmentHandle)"; claim = $c }
}

function Invoke-PimEnrollmentClaimUntilReady {
    <#
      The claim with Invardia's ASYNC licence signing: claims, and while the licence is 'signing' waits pollAfterSeconds
      (clamped 5..120) and claims AGAIN, until 'ready' or -TimeoutSeconds (default 15 min). Every claim issues a NEW install
      key, so the result carries ONLY the last one -- earlier keys are dead the moment the next claim answers and are never
      returned, stored or printed. -Sleep { param($seconds) } and -Progress { param($message) } are seams.
      Returns Invoke-PimEnrollmentClaim's shape plus 'claims' (how many were made).
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][string]$EnrollmentKey,
          [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId,
          [int]$TimeoutSeconds = 900, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Progress = { param($m) },
          [ValidateSet('Managed', 'Single')][string]$Kind = 'Managed')
    $waited = 0; $n = 0
    while ($true) {
        $n++
        $r = Invoke-PimEnrollmentClaim -Http $Http -BaseUrl $BaseUrl -EnrollmentKey $EnrollmentKey -TenantId $TenantId -SubscriptionId $SubscriptionId -Kind $Kind
        $r['claims'] = $n
        if (-not $r.ok -or -not $r.claim.pending) { return $r }
        $wait = [Math]::Min(120, [Math]::Max(5, [int]$r.claim.pollAfterSeconds))
        if ($waited + $wait -gt $TimeoutSeconds) {
            $again = if ($Kind -eq 'Single') { 'Run the installation again in a few minutes with the same enrollment key' } else { 'Run the build again in a few minutes (Invoke-PimMspBuild ... -From enroll)' }
            return @{ ok = $false; status = $r.status; claims = $n; claim = $null
                      reason = "Invardia is still signing this tenant's licence after $([Math]::Round($waited / 60, 1)) minutes. $again; the enrollment itself is kept." }
        }
        & $Progress ("Invardia is signing the licence -- asking again in $wait s (waited $waited s so far)")
        & $Sleep $wait
        $waited += $wait
    }
}

function Add-PimEnrollmentLicenceToRunOrder {
    <#
      PURE. After a claim the environment's previous install key no longer works, so the 'licence' step (which stores the new
      key) must run. -Order is the plan indexes still to run; when 'licence' is not among them it is put FIRST -- after
      'sqlopen' when the order opens a private store's build window -- and the rest keeps its order.
    #>
    param([string[]]$StepIds = @(), [int[]]$Order = @())
    $lic = [array]::IndexOf([string[]]$StepIds, 'licence')
    $o = @($Order)
    if ($lic -lt 0 -or $o -contains $lic) { return $o }
    $open = [array]::IndexOf([string[]]$StepIds, 'sqlopen')
    if ($o.Count -and $open -ge 0 -and $o[0] -eq $open) { return @(@($o[0]) + @($lic) + @($o | Select-Object -Skip 1)) }
    return @(@($lic) + $o)
}

# ---- shared by every install path that takes an enrollment key (MSP managed tenant + single tenant) -------------------

function New-PimEnrollmentRunDirectory {
    <#
      A per-run directory for the claimed licence + install key: only the running account (+ SYSTEM and Administrators on
      Windows) can read it; on Linux (Azure Cloud Shell) mode 700. -Path optional (default: a new folder under the temp
      directory). Returns the path. The caller removes it with Remove-PimEnrollmentRunDirectory when the run ends.
    #>
    param([string]$Path = '')
    if (-not "$Path".Trim()) { $Path = Join-Path ([IO.Path]::GetTempPath()) ('pim-enrol-' + [guid]::NewGuid().ToString('N')) }
    $null = [IO.Directory]::CreateDirectory($Path)
    $onWindows = ("$env:OS" -eq 'Windows_NT')
    if ($onWindows) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        # SIDs, never names (2026-10-10: on a Danish Windows 'BUILTIN\Administrators' / 'NT AUTHORITY\SYSTEM' do not exist --
        # 'Some or all identity references could not be translated' stopped a customer's install): current user, SYSTEM, Administrators.
        foreach ($id in @([System.Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        Set-Acl -Path $Path -AclObject $acl
    } else {
        $done = $false
        try { [IO.File]::SetUnixFileMode($Path, [IO.UnixFileMode]'UserRead, UserWrite, UserExecute'); $done = $true } catch { $done = $false }
        if (-not $done) { & chmod 700 $Path 2>$null }
    }
    return $Path
}

function Save-PimEnrollmentClaimFiles {
    <#
      The claim's licence (decoded, checksum-verified) and its install key as two FILES in -Directory (UTF-8, no BOM), so
      neither is ever a command-line or step argument. Returns @{ licencePath; installKeyPath }. Only the LAST claim's key
      is ever written (every claim issues a new one).
    #>
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][object]$Claim)
    $lic = Join-Path $Directory 'enrolled.pimlicense'; $key = Join-Path $Directory 'enrolled.installkey'
    $enc = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($lic, "$($Claim.licenceText)", $enc)
    [IO.File]::WriteAllText($key, "$($Claim.installKey)", $enc)
    return @{ licencePath = $lic; installKeyPath = $key }
}

function Remove-PimEnrollmentRunDirectory {
    # Overwrite every file in the run directory (a licence-minting install key), then delete it. Never throws.
    param([string]$Path)
    if (-not "$Path".Trim() -or -not (Test-Path -LiteralPath $Path)) { return }
    try {
        foreach ($f in @(Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue)) {
            try { $len = [int]$f.Length; if ($len -gt 0) { [IO.File]::WriteAllBytes($f.FullName, (New-Object byte[] $len)) } } catch { }
        }
    } catch { }
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
}

function Invoke-PimEnrollmentSingleClaim {
    <#
      framework 8.6 "SINGLE-TENANT enrollment too" -- the claim of a SINGLE-tenant install (Invoke-PimDeployAll -EnrollmentKey,
      Install-PimManager's 'enrollmentKey'). Seams injected; the same calls as the managed-tenant build:
        1. claim (product pim-manager, tenantId, subscriptionId) -- -Kind Single: managing must be null, else REFUSED
        2. the async licence: claim again after pollAfterSeconds until 'ready' (bounded), SHA-256 checked, decoded
        3. -Directory given: the licence + the LAST claim's install key written there (Save-PimEnrollmentClaimFiles)
      Returns @{ ok; status; reason; refused (Invardia said no: a 4xx, or a managed key); claims; environmentHandle;
                 licenceText; licence = @{ licenceId; fileName; validFrom; validUntil }; licencePath; installKeyPath }.
      The enrollment key is in NO field of the result, and neither is the install key (it is only in the file).
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][string]$EnrollmentKey,
          [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$SubscriptionId, [string]$Directory = '',
          [int]$TimeoutSeconds = 900, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Progress = { param($m) })
    $r = Invoke-PimEnrollmentClaimUntilReady -Http $Http -BaseUrl $BaseUrl -EnrollmentKey $EnrollmentKey -TenantId $TenantId -SubscriptionId $SubscriptionId `
            -TimeoutSeconds $TimeoutSeconds -Sleep $Sleep -Progress $Progress -Kind Single
    $st = 0; try { $st = [int]$r.status } catch { $st = 0 }
    $out = @{ ok = $false; status = $st; reason = "$($r.reason)"; refused = $false; claims = [int]$r.claims; environmentHandle = ''; licenceText = ''; licence = @{}; licencePath = ''; installKeyPath = '' }
    $out['alreadyInstalled'] = [bool]$r.alreadyInstalled
    if (-not $r.ok) {
        if ($r.alreadyInstalled) { $out.environmentHandle = "$($r.environmentHandle)"; return $out }   # not a refusal: nothing to store, the tenant has its key
        $out.refused = ([bool]$r.managedKey) -or ($st -ge 400 -and $st -lt 500 -and $st -ne 404 -and $st -ne 429)
        return $out
    }
    $c = $r.claim
    $out.ok = $true; $out.environmentHandle = "$($c.environmentHandle)"; $out.licenceText = "$($c.licenceText)"; $out.licence = $c.licence
    $out.reason = "enrolled at Invardia as environment '$($c.environmentHandle)'"
    if ("$Directory".Trim()) {
        $files = Save-PimEnrollmentClaimFiles -Directory $Directory -Claim $c
        $out.licencePath = $files.licencePath; $out.installKeyPath = $files.installKeyPath
    }
    return $out
}

function Get-PimEnrollmentManagingFacts {
    # Managed tenant: GET /api/enrollments/managing with its OWN install key. @{ ok; status; reason; managing }.
    param([Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][string]$InstallKey)
    $base = Resolve-PimEnrollmentBaseUrl -BaseUrl $BaseUrl
    $r = $null
    try { $r = & $Http 'GET' "$base/api/enrollments/managing" $null @{ 'X-Invardia-Install-Key' = "$InstallKey" } } catch { $r = @{ status = 0 } }
    $st = 0; try { $st = [int]$r.status } catch { }
    if ($st -eq 404) { return @{ ok = $false; status = 404; reason = 'Invardia does not have this tenant as enrolled'; managing = $null } }
    if ($st -ne 200) { return @{ ok = $false; status = $st; reason = "Invardia answered HTTP $st"; managing = $null } }
    $m = ConvertFrom-PimEnrollmentManaging -Managing $r.body.managing -ManagingTenantId "$($r.body.managingTenantId)"
    if ($m -and $m.ContainsKey('bad')) { return @{ ok = $false; status = 200; reason = $m.bad; managing = $null } }
    return @{ ok = $true; status = 200; reason = ''; managing = $m }
}

function Merge-PimEnrollmentMaster {
    <#
      PURE. Fill the managed tenant's master{} block from the managing facts. A value the config ALREADY has wins (the operator
      wrote it on purpose) and a difference is returned as a warning. Returns @{ config; filled[]; warnings[] } -- 'config' is a
      COPY (the caller's object is never changed). -Managing $null fills nothing.
    #>
    param([Parameter(Mandatory)][object]$Config, [AllowNull()][hashtable]$Managing)
    $copy = $Config | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    $filled = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    if (-not $Managing) { return @{ config = $copy; filled = @(); warnings = @() } }
    if (-not $copy.PSObject.Properties['master'] -or $null -eq $copy.master) { $copy | Add-Member -NotePropertyName master -NotePropertyValue ([pscustomobject]@{}) -Force }
    $m = $copy.master
    $pairs = @(@{ k = 'storageAccount'; v = "$($Managing.storageAccount)" }, @{ k = 'container'; v = "$($Managing.container)" }, @{ k = 'tenantId'; v = "$($Managing.tenantId)" })
    foreach ($p in $pairs) {
        if (-not "$($p.v)".Trim()) { continue }
        $have = if ($m.PSObject.Properties[$p.k]) { "$($m.$($p.k))".Trim() } else { '' }
        if (-not $have) { $m | Add-Member -NotePropertyName $p.k -NotePropertyValue "$($p.v)" -Force; $filled.Add("master.$($p.k)") }
        elseif ($have -ne "$($p.v)") { $warn.Add("master.$($p.k) in the config ('$have') differs from what the enrollment returned ('$($p.v)') -- the config value is used") }
    }
    $havePins = @(); if ($m.PSObject.Properties['signingKeyIds']) { $havePins = @(@($m.signingKeyIds) | Where-Object { $null -ne $_ -and "$_".Trim() }) }
    if (-not $havePins.Count) { $m | Add-Member -NotePropertyName signingKeyIds -NotePropertyValue @($Managing.signingKeyIds) -Force; $filled.Add('master.signingKeyIds') }
    elseif ((@($havePins | Sort-Object) -join ',') -cne (@(@($Managing.signingKeyIds) | Sort-Object) -join ',')) { $warn.Add('master.signingKeyIds in the config differ from what the enrollment returned -- the config value is used') }
    return @{ config = $copy; filled = @($filled.ToArray()); warnings = @($warn.ToArray()) }
}

function Test-PimEnrollmentMasterComplete {
    # PURE. Does the config carry what the pull needs from the managing tenant (storage account + at least one key id)?
    param([Parameter(Mandatory)][object]$Config)
    $m = $Config.master
    if (-not $m) { return $false }
    $pins = @(@($m.signingKeyIds) | Where-Object { $null -ne $_ -and "$_".Trim() })
    return [bool]("$($m.storageAccount)".Trim() -and $pins.Count)
}

function New-PimEnrollmentFactsBody {
    <#
      PURE. What an environment PUTs to /api/enrollments/facts (its OWN environment; only the fields given change).
        Managing: { product, bundleStorage, container, signingKeyIds[] }
        Managed : { product, pullSubnetIds[] }
      Returns @{ ok; reason; body }. Never carries an enrollment key, an install key, a tenant id or anything credential-shaped.
    #>
    param([Parameter(Mandatory)][ValidateSet('Managing', 'Managed')][string]$Role,
          [string]$BundleStorage = '', [string]$Container = 'baselines', [string[]]$SigningKeyIds = @(), [string[]]$PullSubnetIds = @())
    if ($Role -eq 'Managing') {
        $st = "$BundleStorage".Trim().ToLowerInvariant()
        if ($st -notmatch '^[a-z0-9]{3,24}$') { return @{ ok = $false; reason = 'the bundle storage account is not recorded'; body = $null } }
        $pins = @(@($SigningKeyIds) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Where-Object { $_ -cmatch '^[A-Za-z0-9_-]{43}$' })
        if (-not $pins.Count) { return @{ ok = $false; reason = 'no signing key id is recorded (the signingkey build step pins it on the Manager)'; body = $null } }
        $ct = "$Container".Trim().ToLowerInvariant(); if (-not $ct) { $ct = 'baselines' }
        return @{ ok = $true; reason = ''; body = [ordered]@{ product = $script:PimEnrollmentProduct; bundleStorage = $st; container = $ct; signingKeyIds = @($pins) } }
    }
    $sn = @(@($PullSubnetIds) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if (-not $sn.Count -or @($sn | Where-Object { $_ -notmatch $script:PimEnrollmentSubnet }).Count) { return @{ ok = $false; reason = 'the pull subnet id is not recorded'; body = $null } }
    return @{ ok = $true; reason = ''; body = [ordered]@{ product = $script:PimEnrollmentProduct; pullSubnetIds = @($sn) } }
}

function Send-PimEnrollmentFacts {
    # Seams injected. PUT /api/enrollments/facts with the caller's own install key. @{ ok; status; reason }.
    param([Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][string]$InstallKey, [Parameter(Mandatory)][object]$Body)
    $base = Resolve-PimEnrollmentBaseUrl -BaseUrl $BaseUrl
    $r = $null
    try { $r = & $Http 'PUT' "$base/api/enrollments/facts" $Body @{ 'X-Invardia-Install-Key' = "$InstallKey" } } catch { $r = @{ status = 0 } }
    $st = 0; try { $st = [int]$r.status } catch { }
    if ($st -ge 200 -and $st -lt 300) { return @{ ok = $true; status = $st; reason = 'reported to Invardia' } }
    $why = switch ($st) {
        401 { 'Invardia did not accept this environment''s install key' }
        403 { 'Invardia refused the report for this environment' }
        404 { 'Invardia does not know this environment as enrolled' }
        422 { 'Invardia refused the report as malformed' }
        429 { 'Invardia is rate-limiting; try again later' }
        0   { 'Invardia could not be reached' }
        default { "Invardia answered HTTP $st" } }
    return @{ ok = $false; status = $st; reason = $why }
}

function Invoke-PimEnrollmentFactsPublish {
    <#
      The build's half of the FACTS report, seams injected (tools/setup/Publish-PimEnrollmentFacts.ps1 binds them to the store):
        Master: pim.Settings 'MspBundleFacts' = { role; storageAccount; container; resourceGroup; subscriptionId; access;
                signingKeyIds[]; updatedUtc } (read back), then PUT facts { bundleStorage, container, signingKeyIds }. With no
                install key yet the report is skipped and said so (the daily job repeats it); a report that does not land is a
                warning -- the managing tenant's build does not depend on it.
        Slave : pim.Settings 'MspPullSubnetId' (read back), then PUT facts { pullSubnetIds } with ITS OWN install key -- the
                supported path (Invardia 2026-10-08). A missing key or a refused report FAILS the step (ok = $false): with an
                enrollment nobody else hands the subnet to the managing tenant.
      Returns @{ ok; stored; reported; reason }.
    #>
    param([Parameter(Mandatory)][ValidateSet('Master', 'Slave')][string]$Role, [Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$SetSetting,
          [Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '',
          [string]$StorageAccount = '', [string]$Container = 'baselines', [string]$ResourceGroup = '', [string]$SubscriptionId = '', [string]$Access = 'publicSigned',
          [string[]]$SigningKeyIds = @(), [string]$PullSubnetId = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $res = @{ ok = $false; stored = $false; reported = $false; reason = '' }
    if ($Role -eq 'Master') {
        $fb = New-PimEnrollmentFactsBody -Role Managing -BundleStorage $StorageAccount -Container $Container -SigningKeyIds $SigningKeyIds
        if (-not $fb.ok) { $res.reason = "the bundle facts are incomplete: $($fb.reason)"; return $res }
        $facts = [pscustomobject][ordered]@{ role = 'managing'; storageAccount = $fb.body.bundleStorage; container = $fb.body.container; resourceGroup = "$ResourceGroup".Trim()
                                             subscriptionId = "$SubscriptionId".Trim().ToLowerInvariant(); access = $(if ("$Access".Trim()) { "$Access".Trim() } else { 'publicSigned' })
                                             signingKeyIds = @($fb.body.signingKeyIds); updatedUtc = $NowUtc.ToUniversalTime().ToString('o') }
        try {
            & $SetSetting $script:PimEnrollmentSettingFacts $facts
            $back = & $GetSetting $script:PimEnrollmentSettingFacts
            if ("$($back.storageAccount)" -ne "$($facts.storageAccount)" -or (@($back.signingKeyIds) -join ',') -cne (@($facts.signingKeyIds) -join ',')) { $res.reason = 'read-back mismatch: the bundle facts were not stored'; return $res }
        } catch { $res.reason = "the bundle facts could not be stored: $($_.Exception.Message)"; return $res }
    } else {
        $fb = New-PimEnrollmentFactsBody -Role Managed -PullSubnetIds @($PullSubnetId)
        if (-not $fb.ok) { $res.reason = $fb.reason; return $res }
        try {
            & $SetSetting $script:PimEnrollmentSettingSubnet "$PullSubnetId".Trim()
            if ("$(& $GetSetting $script:PimEnrollmentSettingSubnet)".Trim() -ne "$PullSubnetId".Trim()) { $res.reason = 'read-back mismatch: the pull subnet id was not stored'; return $res }
        } catch { $res.reason = "the pull subnet id could not be stored: $($_.Exception.Message)"; return $res }
    }
    $res.stored = $true
    $key = ''; try { $key = "$(& $GetSetting 'InvardiaInstallKey')".Trim() } catch { $key = '' }
    if ($key -notmatch '^inv-[A-Za-z0-9_-]{20,100}$') {
        if ($Role -eq 'Slave') { $res.reason = 'the pull subnet id is stored, but this environment has no Invardia install key to report it with (the licence step stores it) -- run the build again from the licence step'; return $res }
        $res.ok = $true; $res.reason = 'stored; not reported yet -- this install has no Invardia install key (the enrolled-tenants job reports once it has one)'; return $res
    }
    $rep = Send-PimEnrollmentFacts -Http $Http -BaseUrl $BaseUrl -InstallKey $key -Body $fb.body
    if ($rep.ok) { $res.ok = $true; $res.reported = $true; $res.reason = 'stored and reported to Invardia'; return $res }
    if ($Role -eq 'Slave') { $res.reason = "the pull subnet id is stored, but reporting it to Invardia failed: $($rep.reason). Until it is reported the managing tenant cannot allow this tenant; run the build again from enrollreport"; return $res }
    $res.ok = $true; $res.reason = "stored; the report did not land: $($rep.reason) (the enrolled-tenants job repeats it daily)"
    return $res
}

function Get-PimEnrolledTenants {
    # Seams injected. @{ ok; available; status; reason; tenants = @(@{ tenantId; environmentHandle; subscriptionId; pullSubnetIds[] }) }.
    param([Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][string]$InstallKey)
    $base = Resolve-PimEnrollmentBaseUrl -BaseUrl $BaseUrl
    $r = $null
    try { $r = & $Http 'GET' "$base/api/enrollments/tenants" $null @{ 'X-Invardia-Install-Key' = "$InstallKey" } } catch { $r = @{ status = 0 } }
    $st = 0; try { $st = [int]$r.status } catch { }
    if ($st -eq 404) { return @{ ok = $true; available = $false; status = 404; reason = 'Invardia enrollment not available yet'; tenants = @() } }
    if ($st -ne 200) {
        $why = switch ($st) { 401 { 'Invardia did not accept this environment''s install key' } 403 { 'Invardia refused the list' } 429 { 'Invardia is rate-limiting; retried next run' } 0 { 'Invardia could not be reached' } default { "Invardia answered HTTP $st" } }
        return @{ ok = $false; available = $true; status = $st; reason = $why; tenants = @() }
    }
    $raw = $r.body
    if ($raw -and -not ($raw -is [array]) -and $raw.PSObject.Properties['tenants']) { $raw = $raw.tenants }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($raw)) {
        if ($null -eq $t) { continue }
        $sn = @(@($t.pullSubnetIds) | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() })
        $list.Add(@{ tenantId = "$($t.tenantId)".Trim().ToLowerInvariant(); environmentHandle = "$($t.environmentHandle)".Trim(); subscriptionId = "$($t.subscriptionId)".Trim(); pullSubnetIds = @($sn) })
    }
    return @{ ok = $true; available = $true; status = 200; reason = ''; tenants = @($list.ToArray()) }
}

function Get-PimEnrolledTenantsNetworkPlan {
    <#
      PURE. What the job changes on the bundle store.
        -CurrentSubnetIds : the store's virtual network rules now (read from ARM)
        -Tenants          : Invardia's enrolled tenants (each with pullSubnetIds[])
        -AddedByJob       : the subnet ids THIS JOB added earlier (its own state)
      add    = every enrolled tenant's subnet that the store does not allow yet;
      remove = ONLY a subnet this job added that no enrolled tenant lists any more, and still on the store. A rule the job did
               not add (the build's network-<n> step, a hand rule, the publisher's own subnet) is NEVER removed. When Invardia
               lists no tenant at all, nothing is removed (an empty answer is not trusted to take every tenant's access away).
      Returns @{ add = @(@{ subnetId; tenantId; handle }); remove = @(@{ subnetId }); already[]; waiting[]; invalid[]; held }.
    #>
    param([string[]]$CurrentSubnetIds = @(), [object[]]$Tenants = @(), [string[]]$AddedByJob = @())
    $cur = @{}; foreach ($s in @($CurrentSubnetIds)) { if ("$s".Trim()) { $cur["$s".Trim().ToLowerInvariant()] = $true } }
    $add = New-Object System.Collections.Generic.List[object]
    $already = New-Object System.Collections.Generic.List[object]
    $waiting = New-Object System.Collections.Generic.List[object]
    $invalid = New-Object System.Collections.Generic.List[object]
    $want = @{}
    foreach ($t in @($Tenants)) {
        if ($null -eq $t) { continue }
        $sns = @(@($t.pullSubnetIds) | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() })
        $who = @{ tenantId = "$($t.tenantId)"; handle = "$($t.environmentHandle)" }
        if (-not $sns.Count) { $waiting.Add($who); continue }
        foreach ($sn in $sns) {
            if ($sn -notmatch $script:PimEnrollmentSubnet) { $invalid.Add($who); continue }
            $k = $sn.ToLowerInvariant()
            if ($want.ContainsKey($k)) { continue }
            $want[$k] = $true
            if ($cur.ContainsKey($k)) { $already.Add($who) } else { $add.Add(@{ subnetId = $sn; tenantId = $who.tenantId; handle = $who.handle }) }
        }
    }
    $remove = New-Object System.Collections.Generic.List[object]
    $held = $false
    $own = @(@($AddedByJob) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    foreach ($o in $own) {
        $k = $o.ToLowerInvariant()
        if ($want.ContainsKey($k) -or -not $cur.ContainsKey($k)) { continue }
        if (-not @($Tenants | Where-Object { $null -ne $_ }).Count) { $held = $true; continue }
        $remove.Add(@{ subnetId = $o })
    }
    return @{ add = @($add.ToArray()); remove = @($remove.ToArray()); already = @($already.ToArray()); waiting = @($waiting.ToArray()); invalid = @($invalid.ToArray()); held = $held }
}

function Invoke-PimEnrolledTenantsCycle {
    <#
      The managing tenant's 'enrolled-tenants' run, every seam injected (tests run it offline):
        -GetSetting { param($Name) }  -SetSetting { param($Name, $Value) }      pim.Settings
        -Http { param($Method, $Url, $Body, $Headers) } -> @{ status; body }     Invardia
        -ReadStore { } -> @{ subnetIds = @(...) }                               the bundle store's VNet rules (ARM)
        -WriteStore { param([string[]]$SubnetIds) }                             replace the VNet rule list (ARM PATCH)
        -Audit { param($Action, $Target, $Before, $After) }                     pim.AuditEvents
      Returns @{ ran; ok; available; detail; added[]; removed[] }. THROWS only for a real failure (the run is then red):
      a refused install key, an unreadable store, a write that does not read back.
    #>
    param([Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$SetSetting, [Parameter(Mandatory)][scriptblock]$Http,
          [Parameter(Mandatory)][scriptblock]$ReadStore, [Parameter(Mandatory)][scriptblock]$WriteStore, [scriptblock]$Audit = { param($a, $t, $b, $f) },
          [string]$InstallKey = '', [string]$BaseUrl = '', [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $res = @{ ran = $false; ok = $true; available = $true; detail = ''; added = @(); removed = @() }
    $facts = $null; try { $facts = & $GetSetting $script:PimEnrollmentSettingFacts } catch { $facts = $null }
    if ($facts -is [string]) { try { $facts = $facts | ConvertFrom-Json } catch { $facts = $null } }
    if (-not $facts -or -not "$($facts.storageAccount)".Trim()) { $res.detail = 'enrolled-tenants: this managing tenant''s bundle store is not recorded yet -- re-run its build from the enrollment step'; return $res }
    if (-not "$InstallKey".Trim()) { $res.detail = 'enrolled-tenants: this install has no Invardia install key yet -- nothing reported or read'; return $res }
    $res.ran = $true
    # 1. REPORT this managing tenant's bundle facts (Invardia hands them to every enrolling tenant).
    $fb = New-PimEnrollmentFactsBody -Role Managing -BundleStorage "$($facts.storageAccount)" -Container "$($facts.container)" -SigningKeyIds @($facts.signingKeyIds)
    if (-not $fb.ok) { throw "[enrolled-tenants] the bundle facts cannot be reported: $($fb.reason)" }
    if (-not $WhatIf) {
        $rep = Send-PimEnrollmentFacts -Http $Http -BaseUrl $BaseUrl -InstallKey $InstallKey -Body $fb.body
        if (-not $rep.ok -and $rep.status -eq 404) { $res.available = $false; $res.detail = 'enrolled-tenants: ok -- Invardia enrollment not available yet'; return $res }
        if (-not $rep.ok) { throw "[enrolled-tenants] reporting the bundle facts failed: $($rep.reason)" }
    }
    # 2. READ the enrolled tenants.
    $list = Get-PimEnrolledTenants -Http $Http -BaseUrl $BaseUrl -InstallKey $InstallKey
    if (-not $list.available) { $res.available = $false; $res.detail = 'enrolled-tenants: ok -- Invardia enrollment not available yet'; return $res }
    if (-not $list.ok) { throw "[enrolled-tenants] reading the enrolled tenants failed: $($list.reason)" }
    if ("$($facts.access)".Trim() -eq 'privateEndpoint') {
        $res.detail = "enrolled-tenants: $(@($list.tenants).Count) enrolled tenant(s); the bundle store is reached over a private endpoint and VNet peering -- no network rule to allow (peering is an operator step)"
        return $res
    }
    # 3. ALLOW their subnets on the store -- adds, and only this job's own stale rules removed.
    $state = $null; try { $state = & $GetSetting $script:PimEnrollmentSettingState } catch { $state = $null }
    if ($state -is [string]) { try { $state = $state | ConvertFrom-Json } catch { $state = $null } }
    $own = @(); if ($state -and $state.PSObject.Properties['addedSubnetIds']) { $own = @(@($state.addedSubnetIds) | Where-Object { "$_".Trim() } | ForEach-Object { "$_" }) }
    $before = & $ReadStore
    if (-not $before) { throw '[enrolled-tenants] the bundle store''s network rules could not be read (the job identity needs the bundle store network role -- re-run the managing tenant build from the enrollment step)' }
    $curIds = @(@($before.subnetIds) | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
    $plan = Get-PimEnrolledTenantsNetworkPlan -CurrentSubnetIds $curIds -Tenants @($list.tenants) -AddedByJob $own
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add("$(@($list.tenants).Count) enrolled tenant(s)")
    if (@($plan.add).Count -or @($plan.remove).Count) {
        $removeKeys = @{}; foreach ($x in @($plan.remove)) { $removeKeys["$($x.subnetId)".ToLowerInvariant()] = $true }
        $newList = New-Object System.Collections.Generic.List[string]
        foreach ($c in $curIds) { if (-not $removeKeys.ContainsKey("$c".ToLowerInvariant())) { $newList.Add("$c") } }
        foreach ($a in @($plan.add)) { $newList.Add("$($a.subnetId)") }
        if (-not $WhatIf) {
            & $WriteStore ([string[]]$newList.ToArray())
            $after = & $ReadStore
            $afterKeys = @{}; foreach ($s in @($after.subnetIds)) { if ("$s".Trim()) { $afterKeys["$s".Trim().ToLowerInvariant()] = $true } }
            $miss = @(@($plan.add) | Where-Object { -not $afterKeys.ContainsKey("$($_.subnetId)".ToLowerInvariant()) })
            $left = @(@($plan.remove) | Where-Object { $afterKeys.ContainsKey("$($_.subnetId)".ToLowerInvariant()) })
            if ($miss.Count -or $left.Count) { throw "[enrolled-tenants] read-back FAILED on the bundle store: $($miss.Count) subnet rule(s) missing, $($left.Count) still present" }
            $ownNew = New-Object System.Collections.Generic.List[string]
            foreach ($o in $own) { if (-not $removeKeys.ContainsKey("$o".ToLowerInvariant())) { $ownNew.Add("$o") } }
            foreach ($a in @($plan.add)) { $ownNew.Add("$($a.subnetId)") }
            foreach ($a in @($plan.add)) { try { & $Audit 'msp.tenant.network' "$($a.tenantId)" @{ subnets = $curIds } @{ store = "$($facts.storageAccount)/$($facts.container)"; allowed = "$($a.subnetId)"; environment = "$($a.handle)"; by = 'enrolled-tenants' } } catch { } }
            foreach ($x in @($plan.remove)) { try { & $Audit 'msp.tenant.network' "$($facts.storageAccount)/$($facts.container)" @{ subnets = $curIds } @{ removed = "$($x.subnetId)"; reason = 'no longer enrolled at Invardia'; by = 'enrolled-tenants' } } catch { } }
            & $SetSetting $script:PimEnrollmentSettingState ([pscustomobject][ordered]@{ addedSubnetIds = @($ownNew.ToArray()); lastRunUtc = $NowUtc.ToUniversalTime().ToString('o'); lastAllowed = @(@($plan.add) | ForEach-Object { "$($_.handle) ($($_.tenantId))" }) })
        }
        if (@($plan.add).Count) { $parts.Add("allowed $(@($plan.add).Count) new subnet(s): $(@(@($plan.add) | ForEach-Object { "$($_.handle) ($($_.tenantId))" }) -join ', ')") }
        if (@($plan.remove).Count) { $parts.Add("removed $(@($plan.remove).Count) subnet(s) this job had added for tenants no longer enrolled") }
    } else { $parts.Add('no change on the bundle store') }
    if (@($plan.already).Count) { $parts.Add("$(@($plan.already).Count) already allowed") }
    if (@($plan.waiting).Count) { $parts.Add("$(@($plan.waiting).Count) waiting for their pull subnet id") }
    if (@($plan.invalid).Count) { $parts.Add("$(@($plan.invalid).Count) with a subnet id that is not valid (skipped)") }
    if ($plan.held) { $parts.Add('Invardia listed no tenant, so no rule was removed') }
    $res.added = @($plan.add); $res.removed = @($plan.remove)
    $res.detail = "enrolled-tenants: $(@($parts.ToArray()) -join '; ')$(if ($WhatIf) { ' (what-if: nothing written)' })"
    return $res
}

function Get-PimEnrollmentMspRole {
    # The environment's MSP role from its active scenario: Master | Slave | '' (single tenant / unknown).
    if (-not (Get-Command Get-PimActiveScenario -ErrorAction SilentlyContinue)) {
        $sp = Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\PIM-ScenarioProfile.ps1'
        if (Test-Path -LiteralPath $sp) { . $sp }
    }
    $sc = $null; try { if (Get-Command Get-PimActiveScenario -ErrorAction SilentlyContinue) { $sc = Get-PimActiveScenario } } catch { $sc = $null }
    if (-not $sc) { return '' }
    if ("$($sc.role)" -eq 'msp-master') { return 'Master' }
    if ("$($sc.role)" -eq 'msp-managed') { return 'Slave' }
    return ''
}

function Invoke-PimEnrolledTenantsJob {
    <#
      Job 'enrolled-tenants' (managing tenant only; daily + on demand). The tick's managed identity reads its install key from
      pim.Settings, Invardia's list over HTTPS, and the bundle store's network rules over ARM (the build's 'enrollment' step
      grants it a role on that ONE storage account: read + write of the account, which is where the network rules live).
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $role = Get-PimEnrollmentMspRole
    if ($role -ne 'Master') { return [pscustomobject]@{ ran = $false; whatIf = [bool]$WhatIf; detail = 'enrolled-tenants: not a managing tenant -- nothing to do' } }
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { throw '[enrolled-tenants] no SQL store -- the install key and the bundle facts cannot be read' }
    # PLAIN scriptblocks, never .GetNewClosure() (Test-PimHybridWorker L19): they read $cs / $acctPath through dynamic scope.
    $get = { param($n) Get-PimSqlSetting -ConnectionString $cs -Name $n }
    $set = { param($n, $v) Set-PimSqlSetting -ConnectionString $cs -Name $n -Value $v }
    $facts = $null; try { $facts = & $get $script:PimEnrollmentSettingFacts } catch { $facts = $null }
    $acctPath = if ($facts) { "/subscriptions/$($facts.subscriptionId)/resourceGroups/$($facts.resourceGroup)/providers/Microsoft.Storage/storageAccounts/$($facts.storageAccount)" } else { '' }
    $read = {
        $a = $null; try { $a = Invoke-PimArm -Method GET -Path $acctPath -ApiVersion '2023-01-01' } catch { $a = $null }
        if (-not $a) { return $null }
        $acl = $a.properties.networkAcls
        @{ subnetIds = @(@($acl.virtualNetworkRules) | Where-Object { $_ } | ForEach-Object { "$($_.id)" }); defaultAction = "$($acl.defaultAction)"; acl = $acl }
    }
    $write = {
        param([string[]]$SubnetIds)
        $cur = & $read
        if (-not $cur) { throw '[enrolled-tenants] the bundle store could not be read before the write' }
        $acl = $cur.acl
        $ips = @(@($acl.ipRules) | Where-Object { $_ } | ForEach-Object { @{ value = "$($_.value)"; action = 'Allow' } })
        $body = @{ properties = @{ networkAcls = @{ defaultAction = $(if ("$($acl.defaultAction)".Trim()) { "$($acl.defaultAction)" } else { 'Deny' }); bypass = $(if ("$($acl.bypass)".Trim()) { "$($acl.bypass)" } else { 'AzureServices' })
                                                    ipRules = @($ips); virtualNetworkRules = @(@($SubnetIds) | ForEach-Object { @{ id = "$_"; action = 'Allow' } }) } } }
        [void](Invoke-PimArm -Method PATCH -Path $acctPath -ApiVersion '2023-01-01' -Body $body)
    }
    $audit = { param($a, $t, $b, $f) if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) { Write-PimAuditEvent -Action $a -Target $t -Before $b -After $f -Actor 'job:enrolled-tenants' } }
    $http = { param($m, $u, $b, $h) Invoke-PimEnrollmentHttp -Method $m -Url $u -Body $b -Headers $h }
    $key = ''; if (Get-Command Resolve-PimInvardiaInstallKey -ErrorAction SilentlyContinue) { $key = Resolve-PimInvardiaInstallKey -GetSetting $get } else { $key = "$env:PIM_UPLINK_KEY".Trim() }
    $base = ''; try { $base = "$(& $get 'LicenceRequestBaseUrl')".Trim() } catch { $base = '' }
    $r = Invoke-PimEnrolledTenantsCycle -GetSetting $get -SetSetting $set -Http $http -ReadStore $read -WriteStore $write -Audit $audit `
            -InstallKey $key -BaseUrl $base -NowUtc $NowUtc -WhatIf:$WhatIf
    [pscustomobject]@{ ran = [bool]$r.ran; whatIf = [bool]$WhatIf; detail = "$($r.detail)" }
}
