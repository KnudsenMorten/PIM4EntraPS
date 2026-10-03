#Requires -Version 5.1
<#
.SYNOPSIS
  §95.2 -- the LICENCE REQUEST CLIENT (job 'licence-request'): PIM asks Invardia for its licence and installs the signed
  file itself. Contract: Invardia's LICENCE-REQUESTS.md (2026-10-04).

.DESCRIPTION
  KNOCK  when no Pro licence is valid for this tenant, or the installed one ends within 30 days:
           POST <base>/api/licence-requests  { product; version; tenantId; installId; edition?; contactEmail?;
                                               currentLicenceId?; currentValidTo? }
           -> 202 { requestId; pullToken; status = Pending|Approved; pollAfterSeconds }
  PULL   on each run, no faster than pollAfterSeconds:
           POST <base>/api/licence-requests/pull   header X-Invardia-Pull-Token
           -> { status = Pending|Rejected|Approved; licence? = { fileName; sha256; contentBase64 } }
  VERIFY offline -- the SHA-256, the signature against the trusted signers, sku Pro, the REAL tenant in tenantIds, the
         dates -- then store it exactly as Set-PimLicense does. Nothing Invardia sends is trusted before that.

  🔒 OFF by default: the feature gate 'licence.autoRequest' must be switched on. It is PIM's first call to invardia.com,
  and the operator confirms it in the PIM session (a decision relayed by another session is not that confirmation).
  🔒 The tenant sent is the REAL one (Resolve-PimLicenseTenantId: the managed identity's own token; an SPN's configured
     tenant), never a value a customer can edit to fetch another tenant's licence.
  The pull token (it only fetches this install's licence; 30 days) is kept in pim.Settings 'LicenceRequestToken', a
  setting no API or page returns. State for the admin: pim.Settings 'LicenceRequestState'.
#>

$script:PimLicenceRequestDefaultBase = 'https://invardia.com'
$script:PimLicenceRenewDays = 30

function Get-PimLicenceRequestDecision {
    <#
      PURE. What the job does this run: @{ action = none|knock|pull; reason }.
        * gate off                                    -> none
        * a request is pending (state Pending + token) -> pull, unless now < nextPollUtc (then none, "waiting")
        * the licence is Pro for this tenant and ends later than 30 days from now -> none
        * otherwise (no licence, not Pro here, expired, grace, or ending within 30 days) -> knock
      A Rejected state never knocks again by itself (Invardia's rule) -- the admin requests again.
    #>
    param([bool]$Enabled, $License, [bool]$ProHere, $State, [bool]$HasToken, [datetime]$NowUtc)
    $NowUtc = $NowUtc.ToUniversalTime()   # .NET compares DateTimes WITHOUT their kind -- everything here is UTC
    if (-not $Enabled) { return @{ action = 'none'; reason = "the licence request client is off (feature 'licence.autoRequest')" } }
    $st = "$($State.status)"
    if ($st -eq 'Pending' -and $HasToken) {
        $next = $null; try { if ("$($State.nextPollUtc)") { $next = ([datetime]"$($State.nextPollUtc)").ToUniversalTime() } } catch { }
        if ($next -and $NowUtc -lt $next) { return @{ action = 'none'; reason = "waiting for Invardia (next check $($next.ToString('u')))" } }
        return @{ action = 'pull'; reason = 'a request is pending at Invardia' }
    }
    $validTo = $null; try { if ($License -and $License.ValidTo) { $validTo = ([datetime]$License.ValidTo).ToUniversalTime() } } catch { }
    if ($ProHere -and "$($License.Status)" -eq 'Valid' -and $validTo -and $validTo -gt $NowUtc.AddDays($script:PimLicenceRenewDays)) {
        return @{ action = 'none'; reason = "the licence is valid until $($validTo.ToString('yyyy-MM-dd'))" }
    }
    # Invardia's contract (2026-10-04): a rejection is shown to the admin and NEVER re-requested automatically -- the
    # admin clears it (Settings > Licence: "request again", which removes LicenceRequestState) after talking to Invardia.
    if ($st -eq 'Rejected') { return @{ action = 'none'; reason = "Invardia rejected the licence request$(if ("$($State.reason)") { ": $($State.reason)" }) -- contact Invardia, then request again" } }
    $why = if (-not $License -or "$($License.Status)" -eq 'Missing') { 'no licence is installed' }
           elseif (-not $ProHere) { 'the installed licence is not a Pro licence for this tenant' }
           else { "the licence ends $($validTo.ToString('yyyy-MM-dd')) (within $($script:PimLicenceRenewDays) days)" }
    return @{ action = 'knock'; reason = $why }
}

function New-PimLicenceKnockBody {
    <# PURE. The knock request body (contract field names). Empty optional fields are left out. #>
    param([Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$InstallId,
          [string]$Edition = '', [string]$ContactEmail = '', [string]$CurrentLicenceId = '', $CurrentValidTo)
    $b = [ordered]@{ product = 'pim-manager'; version = $Version; tenantId = "$TenantId".ToLowerInvariant(); installId = $InstallId }
    if ("$Edition".Trim()) { $b['edition'] = "$Edition".Trim() }
    if ("$ContactEmail".Trim()) { $b['contactEmail'] = "$ContactEmail".Trim() }
    if ("$CurrentLicenceId".Trim()) { $b['currentLicenceId'] = "$CurrentLicenceId".Trim() }
    if ($CurrentValidTo) { try { $b['currentValidTo'] = ([datetime]$CurrentValidTo).ToString('yyyy-MM-dd') } catch { } }
    return $b
}

function Test-PimLicenceDelivery {
    <#
      PURE (given the verifier). Is a delivered licence installable HERE? Returns @{ ok; reason; text }.
      SHA-256 of the decoded bytes must match; the file must verify (Get-PimLicense, the trusted signers); Pro; bound to
      THIS tenant (Test-PimLicenseTenantBinding); not expired. Never trusts Invardia's word for any of it.
    #>
    param([Parameter(Mandatory)]$Delivery, [Parameter(Mandatory)][string]$TenantId, [string]$PublicCertB64 = '')
    try { $bytes = [Convert]::FromBase64String("$($Delivery.contentBase64)") } catch { return @{ ok = $false; reason = 'the delivered licence is not base64' } }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = -join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    if ("$($Delivery.sha256)".Trim().ToLowerInvariant() -ne $h) { return @{ ok = $false; reason = 'the delivered licence does not match its SHA-256 -- refused' } }
    $text = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
    $lic = if ($PublicCertB64) { Get-PimLicense -LicenseText $text -PublicCertB64 $PublicCertB64 } else { Get-PimLicense -LicenseText $text }
    if ("$($lic.Status)" -notin 'Valid', 'Grace') { return @{ ok = $false; reason = "the delivered licence is $($lic.Status): $($lic.Reason)" } }
    if ("$($lic.Sku)" -notmatch '^(?i)pro(-.+)?$') { return @{ ok = $false; reason = "the delivered licence is a '$($lic.Sku)' licence, not Pro" } }
    $bind = Test-PimLicenseTenantBinding -License $lic -TenantId $TenantId
    if (-not $bind.ok) { return @{ ok = $false; reason = "the delivered licence: $($bind.reason)" } }
    return @{ ok = $true; reason = ''; text = $text; licence = $lic }
}

function Invoke-PimLicenceRequestCycle {
    <#
      One run of the job. Seams: -Http { param($Method, $Url, $Body, $Headers) -> @{ status; body } }, -GetSetting / -SetSetting
      (pim.Settings), -StoreLicence { param($Text) } (Set-PimLicense's store path). Returns @{ action; ok; state; message }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Http, [Parameter(Mandatory)][scriptblock]$GetSetting, [Parameter(Mandatory)][scriptblock]$SetSetting,
          [Parameter(Mandatory)][scriptblock]$StoreLicence, [Parameter(Mandatory)][string]$Version, [string]$TenantId = '',
          [bool]$Enabled = $false, [datetime]$NowUtc = [datetime]::UtcNow, [string]$BaseUrl = '', [string]$PublicCertB64 = '')
    $NowUtc = $NowUtc.ToUniversalTime()
    $base = if ("$BaseUrl".Trim()) { "$BaseUrl".TrimEnd('/') } else { $script:PimLicenceRequestDefaultBase }
    $tid = Resolve-PimLicenseTenantId -TenantId $TenantId
    $state = & $GetSetting 'LicenceRequestState'
    $token = "$(& $GetSetting 'LicenceRequestToken')".Trim()
    $lic = if ($PublicCertB64) { $null } else { try { Get-PimLicense -Refresh } catch { $null } }
    if ($PublicCertB64) { $t = & $GetSetting 'License'; if ($t) { $lic = Get-PimLicense -LicenseText "$t" -PublicCertB64 $PublicCertB64 } }
    $proHere = [bool]($lic -and (Test-PimLicenseIsProForTenant -License $lic -TenantId $tid).pro)
    $d = Get-PimLicenceRequestDecision -Enabled $Enabled -License $lic -ProHere $proHere -State $state -HasToken ([bool]$token) -NowUtc $NowUtc
    $save = { param($Status, $Msg, $Extra) $o = [ordered]@{ status = $Status; message = $Msg; updatedUtc = $NowUtc.ToString('o') }
              if ($state) { foreach ($k in 'requestId', 'requestedUtc', 'nextPollUtc') { if ($state.PSObject.Properties[$k] -and -not ($Extra -and $Extra.Contains($k))) { $o[$k] = $state.$k } } }
              if ($Extra) { foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] } }
              & $SetSetting 'LicenceRequestState' ([pscustomobject]$o); [pscustomobject]$o }
    if ($d.action -eq 'none') { return @{ action = 'none'; ok = $true; state = $state; message = $d.reason } }
    if (-not $tid) { return @{ action = $d.action; ok = $false; state = $state; message = "this environment's tenant is not known -- no request is sent" } }

    if ($d.action -eq 'knock') {
        $installId = "$(& $GetSetting 'InstallId')".Trim()
        if (-not $installId) { $installId = [guid]::NewGuid().ToString(); & $SetSetting 'InstallId' $installId }
        $body = New-PimLicenceKnockBody -Version $Version -TenantId $tid -InstallId $installId -CurrentLicenceId "$(if ($lic) { $lic.LicenseId })" -CurrentValidTo $(if ($lic) { $lic.ValidTo })
        $r = $null; try { $r = & $Http 'POST' "$base/api/licence-requests" $body @{} } catch { $r = @{ status = 0; body = $null; error = $_.Exception.Message } }
        if ("$($r.status)" -notin '200', '201', '202' -or -not "$($r.body.pullToken)") {
            $st = & $save 'Error' "the licence request could not be sent ($($r.status) $($r.error))" $null
            return @{ action = 'knock'; ok = $false; state = $st; message = $st.message }
        }
        & $SetSetting 'LicenceRequestToken' "$($r.body.pullToken)"
        $wait = [Math]::Max(60, [int]"0$($r.body.pollAfterSeconds)")
        $st = & $save 'Pending' "licence requested $($NowUtc.ToString('yyyy-MM-dd')), waiting for Invardia" ([ordered]@{ requestId = "$($r.body.requestId)"; requestedUtc = $NowUtc.ToString('o'); nextPollUtc = $NowUtc.AddSeconds($wait).ToString('o') })
        if ("$($r.body.status)" -ne 'Approved') { return @{ action = 'knock'; ok = $true; state = $st; message = $st.message } }
        $token = "$($r.body.pullToken)"   # automatic renewal: Approved on the first knock -> pull at once
    }

    # pull
    # an EMPTY JSON object, not no body: with a JSON content type and no body the endpoint answers 400 (live, 2026-10-04)
    $p = $null; try { $p = & $Http 'POST' "$base/api/licence-requests/pull" ([ordered]@{}) @{ 'X-Invardia-Pull-Token' = $token } } catch { $p = @{ status = 0; error = $_.Exception.Message } }
    if ("$($p.status)" -eq '401' -or "$($p.status)" -eq '410') {
        & $SetSetting 'LicenceRequestToken' ''
        $st = & $save 'Expired' 'the request expired at Invardia -- a new one is sent on the next run' $null
        return @{ action = 'pull'; ok = $false; state = $st; message = $st.message }
    }
    if ("$($p.status)" -notin '200', '202') { $st = & $save 'Pending' "Invardia could not be reached ($($p.status) $($p.error)) -- asked again on the next run" $null; return @{ action = 'pull'; ok = $false; state = $st; message = $st.message } }
    switch ("$($p.body.status)") {
        'Rejected' { & $SetSetting 'LicenceRequestToken' ''; $st = & $save 'Rejected' "Invardia rejected the licence request$(if ("$($p.body.reason)") { ": $($p.body.reason)" }) -- contact Invardia" ([ordered]@{ reason = "$($p.body.reason)" }); return @{ action = 'pull'; ok = $true; state = $st; message = $st.message } }
        'Approved' {
            if (-not $p.body.licence) { $st = & $save 'Pending' 'approved -- the licence is being signed' $null; return @{ action = 'pull'; ok = $true; state = $st; message = $st.message } }
            $v = Test-PimLicenceDelivery -Delivery $p.body.licence -TenantId $tid -PublicCertB64 $PublicCertB64
            if (-not $v.ok) { $st = & $save 'Error' "NOT installed: $($v.reason)" $null; return @{ action = 'pull'; ok = $false; state = $st; message = $st.message } }
            & $StoreLicence $v.text
            & $SetSetting 'LicenceRequestToken' ''
            $st = & $save 'Installed' "installed, valid to $(([datetime]$v.licence.ValidTo).ToString('yyyy-MM-dd'))" ([ordered]@{ nextPollUtc = '' })
            return @{ action = 'pull'; ok = $true; state = $st; message = $st.message }
        }
        default {
            $wait = [Math]::Max(60, [int]"0$($p.body.pollAfterSeconds)")
            $st = & $save 'Pending' "licence requested, waiting for Invardia" ([ordered]@{ nextPollUtc = $NowUtc.AddSeconds($wait).ToString('o') })
            return @{ action = 'pull'; ok = $true; state = $st; message = $st.message }
        }
    }
}

function Invoke-PimLicenceHttp {
    <#
      The real HTTP seam: @{ status; body; error }. Works on PowerShell 7 AND Windows PowerShell 5.1 (a non-2xx answer is
      read from the exception, never thrown). JSON in, JSON out; 30 s timeout; a 429 is just a status (asked next run).
    #>
    param([string]$Method, [string]$Url, $Body, [hashtable]$Headers)
    $a = @{ Method = $Method; Uri = $Url; Headers = $(if ($Headers) { $Headers } else { @{} }); ContentType = 'application/json'; TimeoutSec = 30; UseBasicParsing = $true }
    if ($null -ne $Body) { $a['Body'] = ($Body | ConvertTo-Json -Depth 6 -Compress) }
    try {
        $r = Invoke-WebRequest @a -ErrorAction Stop
        $b = $null; if ("$($r.Content)".Trim()) { try { $b = "$($r.Content)" | ConvertFrom-Json } catch { } }
        return @{ status = [int]$r.StatusCode; body = $b }
    } catch {
        $resp = $_.Exception.Response
        $code = 0; if ($resp) { try { $code = [int]$resp.StatusCode } catch { } }
        return @{ status = $code; body = $null; error = "$($_.Exception.Message)" }
    }
}

function Invoke-PimLicenceRequestJob {
    <#
      Job 'licence-request' (every 30 min -- Invardia's poll interval). Inert unless the feature 'licence.autoRequest' is ON.
      Settings in pim.Settings: LicenceRequestState (shown to the admin), LicenceRequestToken (never returned by any API),
      InstallId, LicenceRequestBaseUrl (optional; default https://invardia.com). A delivered licence is stored only after
      Test-PimLicenceDelivery (SHA-256, signature, Pro, THIS tenant); the edition switches without a restart.
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    $on = [bool]((Get-Command Test-PimFeatureAvailable -ErrorAction SilentlyContinue) -and (Test-PimFeatureAvailable -Key 'licence.autoRequest' -Quiet))
    if (-not $on) { return [pscustomobject]@{ ran = $false; whatIf = [bool]$WhatIf; detail = "licence-request: off (feature 'licence.autoRequest')" } }
    $cs = $null
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = $null } }
    if (-not $cs) { throw '[licence-request] no SQL store -- the licence and the request state cannot be read' }
    # PLAIN scriptblocks, never .GetNewClosure(): a closure gets its own module scope and cannot see the dot-sourced store
    # functions (Get-PimSqlSetting) -- the rule Test-PimHybridWorker L19 enforces. Invoked by Invoke-PimLicenceRequestCycle,
    # called from here, they read $cs / $WhatIf through PowerShell's dynamic scope.
    $get = { param($n) Get-PimSqlSetting -ConnectionString $cs -Name $n }
    $set = { param($n, $v) if (-not $WhatIf) { Set-PimSqlSetting -ConnectionString $cs -Name $n -Value $v } }
    $store = { param($t) if (-not $WhatIf) { Set-PimSqlSetting -ConnectionString $cs -Name 'License' -Value $t; $script:PimLicenseCache = $null } }
    $sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $verFile = Join-Path $sol 'VERSION'
    $ver = if (Test-Path -LiteralPath $verFile) { "$(Get-Content -Raw -LiteralPath $verFile)".Trim() } elseif ($env:PIM_VERSION) { "$env:PIM_VERSION" } else { '0.0.0' }
    $base = "$(& $get 'LicenceRequestBaseUrl')".Trim()
    $r = Invoke-PimLicenceRequestCycle -Http { param($m, $u, $b, $h) Invoke-PimLicenceHttp -Method $m -Url $u -Body $b -Headers $h } -GetSetting $get -SetSetting $set -StoreLicence $store `
            -Version $ver -Enabled $true -NowUtc $NowUtc -BaseUrl $base
    [pscustomobject]@{ ran = ($r.action -ne 'none'); whatIf = [bool]$WhatIf; detail = "licence-request: $($r.action) -- $($r.message)" }
}
