#Requires -Version 5.1
<#
  §82 P3 + §90 -- the PUBLIC BROKER's pure core (Pro). REQUIREMENTS §82.6, §90.

  The broker (tools/pim-rfa/Start-PimRfaBroker.ps1) is the only public surface: the consultant portal (PIN sign-in,
  request, status), the company contacts' review page, and the REST API /api/v1 for ServiceNow and other systems. It
  holds NO PIM rights: it reads the published eligibility / reviews / API keys from the RFA store and WRITES requests,
  PIN challenges, sessions and answers there. The engine takes everything in and re-decides it.

  Everything here is PURE (no network, no storage) and PS 5.1-safe. Store tables (besides PIM-RfaStore.ps1's):
    RfaPins      PK 'pin'   RK <subject key>   the PIN challenge (salted hash only)
    RfaSessions  PK 'sess'  RK <token hash>    subject, kind (consultant | contact), email, expiresUtc
    RfaRate      PK 'rate'  RK <bucket hash>   hits (JSON list of ISO times)
    RfaApiKeys   PK 'key'   RK <key hash>      id, name, scopes, expiresUtc (published by the engine)
#>

if (-not (Get-Command Get-PimRfaHash -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-Rfa.ps1') }

$script:PimRfaSessionMinutes = 30
$script:PimApiKeyPrefix = 'pimk_'
$script:PimApiScopes = @('requests.write', 'requests.read')

function ConvertTo-PimBase64UrlText {
    param([byte[]]$Bytes)
    return ([Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'))
}

function New-PimRandomBytes {
    param([int]$Count = 32)
    $b = New-Object byte[] $Count
    $r = [System.Security.Cryptography.RandomNumberGenerator]::Create(); try { $r.GetBytes($b) } finally { $r.Dispose() }
    return ,$b
}

function New-PimRfaSessionToken {
    # A browser session token (32 random bytes) and the hash that is stored -- never the token itself.
    param([datetime]$NowUtc = [datetime]::UtcNow)
    $t = ConvertTo-PimBase64UrlText -Bytes (New-PimRandomBytes -Count 32)
    return [pscustomobject]@{ token = $t; hash = (Get-PimRfaHash -Salt 'sess' -Text $t); expiresUtc = $NowUtc.ToUniversalTime().AddMinutes($script:PimRfaSessionMinutes).ToString('o') }
}

function Test-PimRfaSessionRecord {
    # PURE. A stored session row is valid until expiresUtc.
    param([AllowNull()][object]$Record, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Record) { return $false }
    $e = ConvertFrom-PimRfaUtc $Record.expiresUtc
    return [bool]($e -and $e -gt $NowUtc.ToUniversalTime())
}

function Get-PimRfaContactKey {
    # The published key for a company contact's e-mail (salted hash; the broker never holds the contact list in clear).
    param([Parameter(Mandatory)][string]$Salt, [Parameter(Mandatory)][string]$Email)
    return (Get-PimRfaHash -Salt $Salt -Text "$Email".Trim().ToLowerInvariant())
}

function Get-PimRfaPinTarget {
    <#
      PURE. Who gets a PIN for this sign-in name? A consultant signs in with the ADMIN UPN (the PIN goes to the
      ContactEmail on the eligibility row); a company contact signs in with their own e-mail (the PIN goes there, if
      some open review lists that contact). Returns { kind; subject; email } or $null -- and the caller answers the
      SAME sentence either way, so the portal never tells who exists.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Salt, [object[]]$Eligibility = @(), [object[]]$Reviews = @())
    $n = "$Name".Trim().ToLowerInvariant()
    if ($n -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return $null }
    $ak = Get-PimRfaAccountKey -Salt $Salt -UserPrincipalName $n
    $e = @($Eligibility | Where-Object { "$($_.RowKey)" -eq $ak })[0]
    if ($e -and "$($e.contactEmail)".Trim()) { return [pscustomobject]@{ kind = 'consultant'; subject = $ak; email = "$($e.contactEmail)".Trim() } }
    $ck = Get-PimRfaContactKey -Salt $Salt -Email $n
    if (@($Reviews | Where-Object { @("$($_.contactKeys)" -split '\|') -contains $ck }).Count) { return [pscustomobject]@{ kind = 'contact'; subject = $ck; email = $n } }
    return $null
}

function New-PimRfaPortalRequestRow {
    <#
      PURE. A consultant's request as the broker writes it (the ENGINE re-validates everything). -Eligibility is the
      signed-in account's eligibility row. Returns { ok; reason; rowKey; entity }.
    #>
    param([Parameter(Mandatory)][object]$Eligibility, [Parameter(Mandatory)][string]$AccountKey, [int]$Hours, [string]$Reason = '', [datetime]$NowUtc = [datetime]::UtcNow,
          # §91.7: 'group' = AD-HOC membership of one of the groups the eligibility row offers, for one of its groupHours
          [ValidateSet('enable', 'group')][string]$Kind = 'enable', [string]$GroupName = '')
    $r = "$Reason".Trim(); if ($r.Length -gt 500) { $r = $r.Substring(0, 500) }
    if ($Kind -eq 'group') {
        $offered = @(Get-PimRfaOfferedGroups -Eligibility $Eligibility)
        $g = @($offered | Where-Object { $_.tag -ieq "$GroupName".Trim() })[0]
        if (-not $g) { return [pscustomobject]@{ ok = $false; reason = 'that group is not offered to this account' } }
        $gh = @("$($Eligibility.groupHours)" -split '\|' | ForEach-Object { $n = 0; if ([int]::TryParse("$_", [ref]$n)) { $n } })
        if ($gh -notcontains $Hours) { return [pscustomobject]@{ ok = $false; reason = ("choose {0} hours" -f ($gh -join ' / ')) } }
        return [pscustomobject]@{ ok = $true; reason = ''; rowKey = [guid]::NewGuid().ToString('n')
                                  entity = [ordered]@{ state = 'submitted'; source = 'portal'; kind = 'group'; groupName = $g.tag; accountKey = $AccountKey; hours = $Hours; reason = $r; submittedUtc = $NowUtc.ToUniversalTime().ToString('o') } }
    }
    $allowed = @("$($Eligibility.durations)" -split '\|' | ForEach-Object { $n = 0; if ([int]::TryParse("$_", [ref]$n)) { $n } })
    if ($allowed -notcontains $Hours) { return [pscustomobject]@{ ok = $false; reason = ("choose {0} hours" -f ($allowed -join ' / ')) } }
    return [pscustomobject]@{ ok = $true; reason = ''; rowKey = [guid]::NewGuid().ToString('n')
                              entity = [ordered]@{ state = 'submitted'; source = 'portal'; accountKey = $AccountKey; hours = $Hours; reason = $r; submittedUtc = $NowUtc.ToUniversalTime().ToString('o') } }
}
function Get-PimRfaOfferedGroups {
    # PURE. §91.7: the eligibility row's 'groups' ("tag=name|tag=name") -> @( @{ tag; name } ).
    param([AllowNull()][object]$Eligibility)
    if (-not $Eligibility) { return @() }
    $raw = "$(if ($Eligibility.PSObject.Properties['groups']) { $Eligibility.groups })".Trim()
    if (-not $raw) { return @() }
    return @($raw -split '\|' | Where-Object { "$_".Trim() } | ForEach-Object { $p = "$_" -split '=', 2; [pscustomobject]@{ tag = $p[0].Trim(); name = $(if ($p.Count -gt 1 -and $p[1].Trim()) { $p[1].Trim() } else { $p[0].Trim() }) } })
}

function ConvertFrom-PimRfaPrincipalHeader {
    <#
      PURE. Easy Auth's X-MS-CLIENT-PRINCIPAL (base64 JSON { claims:[{typ,val}] }) -> { appId; appOnly; ok; reason }.
      Only an APP-ONLY token (client credentials: idtyp=app, or no user claims) counts as an API caller.
    #>
    param([AllowEmptyString()][string]$Header)
    $no = { param($r) [pscustomobject]@{ ok = $false; appId = ''; appOnly = $false; reason = $r } }
    if (-not "$Header".Trim()) { return (& $no 'no Entra token') }
    try { $doc = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("$Header".Trim())) | ConvertFrom-Json } catch { return (& $no 'the principal header is not readable') }
    $claims = @{}
    foreach ($c in @($doc.claims)) { $k = "$($c.typ)"; if (-not $claims.ContainsKey($k)) { $claims[$k] = "$($c.val)" } }
    $app = "$(if ($claims['appid']) { $claims['appid'] } elseif ($claims['azp']) { $claims['azp'] })".Trim().ToLowerInvariant()
    $isUser = [bool]($claims['scp'] -or $claims['http://schemas.microsoft.com/identity/claims/scope'] -or $claims['preferred_username'] -or $claims['upn'])
    $appOnly = ("$($claims['idtyp'])" -eq 'app') -or -not $isUser
    if (-not $app) { return (& $no 'the token names no application') }
    if (-not $appOnly) { return [pscustomobject]@{ ok = $false; appId = $app; appOnly = $false; reason = 'a user token is not an API caller -- use client credentials (an application token)' } }
    return [pscustomobject]@{ ok = $true; appId = $app; appOnly = $true; reason = '' }
}

function New-PimApiKey {
    # A new API key: shown ONCE; only its hash is ever stored. Returns { key; id; hash; prefix }.
    $k = $script:PimApiKeyPrefix + (ConvertTo-PimBase64UrlText -Bytes (New-PimRandomBytes -Count 32))
    return [pscustomobject]@{ key = $k; id = [guid]::NewGuid().ToString('n').Substring(0, 12); hash = (Get-PimRfaHash -Salt 'apikey' -Text $k); prefix = $k.Substring(0, 9) }
}

function Get-PimApiKeyHash { param([AllowEmptyString()][string]$Key) return (Get-PimRfaHash -Salt 'apikey' -Text "$Key".Trim()) }

function Test-PimApiKeyRecord {
    <# PURE. A published key row (or the Manager's record): not revoked, not expired, carries the scope. #>
    param([AllowNull()][object]$Record, [Parameter(Mandatory)][string]$Scope, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Record) { return [pscustomobject]@{ ok = $false; reason = 'unknown API key' } }
    if ("$($Record.revoked)" -match '^(?i)true|1$') { return [pscustomobject]@{ ok = $false; reason = 'the API key is revoked' } }
    $e = ConvertFrom-PimRfaUtc $Record.expiresUtc
    if (-not $e -or $e -le $NowUtc.ToUniversalTime()) { return [pscustomobject]@{ ok = $false; reason = 'the API key has expired' } }
    $scopes = @("$($Record.scopes)" -split '[|,\s]+' | Where-Object { $_ })
    if ($scopes -notcontains $Scope) { return [pscustomobject]@{ ok = $false; reason = "the API key does not carry '$Scope'" } }
    return [pscustomobject]@{ ok = $true; reason = '' }
}

function New-PimRfaApiRequestRow {
    <#
      PURE. POST /api/v1/requests -> the store row. -Caller = { kind = 'app' | 'key'; id }. Body:
        { userPrincipalName; hours (1..744); type = 'enable' | 'group'; groupName (type group); ticket (required); reason }
      The row key is DETERMINISTIC per caller + ticket + type + account + group, so a retried call lands on the same row
      (idempotent at the broker; the engine is idempotent on the ticket too). Returns { ok; status; reason; rowKey; entity }.
    #>
    param([Parameter(Mandatory)][object]$Body, [Parameter(Mandatory)][object]$Caller, [datetime]$NowUtc = [datetime]::UtcNow)
    $no = { param($s, $r) [pscustomobject]@{ ok = $false; status = $s; reason = $r } }
    $upn = "$($Body.userPrincipalName)".Trim().ToLowerInvariant()
    if ($upn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return (& $no 400 'userPrincipalName is required (the admin account)') }
    $hours = 0; if (-not [int]::TryParse("$($Body.hours)", [ref]$hours) -or $hours -lt 1 -or $hours -gt 744) { return (& $no 400 'hours must be a whole number from 1 to 744') }
    $type = "$(if ("$($Body.type)".Trim()) { $Body.type } else { 'enable' })".Trim().ToLowerInvariant()
    if ($type -notin @('enable', 'group')) { return (& $no 400 "type must be 'enable' or 'group'") }
    $grp = "$($Body.groupName)".Trim()
    if ($type -eq 'group' -and -not $grp) { return (& $no 400 'a group request needs groupName') }
    $ticket = "$($Body.ticket)".Trim()
    if (-not $ticket -or $ticket.Length -gt 100) { return (& $no 400 'ticket is required (your request / ticket number, at most 100 characters) -- it makes a retried call safe') }
    $why = "$($Body.reason)".Trim(); if ($why.Length -gt 500) { $why = $why.Substring(0, 500) }
    $ck = "$($Caller.kind):$($Caller.id)".ToLowerInvariant()
    $rk = 'api-' + (Get-PimRfaHash -Salt '' -Text "$ck|$ticket|$type|$upn|$grp".ToLowerInvariant()).Substring(0, 32)
    $e = [ordered]@{ state = 'submitted'; source = 'api'; upn = $upn; hours = $hours; kind = $type; groupName = $grp; externalRef = $ticket; reason = $why; submittedUtc = $NowUtc.ToUniversalTime().ToString('o') }
    if ($Caller.kind -eq 'app') { $e['callerAppId'] = "$($Caller.id)" } else { $e['callerKeyId'] = "$($Caller.id)" }
    return [pscustomobject]@{ ok = $true; status = 202; reason = ''; rowKey = $rk; entity = $e }
}

function ConvertTo-PimRfaApiStatus {
    # PURE. A store row -> what the API returns (never the internal fields).
    param([Parameter(Mandatory)][object]$Row)
    return [ordered]@{ id = "$($Row.RowKey)"; state = "$($Row.state)"; status = "$($Row.statusText)"; userPrincipalName = "$($Row.upn)"; type = "$(if ($Row.kind) { $Row.kind } else { 'enable' })"
                       groupName = "$($Row.groupName)"; hours = "$($Row.hours)"; ticket = "$($Row.externalRef)"; windowEndUtc = "$($Row.windowEndUtc)"; submittedUtc = "$($Row.submittedUtc)" }
}

function New-PimRfaAnswerRow {
    <#
      PURE. A company contact's answer from the portal. -Review = the published review row (items = JSON list).
      Returns { ok; reason; rowKey; entity }. The ENGINE re-checks the contact against the company (Set-PimCompanyReviewAnswer).
    #>
    param([Parameter(Mandatory)][object]$Review, [Parameter(Mandatory)][string]$Email, [Parameter(Mandatory)][string]$Upn,
          [ValidateSet('working', 'left', 'leave')][string]$Answer, [string]$LeaveUntil = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $items = @(); try { $items = @("$($Review.items)" | ConvertFrom-Json) } catch { $items = @() }
    $u = "$Upn".Trim().ToLowerInvariant()
    if (-not @($items | Where-Object { "$($_.upn)".ToLowerInvariant() -eq $u }).Count) { return [pscustomobject]@{ ok = $false; reason = "$Upn is not on this review" } }
    if ($Answer -eq 'leave') { $d = ConvertFrom-PimRfaUtc $LeaveUntil; if (-not $d -or $d -le $NowUtc.ToUniversalTime()) { return [pscustomobject]@{ ok = $false; reason = 'on leave needs a return date in the future' } } }
    return [pscustomobject]@{ ok = $true; reason = ''; rowKey = [guid]::NewGuid().ToString('n')
                              entity = [ordered]@{ campaignId = "$($Review.RowKey)"; upn = $u; answer = $Answer; leaveUntil = "$LeaveUntil"; by = "$Email".Trim().ToLowerInvariant(); submittedUtc = $NowUtc.ToUniversalTime().ToString('o') } }
}

function Get-PimApiKeyPublishRows {
    # PURE. The Manager's API keys (pim.Settings 'ApiKeys') -> the rows the engine publishes: valid ones only, hash keyed.
    param([object[]]$Keys = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    return @(@($Keys) | Where-Object { $_ -and "$($_.hash)".Trim() -and (Test-PimApiKeyRecord -Record $_ -Scope (@("$($_.scopes)" -split '[|,\s]+' | Where-Object { $_ })[0]) -NowUtc $NowUtc).ok } |
        ForEach-Object { [pscustomobject]@{ hash = "$($_.hash)"; id = "$($_.id)"; name = "$($_.name)"; scopes = "$($_.scopes)"; expiresUtc = (Format-PimRfaValue $_.expiresUtc) } })
}
