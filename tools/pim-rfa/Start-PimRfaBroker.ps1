#Requires -Version 7.0
<#
.SYNOPSIS
  §82 P3 + §90 -- the PUBLIC RFA BROKER (Pro): the consultant portal, the company contacts' review page and the REST
  API /api/v1. REQUIREMENTS §82.6, §90.

.DESCRIPTION
  The broker is the ONLY public surface of PIM. It holds NO PIM rights -- no SQL, no Graph directory rights, no Key
  Vault. Its managed identity may only (1) read / write its own RFA store (Azure Tables) and (2) send mail as the PIM
  sender mailbox (Exchange-scoped). The internal engine pulls everything from the store and decides; nothing here is
  trusted by the engine.

  Routes (all JSON unless noted):
    GET  /                       the portal page (HTML)
    GET  /health                 200 "ok"
    POST /portal/pin             { name }                 a PIN by mail (the same answer whether or not the name exists)
    POST /portal/verify          { name, pin }            a 30-min session cookie (HttpOnly, Secure, SameSite=Strict)
    GET  /portal/me                                       consultant: eligibility + own requests | contact: reviews
    POST /portal/request         { hours, reason }        consultant: ask to have the account enabled
    POST /portal/cancel          { id }                   consultant: end an own request early
    POST /portal/answer          { campaignId, upn, answer, leaveUntil }   company contact
    POST /portal/signout
    POST /api/v1/requests        { userPrincipalName, hours, type, groupName, ticket, reason }   202 { id, state }
    GET  /api/v1/requests/{id}   the caller's own request
    POST /api/v1/requests/{id}/cancel
    GET  /api/v1/openapi.json    the API description
  API auth: an Entra APPLICATION token (Easy Auth validates it; the app id must be allow-listed) or an API key
  (X-Api-Key; hash-matched against the keys the engine publishes). Portal POSTs need the header X-Rfa: 1 (CSRF).

  Environment: PIM_RFA_STORE (storage account), PIM_RFA_SENDER (the mailbox mail is sent as), PIM_RFA_TENANT_NAME,
  PORT (default 8080).
#>
[CmdletBinding()]
param([switch]$NoListen)

$ErrorActionPreference = 'Stop'
$sol = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $sol 'engine\rfa\PIM-Rfa.ps1')
. (Join-Path $sol 'engine\rfa\PIM-RfaStore.ps1')
. (Join-Path $sol 'engine\rfa\PIM-RfaBroker.ps1')

$script:RfaPageFile = Join-Path $PSScriptRoot 'rfa-portal.html'
$script:RfaMailTemplate = Join-Path $sol 'templates\mail\rfa-notice.mailtemplate.html'

function Read-PimRfaBrokerConfig {
    param([Parameter(Mandatory)][hashtable]$Store)
    $cfg = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaConfig' -PartitionKey 'config')
    $salt = "$(@($cfg | Where-Object { $_.RowKey -eq 'salt' })[0].value)".Trim()
    $apps = @("$(@($cfg | Where-Object { $_.RowKey -eq 'settings' })[0].apiAppIds)" -split ',' | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    return [pscustomobject]@{ salt = $salt; apiAppIds = $apps }
}

function Send-PimRfaBrokerMail {
    # Graph sendMail as the PIM sender mailbox, with the broker's managed identity (Exchange-scoped Mail.Send).
    param([Parameter(Mandatory)][string]$To, [Parameter(Mandatory)][hashtable]$Tokens)
    $sender = "$env:PIM_RFA_SENDER".Trim()
    if (-not $sender) { throw 'PIM_RFA_SENDER is not set -- the broker cannot send mail' }
    $html = [IO.File]::ReadAllText($script:RfaMailTemplate)
    $subject = 'PIM'; if ($html -match '<!--\s*subject:\s*(.+?)\s*-->') { $subject = $Matches[1] }
    foreach ($k in $Tokens.Keys) { $v = [System.Net.WebUtility]::HtmlEncode("$($Tokens[$k])"); if ($k -in @('Detail')) { $v = "$($Tokens[$k])" }; $html = $html.Replace("{{$k}}", $v); $subject = $subject.Replace("{{$k}}", "$($Tokens[$k])") }
    $tok = Get-PimRestToken -Resource 'graph'
    $body = @{ message = @{ subject = $subject; body = @{ contentType = 'HTML'; content = $html }; toRecipients = @(@{ emailAddress = @{ address = $To } }) }; saveToSentItems = $false } | ConvertTo-Json -Depth 8
    Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($sender))/sendMail" -Headers @{ Authorization = "Bearer $tok" } -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body)) | Out-Null
}

function Test-PimRfaBrokerRate {
    # Sliding window per bucket, kept in the store (the broker may run more than one replica).
    param([Parameter(Mandatory)][hashtable]$Store, [Parameter(Mandatory)][string]$Bucket, [int]$Max, [int]$WindowMinutes, [datetime]$NowUtc)
    $rk = Get-PimRfaHash -Salt 'rate' -Text $Bucket
    $row = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaRate' -PartitionKey 'rate' | Where-Object { $_.RowKey -eq $rk })[0]
    $hits = @(); if ($row -and "$($row.hits)".Trim()) { try { $hits = @("$($row.hits)" | ConvertFrom-Json) } catch { $hits = @() } }
    $v = Test-PimRfaRateLimit -Hits $hits -Max $Max -WindowMinutes $WindowMinutes -NowUtc $NowUtc
    if ($v.allowed) { Set-PimRfaStoreEntity -Store $Store -Table 'RfaRate' -PartitionKey 'rate' -RowKey $rk -Entity @{ hits = (@($v.hits) | ConvertTo-Json -Compress) } }
    return $v
}

function Get-PimRfaBrokerSession {
    param([Parameter(Mandatory)][hashtable]$Store, [hashtable]$Headers, [datetime]$NowUtc)
    $c = "$($Headers['Cookie'])"
    if ($c -notmatch '(?:^|;\s*)pimrfa=([A-Za-z0-9_\-]{20,})') { return $null }
    $h = Get-PimRfaHash -Salt 'sess' -Text $Matches[1]
    $row = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaSessions' -PartitionKey 'sess' | Where-Object { $_.RowKey -eq $h })[0]
    if (-not (Test-PimRfaSessionRecord -Record $row -NowUtc $NowUtc)) { return $null }
    return $row
}

function Invoke-PimRfaBrokerRequest {
    <#
      One request -> { status; body (object or string); contentType; headers (hashtable) }. -Mailer = { param($to, $tokens) }
      (tests inject one; the listener passes Send-PimRfaBrokerMail). Never throws: an internal error is a 500 with no detail.
    #>
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Path, [hashtable]$Headers = @{}, [string]$BodyText = '',
          [string]$ClientIp = '', [Parameter(Mandatory)][hashtable]$Store, [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$Mailer)
    $json = { param($s, $o) [pscustomobject]@{ status = $s; body = $o; contentType = 'application/json'; headers = @{} } }
    try {
        $now = $NowUtc.ToUniversalTime()
        $b = $null; if ("$BodyText".Trim()) { try { $b = $BodyText | ConvertFrom-Json } catch { return (& $json 400 @{ error = 'the body is not JSON' }) } }
        # HEAD = GET without a body (load balancers and probes send it; it used to fall through to the store read)
        if ($Method -eq 'HEAD' -and $Path -in @('/', '/index.html', '/health')) { return [pscustomobject]@{ status = 200; body = ''; contentType = 'text/plain'; headers = @{} } }
        if ($Method -eq 'GET' -and $Path -eq '/health') { return [pscustomobject]@{ status = 200; body = 'ok'; contentType = 'text/plain'; headers = @{} } }
        if ($Method -eq 'GET' -and ($Path -eq '/' -or $Path -eq '/index.html')) {
            return [pscustomobject]@{ status = 200; body = [IO.File]::ReadAllText($script:RfaPageFile); contentType = 'text/html; charset=utf-8'; headers = @{} }
        }
        $cfg = Read-PimRfaBrokerConfig -Store $Store
        if (-not $cfg.salt) { return (& $json 503 @{ error = 'the portal is starting up -- try again in a few minutes' }) }

        # ------------------------------ portal ------------------------------
        if ($Path -like '/portal/*') {
            if ($Method -eq 'POST' -and "$($Headers['X-Rfa'])" -ne '1') { return (& $json 403 @{ error = 'missing X-Rfa header' }) }
            if ($Method -eq 'POST' -and $Path -eq '/portal/pin') {
                $ipv = Test-PimRfaBrokerRate -Store $Store -Bucket "pin-ip|$ClientIp" -Max 10 -WindowMinutes 15 -NowUtc $now
                if (-not $ipv.allowed) { return (& $json 429 @{ error = "too many attempts -- try again in $([Math]::Ceiling($ipv.retryAfterSeconds / 60)) min" }) }
                $same = 'If this name can use the portal, a PIN is on its way to the e-mail address we have for it. It is valid for 15 minutes.'
                $name = "$($b.name)".Trim()
                $t = Get-PimRfaPinTarget -Name $name -Salt $cfg.salt -Eligibility @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaEligibility' -PartitionKey 'acct') -Reviews @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaReviews' -PartitionKey 'review')
                if (-not $t) { return (& $json 200 @{ ok = $true; message = $same }) }
                $acv = Test-PimRfaBrokerRate -Store $Store -Bucket "pin-acct|$($t.subject)" -Max 5 -WindowMinutes 15 -NowUtc $now
                if (-not $acv.allowed) { return (& $json 200 @{ ok = $true; message = $same }) }
                $ch = New-PimRfaPinChallenge -AccountKey $t.subject -NowUtc $now
                Set-PimRfaStoreEntity -Store $Store -Table 'RfaPins' -PartitionKey 'pin' -RowKey $t.subject -Entity $ch.record
                if ($Mailer) { & $Mailer $t.email @{ Title = 'Your PIN'; Headline = "Your PIN is $($ch.code)"; Detail = 'Enter it in the access request portal. It is valid for 15 minutes and works once.'; Action = 'If you did not ask for it, ignore this mail -- nobody can use the PIN without your mailbox.'; PortalUrl = ''; TenantName = "$env:PIM_RFA_TENANT_NAME"; WhenUtc = $now.ToString('yyyy-MM-dd HH:mm') + ' UTC' } }
                return (& $json 200 @{ ok = $true; message = $same })
            }
            if ($Method -eq 'POST' -and $Path -eq '/portal/verify') {
                $ipv = Test-PimRfaBrokerRate -Store $Store -Bucket "verify-ip|$ClientIp" -Max 30 -WindowMinutes 15 -NowUtc $now
                if (-not $ipv.allowed) { return (& $json 429 @{ error = 'too many attempts -- try again later' }) }
                $t = Get-PimRfaPinTarget -Name "$($b.name)" -Salt $cfg.salt -Eligibility @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaEligibility' -PartitionKey 'acct') -Reviews @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaReviews' -PartitionKey 'review')
                $bad = 'the PIN is wrong, expired or already used'
                if (-not $t) { return (& $json 401 @{ error = $bad }) }
                $rec = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaPins' -PartitionKey 'pin' | Where-Object { $_.RowKey -eq $t.subject })[0]
                $v = Test-PimRfaPin -Record $rec -Code "$($b.pin)" -NowUtc $now
                if ($v.record) { Set-PimRfaStoreEntity -Store $Store -Table 'RfaPins' -PartitionKey 'pin' -RowKey $t.subject -Entity $v.record }
                if (-not $v.ok) { return (& $json 401 @{ error = $(if ($v.reason -match 'locked') { $v.reason } else { $bad }) }) }
                $s = New-PimRfaSessionToken -NowUtc $now
                Set-PimRfaStoreEntity -Store $Store -Table 'RfaSessions' -PartitionKey 'sess' -RowKey $s.hash -Entity @{ subject = $t.subject; kind = $t.kind; email = $t.email; name = "$($b.name)".Trim().ToLowerInvariant(); expiresUtc = $s.expiresUtc }
                $r = & $json 200 @{ ok = $true; kind = $t.kind }
                $r.headers['Set-Cookie'] = "pimrfa=$($s.token); Path=/; Max-Age=1800; HttpOnly; Secure; SameSite=Strict"
                return $r
            }
            $sess = Get-PimRfaBrokerSession -Store $Store -Headers $Headers -NowUtc $now
            if (-not $sess) { return (& $json 401 @{ error = 'sign in with your PIN first' }) }
            if ($Method -eq 'POST' -and $Path -eq '/portal/signout') {
                Remove-PimRfaStoreEntity -Store $Store -Table 'RfaSessions' -PartitionKey 'sess' -RowKey "$($sess.RowKey)"
                $r = & $json 200 @{ ok = $true }; $r.headers['Set-Cookie'] = 'pimrfa=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict'; return $r
            }
            if ($sess.kind -eq 'consultant') {
                $el = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaEligibility' -PartitionKey 'acct' | Where-Object { $_.RowKey -eq $sess.subject })[0]
                $mine = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaRequests' -PartitionKey 'req' | Where-Object { "$($_.accountKey)" -eq "$($sess.subject)" })
                if ($Method -eq 'GET' -and $Path -eq '/portal/me') {
                    return (& $json 200 ([ordered]@{ kind = 'consultant'; name = "$($sess.name)"; eligible = [bool]$el; mode = "$(if ($el) { $el.mode })"
                        durations = @(if ($el) { "$($el.durations)" -split '\|' | Where-Object { $_ } | ForEach-Object { [int]$_ } })
                        # §91.7: ad-hoc permission groups this account may ask for, and the lengths offered for them
                        groups = @(Get-PimRfaOfferedGroups -Eligibility $el | ForEach-Object { [ordered]@{ tag = $_.tag; name = $_.name } })
                        groupHours = @(if ($el -and $el.PSObject.Properties['groupHours']) { "$($el.groupHours)" -split '\|' | Where-Object { $_ } | ForEach-Object { [int]$_ } })
                        requests = @($mine | Sort-Object { "$($_.submittedUtc)" } -Descending | Select-Object -First 20 | ForEach-Object { [ordered]@{ id = "$($_.RowKey)"; kind = "$(if ($_.kind) { $_.kind } else { 'enable' })"; groupName = "$($_.groupName)"; state = "$($_.state)"; status = "$($_.statusText)"; hours = "$($_.hours)"; submittedUtc = "$($_.submittedUtc)"; windowEndUtc = "$($_.windowEndUtc)" } }) }))
                }
                if ($Method -eq 'POST' -and $Path -eq '/portal/request') {
                    if (-not $el) { return (& $json 403 @{ error = 'this account can no longer use the portal' }) }
                    $kind = if ("$($b.kind)" -eq 'group') { 'group' } else { 'enable' }
                    $gname = "$($b.groupName)".Trim()
                    # one waiting request per THING: the account itself, or each group
                    $same = @($mine | Where-Object { "$($_.state)" -in @('submitted', 'pending-approval', 'approved') -and "$(if ($_.kind) { $_.kind } else { 'enable' })" -eq $kind -and ($kind -ne 'group' -or "$($_.groupName)" -ieq $gname) })
                    if ($same.Count) { return (& $json 409 @{ error = $(if ($kind -eq 'group') { "a request for $gname is already waiting -- see its status below" } else { 'a request is already waiting -- see its status below' }) }) }
                    $hours = 0; [void][int]::TryParse("$($b.hours)", [ref]$hours)
                    $nr = New-PimRfaPortalRequestRow -Eligibility $el -AccountKey $sess.subject -Hours $hours -Reason "$($b.reason)" -NowUtc $now -Kind $kind -GroupName $gname
                    if (-not $nr.ok) { return (& $json 400 @{ error = $nr.reason }) }
                    Set-PimRfaStoreEntity -Store $Store -Table 'RfaRequests' -PartitionKey 'req' -RowKey $nr.rowKey -Entity $nr.entity
                    $msg = if ($kind -eq 'group') { "Sent. Your sponsor department decides within 24 hours; you get a mail. The membership of $gname is removed automatically when the time is up." }
                           elseif ($el.mode -eq 'Auto') { 'Sent. Your account is enabled within a few minutes; you get a mail.' } else { 'Sent. Your sponsor department decides within 24 hours; you get a mail.' }
                    return (& $json 202 @{ ok = $true; id = $nr.rowKey; message = $msg })
                }
                if ($Method -eq 'POST' -and $Path -eq '/portal/cancel') {
                    $row = @($mine | Where-Object { "$($_.RowKey)" -eq "$($b.id)" })[0]
                    if (-not $row) { return (& $json 404 @{ error = 'no such request' }) }
                    $o = [ordered]@{}; foreach ($p in $row.PSObject.Properties) { if ($p.Name -notin @('PartitionKey', 'RowKey', 'Timestamp', 'odata.etag')) { $o[$p.Name] = $p.Value } }
                    $o['state'] = 'cancel-requested'
                    Set-PimRfaStoreEntity -Store $Store -Table 'RfaRequests' -PartitionKey 'req' -RowKey "$($row.RowKey)" -Entity $o
                    return (& $json 202 @{ ok = $true; message = 'Ending -- the account is disabled within a few minutes.' })
                }
            }
            if ($sess.kind -eq 'contact') {
                $revs = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaReviews' -PartitionKey 'review' | Where-Object { @("$($_.contactKeys)" -split '\|') -contains "$($sess.subject)" })
                if ($Method -eq 'GET' -and $Path -eq '/portal/me') {
                    return (& $json 200 ([ordered]@{ kind = 'contact'; name = "$($sess.email)"; reviews = @($revs | ForEach-Object { [ordered]@{ id = "$($_.RowKey)"; company = "$($_.company)"; startedUtc = "$($_.startedUtc)"; items = @("$($_.items)" | ConvertFrom-Json) } }) }))
                }
                if ($Method -eq 'POST' -and $Path -eq '/portal/answer') {
                    $rv = @($revs | Where-Object { "$($_.RowKey)" -eq "$($b.campaignId)" })[0]
                    if (-not $rv) { return (& $json 404 @{ error = 'no such review for you' }) }
                    $a = New-PimRfaAnswerRow -Review $rv -Email "$($sess.email)" -Upn "$($b.upn)" -Answer "$($b.answer)" -LeaveUntil "$($b.leaveUntil)" -NowUtc $now
                    if (-not $a.ok) { return (& $json 400 @{ error = $a.reason }) }
                    Set-PimRfaStoreEntity -Store $Store -Table 'RfaAnswers' -PartitionKey 'ans' -RowKey $a.rowKey -Entity $a.entity
                    return (& $json 202 @{ ok = $true; message = 'Thank you -- recorded.' })
                }
            }
            return (& $json 404 @{ error = 'unknown route' })
        }

        # ------------------------------ API /api/v1 ------------------------------
        if ($Path -like '/api/v1/*') {
            if ($Method -eq 'GET' -and $Path -eq '/api/v1/openapi.json') { return (& $json 200 (Get-PimRfaOpenApi)) }
            $ipv = Test-PimRfaBrokerRate -Store $Store -Bucket "api-ip|$ClientIp" -Max 120 -WindowMinutes 1 -NowUtc $now
            if (-not $ipv.allowed) { $r = & $json 429 @{ error = 'too many requests' }; $r.headers['Retry-After'] = "$($ipv.retryAfterSeconds)"; return $r }
            $caller = $null
            $key = "$($Headers['X-Api-Key'])".Trim()
            $scopeNeeded = if ($Method -eq 'GET') { 'requests.read' } else { 'requests.write' }
            if ($key) {
                $kr = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaApiKeys' -PartitionKey 'key' | Where-Object { $_.RowKey -eq (Get-PimApiKeyHash -Key $key) })[0]
                $kv = Test-PimApiKeyRecord -Record $kr -Scope $scopeNeeded -NowUtc $now
                if (-not $kv.ok) { return (& $json $(if ($kr) { 403 } else { 401 }) @{ error = $kv.reason }) }
                $caller = [pscustomobject]@{ kind = 'key'; id = "$($kr.id)" }
            } else {
                $pr = ConvertFrom-PimRfaPrincipalHeader -Header "$($Headers['X-MS-CLIENT-PRINCIPAL'])"
                if (-not $pr.ok) { return (& $json 401 @{ error = $pr.reason }) }
                if ($cfg.apiAppIds -notcontains $pr.appId) { return (& $json 403 @{ error = 'this application is not allowed to use the API' }) }
                $caller = [pscustomobject]@{ kind = 'app'; id = $pr.appId }
            }
            $own = { param($row) ($caller.kind -eq 'app' -and "$($row.callerAppId)".ToLowerInvariant() -eq $caller.id) -or ($caller.kind -eq 'key' -and "$($row.callerKeyId)" -eq $caller.id) }
            if ($Method -eq 'POST' -and $Path -eq '/api/v1/requests') {
                $nr = New-PimRfaApiRequestRow -Body $b -Caller $caller -NowUtc $now
                if (-not $nr.ok) { return (& $json $nr.status @{ error = $nr.reason }) }
                $have = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaRequests' -PartitionKey 'req' | Where-Object { $_.RowKey -eq $nr.rowKey })[0]
                if ($have) { return (& $json 200 (ConvertTo-PimRfaApiStatus -Row $have)) }   # the same ticket again: its status
                Set-PimRfaStoreEntity -Store $Store -Table 'RfaRequests' -PartitionKey 'req' -RowKey $nr.rowKey -Entity $nr.entity
                return (& $json 202 ([ordered]@{ id = $nr.rowKey; state = 'submitted'; status = 'Accepted -- PIM takes it in within a few minutes. Poll GET /api/v1/requests/{id}.' }))
            }
            if ($Path -match '^/api/v1/requests/([A-Za-z0-9\-]{8,80})(/cancel)?$') {
                $id = $Matches[1]; $isCancel = [bool]$Matches[2]
                $row = @(Get-PimRfaStoreEntities -Store $Store -Table 'RfaRequests' -PartitionKey 'req' | Where-Object { $_.RowKey -eq $id })[0]
                if (-not $row -or -not (& $own $row)) { return (& $json 404 @{ error = 'no such request for this caller' }) }
                if ($Method -eq 'GET' -and -not $isCancel) { return (& $json 200 (ConvertTo-PimRfaApiStatus -Row $row)) }
                if ($Method -eq 'POST' -and $isCancel) {
                    $o = [ordered]@{}; foreach ($p in $row.PSObject.Properties) { if ($p.Name -notin @('PartitionKey', 'RowKey', 'Timestamp', 'odata.etag')) { $o[$p.Name] = $p.Value } }
                    $o['state'] = 'cancel-requested'
                    Set-PimRfaStoreEntity -Store $Store -Table 'RfaRequests' -PartitionKey 'req' -RowKey $id -Entity $o
                    return (& $json 202 @{ id = $id; state = 'cancel-requested' })
                }
            }
            return (& $json 404 @{ error = 'unknown route' })
        }
        return (& $json 404 @{ error = 'unknown route' })
    } catch {
        Write-Warning "[rfa-broker] $Method $Path failed: $($_.Exception.Message)"
        return (& $json 500 @{ error = 'internal error' })
    }
}

function Get-PimRfaOpenApi {
    return [ordered]@{
        openapi = '3.0.3'; info = [ordered]@{ title = 'PIM access request API'; version = '1.0' }
        components = [ordered]@{ securitySchemes = [ordered]@{ entra = [ordered]@{ type = 'oauth2'; flows = [ordered]@{ clientCredentials = [ordered]@{ tokenUrl = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'; scopes = @{} } } }; apiKey = [ordered]@{ type = 'apiKey'; in = 'header'; name = 'X-Api-Key' } } }
        security = @(@{ entra = @() }, @{ apiKey = @() })
        paths = [ordered]@{
            '/api/v1/requests' = [ordered]@{ post = [ordered]@{ summary = 'Request an admin account enabled, or an ad-hoc group membership, for a number of hours (already approved by the caller''s own workflow) -- or propose a standing change (type proposal: requestType + groupTag + requestor, no hours), which PIM queues for an administrator to review'
                requestBody = [ordered]@{ required = $true; content = [ordered]@{ 'application/json' = [ordered]@{ schema = [ordered]@{ type = 'object'; required = @('userPrincipalName', 'ticket')
                    properties = [ordered]@{ userPrincipalName = @{ type = 'string' }; hours = @{ type = 'integer'; minimum = 1; maximum = 744 }; type = @{ type = 'string'; enum = @('enable', 'group', 'proposal') }; groupName = @{ type = 'string' }; requestType = @{ type = 'string'; enum = @('group-add', 'delegation-request', 'group-membership', 'admin-group-assignment') }; groupTag = @{ type = 'string' }; requestor = @{ type = 'string'; maxLength = 200 }; ticket = @{ type = 'string'; maxLength = 100 }; reason = @{ type = 'string'; maxLength = 500 } } } } } }
                responses = [ordered]@{ '202' = @{ description = 'accepted' }; '200' = @{ description = 'the same ticket again: its status' }; '400' = @{ description = 'invalid' }; '401' = @{ description = 'no valid token / key' }; '403' = @{ description = 'not allowed' } } } }
            '/api/v1/requests/{id}' = [ordered]@{ get = [ordered]@{ summary = 'The status of a request this caller made'; responses = [ordered]@{ '200' = @{ description = 'status' }; '404' = @{ description = 'not found for this caller' } } } }
            '/api/v1/requests/{id}/cancel' = [ordered]@{ post = [ordered]@{ summary = 'End the window early'; responses = [ordered]@{ '202' = @{ description = 'ending' } } } }
        }
    }
}

if ($NoListen) { return }

# ------------------------------ the listener ------------------------------
$acct = "$env:PIM_RFA_STORE".Trim()
if (-not $acct) { throw 'PIM_RFA_STORE is not set' }
$store = New-PimRfaStore -Settings ([pscustomobject]@{ storeAccount = $acct })
$port = if ("$env:PORT".Trim()) { [int]$env:PORT } else { 8080 }
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://+:$port/")
$listener.Start()
Write-Host "[rfa-broker] listening on $port (store $acct)" -ForegroundColor Cyan
$mailer = { param($to, $tok) Send-PimRfaBrokerMail -To $to -Tokens $tok }
while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    $req = $ctx.Request; $resp = $ctx.Response
    try {
        $hdr = @{}; foreach ($k in $req.Headers.AllKeys) { $hdr[$k] = $req.Headers[$k] }
        $bodyText = ''; if ($req.HasEntityBody) { $sr = [IO.StreamReader]::new($req.InputStream, [Text.Encoding]::UTF8); try { $bodyText = $sr.ReadToEnd() } finally { $sr.Dispose() } }
        if ($bodyText.Length -gt 16384) { $bodyText = '' }
        $ip = "$(("$($hdr['X-Forwarded-For'])" -split ',')[0])".Trim(); if (-not $ip) { $ip = "$($req.RemoteEndPoint.Address)" }
        $r = Invoke-PimRfaBrokerRequest -Method $req.HttpMethod -Path $req.Url.AbsolutePath -Headers $hdr -BodyText $bodyText -ClientIp $ip -Store $store -Mailer $mailer
        $resp.StatusCode = [int]$r.status
        $resp.ContentType = $r.contentType
        foreach ($k in $r.headers.Keys) { $resp.Headers[$k] = "$($r.headers[$k])" }
        $resp.Headers['X-Content-Type-Options'] = 'nosniff'
        $resp.Headers['Referrer-Policy'] = 'no-referrer'
        $resp.Headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        $resp.Headers['Cache-Control'] = 'no-store'
        $out = if ($r.body -is [string]) { $r.body } else { $r.body | ConvertTo-Json -Depth 8 -Compress }
        $bytes = [Text.Encoding]::UTF8.GetBytes($out)
        $resp.OutputStream.Write($bytes, 0, $bytes.Length)
    } catch { try { $resp.StatusCode = 500 } catch { } }
    finally { try { $resp.Close() } catch { } }
}
