#Requires -Version 5.1
<#
.SYNOPSIS
  Read the release review thread of a PIM release at Invardia, and reply to it, as PIM's OWN publisher identity.
  Maintainer / release-host script: never run in a customer environment.

.DESCRIPTION
  Framework DOCS/REQUIREMENTS.md 12.11e item 6 (CR3, THE RELEASE REVIEW): one thread per release on Invardia's release record.
  Invardia's support agent (an advisor only) writes its findings there; each product READS the thread and REPLIES with its
  publisher identity. PIM REQUIREMENTS 100.158 (d). Invardia's route (live 2026-10-15, Invardia DESIGN 10):
    GET  <endpoint>/api/releases/<product>/<kind>/<version>/review              -> the thread
    POST <endpoint>/api/releases/<product>/<kind>/<version>/review  { text, inReplyTo? }   (+ replyId? / stance? only when
         passed: -ReplyId / -Stance -- Invardia's optional fields, never invented here)

  Three modes:
    no -Text           READ: sign in, GET the thread, print it (author, time, stance, the message it answers, the text).
                       Read-only; nothing is posted.
    -Text, no -Apply   PLAN (the default, the -WhatIf of this script): the reply is built and checked and the exact JSON is
                       printed with the URL; NOTHING leaves this machine (no sign-in, no read, no post).
    -Text -Apply       SEND: sign in, GET the thread (a -InReplyTo that is not in the thread is refused before posting), POST.
                       2xx done. 4xx refused (Invardia's answer printed, exit 1, no retry). 5xx = "unknown" until read back
                       (framework 12.22 3(c)): the thread is read again -- a message with OUR text = done; otherwise unknown,
                       and the script says so and does NOT post again (a second POST would be a second reply).

  The reply: plain text (control characters other than line breaks removed), at most 4000 characters (refused above, never
  cut: a reply is the product's position and is not shortened silently); -InReplyTo = the id of the message answered.

  Identity: -ClientId + -CertThumbprint, or -KeyVault: invardia-publisher-clientid-pim-manager /
  invardia-publisher-thumbprint-pim-manager are read from that vault over its REST API (no command-line tool, no module),
  as -KeyVaultClientId + -KeyVaultCertThumbprint (a vault reader, certificate; in -KeyVaultTenantId, default -TenantId) or
  else this host's managed identity. The publisher certificate (key not exportable) is in Cert:\LocalMachine\My on the
  publishing machine. Certificate only -- never a secret.

.EXAMPLE
  .\tools\setup\Send-PimInvardiaReleaseReview.ps1 -Version 2.4.650 -TenantId <tenant of the publisher app> -ClientId <id> -CertThumbprint <thumb>   # read the thread
.EXAMPLE
  .\tools\setup\Send-PimInvardiaReleaseReview.ps1 -Version 2.4.650 -TenantId <tenant> -Text 'The guard trips came from one tenant clean-up; no engine fault.' -InReplyTo <message id>          # plan
  .\tools\setup\Send-PimInvardiaReleaseReview.ps1 -Version 2.4.650 -TenantId <tenant> -Text 'The guard trips came from one tenant clean-up; no engine fault.' -InReplyTo <message id> -ClientId <id> -CertThumbprint <thumb> -Apply   # send
#>
[CmdletBinding()]
param(
    [string]$Version = '',
    [Parameter(Mandatory)][string]$TenantId,
    [string]$ClientId = '',
    [string]$CertThumbprint = '',
    [string]$KeyVault = '',
    [string]$KeyVaultClientId = '',
    [string]$KeyVaultCertThumbprint = '',
    [string]$KeyVaultTenantId = '',
    [string]$Endpoint = 'https://invardia.com',
    [string]$Audience = 'api://a5a57537-c847-482b-8878-9a229cbca61b',
    [ValidateSet('pim-manager')][string]$Product = 'pim-manager',
    [ValidateSet('code')][string]$Kind = 'code',
    [string]$Text = '',
    [string]$InReplyTo = '',
    [string]$Stance = '',
    [string]$ReplyId = '',
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
function Step([string]$m) { Write-Host "==> $m" -ForegroundColor Cyan }

function Get-PimReleaseReviewUrl {
    # PURE. <endpoint>/api/releases/<product>/<kind>/<version>/review
    param([Parameter(Mandatory)][string]$Endpoint, [string]$Product = 'pim-manager', [string]$Kind = 'code', [Parameter(Mandatory)][string]$Version)
    return "$($Endpoint.TrimEnd('/'))/api/releases/$Product/$Kind/$Version/review"
}

function New-PimReleaseReviewReplyBody {
    <# PURE. The POST body and what is wrong with it: @{ body = [ordered] or $null; errors = @() }. text required, plain, at most
       4000 (refused above); inReplyTo / replyId an id (letters, digits, . _ : -, at most 100); stance a lower-case word.
       Only what is given is sent. #>
    param([AllowNull()][string]$Text, [AllowNull()][string]$InReplyTo, [AllowNull()][string]$Stance, [AllowNull()][string]$ReplyId)
    $errors = New-Object System.Collections.Generic.List[string]
    $t = ("$Text" -replace "`r`n", "`n" -replace "`r", "`n" -replace '[\x00-\x09\x0B-\x1F\x7F]', ' ').Trim()
    if (-not $t) { [void]$errors.Add('the reply text is empty (pass -Text)') }
    elseif ($t.Length -gt 4000) { [void]$errors.Add("the reply is $($t.Length) characters (at most 4000; it is never cut -- shorten it)") }
    $body = [ordered]@{ text = $t }
    $irt = "$InReplyTo".Trim()
    if ($irt) { if ($irt -notmatch '^[A-Za-z0-9._:-]{1,100}$') { [void]$errors.Add("-InReplyTo '$irt' is not a message id") } else { $body['inReplyTo'] = $irt } }
    $rid = "$ReplyId".Trim()
    if ($rid) { if ($rid -notmatch '^[A-Za-z0-9._:-]{1,100}$') { [void]$errors.Add("-ReplyId '$rid' is not an id") } else { $body['replyId'] = $rid } }
    $sta = "$Stance".Trim()
    if ($sta) { if ($sta -cnotmatch '^[a-z][a-z-]{0,31}$') { [void]$errors.Add("-Stance '$sta' is not a lower-case word") } else { $body['stance'] = $sta } }
    return @{ body = $(if ($errors.Count) { $null } else { $body }); errors = @($errors) }
}

function ConvertFrom-PimReleaseReviewThread {
    <# PURE. Invardia's thread answer (JSON text or object) -> @{ ok; entries = @( @{ id; author; at; stance; inReplyTo; text } ) }.
       The list is read from the root array or from entries / messages / posts / items / thread (also under review); each
       field from its usual names. Not JSON = ok $false. #>
    param([AllowNull()][object]$Content)
    $j = $Content
    if ($j -is [string]) { if (-not "$j".Trim()) { return @{ ok = $true; entries = @() } }; try { $j = $j | ConvertFrom-Json } catch { return @{ ok = $false; entries = @() } } }
    if ($null -eq $j) { return @{ ok = $true; entries = @() } }
    $f = { param($o, [string[]]$names) foreach ($n in $names) { if ($null -ne $o -and $o.PSObject.Properties[$n] -and $null -ne $o.$n -and "$($o.$n)".Trim()) { return $o.$n } }; return $null }
    $list = $null
    if ($j -is [System.Array]) { $list = $j }
    else {
        $holder = $j
        if ($j.PSObject.Properties['review'] -and $j.review -and -not ($j.review -is [string])) { $holder = $j.review }
        foreach ($n in @('entries', 'messages', 'posts', 'items', 'thread')) { if ($holder.PSObject.Properties[$n] -and $null -ne $holder.$n) { $list = @($holder.$n); break } }
        if ($null -eq $list) { $list = @() }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($list | Where-Object { $null -ne $_ })) {
        $who = & $f $e @('author', 'by', 'from', 'role', 'actor')
        if ($who -and -not ($who -is [string])) { $w2 = & $f $who @('name', 'role', 'kind', 'id'); $who = $w2 }
        # PowerShell 7's ConvertFrom-Json makes an ISO time a [datetime]: printed as UTC ISO again, never in the host's format
        $at = & $f $e @('at', 'createdAt', 'createdUtc', 'postedAt', 'time')
        if ($at -is [datetime]) { $at = $at.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture) }
        $out.Add(@{ id = "$(& $f $e @('id', 'messageId', 'replyId'))"; author = "$who"; at = "$at"
                    stance = "$(& $f $e @('stance'))"; inReplyTo = "$(& $f $e @('inReplyTo', 'replyTo', 'parentId'))"; text = "$(& $f $e @('text', 'body', 'message'))" })
    }
    return @{ ok = $true; entries = @($out.ToArray()) }
}

function Format-PimReleaseReviewThread {
    # PURE. The thread as lines for the console: one header line per message, then its text indented.
    param([object[]]$Entries = @())
    $lines = New-Object System.Collections.Generic.List[string]
    if (-not @($Entries).Count) { [void]$lines.Add('    (the thread has no messages yet)'); return @($lines.ToArray()) }
    foreach ($e in @($Entries)) {
        $h = '    [{0}] {1}{2}{3}{4}' -f $(if ($e.id) { $e.id } else { '?' }), $(if ($e.author) { $e.author } else { 'unknown' }), $(if ($e.at) { " at $($e.at)" } else { '' }), $(if ($e.stance) { " -- $($e.stance)" } else { '' }), $(if ($e.inReplyTo) { " (answers $($e.inReplyTo))" } else { '' })
        [void]$lines.Add($h)
        foreach ($tl in @("$($e.text)" -split "\r?\n")) { [void]$lines.Add("        $tl") }
    }
    return @($lines.ToArray())
}

function Invoke-PimInvardiaReviewCall {
    # One HTTP call, PS 5.1 + 7: a non-2xx answer is read from the exception's response. @{ status; content } (status 0 = no answer).
    param([string]$Method, [string]$Url, [string]$Token, $Body = $null, [string]$ContentType = 'application/json; charset=utf-8', [int]$TimeoutSec = 120)
    try {
        $a = @{ Method = $Method; Uri = $Url; Headers = @{ Authorization = "Bearer $Token" }; TimeoutSec = $TimeoutSec; UseBasicParsing = $true }
        if ($null -ne $Body) { $a['Body'] = $Body; $a['ContentType'] = $ContentType }
        $r = Invoke-WebRequest @a
        return @{ status = [int]$r.StatusCode; content = "$($r.Content)" }
    } catch {
        $resp = $_.Exception.Response
        if (-not $resp) { return @{ status = 0; content = "the request failed: $($_.Exception.Message)" } }
        $c = "$($_.ErrorDetails.Message)"; if (-not $c) { $c = "$($_.Exception.Message)" }
        return @{ status = [int]$resp.StatusCode; content = $c }
    }
}

function Read-PimReleaseReviewThread {
    # GET the thread: @{ ok; status; entries; reason }. 404 = no thread for this release (yet); any other non-2xx = not read.
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Token)
    $r = Invoke-PimInvardiaReviewCall -Method GET -Url $Url -Token $Token
    $st = [int]$r.status
    if ($st -ge 200 -and $st -lt 300) {
        $t = ConvertFrom-PimReleaseReviewThread -Content "$($r.content)"
        if (-not $t.ok) { return @{ ok = $false; status = $st; entries = @(); reason = 'the thread answer is not JSON' } }
        return @{ ok = $true; status = $st; entries = @($t.entries); reason = '' }
    }
    if ($st -eq 404) { return @{ ok = $false; status = 404; entries = @(); reason = 'Invardia has no review thread for this release (yet)' } }
    return @{ ok = $false; status = $st; entries = @(); reason = "the thread could not be read (HTTP $st)" }
}

function Send-PimReleaseReviewReply {
    <# The POST and what it means: @{ ok; status; content; verdict = done | refused | not-done | unknown; reason; exitCode }.
       2xx done; 4xx refused (exit 1, no retry); 5xx / no answer: the thread is read back -- a message with our text = done,
       else unknown (never posted again: a second POST would be a second reply). #>
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][string]$Json, [string]$Text = '')
    $r = Invoke-PimInvardiaReviewCall -Method POST -Url $Url -Token $Token -Body ([Text.Encoding]::UTF8.GetBytes($Json))
    $st = [int]$r.status; $c = "$($r.content)"
    if ($st -ge 200 -and $st -lt 300) { return @{ ok = $true; status = $st; content = $c; verdict = 'done'; reason = 'Invardia stored the reply'; exitCode = 0 } }
    if ($st -ge 400 -and $st -lt 500) { return @{ ok = $false; status = $st; content = $c; verdict = 'refused'; reason = "Invardia refused the reply (HTTP $st)"; exitCode = 1 } }
    $rb = Read-PimReleaseReviewThread -Url $Url -Token $Token
    if ($rb.ok -and @($rb.entries | Where-Object { "$($_.text)".Trim() -eq "$Text".Trim() }).Count) {
        return @{ ok = $true; status = $st; content = $c; verdict = 'done'; reason = 'the thread holds the reply (read back) -- the error came after the write'; exitCode = 0 }
    }
    $why = if ($rb.ok) { 'the thread was read back and does not hold the reply' } else { "$($rb.reason)" }
    return @{ ok = $false; status = $st; content = $c; verdict = 'unknown'; reason = "UNKNOWN -- HTTP $st and $why; check the thread before sending it again (a second POST is a second reply)"; exitCode = 1 }
}

function Get-PimKeyVaultSecretValue {
    # One Key Vault secret over REST (no command-line tool, no module); '' when it cannot be read.
    param([Parameter(Mandatory)][string]$Vault, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Token)
    try {
        $u = "https://$Vault.vault.azure.net/secrets/$Name" + '?api-version=7.4'
        $r = Invoke-RestMethod -Method GET -Uri $u -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 60
        return "$($r.value)".Trim()
    } catch { return '' }
}

# ---- main ------------------------------------------------------------------------------------------------------------
$sol = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not "$Version".Trim()) { $Version = (Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw).Trim() }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "not a release version: '$Version'" }
$url = Get-PimReleaseReviewUrl -Endpoint $Endpoint -Product $Product -Kind $Kind -Version $Version
$reading = -not "$Text".Trim()
Step $(if ($reading) { "the release review of $Product $Version (read)" } else { "a reply to the release review of $Product $Version" })

$json = ''
if (-not $reading) {
    $rb0 = New-PimReleaseReviewReplyBody -Text $Text -InReplyTo $InReplyTo -Stance $Stance -ReplyId $ReplyId
    if (@($rb0.errors).Count) {
        foreach ($e in @($rb0.errors)) { Write-Host "    REFUSED: $e" -ForegroundColor Red }
        throw ("the reply to the release review of {0} is not valid ({1}) -- nothing was sent" -f $Version, (@($rb0.errors) -join '; '))
    }
    $json = $rb0.body | ConvertTo-Json -Depth 4 -Compress
    Write-Host "    POST $url"
    Write-Host ($rb0.body | ConvertTo-Json -Depth 4)
    if (-not $Apply) {
        Write-Host ("`nPLAN ONLY -- nothing was sent. With -Apply the JSON above is POSTed to {0} as Invardia.Publisher.{1} (tenant {2})." -f $url, $Product, $TenantId) -ForegroundColor Yellow
        Write-Host ("RESULT: version {0}, reply {1} characters, HTTP none (plan)" -f $Version, "$($rb0.body.text)".Length)
        return [pscustomobject]@{ sent = $false; version = $Version; url = $url; json = $json; status = 0 }
    }
}

Step 'publisher identity (certificate, from Key Vault unless passed)'
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
if (-not $ClientId -or -not $CertThumbprint) {
    # No vault is baked in (the source ships publicly): name it, or pass -ClientId and -CertThumbprint.
    if (-not $KeyVault) { throw 'pass -ClientId and -CertThumbprint, or -KeyVault (with -KeyVaultClientId + -KeyVaultCertThumbprint, or on a host with a managed identity) to read them' }
    $kvTenant = $TenantId
    if ($KeyVaultTenantId) { $kvTenant = $KeyVaultTenantId.Trim() }
    $kvToken = if ($KeyVaultClientId -and $KeyVaultCertThumbprint) { Get-PimRestToken -Resource 'https://vault.azure.net' -TenantId $kvTenant -ClientId $KeyVaultClientId -CertThumbprint $KeyVaultCertThumbprint -Force }
               else { Get-PimRestToken -Resource 'https://vault.azure.net' -TenantId $kvTenant -UseManagedIdentity -Force }
    if (-not "$kvToken".Trim()) { throw "no token for Key Vault $KeyVault" }
    if (-not $ClientId) { $ClientId = Get-PimKeyVaultSecretValue -Vault $KeyVault -Name 'invardia-publisher-clientid-pim-manager' -Token $kvToken }
    if (-not $CertThumbprint) { $CertThumbprint = Get-PimKeyVaultSecretValue -Vault $KeyVault -Name 'invardia-publisher-thumbprint-pim-manager' -Token $kvToken }
}
if ($ClientId -notmatch '^[0-9a-fA-F-]{36}$' -or $CertThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'publisher client id / certificate thumbprint not found (Key Vault or parameters)' }
$token = Get-PimRestToken -Resource $Audience -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -Force
if (-not "$token".Trim()) { throw 'no token for the Invardia Back Office audience' }

Step "GET $url"
$thread = Read-PimReleaseReviewThread -Url $url -Token $token
if ($thread.ok) { foreach ($l in @(Format-PimReleaseReviewThread -Entries @($thread.entries))) { Write-Host $l } }
else { Write-Host "    $($thread.reason)" -ForegroundColor Yellow }
if ($reading) {
    Write-Host ("RESULT: version {0}, {1} message(s), HTTP {2}" -f $Version, @($thread.entries).Count, $thread.status)
    if (-not $thread.ok -and $thread.status -ne 404) { exit 1 }
    return [pscustomobject]@{ sent = $false; version = $Version; url = $url; status = $thread.status; messages = @($thread.entries).Count; entries = @($thread.entries) }
}
$irt0 = "$InReplyTo".Trim()
if ($irt0 -and $thread.ok -and -not @($thread.entries | Where-Object { "$($_.id)" -eq $irt0 }).Count) {
    throw ("the thread of {0} has no message '{1}' -- check -InReplyTo; nothing was sent" -f $Version, $irt0)
}

Step "POST $url"
$res = Send-PimReleaseReviewReply -Url $url -Token $token -Json $json -Text "$($rb0.body.text)"
$c = "$($res.content)"
Write-Host ("    HTTP {0} {1}" -f $res.status, $c.Substring(0, [Math]::Min(800, $c.Length))) -ForegroundColor $(if ($res.ok) { 'Green' } else { 'Red' })
Write-Host ("RESULT: version {0}, HTTP {1} -- {2}" -f $Version, $res.status, $res.reason)
if ($res.exitCode -ne 0) {
    if ($res.verdict -eq 'refused') { Write-Host "    Invardia's answer: $c" -ForegroundColor Red }
    exit 1
}
[pscustomobject]@{ sent = $true; version = $Version; url = $url; status = $res.status; verdict = $res.verdict }
