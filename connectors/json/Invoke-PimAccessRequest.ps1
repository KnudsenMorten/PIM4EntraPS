#Requires -Version 5.1
<#
.SYNOPSIS
    Sample client for the PIM access request API (Pro): ask for an admin account to be enabled, or for ad-hoc membership
    of a permission group, for a number of hours -- then (optionally) wait for the outcome, read a status, or end it early.

.DESCRIPTION
    One REST API serves every caller (ServiceNow, a JSON / webhook system, Power Automate, Logic Apps, a script). This file
    is the reference client: it does exactly what any connector must do, in the order it must do it.

      1. Authenticate -- EITHER an Entra application token (recommended; client credentials with a CERTIFICATE, the
         application allow-listed under PIM Manager > Settings > Access requests > API applications), OR a PIM API key
         (X-Api-Key) issued under the same settings page. Never a client secret.
      2. POST /api/v1/requests with your OWN ticket number. The call is idempotent on the ticket: sending the same ticket
         again returns that request's status instead of creating a second one, so a retry after a timeout is always safe.
      3. GET /api/v1/requests/{id} until the state is final (active, ended, denied, rejected, expired, cancelled).
      4. POST /api/v1/requests/{id}/cancel to end a window early.

    The caller's own workflow is the approval: a request created through the API is approved on arrival (the ticket IS the
    approval), and PIM applies it within a few minutes. The API never reveals anything about accounts the caller did not
    ask about.

.EXAMPLE
    # Entra application token (certificate) -- enable an admin account for 8 hours
    ./Invoke-PimAccessRequest.ps1 -BrokerUrl https://<broker-host> -TenantId <tenant> -ClientId <app id> `
        -CertificateThumbprint <thumb> -Scope 'api://<broker app id>/.default' `
        -UserPrincipalName adm-jane@contoso.com -Hours 8 -Ticket RITM0012345 -Reason 'quarterly patching' -Wait

.EXAMPLE
    # API key -- ad-hoc membership of a permission group for 24 hours
    ./Invoke-PimAccessRequest.ps1 -BrokerUrl https://<broker-host> -ApiKey $env:PIM_API_KEY `
        -UserPrincipalName adm-jane@contoso.com -Type group -GroupName ERP-Admins -Hours 24 -Ticket CHG0042

.EXAMPLE
    ./Invoke-PimAccessRequest.ps1 -BrokerUrl https://<broker-host> -ApiKey $env:PIM_API_KEY -StatusId api-0123456789abcdef
    ./Invoke-PimAccessRequest.ps1 -BrokerUrl https://<broker-host> -ApiKey $env:PIM_API_KEY -CancelId api-0123456789abcdef
#>
[CmdletBinding(DefaultParameterSetName = 'Request')]
param(
    [Parameter(Mandatory)][string]$BrokerUrl,
    # ---- authentication: an Entra application with a certificate, OR an API key ----
    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint,
    [string]$Scope,
    [string]$ApiKey,
    # ---- a new request ----
    [Parameter(ParameterSetName = 'Request', Mandatory)][string]$UserPrincipalName,
    [Parameter(ParameterSetName = 'Request', Mandatory)][ValidateRange(1, 744)][int]$Hours,
    [Parameter(ParameterSetName = 'Request', Mandatory)][ValidateLength(1, 100)][string]$Ticket,
    [Parameter(ParameterSetName = 'Request')][ValidateSet('enable', 'group')][string]$Type = 'enable',
    [Parameter(ParameterSetName = 'Request')][string]$GroupName,
    [Parameter(ParameterSetName = 'Request')][string]$Reason = '',
    [Parameter(ParameterSetName = 'Request')][switch]$Wait,
    [Parameter(ParameterSetName = 'Request')][int]$WaitMinutes = 30,
    # ---- an existing request ----
    [Parameter(ParameterSetName = 'Status', Mandatory)][string]$StatusId,
    [Parameter(ParameterSetName = 'Cancel', Mandatory)][string]$CancelId
)
$ErrorActionPreference = 'Stop'
$base = $BrokerUrl.TrimEnd('/')
if ($base -notmatch '^https://') { throw 'BrokerUrl must start with https://' }
if ($Type -eq 'group' -and -not "$GroupName".Trim()) { throw '-Type group needs -GroupName' }

function ConvertTo-B64Url([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

function Get-PimApiHeaders {
    if ("$ApiKey".Trim()) { return @{ 'X-Api-Key' = $ApiKey.Trim() } }
    foreach ($p in 'TenantId', 'ClientId', 'CertificateThumbprint', 'Scope') {
        if (-not "$((Get-Variable $p -ValueOnly))".Trim()) { throw "Entra sign-in needs -$p (or use -ApiKey)" }
    }
    $cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) { $cert = Get-Item -LiteralPath "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction SilentlyContinue }
    if (-not $cert -or -not $cert.HasPrivateKey) { throw "certificate $CertificateThumbprint (with its private key) not found in CurrentUser\My or LocalMachine\My" }
    # client credentials with a signed assertion (RFC 7523) -- no client secret anywhere
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $now = [DateTimeOffset]::UtcNow
    $h = ConvertTo-B64Url ([Text.Encoding]::UTF8.GetBytes((@{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-B64Url $cert.GetCertHash()) } | ConvertTo-Json -Compress)))
    $c = ConvertTo-B64Url ([Text.Encoding]::UTF8.GetBytes((@{ aud = $tokenUrl; iss = $ClientId; sub = $ClientId; jti = [guid]::NewGuid().ToString(); nbf = $now.ToUnixTimeSeconds(); exp = $now.AddMinutes(10).ToUnixTimeSeconds() } | ConvertTo-Json -Compress)))
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $sig = ConvertTo-B64Url ($rsa.SignData([Text.Encoding]::UTF8.GetBytes("$h.$c"), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1))
    $tok = Invoke-RestMethod -Method POST -Uri $tokenUrl -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body @{
        grant_type = 'client_credentials'; client_id = $ClientId; scope = $Scope
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'; client_assertion = "$h.$c.$sig" }
    return @{ Authorization = "Bearer $($tok.access_token)" }
}

function Invoke-PimApi([string]$Method, [string]$Path, $Body = $null) {
    $a = @{ Method = $Method; Uri = "$base$Path"; Headers = (Get-PimApiHeaders); TimeoutSec = 60 }
    if ($null -ne $Body) { $a.Body = ($Body | ConvertTo-Json -Compress); $a.ContentType = 'application/json' }
    try { return Invoke-RestMethod @a }
    catch {
        $code = $null; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        $msg = "$($_.ErrorDetails.Message)"; try { $m = ($msg | ConvertFrom-Json).error; if ($m) { $msg = $m } } catch { }
        throw "$Method $Path -> HTTP $code : $msg"
    }
}

$final = @('active', 'ended', 'denied', 'rejected', 'expired', 'cancelled')
switch ($PSCmdlet.ParameterSetName) {
    'Status' { return (Invoke-PimApi GET "/api/v1/requests/$([uri]::EscapeDataString($StatusId))") }
    'Cancel' { return (Invoke-PimApi POST "/api/v1/requests/$([uri]::EscapeDataString($CancelId))/cancel") }
}
$body = [ordered]@{ userPrincipalName = $UserPrincipalName; hours = $Hours; type = $Type; ticket = $Ticket; reason = $Reason }
if ($Type -eq 'group') { $body.groupName = $GroupName }
$r = Invoke-PimApi POST '/api/v1/requests' $body
Write-Host "request $($r.id): $($r.state) -- $($r.status)"
if (-not $Wait) { return $r }
$deadline = (Get-Date).AddMinutes($WaitMinutes)
while ((Get-Date) -lt $deadline) {
    if ($final -contains "$($r.state)") { return $r }
    Start-Sleep -Seconds 20
    $r = Invoke-PimApi GET "/api/v1/requests/$([uri]::EscapeDataString($r.id))"
    Write-Host "  $($r.state) -- $($r.status)"
}
Write-Warning "no final state within $WaitMinutes minutes -- the request is still '$($r.state)'; poll it with -StatusId $($r.id)"
return $r
