#Requires -Version 5.1
<#
.SYNOPSIS
    Example client for the PIM Manager API as an APPLICATION (scripts and services). Self-contained: REST and .NET only,
    no PowerShell module, no Azure CLI, no secret.

.DESCRIPTION
    SETTINGS-API-1 (framework 12.31). Gets an app-only token from Microsoft Entra ID and calls https://<manager>/api/app/<route>
    -- the same routes the PIM Manager page uses, under /api/app/.

    The token, one of:
      * a CERTIFICATE in the local certificate store (CurrentUser\My, else LocalMachine\My): the client-credentials grant with
        a client assertion (a JWT signed with the certificate's private key). -TenantId, -ClientId, -CertificateThumbprint.
      * a MANAGED IDENTITY when it runs in Azure (App Service / Container Apps / Functions: IDENTITY_ENDPOINT, else the VM
        instance metadata endpoint). -ManagedIdentity (+ -ManagedIdentityClientId for a user-assigned identity).
    The scope is api://<API application id>/.default (-ApiAppId: the Manager's application id).

    What the application may do is decided in PIM Manager (Settings > API applications): Reader reads; Admin also changes
    settings and commits settings-type changes through the same checks as a person (a change that weakens a protection waits
    for a SuperAdmin) and PROPOSES changes to admins and their roles, which a person approves. Security settings stay with people.

    ONE-TIME BASELINE (owner 2026-11-16 "it is onetime" / "i set once"): -ChangesFile <json> -EnvironmentsFile <json> applies N
    changes (settings AND permission packs) to every environment listed -- a PREVIEW first (nothing is sent but reads), then the
    same command with -Apply, and a per-change result table (applied / held for a SuperAdmin / refused / failed).
      ChangesFile:      { "changes": [
                            { "name": "Engine at 02:00", "method": "PUT", "route": "/job-schedule", "body": { ... } },
                            { "name": "Audit 24 months", "method": "PUT", "route": "/settings/audit-retention", "body": { "months": 24 } },
                            { "name": "Enable a pack", "templatePack": "<pack id>", "enable": true } ] }
      EnvironmentsFile: [ { "name": "Contoso prod", "managerUrl": "https://pim.contoso.example", "apiAppId": "<id>",
                            "tenantId": "<id>", "clientId": "<id>", "certificateThumbprint": "<thumbprint>" } ]   (no secrets)
      -Environment <names>: only these environments of the file.

    Examples (-Example):
      ExportSettings   GET  /api/app/settings/export                    -> every setting as ONE JSON (secret values withheld)
      SetJobSchedule   GET + PUT /api/app/job-schedule                   -> reads the schedule and saves it back (edit -Body to change it)
      StageAndCommit   GET  /api/app/csv/PIM-Definitions-AU              -> PUT /api/app/csv/<entity> (commit, with the rowsHash it read;
                                                                            staging first in Pending changes is optional: PUT /api/app/pending/<entity>)
      ProposeChange    GET  /api/app/csv/<entity> -> POST /api/app/approvals/app-submit/<entity>   -> a person approves it

    Or any single call: -Method GET|PUT|POST|DELETE -Route '/settings/export' [-Body <object or JSON text>].

.EXAMPLE
    .\Invoke-PimManagerApi.ps1 -ManagerUrl https://pim.contoso.example -TenantId <tenant id> -ClientId <app id> `
        -CertificateThumbprint <thumbprint> -ApiAppId <Manager application id> -Example ExportSettings -OutFile .\settings.json
.EXAMPLE
    .\Invoke-PimManagerApi.ps1 -ChangesFile .\baseline.json -EnvironmentsFile .\environments.json            # preview
    .\Invoke-PimManagerApi.ps1 -ChangesFile .\baseline.json -EnvironmentsFile .\environments.json -Apply     # apply once
#>
[CmdletBinding()]
param(
    [string]$ManagerUrl = '',
    [string]$ApiAppId = '',
    [string]$TenantId = '',
    [string]$ClientId = '',
    [string]$CertificateThumbprint = '',
    [switch]$ManagedIdentity,
    [string]$ManagedIdentityClientId = '',
    [ValidateSet('', 'ExportSettings', 'SetJobSchedule', 'StageAndCommit', 'ProposeChange')][string]$Example = '',
    [ValidateSet('GET', 'PUT', 'POST', 'DELETE')][string]$Method = 'GET',
    [string]$Route = '',
    [object]$Body = $null,
    [string]$Entity = 'PIM-Definitions-AU',
    [string]$OutFile = '',
    # one-time baseline (multi-change mode)
    [string]$ChangesFile = '',
    [string]$EnvironmentsFile = '',
    [string[]]$Environment = @(),
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

function ConvertTo-B64Url([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

function Get-AppToken {
    param([string]$Api, [string]$Tenant, [string]$Client, [string]$Thumb, [bool]$UseMi, [string]$MiClient)
    $scope = "api://$Api/.default"
    if ($UseMi) {
        $resource = "api://$Api"
        if ("$env:IDENTITY_ENDPOINT".Trim() -and "$env:IDENTITY_HEADER".Trim()) {
            $u = "$($env:IDENTITY_ENDPOINT)?api-version=2019-08-01&resource=$([uri]::EscapeDataString($resource))"
            if ($MiClient) { $u += "&client_id=$([uri]::EscapeDataString($MiClient))" }
            return (Invoke-RestMethod -Method GET -Uri $u -Headers @{ 'X-IDENTITY-HEADER' = "$env:IDENTITY_HEADER" }).access_token
        }
        $u = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$([uri]::EscapeDataString($resource))"
        if ($MiClient) { $u += "&client_id=$([uri]::EscapeDataString($MiClient))" }
        return (Invoke-RestMethod -Method GET -Uri $u -Headers @{ Metadata = 'true' }).access_token
    }
    if (-not $Tenant -or -not $Client -or -not $Thumb) { throw 'give the tenant id, client id and certificate thumbprint (or use a managed identity)' }
    $cert = $null
    foreach ($store in 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My') { $p = Join-Path $store $Thumb; if (Test-Path -LiteralPath $p) { $cert = Get-Item -LiteralPath $p; break } }
    if (-not $cert) { throw "certificate $Thumb is not in CurrentUser\My or LocalMachine\My" }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $rsa) { throw 'the certificate has no usable RSA private key' }
    $tokenUrl = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token"
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $hdr = @{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-B64Url $cert.GetCertHash()) } | ConvertTo-Json -Compress
    $pl = @{ aud = $tokenUrl; iss = $Client; sub = $Client; jti = [guid]::NewGuid().ToString(); nbf = $now; exp = $now + 300 } | ConvertTo-Json -Compress
    $unsigned = (ConvertTo-B64Url ([Text.Encoding]::UTF8.GetBytes($hdr))) + '.' + (ConvertTo-B64Url ([Text.Encoding]::UTF8.GetBytes($pl)))
    $sig = $rsa.SignData([Text.Encoding]::ASCII.GetBytes($unsigned), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $form = @{ grant_type = 'client_credentials'; client_id = $Client; scope = $scope
               client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'; client_assertion = ($unsigned + '.' + (ConvertTo-B64Url $sig)) }
    return (Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $form -ContentType 'application/x-www-form-urlencoded').access_token
}

function Invoke-PimApp {
    # one call; -Raw returns @{ status; body } instead of throwing on a refusal (the multi-change result table)
    param([string]$Url, [string]$Token, [string]$M, [string]$R, $B = $null, [switch]$Raw)
    $r = "$R".Trim(); if ($r -like '/api/app/*') { $r = $r.Substring(8) } elseif ($r -like '/api/*') { $r = $r.Substring(4) }
    if (-not $r.StartsWith('/')) { $r = '/' + $r }
    $uri = $Url.TrimEnd('/') + '/api/app' + $r
    $args2 = @{ Method = $M; Uri = $uri; Headers = @{ Authorization = "Bearer $Token" } }
    if ($null -ne $B) { $args2['ContentType'] = 'application/json'; $args2['Body'] = $(if ($B -is [string]) { $B } else { ConvertTo-Json -InputObject $B -Depth 30 -Compress }) }
    try { $res = Invoke-RestMethod @args2; if ($Raw) { return @{ status = 200; body = $res } }; return $res }
    catch {
        $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        $msg = "$($_.Exception.Message)"; $det = ''; try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $det = "$($_.ErrorDetails.Message)" } } catch { }
        if ($Raw) { $bd = $null; try { $bd = $det | ConvertFrom-Json } catch { $bd = $det }; return @{ status = $code; body = $bd } }
        throw "$M $uri failed: $msg$(if ($det) { " -- $det" })"
    }
}

function ConvertTo-PimChangeCall {
    # one change of the file -> @{ name; method; route; body }. A template pack: PUT /template-state { id; disabled = -not enable }.
    param($C)
    if ($C.PSObject.Properties['templatePack'] -and "$($C.templatePack)".Trim()) {
        $en = $true; if ($C.PSObject.Properties['enable']) { $en = [bool]$C.enable }
        return @{ name = $(if ($C.name) { "$($C.name)" } else { "pack $($C.templatePack) $(if ($en) { 'on' } else { 'off' })" }); method = 'PUT'; route = '/template-state'; body = [ordered]@{ id = "$($C.templatePack)"; disabled = (-not $en) } }
    }
    if (-not "$($C.route)".Trim()) { throw "a change has no route: $($C | ConvertTo-Json -Compress -Depth 5)" }
    return @{ name = $(if ($C.name) { "$($C.name)" } else { "$($C.method) $($C.route)" }); method = $(if ($C.method) { "$($C.method)".ToUpperInvariant() } else { 'PUT' }); route = "$($C.route)"; body = $C.body }
}

# ---- one-time baseline: N changes x the environments, preview first, then -Apply -----------------------------------------
if ($ChangesFile) {
    if (-not $EnvironmentsFile) { throw 'give -EnvironmentsFile (the environments to set)' }
    $changes = @((Get-Content -LiteralPath $ChangesFile -Raw | ConvertFrom-Json).changes | ForEach-Object { ConvertTo-PimChangeCall $_ })
    $envs = @(Get-Content -LiteralPath $EnvironmentsFile -Raw | ConvertFrom-Json)
    if ($Environment.Count) { $envs = @($envs | Where-Object { "$($_.name)" -in $Environment }) }
    if (-not $changes.Count -or -not $envs.Count) { throw 'nothing to do: no change or no environment' }
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($en in $envs) {
        $tok = $null
        try { $tok = Get-AppToken -Api "$($en.apiAppId)" -Tenant "$($en.tenantId)" -Client "$($en.clientId)" -Thumb "$($en.certificateThumbprint)" -UseMi ([bool]$en.managedIdentity) -MiClient "$($en.managedIdentityClientId)" }
        catch { foreach ($c in $changes) { $results.Add([pscustomobject]@{ Environment = "$($en.name)"; Change = $c.name; Result = 'failed'; Detail = "no token: $($_.Exception.Message)" }) }; continue }
        foreach ($c in $changes) {
            if (-not $Apply) {
                $cur = 'n/a'
                if ($c.method -eq 'PUT') { $g = Invoke-PimApp -Url "$($en.managerUrl)" -Token $tok -M 'GET' -R $c.route -Raw; if ($g.status -eq 200) { $cur = (ConvertTo-Json -InputObject $g.body -Compress -Depth 6) } }
                if ($cur.Length -gt 120) { $cur = $cur.Substring(0, 117) + '...' }
                $results.Add([pscustomobject]@{ Environment = "$($en.name)"; Change = $c.name; Result = 'preview'; Detail = "now: $cur  ->  $($c.method) $($c.route) $(ConvertTo-Json -InputObject $c.body -Compress -Depth 6)" })
                continue
            }
            $r = Invoke-PimApp -Url "$($en.managerUrl)" -Token $tok -M $c.method -R $c.route -B $c.body -Raw
            $res = switch ([int]$r.status) { 200 { 'applied' } 202 { 'queued' } 409 { if ("$($r.body.gate)" -eq 'weakening-held') { 'held for a SuperAdmin' } else { 'held / conflict' } } 403 { 'refused (person only or not allowed)' } default { "failed ($($r.status))" } }
            $det = if ($r.body -and $r.body.PSObject -and $r.body.PSObject.Properties['error']) { "$($r.body.error)" } elseif ($r.body -and $r.body.PSObject -and $r.body.PSObject.Properties['held']) { "$(@($r.body.held) -join '; ')" } else { '' }
            $results.Add([pscustomobject]@{ Environment = "$($en.name)"; Change = $c.name; Result = $res; Detail = $det })
        }
    }
    $results | Format-Table -AutoSize -Wrap | Out-Host
    if (-not $Apply) { Write-Host 'PREVIEW only -- nothing was changed. Run the same command with -Apply to set it once.' -ForegroundColor Yellow }
    if ($OutFile) { [IO.File]::WriteAllText($OutFile, (ConvertTo-Json -InputObject @($results) -Depth 5), (New-Object System.Text.UTF8Encoding($false))); Write-Host "written: $OutFile" }
    return
}

if (-not $ManagerUrl -or -not $ApiAppId) { throw 'give -ManagerUrl and -ApiAppId (or -ChangesFile with -EnvironmentsFile)' }
$script:Token = Get-AppToken -Api $ApiAppId -Tenant $TenantId -Client $ClientId -Thumb $CertificateThumbprint -UseMi ([bool]$ManagedIdentity) -MiClient $ManagedIdentityClientId
function Invoke-One { param([string]$M, [string]$R, $B = $null) Invoke-PimApp -Url $ManagerUrl -Token $script:Token -M $M -R $R -B $B }

$result = $null
switch ($Example) {
    'ExportSettings' { $result = Invoke-One 'GET' '/settings/export' }
    'SetJobSchedule' {
        $cur = Invoke-One 'GET' '/job-schedule'
        # change $cur here (or pass -Body) before saving it back; saved through the same handler and checks as the page
        $result = Invoke-One 'PUT' '/job-schedule' $(if ($null -ne $Body) { $Body } else { $cur })
    }
    'StageAndCommit' {
        $data = Invoke-One 'GET' "/csv/$Entity"
        $rows = @($data.rows)
        # change $rows here: this example re-saves them unchanged. The commit carries the hash it was read with, so a change
        # made by someone else in between is refused instead of overwritten.
        $result = Invoke-One 'PUT' "/csv/$Entity" @{ rows = $rows; baseRowsHash = "$($data.rowsHash)"; justification = 'saved by script' }
    }
    'ProposeChange' {
        $data = Invoke-One 'GET' "/csv/$Entity"
        $rows = @($data.rows)
        # change $rows here; a person approves the proposal in PIM Manager (Approvals) and it is then saved
        $result = Invoke-One 'POST' "/approvals/app-submit/$Entity" @{ rows = $rows; baseRowsHash = "$($data.rowsHash)"; justification = 'proposed by script' }
    }
    default {
        if (-not $Route) { throw 'give -Example, -Route or -ChangesFile' }
        $result = Invoke-One $Method $Route $Body
    }
}
if ($OutFile) { [IO.File]::WriteAllText($OutFile, (ConvertTo-Json -InputObject $result -Depth 30), (New-Object System.Text.UTF8Encoding($false))); Write-Host "written: $OutFile" }
else { $result }
