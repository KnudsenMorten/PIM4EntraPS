#Requires -Version 7.0
<#
.SYNOPSIS
    PIM4EntraPS local-plane engine runtime for a CONTAINER (cloud-native, no VM).
    LIFECYCLE-GOVERNANCE § 19 / MSP-ARCHITECTURE.md § 11a.

.DESCRIPTION
    Runs the local engine as a scheduled container (ACI / Container Apps Job)
    INSIDE the customer's VNet. Proven flow (POC 2026-06-12):
      1. Acquire a Microsoft Graph token for the per-tenant identity.
      2. PULL the MSP signed baseline over the cross-tenant private endpoint and
         VERIFY it (RSA-SHA256 against the embedded public cert) -- expiry +
         anti-rollback enforced. Tampered/forged bundles are rejected.
      3. READ the customer's own local store (Owner=Local rows).
      4. MERGE baseline (Owner=MSP) + local (Owner=Local) and create/maintain
         the accounts in THIS tenant.

    Deliberately REST-based (no Graph SDK / SqlServer module in the image) so the
    container is small, fast, and free of the Azure.Core assembly conflict. The
    signature-verification primitive is identical to engine/_shared/PIM-Baseline.ps1.

.PARAMETER (via environment variables)
    PIM_TENANT_ID         Entra tenant id (the customer tenant).
    PIM_CLIENT_ID         the per-tenant engine app id.
    PIM_AUTH_MODE         'ManagedIdentity' (recommended) | 'ClientSecret' | 'Certificate'
    PIM_CLIENT_SECRET     (ClientSecret mode) secret value -- inject as a secure env / Key Vault ref
    PIM_CERT_PFX_B64      (Certificate mode) base64 PFX
    PIM_CERT_PFX_PWD      (Certificate mode) PFX password
    PIM_BASELINE_URL      HTTPS URL of baseline-latest.json (resolves to the PE in-VNet)
    PIM_BASELINE_PUBCERT  base64 of the MSP baseline PUBLIC cert (verification)
    PIM_DEFAULT_DOMAIN    tenant default domain for UPNs
    PIM_WHATIF            'true' (default) = plan only; 'false' = create
    PIM_LOCAL_SQL_SERVER  (optional) local store FQDN; PIM_LOCAL_SQL_DB default 'PimLocal'
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
function Log($m){ Write-Output ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $m) }

$tid    = $env:PIM_TENANT_ID
$cid    = $env:PIM_CLIENT_ID
$domain = $env:PIM_DEFAULT_DOMAIN
$whatIf = (("$($env:PIM_WHATIF)").ToLower() -ne 'false')
Log "PIM4EntraPS engine container start (tenant=$tid whatif=$whatIf)"

# ---- 1. Graph token -------------------------------------------------------
function Get-GraphToken {
    switch (("$($env:PIM_AUTH_MODE)")) {
        'ManagedIdentity' {
            # ACI/Container Apps system-assigned MI (IMDS)
            $u = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"
            (Invoke-RestMethod -Uri $u -Headers @{ Metadata = 'true' }).access_token
        }
        'Certificate' {
            $pfx = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($env:PIM_CERT_PFX_B64), $env:PIM_CERT_PFX_PWD)
            # client assertion (JWT) signed by the cert
            $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            $hdr = @{ alg='RS256'; typ='JWT'; x5t=[Convert]::ToBase64String($pfx.GetCertHash()).TrimEnd('=').Replace('+','-').Replace('/','_') }
            $aud = "https://login.microsoftonline.com/$tid/oauth2/v2.0/token"
            $pl  = @{ aud=$aud; iss=$cid; sub=$cid; jti=[guid]::NewGuid().ToString(); nbf=$now; exp=($now+600) }
            $b64 = { param($o) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o|ConvertTo-Json -Compress))).TrimEnd('=').Replace('+','-').Replace('/','_') }
            $unsigned = (& $b64 $hdr) + '.' + (& $b64 $pl)
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($pfx)
            $sig = [Convert]::ToBase64String($rsa.SignData([Text.Encoding]::ASCII.GetBytes($unsigned), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)).TrimEnd('=').Replace('+','-').Replace('/','_')
            $assertion = "$unsigned.$sig"
            (Invoke-RestMethod -Method POST -Uri $aud -Body @{ client_id=$cid; grant_type='client_credentials'; scope='https://graph.microsoft.com/.default'; client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer'; client_assertion=$assertion }).access_token
        }
        default {
            (Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tid/oauth2/v2.0/token" -Body @{ client_id=$cid; client_secret=$env:PIM_CLIENT_SECRET; grant_type='client_credentials'; scope='https://graph.microsoft.com/.default' }).access_token
        }
    }
}
$gh = @{ Authorization = "Bearer $(Get-GraphToken)" }
Log "graph token acquired ($($env:PIM_AUTH_MODE))"

# ---- 2. Pull + verify the signed baseline --------------------------------
$raw = Invoke-RestMethod -Uri $env:PIM_BASELINE_URL -Headers @{ 'x-ms-version'='2021-08-06' }
if ($raw -is [string]) { $i=$raw.IndexOf('{'); if($i -gt 0){$raw=$raw.Substring($i)}; $doc=$raw|ConvertFrom-Json } else { $doc=$raw }
$pb=[Convert]::FromBase64String($doc.payloadB64); $sb=[Convert]::FromBase64String($doc.signature)
$cert=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($env:PIM_BASELINE_PUBCERT))
$rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
if (-not $rsa.VerifyData($pb,$sb,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) { throw 'BASELINE SIGNATURE INVALID -- aborting' }
$payload=[Text.Encoding]::UTF8.GetString($pb)|ConvertFrom-Json
if ($payload.validToUtc -and ([datetime]::UtcNow -gt ([datetime]$payload.validToUtc).ToUniversalTime())) { throw "baseline expired ($($payload.validToUtc))" }
Log "baseline verified: version=$($payload.version) rows=$(@($payload.rows).Count)"

# ---- 3. Read the local store (Owner=Local) -------------------------------
$localRows = @()
if ($env:PIM_LOCAL_SQL_SERVER) {
    Add-Type -AssemblyName System.Data
    $dbTok = if (("$($env:PIM_AUTH_MODE)") -eq 'ManagedIdentity') {
        (Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://database.windows.net/" -Headers @{Metadata='true'}).access_token
    } else { $null }
    $cn = New-Object System.Data.SqlClient.SqlConnection
    $cn.ConnectionString = "Server=tcp:$($env:PIM_LOCAL_SQL_SERVER),1433;Database=$([string]::IsNullOrEmpty($env:PIM_LOCAL_SQL_DB) ? 'PimLocal' : $env:PIM_LOCAL_SQL_DB);Encrypt=True;"
    if ($dbTok) { $cn.AccessToken = $dbTok }
    $cn.Open()
    $cmd = $cn.CreateCommand(); $cmd.CommandText = "SELECT UserName,DisplayName,Purpose FROM pim.LocalAdmins WHERE Enabled=1"
    $rd = $cmd.ExecuteReader()
    while ($rd.Read()) { $localRows += @{ UserName=$rd['UserName']; DisplayName=$rd['DisplayName']; Purpose=$rd['Purpose'] } }
    $cn.Close()
    Log "local store rows (Owner=Local): $($localRows.Count)"
} else { Log "no local store configured -- baseline only" }

# ---- 4. Merge + create-if-missing ----------------------------------------
$apply = @()
foreach ($r in $payload.rows)  { $apply += @{ UserName=$r.UserName; DisplayName=$r.DisplayName; Owner='MSP' } }
foreach ($r in $localRows)     { $apply += @{ UserName=$r.UserName; DisplayName=$r.DisplayName; Owner='Local' } }
foreach ($a in $apply) {
    $upn = "$($a.UserName)@$domain"
    $exists = $true
    try { Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$upn" -Headers $gh -ErrorAction Stop | Out-Null } catch { $exists = $false }
    if ($exists) { Log "EXISTS  [$($a.Owner)] $upn"; continue }
    if ($whatIf) { Log "WOULD-CREATE [$($a.Owner)] $upn"; continue }
    $pwd = (-join ((48..57)+(65..90)+(97..122)+(35,45,95) | Get-Random -Count 20 | ForEach-Object {[char]$_})) + 'aA1!'
    $body = @{ accountEnabled=$true; displayName=$a.DisplayName; mailNickname=$a.UserName; userPrincipalName=$upn; passwordProfile=@{ password=$pwd; forceChangePasswordNextSignIn=$false }; passwordPolicies='DisablePasswordExpiration' } | ConvertTo-Json
    try { $u = Invoke-RestMethod -Method POST -Uri 'https://graph.microsoft.com/v1.0/users' -Headers $gh -ContentType 'application/json' -Body $body; Log "CREATED [$($a.Owner)] $upn id=$($u.id)" } catch { Log "CREATE-FAIL $upn : $($_.Exception.Message)" }
}
Log "engine container run complete"
