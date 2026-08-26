#Requires -Version 5.1
<#
.SYNOPSIS
  Mint a self-signed certificate and attach it to an EXISTING engine SPN -- create or rotate.

.DESCRIPTION
  Operator request 2026-08-12: *"ability to create self-signed certificate and upload to spn must be
  added (script)"*. `Install-PimEngineAppRegistration.ps1` can already do this, but only bundled into
  CREATING the app registration, and it writes `keyCredentials = @($new)` -- which REPLACES the whole
  collection. That is fine for a first install and wrong for a rotation.

  🔴 WHY ROTATION NEEDS MORE THAN A PATCH. Graph does NOT return the public key material of existing
  keyCredentials (`key` comes back null). So the obvious read-modify-write -- read the collection,
  append, PATCH it back -- sends nulls for the existing entries and DESTROYS them. There is no way to
  preserve other certificates through a PATCH.
  The supported additive path is `POST /applications/{id}/addKey`, which requires a **proof JWT**
  signed by a certificate the app ALREADY holds. This script implements that when it can find the
  matching private key locally, so a rotation adds the new certificate WITHOUT invalidating the old
  one -- the overlap that makes a zero-downtime cert roll possible.
  When no existing key can be proven, it refuses and tells you to pass -Replace, rather than
  silently wiping credentials that something else may be authenticating with.

.PARAMETER Replace
  Replace the ENTIRE keyCredentials collection with the new certificate. Destructive by definition:
  every other certificate on the app stops working immediately. Required when the app already has
  certificates and none of their private keys are available locally to sign the addKey proof.

.PARAMETER KeyVaultName
  When given, the new thumbprint is written to `Modern-Thumbprint` so onboarding and
  Setup-PimContainers pick the certificate up (certificate is PREFERRED over the client secret).

.NOTES
  The certificate is created in the LOCAL store; only the PUBLIC key is uploaded. A container cannot
  use a store certificate, which is why the hosted path still falls back to the client secret --
  this script serves the VM / mgmt-box path and any future cert-capable host.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$TenantId,
    # Privileged identity allowed to modify the application object.
    [Parameter(Mandatory)][string]$AdminAppId,
    [string]$AdminSecret,
    [string]$AdminCertThumbprint,
    # The engine SPN to attach the certificate to. Read from Key Vault 'Modern-AppId' when omitted.
    [string]$EngineAppId,
    [string]$KeyVaultName,
    [string]$BootstrapAppId,
    [string]$BootstrapThumbprint,
    [string]$CertSubject       = 'CN=PIM4EntraPS-Engine',
    [int]$ValidityYears        = 2,
    [switch]$MachineStore,
    [switch]$Replace,
    [switch]$NewCertAlways,
    [string]$OutFile
)
$ErrorActionPreference = 'Stop'
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')

$result = [ordered]@{ ok=$false; engineAppId=''; thumbprint=''; keyId=''; method=''; existingKeys=0; reason='' }
function Note($m,$c='Gray'){ Write-Host "    $m" -ForegroundColor $c }
function Write-Result { if("$OutFile".Trim()){ try{ ($result|ConvertTo-Json -Depth 8)|Set-Content -LiteralPath $OutFile -Encoding utf8 -WhatIf:$false }catch{} } }
function Fail($m){ $result.reason=$m; Write-Result; Write-Host "`nRESULT: FAILED -- $m" -ForegroundColor Red; exit 1 }

Write-Host ("=" * 78) -ForegroundColor Cyan
Write-Host " PIM ENGINE CERTIFICATE  tenant $TenantId" -ForegroundColor Cyan
Write-Host ("=" * 78) -ForegroundColor Cyan

# --- privileged Graph token -----------------------------------------------------
$tokArgs = @{ Resource='graph'; TenantId=$TenantId; ClientId=$AdminAppId; Force=$true }
if ("$AdminSecret".Trim())         { $tokArgs['ClientSecret']   = $AdminSecret }
elseif ("$AdminCertThumbprint".Trim()) { $tokArgs['CertThumbprint'] = $AdminCertThumbprint }
else { Fail 'supply -AdminSecret or -AdminCertThumbprint' }
try { $tok = Get-PimRestToken @tokArgs } catch { Fail "could not authenticate as $AdminAppId : $($_.Exception.Message)" }
$GH = @{ Authorization = "Bearer $tok"; 'Content-Type'='application/json' }
function Gr { param([string]$Method='GET',[Parameter(Mandatory)][string]$Path,[object]$Body)
    $a=@{ Method=$Method; Uri="https://graph.microsoft.com/v1.0/$Path"; Headers=$GH }
    if ($null -ne $Body) { $a.Body = ($Body|ConvertTo-Json -Depth 20) }
    Invoke-RestMethod @a }

# --- resolve the engine app -----------------------------------------------------
if (-not "$EngineAppId".Trim()) {
    if (-not ("$KeyVaultName".Trim() -and "$BootstrapAppId".Trim() -and "$BootstrapThumbprint".Trim())) {
        Fail 'no -EngineAppId, and no -KeyVaultName/-BootstrapAppId/-BootstrapThumbprint to read Modern-AppId from'
    }
    try {
        $kvTok = Get-PimRestToken -Resource 'https://vault.azure.net' -TenantId $TenantId -ClientId $BootstrapAppId -CertThumbprint $BootstrapThumbprint -Force
        $EngineAppId = (Invoke-RestMethod -Headers @{Authorization="Bearer $kvTok"} -Uri "https://$KeyVaultName.vault.azure.net/secrets/Modern-AppId`?api-version=7.4").value
    } catch { Fail "could not read Modern-AppId from $KeyVaultName : $($_.Exception.Message)" }
}
$EngineAppId = "$EngineAppId".Trim(); $result.engineAppId = $EngineAppId
$app = (Gr -Path "applications?`$filter=appId eq '$EngineAppId'").value | Select-Object -First 1
if (-not $app) { Fail "no application registration found for appId $EngineAppId" }
Note "app: $($app.displayName)  objectId=$($app.id)" 'DarkGray'

$existing = @($app.keyCredentials | Where-Object { "$($_.type)" -eq 'AsymmetricX509Cert' })
$result.existingKeys = $existing.Count
Note "existing certificates on the app: $($existing.Count)" 'DarkGray'
foreach ($k in $existing) { Note ("  {0,-42} expires {1}" -f $k.displayName, $k.endDateTime) 'DarkGray' }

# --- certificate: reuse a valid one or mint a new one ----------------------------
$store = if ($MachineStore) { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }
$cert = $null
if (-not $NewCertAlways) {
    $cert = Get-ChildItem $store -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $CertSubject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
        Sort-Object NotAfter -Descending | Select-Object -First 1
}
if ($cert) { Note "reusing local certificate $($cert.Thumbprint) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" 'DarkGray' }
elseif ($PSCmdlet.ShouldProcess($CertSubject, "create self-signed certificate in $store")) {
    $cert = New-SelfSignedCertificate -Subject $CertSubject -CertStoreLocation $store `
        -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears($ValidityYears)
    Note "created certificate $($cert.Thumbprint) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))" 'Green'
} else { Note '[WhatIf] would create a self-signed certificate' 'DarkYellow'; $result.ok=$true; Write-Result; exit 0 }
$result.thumbprint = $cert.Thumbprint

$newKey = @{
    type='AsymmetricX509Cert'; usage='Verify'
    key = [Convert]::ToBase64String($cert.GetRawCertData())
    displayName = "PIM4EntraPS Engine cert ($($cert.NotBefore.ToString('yyyy-MM-dd')) -> $($cert.NotAfter.ToString('yyyy-MM-dd')))"
    startDateTime = $cert.NotBefore.ToUniversalTime().ToString('o')
    endDateTime   = $cert.NotAfter.ToUniversalTime().ToString('o')
}

# --- already attached? -----------------------------------------------------------
$already = @($existing | Where-Object {
    $cki = "$($_.customKeyIdentifier)"
    $cki -and ([Convert]::ToBase64String(($cert.GetCertHash())) -eq $cki -or $cki -eq $cert.Thumbprint)
})
if ($already.Count) {
    Note 'this certificate is already attached to the app -- nothing to upload' 'Green'
    $result.ok=$true; $result.method='already-present'; $result.keyId="$($already[0].keyId)"
} else {

# --- upload: addKey (additive, needs a proof) or PATCH (replaces) -----------------
function New-PimAddKeyProof {
    # Proof JWT for POST /applications/{id}/addKey, signed by a certificate the app ALREADY trusts.
    # Without this, addKey is rejected and the only alternative is a destructive PATCH.
    param([Parameter(Mandatory)]$SigningCert,[Parameter(Mandatory)][string]$AppId)
    $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $b64u={ param($b) [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }
    $hdr = & $b64u ([Text.Encoding]::UTF8.GetBytes((@{ alg='RS256'; typ='JWT'; x5t=(& $b64u $SigningCert.GetCertHash()) }|ConvertTo-Json -Compress)))
    $pay = & $b64u ([Text.Encoding]::UTF8.GetBytes((@{ aud='00000002-0000-0000-c000-000000000000'; iss=$AppId; nbf=$now; exp=($now+600) }|ConvertTo-Json -Compress)))
    $rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($SigningCert)
    if (-not $rsa) { return $null }
    $sig = & $b64u ($rsa.SignData([Text.Encoding]::UTF8.GetBytes("$hdr.$pay"), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1))
    return "$hdr.$pay.$sig"
}

    $uploaded=$false
    if ($existing.Count -gt 0 -and -not $Replace) {
        # find a local private key for one of the certs the app already trusts
        $signer = $null
        foreach ($k in $existing) {
            $cki = "$($k.customKeyIdentifier)"
            if (-not $cki) { continue }
            $signer = Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object {
                $_.HasPrivateKey -and ([Convert]::ToBase64String($_.GetCertHash()) -eq $cki -or $_.Thumbprint -eq $cki) } | Select-Object -First 1
            if ($signer) { break }
        }
        if (-not $signer) {
            Fail ("the app already has $($existing.Count) certificate(s) and none of their private keys are available locally, " +
                  "so an additive addKey proof cannot be signed. Graph does not return existing key material, so a PATCH would " +
                  "DESTROY them. Re-run with -Replace if losing the existing certificate(s) is intended.")
        }
        Note "signing an addKey proof with the existing certificate $($signer.Thumbprint)" 'DarkGray'
        if ($PSCmdlet.ShouldProcess($EngineAppId,'addKey (additive)')) {
            $proof = New-PimAddKeyProof -SigningCert $signer -AppId $EngineAppId
            if (-not $proof) { Fail "could not sign the addKey proof with $($signer.Thumbprint) (no usable private key)" }
            try {
                $r = Gr -Method POST -Path "applications/$($app.id)/addKey" -Body @{ keyCredential=$newKey; passwordCredential=$null; proof=$proof }
                $result.keyId="$($r.keyId)"; $result.method='addKey'; $uploaded=$true
                Note 'certificate ADDED alongside the existing one(s)' 'Green'
            } catch {
                $d=''; if ($_.ErrorDetails.Message) { $d=$_.ErrorDetails.Message.Substring(0,[Math]::Min(300,$_.ErrorDetails.Message.Length)) }
                Fail "addKey failed: $(($_.Exception.Message -split "`n")[0]) $d"
            }
        }
    } else {
        if ($existing.Count -gt 0) { Note "REPLACING $($existing.Count) existing certificate(s) -- they stop working now" 'Yellow' }
        if ($PSCmdlet.ShouldProcess($EngineAppId,'PATCH keyCredentials (replace)')) {
            try { Gr -Method PATCH -Path "applications/$($app.id)" -Body @{ keyCredentials=@($newKey) } | Out-Null
                  $result.method='patch-replace'; $uploaded=$true }
            catch { Fail "PATCH keyCredentials failed: $(($_.Exception.Message -split "`n")[0])" }
        }
    }

    # --- verify by read-back ------------------------------------------------------
    if ($uploaded) {
        $want=[Convert]::ToBase64String($cert.GetCertHash())
        $ok=$false
        for ($i=0; $i -lt 12; $i++) {
            Start-Sleep -Seconds 5
            $a2 = Gr -Path "applications/$($app.id)"
            $m = @($a2.keyCredentials | Where-Object { "$($_.customKeyIdentifier)" -eq $want -or "$($_.customKeyIdentifier)" -eq $cert.Thumbprint })
            if ($m.Count) { $ok=$true; $result.keyId="$($m[0].keyId)"; $result.existingKeys=@($a2.keyCredentials).Count; break }
        }
        if (-not $ok) { Fail 'the certificate was uploaded but is not present on read-back' }
        Note "verified on the app (keyId $($result.keyId); certificates now: $($result.existingKeys))" 'Green'
        $result.ok=$true
    }
}

# --- publish the thumbprint so the deploy path can use it -------------------------
if ($result.ok -and "$KeyVaultName".Trim() -and "$BootstrapAppId".Trim() -and "$BootstrapThumbprint".Trim()) {
    if ($PSCmdlet.ShouldProcess($KeyVaultName,'write Modern-Thumbprint')) {
        try {
            $kvTok = Get-PimRestToken -Resource 'https://vault.azure.net' -TenantId $TenantId -ClientId $BootstrapAppId -CertThumbprint $BootstrapThumbprint -Force
            Invoke-RestMethod -Method PUT -Uri "https://$KeyVaultName.vault.azure.net/secrets/Modern-Thumbprint`?api-version=7.4" `
                -Headers @{Authorization="Bearer $kvTok"; 'Content-Type'='application/json'} -Body (@{ value=$cert.Thumbprint }|ConvertTo-Json) | Out-Null
            Note "Modern-Thumbprint updated in $KeyVaultName -- the deploy path prefers the certificate over the secret" 'Green'
        } catch { Note "could not write Modern-Thumbprint: $(($_.Exception.Message -split "`n")[0])" 'Yellow' }
    }
}

Write-Host ""
Write-Host "  engine SPN : $EngineAppId" -ForegroundColor Green
Write-Host "  thumbprint : $($cert.Thumbprint)" -ForegroundColor Green
Write-Host "  method     : $($result.method)" -ForegroundColor Green
Write-Host "  pass to the deploy as: -EngineCertThumbprint $($cert.Thumbprint)"
Write-Result
exit 0
