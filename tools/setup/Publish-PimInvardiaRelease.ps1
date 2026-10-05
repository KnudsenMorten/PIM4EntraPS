#Requires -Version 5.1
<#
.SYNOPSIS
  Publish a PIM release to Invardia's Pro update platform as PIM's OWN publisher identity (Invardia DESIGN §10; framework
  UPDATE-1: Pro installs take their updates from Invardia, verified against the Invardia update-signing key).

.DESCRIPTION
  1. The release zip, from the TAGGED commit (never the working tree): `git archive --format=zip
     --prefix=pim-manager-src-<v>/ <tag> -- .dockerignore SOLUTIONS/PIM4EntraPS` -- the exact shape the updater re-packs
     (ConvertTo-PimBuildContextFromZip: top folder pim-manager-src-<v>/, repo-root shaped inside).
  2. Checks before anything leaves this machine: the tag exists, VERSION inside the zip IS the version, the top folder,
     the zip magic; its SHA-256 and size are printed.
  3. With -Apply only: sign in as the publisher app (client credentials, CERTIFICATE -- never a secret) for the Invardia
     Back Office audience, and POST https://invardia.com/api/releases/pim-manager?kind=code&version=<v> with the zip as
     the body. The app holds only the role Invardia.Publisher.pim-manager: it can publish pim-manager releases, nothing
     else. Publishing registers the version; RELEASING it to a ring is the owner's act in Invardia's back office.
  Without -Apply it is a plan: the zip is built and checked, nothing is sent.

  Identity: client id + certificate thumbprint from kv-automatit-dev (invardia-publisher-clientid-pim-manager /
  invardia-publisher-thumbprint-pim-manager) unless passed; the certificate (key not exportable) is in
  Cert:\LocalMachine\My on the publishing machine.

.EXAMPLE
  .\tools\setup\Publish-PimInvardiaRelease.ps1 -Version 2.4.496 -TenantId <tenant of the publisher app>          # plan
  .\tools\setup\Publish-PimInvardiaRelease.ps1 -Version 2.4.496 -TenantId <tenant of the publisher app> -Apply   # publish
#>
[CmdletBinding()]
param(
    [string]$Version = '',
    [Parameter(Mandatory)][string]$TenantId,
    [string]$ClientId = '',
    [string]$CertThumbprint = '',
    [string]$KeyVault = 'kv-automatit-dev',
    [string]$KeyVaultSubscription = '54468121-98ba-48ba-ba59-ba10a9711ed3',
    [string]$Endpoint = 'https://invardia.com',
    [string]$Audience = 'api://a5a57537-c847-482b-8878-9a229cbca61b',
    [ValidateSet('code')][string]$Kind = 'code',
    [string]$OutDir = '',
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
function Step([string]$m) { Write-Host "==> $m" -ForegroundColor Cyan }
$sol = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$repo = Split-Path (Split-Path $sol -Parent) -Parent
if (-not "$Version".Trim()) { $Version = (Get-Content -LiteralPath (Join-Path $sol 'VERSION') -Raw).Trim() }
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "not a release version: '$Version'" }
$tag = "PIM4EntraPS-v$Version"

Step "release $Version (tag $tag)"
& git -C $repo rev-parse --verify --quiet "refs/tags/$tag" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "the tag $tag does not exist -- publish only a tagged release" }

Step 'build the release zip from the tag'
if (-not $OutDir) { $OutDir = Join-Path ([IO.Path]::GetTempPath()) 'pim-invardia-release' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$zip = Join-Path $OutDir "pim-manager-src-$Version.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
& git -C $repo archive --format=zip "--prefix=pim-manager-src-$Version/" -o $zip $tag -- .dockerignore SOLUTIONS/PIM4EntraPS
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $zip)) { throw "git archive failed (exit $LASTEXITCODE)" }

Step 'check the zip'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$z = [IO.Compression.ZipFile]::OpenRead($zip)
try {
    $bad = @($z.Entries | Where-Object { -not $_.FullName.StartsWith("pim-manager-src-$Version/") })
    if ($bad.Count) { throw "the zip has entries outside pim-manager-src-$Version/ (e.g. $($bad[0].FullName))" }
    $ve = $z.Entries | Where-Object { $_.FullName -eq "pim-manager-src-$Version/SOLUTIONS/PIM4EntraPS/VERSION" } | Select-Object -First 1
    if (-not $ve) { throw 'the zip carries no SOLUTIONS/PIM4EntraPS/VERSION' }
    $sr = New-Object IO.StreamReader($ve.Open()); try { $inner = $sr.ReadToEnd().Trim() } finally { $sr.Dispose() }
    if ($inner -ne $Version) { throw "VERSION inside the zip is '$inner', not $Version" }
    $count = $z.Entries.Count
} finally { $z.Dispose() }
$bytes = [IO.File]::ReadAllBytes($zip)
if ($bytes.Length -lt 4 -or $bytes[0] -ne 0x50 -or $bytes[1] -ne 0x4B) { throw 'not a zip' }
$sha = [System.Security.Cryptography.SHA256]::Create(); try { $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
Write-Host ("    {0}`n    {1} entries, {2:N0} bytes, SHA-256 {3}" -f $zip, $count, $bytes.Length, $hash)

$url = "$($Endpoint.TrimEnd('/'))/api/releases/pim-manager?kind=$Kind&version=$Version"
if (-not $Apply) {
    Write-Host "`nPLAN ONLY -- nothing was sent. With -Apply the zip is POSTed to $url as Invardia.Publisher.pim-manager (tenant $TenantId)." -ForegroundColor Yellow
    return [pscustomobject]@{ published = $false; version = $Version; zip = $zip; sha256 = $hash; size = $bytes.Length; url = $url }
}

Step 'publisher identity (certificate, from Key Vault unless passed)'
if (-not $ClientId -or -not $CertThumbprint) {
    $kvArgs = @('keyvault', 'secret', 'show', '--vault-name', $KeyVault, '--subscription', $KeyVaultSubscription, '--query', 'value', '-o', 'tsv')
    if (-not $ClientId) { $ClientId = (& az @kvArgs --name 'invardia-publisher-clientid-pim-manager' 2>$null | Select-Object -Last 1).Trim() }
    if (-not $CertThumbprint) { $CertThumbprint = (& az @kvArgs --name 'invardia-publisher-thumbprint-pim-manager' 2>$null | Select-Object -Last 1).Trim() }
}
if ($ClientId -notmatch '^[0-9a-fA-F-]{36}$' -or $CertThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'publisher client id / certificate thumbprint not found (Key Vault or parameters)' }
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
$token = Get-PimRestToken -Resource $Audience -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -Force
if (-not "$token".Trim()) { throw 'no token for the Invardia Back Office audience' }

Step "POST $url"
# Windows PowerShell 5.1 as well as 7 (HOST-1: scripts in tools\setup must run on both): a non-2xx answer is read from the
# exception's response instead of -SkipHttpErrorCheck (PS 7 only).
$status = 0; $content = ''
try {
    $r = Invoke-WebRequest -Method POST -Uri $url -Headers @{ Authorization = "Bearer $token" } -Body $bytes -ContentType 'application/zip' -TimeoutSec 600 -UseBasicParsing
    $status = [int]$r.StatusCode; $content = "$($r.Content)"
} catch {
    $resp = $_.Exception.Response
    if (-not $resp) { throw "the publish request failed: $($_.Exception.Message)" }
    $status = [int]$resp.StatusCode
    $content = "$($_.ErrorDetails.Message)"; if (-not $content) { $content = "$($_.Exception.Message)" }
}
$ok = ($status -in 200, 201, 202)
Write-Host ("    HTTP {0} {1}" -f $status, $content.Substring(0, [Math]::Min(400, $content.Length))) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
if (-not $ok) { throw "Invardia refused the release (HTTP $status)" }
[pscustomobject]@{ published = $true; version = $Version; sha256 = $hash; size = $bytes.Length; status = $status; url = $url }
