#Requires -Version 5.1
<#
.SYNOPSIS
    71.18 -- write the machine-local certificate-login config the weekly read-link rotation uses
    (Update-PimBaselineSas.ps1 -CertLoginConfig). Ids only: the file is validated with the SAME rule the rotation applies
    (Test-PimSasCertLoginConfig), so a config that would be refused at 02:00 on a Sunday is refused here instead.

.EXAMPLE
    .\New-PimSasCertLoginConfig.ps1 -Path C:\ProgramData\pim\sas-rotation\wa678-rj466.json -MasterTenantId <t> -MasterClientId <app> `
        -MasterCertThumbprint <thumb> -MasterSubscriptionId <sub> -SlaveTenantId <t> -SlaveClientId <app> -SlaveCertThumbprint <thumb> -SlaveSubscriptionId <sub>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$MasterTenantId, [Parameter(Mandatory)][string]$MasterClientId,
    [Parameter(Mandatory)][string]$MasterCertThumbprint, [Parameter(Mandatory)][string]$MasterSubscriptionId,
    [Parameter(Mandatory)][string]$SlaveTenantId, [Parameter(Mandatory)][string]$SlaveClientId,
    [Parameter(Mandatory)][string]$SlaveCertThumbprint, [Parameter(Mandatory)][string]$SlaveSubscriptionId
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimSasCertLogin.ps1')
$cfg = [ordered]@{
    _comment = 'PIM4EntraPS baseline read-link rotation. Certificate identities ONLY -- Update-PimBaselineSas.ps1 -CertLoginConfig refuses any other field. Written by New-PimSasCertLoginConfig.ps1.'
    master = [ordered]@{ tenantId = $MasterTenantId; clientId = $MasterClientId; certThumbprint = $MasterCertThumbprint.ToUpperInvariant(); subscriptionId = $MasterSubscriptionId }
    slave  = [ordered]@{ tenantId = $SlaveTenantId;  clientId = $SlaveClientId;  certThumbprint = $SlaveCertThumbprint.ToUpperInvariant();  subscriptionId = $SlaveSubscriptionId }
}
$chk = Test-PimSasCertLoginConfig -Config ([pscustomobject]@{ master = [pscustomobject]$cfg.master; slave = [pscustomobject]$cfg.slave; _comment = $cfg._comment })
if (-not $chk.ok) { throw "REFUSED: $($chk.reason)" }
foreach ($t in $MasterCertThumbprint, $SlaveCertThumbprint) {
    if (-not (Get-Item -LiteralPath "Cert:\LocalMachine\My\$t" -ErrorAction SilentlyContinue)) { Write-Warning "certificate $t is not in Cert:\LocalMachine\My on this host -- the rotation will fail to sign in here." }
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
$json = $cfg | ConvertTo-Json -Depth 4
if ((Test-Path -LiteralPath $Path) -and ((Get-Content -LiteralPath $Path -Raw) -replace '\s', '') -eq ($json -replace '\s', '')) { Write-Host "    $Path already current" -ForegroundColor DarkGray; return }
Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
Write-Host "    wrote $Path (ids only; validated)" -ForegroundColor DarkGray
