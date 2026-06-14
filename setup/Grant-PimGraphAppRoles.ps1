<#
.SYNOPSIS
  Idempotently grant the PIM engine SPN its required Microsoft Graph application permissions,
  using a CERTIFICATE-authenticated admin SPN over pure Graph REST (no Graph SDK module, no
  device-code flow). Companion to Install-PimEngineAppRegistration.ps1.

.DESCRIPTION
  The engine needs a fixed set of Graph app roles (see DESIGN.md §7). When new releases add a
  permission, or a tenant's engine SPN was created elsewhere, the SPN can fall behind. This
  script reads the engine SPN's current Graph app-role assignments and grants only the missing
  ones. It authenticates as an ADMIN SPN (one that can write appRoleAssignments -- e.g. a
  Privileged Role Administrator / the AutomateIT management SPN) by certificate; it never uses
  a client secret, device code, or interactive human sign-in.

  Two permissions are easy to miss and break real features:
    * RoleManagementPolicy.ReadWrite.AzureADGroup (+ ...Directory) -- without it the engine
      cannot read/write a PIM-for-Groups member policy, so the approval-required policy apply
      fails with a swallowed 403 surfacing as "no member policy".
    * AccessReview.Read.All -- without it the AccessReviews provider 403s (handled gracefully,
      but the provider stays a no-op).

.EXAMPLE
  # using the management SPN cert on this host:
  .\Grant-PimGraphAppRoles.ps1 -TenantId <tenant> -AdminClientId <mgmt-spn-appid> `
      -AdminCertThumbprint <thumb> -EngineAppId <engine-spn-appid>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$AdminClientId,
    [Parameter(Mandatory)][string]$AdminCertThumbprint,
    [Parameter(Mandatory)][string]$EngineAppId,
    [string[]]$Permissions = @(
        'Directory.Read.All','User.ReadWrite.All','Group.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory','PrivilegedAccess.ReadWrite.AzureADGroup',
        'RoleManagementPolicy.ReadWrite.Directory','RoleManagementPolicy.ReadWrite.AzureADGroup',
        'AdministrativeUnit.ReadWrite.All','Mail.Send','AccessReview.Read.All'
    )
)
$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$shared = Resolve-Path "$here\..\engine\_shared"
. "$shared\PIM-Rest.ps1"
$global:PIM_UseGraphSdk    = $false
$global:PIM_TenantId       = $TenantId
$global:PIM_ClientId       = $AdminClientId
$global:PIM_CertThumbprint = $AdminCertThumbprint

$graphAppId = '00000003-0000-0000-c000-000000000000'
$graphSp = @(Invoke-PimGraph -All -Path "/servicePrincipals?`$filter=appId eq '$graphAppId'&`$select=id,appRoles")
if (-not $graphSp.Count) { throw 'Microsoft Graph SPN not found in this tenant.' }
$graphSpId = $graphSp[0].id
$roleByValue = @{}; foreach ($r in $graphSp[0].appRoles) { if ($r.allowedMemberTypes -contains 'Application') { $roleByValue[$r.value] = $r.id } }

$eng = @(Invoke-PimGraph -All -Path "/servicePrincipals?`$filter=appId eq '$EngineAppId'&`$select=id,displayName")
if (-not $eng.Count) { throw "Engine SPN '$EngineAppId' not found in tenant '$TenantId'." }
$spid = $eng[0].id
Write-Host "Engine SPN: $($eng[0].displayName) ($spid) in tenant $TenantId" -ForegroundColor Cyan

$existing = @(Invoke-PimGraph -All -Path "/servicePrincipals/$spid/appRoleAssignments?`$top=200")
$haveIds  = @($existing | Where-Object { $_.resourceId -eq $graphSpId } | ForEach-Object { $_.appRoleId })

$granted = 0; $already = 0; $failed = 0; $invalid = 0
foreach ($p in $Permissions) {
    $rid = $roleByValue[$p]
    if (-not $rid)              { Write-Host "  ? $p (not a Graph application role)" -ForegroundColor Yellow; $invalid++; continue }
    if ($haveIds -contains $rid){ Write-Host "  = $p (already granted)" -ForegroundColor DarkGray; $already++; continue }
    try {
        Invoke-PimGraph -Method POST -Path "/servicePrincipals/$spid/appRoleAssignments" -Body @{ principalId=$spid; resourceId=$graphSpId; appRoleId=$rid } | Out-Null
        Write-Host "  + $p GRANTED" -ForegroundColor Green; $granted++
    } catch { Write-Host "  x $p FAILED: $($_.Exception.Message)" -ForegroundColor Red; $failed++ }
}
Write-Host ("Done. granted=$granted already=$already failed=$failed invalid=$invalid") -ForegroundColor $(if ($failed) {'Yellow'} else {'Green'})
if ($granted) { Write-Host "Restart any long-running engine process (it caches perms at token-mint time); allow a minute for propagation." -ForegroundColor Yellow }
if ($failed)  { exit 1 }
