<#
.SYNOPSIS
  Provisions a LIVE delegation lab in the internal tenant to simulate a workload
  owner delegating access to resources across two Azure subscriptions + Power BI,
  with an AU-scoped helpdesk (L2) and an L2 approver (helpdesk manager), plus an
  external consultant (guest) whose access the workload owner manages.

  Idempotent (find-or-create). Writes a state file the validation script reads.
  Run with -Cleanup to remove everything it created.

.NOTES
  Auth: reuses the Azure CLI session (az). Tokens for Graph / ARM / Power BI are
  acquired via `az account get-access-token` so there is no Graph-module version
  coupling. No secrets are written to disk -- the state file holds only object ids
  and names. Test users live on the routing onmicrosoft.com domain.
#>
[CmdletBinding()]
param(
  # No tenant-specific defaults committed to the repo -- pass the routing
  # onmicrosoft.com domain and the two target subscription ids at run time.
  [Parameter(Mandatory)][string]$UpnDomain,
  [string]$Prefix      = 'pimlab',
  [Parameter(Mandatory)][string[]]$Subs,
  [string]$StatePath,
  [switch]$Cleanup
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests\live' }
if (-not $StatePath) { $StatePath = Join-Path $here 'pimlab-state.json' }

# ---- token helpers (reuse az session) -------------------------------------
function Get-LabToken([string]$Resource) {
  $j = az account get-access-token --resource $Resource -o json 2>$null | ConvertFrom-Json
  if (-not $j.accessToken) { throw "Could not acquire token for $Resource (az logged in?)" }
  $j.accessToken
}
$script:GraphTok = Get-LabToken 'https://graph.microsoft.com'
function Invoke-Graph {
  param([string]$Method,[string]$Path,$Body,[switch]$Beta)
  $base = if ($Beta) { 'https://graph.microsoft.com/beta' } else { 'https://graph.microsoft.com/v1.0' }
  $url  = if ($Path -match '^https?://') { $Path } else { "$base$Path" }
  $h = @{ Authorization = "Bearer $script:GraphTok"; 'Content-Type' = 'application/json' }
  $args = @{ Method = $Method; Uri = $url; Headers = $h }
  if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
    $args.Body = ($Body | ConvertTo-Json -Depth 12)
  }
  try { Invoke-RestMethod @args }
  catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
      $txt = $sr.ReadToEnd()
      throw "Graph $Method $url failed: $txt"
    }
    throw
  }
}
function New-LabPassword {
  # complex, never persisted; users get forceChangePasswordNextSignIn
  ([guid]::NewGuid().ToString('N').Substring(0,12)) + '!Aa9'
}

# ---- find-or-create primitives --------------------------------------------
function Get-OrNewUser {
  param([string]$Upn,[string]$Display)
  $nick = ($Upn -split '@')[0]
  $found = Invoke-Graph GET "/users?`$filter=userPrincipalName eq '$Upn'&`$select=id,userPrincipalName,displayName"
  if ($found.value -and $found.value.Count -gt 0) {
    Write-Host "  = user exists  $Upn" -ForegroundColor DarkGray
    return $found.value[0]
  }
  $body = @{
    accountEnabled    = $true
    displayName       = $Display
    mailNickname      = $nick
    userPrincipalName = $Upn
    passwordProfile   = @{ forceChangePasswordNextSignIn = $true; password = (New-LabPassword) }
  }
  $u = Invoke-Graph POST "/users" $body
  Write-Host "  + user created $Upn" -ForegroundColor Green
  $u
}
function Get-OrNewGroup {
  param([string]$Name,[string]$Desc)
  $nick = ($Name -replace '[^a-zA-Z0-9]','')
  $found = Invoke-Graph GET "/groups?`$filter=displayName eq '$Name'&`$select=id,displayName"
  if ($found.value -and $found.value.Count -gt 0) {
    Write-Host "  = group exists  $Name" -ForegroundColor DarkGray
    return $found.value[0]
  }
  $body = @{
    displayName     = $Name
    description     = $Desc
    mailEnabled     = $false
    mailNickname    = $nick
    securityEnabled = $true
    isAssignableToRole = $false
  }
  $g = Invoke-Graph POST "/groups" $body
  Write-Host "  + group created $Name" -ForegroundColor Green
  $g
}
function Add-GroupMember {
  param([string]$GroupId,[string]$MemberId)
  try {
    Invoke-Graph POST "/groups/$GroupId/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$MemberId" } | Out-Null
  } catch { if ("$_" -notmatch 'already exist|added object references already') { throw } }
}

# ===========================================================================
if ($Cleanup) {
  Write-Host "CLEANUP: removing pimlab objects" -ForegroundColor Yellow
  if (Test-Path $StatePath) { $st = Get-Content $StatePath -Raw | ConvertFrom-Json } else { $st = $null }
  # ARM role assignments + RGs
  foreach ($s in $Subs) {
    az group delete -n "rg-$Prefix-test" --subscription $s --yes --no-wait 2>$null | Out-Null
    Write-Host "  - rg-$Prefix-test (sub $s) delete requested" -ForegroundColor Yellow
  }
  if ($st) {
    foreach ($g in @($st.groups.PSObject.Properties.Value)) { try { Invoke-Graph DELETE "/groups/$g" | Out-Null; Write-Host "  - group $g" } catch {} }
    foreach ($u in @($st.users.PSObject.Properties.Value)) { try { Invoke-Graph DELETE "/users/$u" | Out-Null; Write-Host "  - user $u" } catch {} }
    if ($st.guestId)  { try { Invoke-Graph DELETE "/users/$($st.guestId)" | Out-Null; Write-Host "  - guest $($st.guestId)" } catch {} }
    if ($st.auId)     { try { Invoke-Graph DELETE "/directory/administrativeUnits/$($st.auId)" | Out-Null; Write-Host "  - AU $($st.auId)" } catch {} }
    foreach ($ws in @($st.powerbi.PSObject.Properties.Value)) {
      try { az rest --method DELETE --url "https://api.powerbi.com/v1.0/myorg/groups/$ws" --resource "https://analysis.windows.net/powerbi/api" 2>$null | Out-Null; Write-Host "  - pbi ws $ws" } catch {}
    }
  }
  Write-Host "Cleanup done." -ForegroundColor Yellow
  return
}

Write-Host "=== PIM4EntraPS LIVE delegation lab ===" -ForegroundColor Cyan
$state = [ordered]@{
  createdUtc = (Get-Date).ToUniversalTime().ToString('o')
  upnDomain  = $UpnDomain
  subs       = $Subs
  users      = [ordered]@{}
  groups     = [ordered]@{}
  powerbi    = [ordered]@{}
  arm        = [ordered]@{}
}

# ---- 1) Administrative Unit (helpdesk L2 scope) ---------------------------
Write-Host "[1] Administrative Unit" -ForegroundColor Cyan
$auName = 'PIMLAB-AU-Helpdesk'
$au = (Invoke-Graph GET "/directory/administrativeUnits?`$filter=displayName eq '$auName'").value | Select-Object -First 1
if (-not $au) { $au = Invoke-Graph POST "/directory/administrativeUnits" @{ displayName=$auName; description='PIM4EntraPS live lab - helpdesk L2 scope'; visibility='HiddenMembership' } ; Write-Host "  + AU created" -ForegroundColor Green }
else { Write-Host "  = AU exists" -ForegroundColor DarkGray }
$state.auId = $au.id

# ---- 2) Personas ----------------------------------------------------------
Write-Host "[2] Personas (workload owners + helpdesk L2 + L2 approver)" -ForegroundColor Cyan
$personas = [ordered]@{
  ownerAzure       = @{ upn = "$Prefix-owner-azure@$UpnDomain";        name = 'PIMLAB Owner - Azure Workload' }
  ownerPowerbi     = @{ upn = "$Prefix-owner-powerbi@$UpnDomain";      name = 'PIMLAB Owner - Power BI Workload' }
  adminHelpdesk    = @{ upn = "$Prefix-admin-helpdesk@$UpnDomain";     name = 'PIMLAB Admin Helpdesk (L2)' }
  helpdeskManager  = @{ upn = "$Prefix-admin-helpdeskmanager@$UpnDomain"; name = 'PIMLAB Admin Helpdesk Manager (L2 approver)' }
}
foreach ($k in $personas.Keys) {
  $u = Get-OrNewUser -Upn $personas[$k].upn -Display $personas[$k].name
  $state.users[$k] = $u.id
}

# ---- 3) External consultant (guest invite, cloud-only) --------------------
Write-Host "[3] External consultant (guest)" -ForegroundColor Cyan
$guestEmail = "$Prefix.consultant@contoso-external.example"
$existingGuest = (Invoke-Graph GET "/users?`$filter=mail eq '$guestEmail'&`$select=id,mail").value | Select-Object -First 1
if (-not $existingGuest) {
  $inv = Invoke-Graph POST "/invitations" @{
    invitedUserEmailAddress = $guestEmail
    invitedUserDisplayName  = 'PIMLAB External Consultant'
    inviteRedirectUrl       = 'https://myapps.microsoft.com'
    sendInvitationMessage   = $false
  }
  $state.guestId = $inv.invitedUser.id
  Write-Host "  + guest invited $guestEmail" -ForegroundColor Green
} else {
  $state.guestId = $existingGuest.id
  Write-Host "  = guest exists $guestEmail" -ForegroundColor DarkGray
}

# ---- 4) PIM groups (naming grammar PIM-Service-Name-Lx-Tx-Code-Domain) ----
Write-Host "[4] PIM delegation groups" -ForegroundColor Cyan
$grpDefs = [ordered]@{
  pbiContributor = @{ name = 'PIM-PBI-WorkspaceContributor-L1-T1-APP-ID';  desc = 'Power BI workspace contributor (consultant L1)' }
  azResOwner     = @{ name = 'PIM-AzRes-ResourceOwner-L1-T1-APP-RES';      desc = 'Azure resource owner across lab subs (consultant L1)' }
  helpdeskL2     = @{ name = 'PIM-Entra-Helpdesk-L2-T2-USER-ID';           desc = 'Entra helpdesk L2, AU-scoped' }
}
foreach ($k in $grpDefs.Keys) {
  $g = Get-OrNewGroup -Name $grpDefs[$k].name -Desc $grpDefs[$k].desc
  $state.groups[$k] = $g.id
}

# ---- 5) AU membership + AU-scoped helpdesk role ---------------------------
Write-Host "[5] AU membership + AU-scoped Helpdesk Administrator" -ForegroundColor Cyan
# add the helpdesk admin + the L2 group into the AU
foreach ($mid in @($state.users.adminHelpdesk, $state.groups.helpdeskL2)) {
  try { Invoke-Graph POST "/directory/administrativeUnits/$($au.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$mid" } | Out-Null }
  catch { if ("$_" -notmatch 'already exist|references already') { Write-Host "    (au member add: $_)" -ForegroundColor DarkYellow } }
}
# Helpdesk Administrator roleTemplateId = 729827e3-9c14-49f7-bb1b-9608f156bbb8
$helpdeskRoleTemplate = '729827e3-9c14-49f7-bb1b-9608f156bbb8'
$role = (Invoke-Graph GET "/directoryRoles?`$filter=roleTemplateId eq '$helpdeskRoleTemplate'").value | Select-Object -First 1
if (-not $role) {
  $role = Invoke-Graph POST "/directoryRoles" @{ roleTemplateId = $helpdeskRoleTemplate }
  Write-Host "  + activated Helpdesk Administrator role" -ForegroundColor Green
}
# scoped membership: helpdesk admin scoped to the AU
$scoped = (Invoke-Graph GET "/directory/administrativeUnits/$($au.id)/scopedRoleMembers").value
$already = $scoped | Where-Object { $_.roleId -eq $role.id -and $_.roleMemberInfo.id -eq $state.users.adminHelpdesk }
if (-not $already) {
  try {
    Invoke-Graph POST "/directory/administrativeUnits/$($au.id)/scopedRoleMembers" @{
      roleId = $role.id
      roleMemberInfo = @{ id = $state.users.adminHelpdesk }
    } | Out-Null
    Write-Host "  + admin-helpdesk scoped as Helpdesk Administrator over AU" -ForegroundColor Green
  } catch { Write-Host "    (scoped role add: $_)" -ForegroundColor DarkYellow }
} else { Write-Host "  = scoped role already present" -ForegroundColor DarkGray }

# ---- 6) Azure RBAC delegation across the two subs -------------------------
Write-Host "[6] Azure: RG + role-assignment delegation in both subs" -ForegroundColor Cyan
$azGroupOid = $state.groups.azResOwner
foreach ($s in $Subs) {
  $rg = "rg-$Prefix-test"
  az group create -n $rg -l westeurope --subscription $s -o none 2>$null
  $scope = "/subscriptions/$s/resourceGroups/$rg"
  # delegate Contributor on the lab RG to the AzRes PIM group (the "resource" the owner delegates)
  az role assignment create --assignee-object-id $azGroupOid --assignee-principal-type Group `
     --role "Contributor" --scope $scope -o none 2>$null
  $state.arm[$s] = @{ rg = $rg; scope = $scope; delegatedGroup = $azGroupOid; role = 'Contributor' }
  Write-Host "  + $rg (sub $s): Contributor -> AzRes PIM group" -ForegroundColor Green
}

# ---- 7) Power BI workspaces ----------------------------------------------
Write-Host "[7] Power BI workspaces" -ForegroundColor Cyan
$pbiOk = $true
try { $pbiTok = Get-LabToken 'https://analysis.windows.net/powerbi/api' } catch { $pbiOk = $false; Write-Host "  ! no Power BI token: $_" -ForegroundColor Red }
if ($pbiOk) {
  $pbiHdr = @{ Authorization = "Bearer $pbiTok"; 'Content-Type'='application/json' }
  foreach ($wsName in @("PIMLAB-Workspace-Finance","PIMLAB-Workspace-Sales")) {
    try {
      $list = Invoke-RestMethod -Method GET -Uri "https://api.powerbi.com/v1.0/myorg/groups?`$filter=name eq '$wsName'" -Headers $pbiHdr
      $ws = $list.value | Select-Object -First 1
      if (-not $ws) {
        $ws = Invoke-RestMethod -Method POST -Uri "https://api.powerbi.com/v1.0/myorg/groups?workspaceV2=true" -Headers $pbiHdr -Body (@{ name = $wsName } | ConvertTo-Json)
        Write-Host "  + workspace $wsName" -ForegroundColor Green
      } else { Write-Host "  = workspace $wsName exists" -ForegroundColor DarkGray }
      $state.powerbi[$wsName] = $ws.id
    } catch { Write-Host "  ! workspace $wsName failed: $_" -ForegroundColor Red }
  }
}

# ---- save state -----------------------------------------------------------
$state | ConvertTo-Json -Depth 12 | Set-Content -Path $StatePath -Encoding UTF8
Write-Host "`nState written: $StatePath" -ForegroundColor Cyan
Write-Host "Provisioning complete." -ForegroundColor Green
