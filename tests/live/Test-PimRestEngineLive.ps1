<#
.SYNOPSIS
  REST-ONLY engine integration test against the LIVE tenant. Proves the engine can
  CREATE + MANAGE + READ real Entra/Azure resources with NO PowerShell modules
  (no Graph/Az) -- 100% via PIM-Rest.ps1 -- then runs the decision core over the
  freshly-created live objects and scans its own run-log for issues.

  Creates objects under the 'pimrest' prefix and LEAVES them so they are visible in
  the tenant. Re-runnable (find-or-create). Run with -Cleanup to remove them.

  Target runtime: PowerShell 7 (the container/VM target) -- but uses only language
  + .NET + REST, so it also runs on Windows PowerShell 5.1.
#>
[CmdletBinding()]
param(
  [string]$UpnDomain = 'myfamilynetwork.onmicrosoft.com',
  [string]$Sub       = 'ad2ea027-413e-4edc-bc92-cf8b9b5c9aa6',
  [switch]$Cleanup
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests\live' }
$shared = Resolve-Path "$here\..\..\engine\_shared"
$config = Resolve-Path "$here\..\..\config"

# ---- run-log ---------------------------------------------------------------
$logDir = Join-Path $here 'logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Join-Path $logDir "pimrest-engine-$stamp.log"
$script:errN = 0; $script:warnN = 0; $script:pass = 0; $script:fail = 0
function Log {
  param([ValidateSet('INFO','WARN','ERROR','PASS','FAIL','STEP')][string]$Level,[string]$Msg)
  $line = "{0} [{1,-5}] {2}" -f (Get-Date -Format 'o'), $Level, $Msg
  Add-Content -Path $logPath -Value $line
  $color = switch ($Level) { 'ERROR'{'Red'} 'FAIL'{'Red'} 'WARN'{'Yellow'} 'PASS'{'Green'} 'STEP'{'Cyan'} default{'Gray'} }
  Write-Host $line -ForegroundColor $color
  if ($Level -eq 'ERROR') { $script:errN++ }
  if ($Level -eq 'WARN')  { $script:warnN++ }
}
function Assert { param([string]$n,[bool]$c) if ($c) { $script:pass++; Log PASS $n } else { $script:fail++; Log FAIL $n } }

# ---- load REST-only stack (NO modules) -------------------------------------
$global:PIM_UseGraphSdk = $false
. "$shared\PIM-Rest.ps1"
. "$config\PIM4EntraPS.Filters.locked.ps1"
. "$shared\PIM-ContextBuilder.ps1"
. "$shared\PIM-PortalAccess.ps1"
. "$shared\PIM-ChangeQueue.ps1"
. "$shared\PIM-Approvals.ps1"

function ModulesLoaded { @(Get-Module | Where-Object { $_.Name -like 'Microsoft.Graph*' -or $_.Name -like 'Az.*' -or $_.Name -eq 'Az' -or $_.Name -eq 'ExchangeOnlineManagement' }) }

Log STEP "=== REST-ONLY engine live test  (log: $logPath) ==="
Log INFO ("PowerShell {0} | UpnDomain {1} | Sub {2}" -f $PSVersionTable.PSVersion, $UpnDomain, $Sub)

# naming
$adminUpn = "Admin-pimrest-ID@$UpnDomain"          # matches AdminCandidate filter (Admin-* AND *-ID*)
$grpName  = 'PIM-Entra-RestTest-L1-T1-USER-ID'      # matches PimGroup filter (PIM-*)
$auName   = 'PIMREST-AU-Test'
$rg       = 'rg-pimrest-test'
$contributorRoleId = 'b24988ac-6180-42a0-ab88-20f7382dd24c'

# ---- helpers (idempotent, REST) -------------------------------------------
function Get-GraphFirst($path) { $r = Invoke-PimGraph -Path $path; if ($r.value) { return @($r.value)[0] } return $null }

if ($Cleanup) {
  Log STEP "CLEANUP pimrest objects"
  try { az group delete -n $rg --subscription $Sub --yes --no-wait 2>$null | Out-Null; Log INFO "rg delete requested" } catch {}
  $g = Get-GraphFirst "/groups?`$filter=displayName eq '$grpName'&`$select=id"
  if ($g) { Invoke-PimGraph -Method DELETE -Path "/groups/$($g.id)" | Out-Null; Log INFO "deleted group" }
  $u = Get-GraphFirst "/users?`$filter=userPrincipalName eq '$adminUpn'&`$select=id"
  if ($u) { Invoke-PimGraph -Method DELETE -Path "/users/$($u.id)" | Out-Null; Log INFO "deleted user" }
  $a = Get-GraphFirst "/directory/administrativeUnits?`$filter=displayName eq '$auName'&`$select=id"
  if ($a) { Invoke-PimGraph -Method DELETE -Path "/directory/administrativeUnits/$($a.id)" | Out-Null; Log INFO "deleted AU" }
  Log STEP "cleanup done"; return
}

try {
  # ---- 0) prove module-free ------------------------------------------------
  ModulesLoaded | ForEach-Object { Remove-Module $_.Name -Force -ErrorAction SilentlyContinue }
  Assert "no Graph/Az modules loaded at start" ((ModulesLoaded).Count -eq 0)

  # ---- 1) CREATE user (REST POST) -----------------------------------------
  Log STEP "1) create admin user via REST"
  $u = Get-GraphFirst "/users?`$filter=userPrincipalName eq '$adminUpn'&`$select=id,userPrincipalName"
  if (-not $u) {
    $pw = ([guid]::NewGuid().ToString('N').Substring(0,12)) + '!Aa9'
    $u = Invoke-PimGraph -Method POST -Path "/users" -Body @{
      accountEnabled=$true; displayName='PIMREST Admin (ID)'; mailNickname='Admin-pimrest-ID'
      userPrincipalName=$adminUpn; passwordProfile=@{ forceChangePasswordNextSignIn=$true; password=$pw }
    }
    Log INFO "created user $adminUpn ($($u.id))"
  } else { Log INFO "user exists $adminUpn ($($u.id))" }
  $userId = "$($u.id)"
  Log INFO "userId=$userId"

  # ---- 2) CREATE PIM group (REST POST) ------------------------------------
  Log STEP "2) create PIM group via REST"
  $g = Get-GraphFirst "/groups?`$filter=displayName eq '$grpName'&`$select=id,displayName"
  if (-not $g) {
    $g = Invoke-PimGraph -Method POST -Path "/groups" -Body @{
      displayName=$grpName; description='PIM4EntraPS REST-only engine test'; mailEnabled=$false
      mailNickname='PIMEntraRestTestL1T1USERID'; securityEnabled=$true
    }
    Log INFO "created group $grpName ($($g.id))"
  } else { Log INFO "group exists $grpName ($($g.id))" }
  $groupId = $g.id

  # ---- 3) ADD member (REST POST $ref) -------------------------------------
  Log STEP "3) add user to group via REST"
  try {
    Invoke-PimGraph -Method POST -Path "/groups/$groupId/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$userId" } | Out-Null
    Log INFO "member add ok"
  } catch { if ("$_" -match 'already exist|references already') { Log INFO "member already present" } else { throw } }

  # ---- 4) CREATE AU + add group (REST POST) -------------------------------
  Log STEP "4) create AU + add group via REST"
  $a = Get-GraphFirst "/directory/administrativeUnits?`$filter=displayName eq '$auName'&`$select=id"
  if (-not $a) { $a = Invoke-PimGraph -Method POST -Path "/directory/administrativeUnits" -Body @{ displayName=$auName; description='PIMREST test AU' }; Log INFO "created AU ($($a.id))" }
  else { Log INFO "AU exists ($($a.id))" }
  try { Invoke-PimGraph -Method POST -Path "/directory/administrativeUnits/$($a.id)/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$groupId" } | Out-Null; Log INFO "AU member add ok" }
  catch { if ("$_" -match 'already exist|references already|conflicting object') { Log INFO "AU member present" } else { Log WARN "AU member add: $_" } }

  # ---- 5) Azure RG + role assignment (REST PUT via ARM) -------------------
  Log STEP "5) create Azure RG + delegate Contributor to the group via REST (ARM)"
  Invoke-PimArm -Method PUT -Path "/subscriptions/$Sub/resourceGroups/$rg" -ApiVersion '2021-04-01' -Body @{ location='westeurope' } | Out-Null
  Log INFO "RG $rg ensured"
  $raId = [guid]::NewGuid().ToString()
  $scope = "/subscriptions/$Sub/resourceGroups/$rg"
  try {
    Invoke-PimArm -Method PUT -Path "$scope/providers/Microsoft.Authorization/roleAssignments/$raId" -ApiVersion '2022-04-01' -Body @{
      properties=@{ roleDefinitionId="/subscriptions/$Sub/providers/Microsoft.Authorization/roleDefinitions/$contributorRoleId"; principalId=$groupId; principalType='Group' }
    } | Out-Null
    Log INFO "Contributor -> group assigned on $rg"
  } catch { if ("$_" -match 'RoleAssignmentExists|already exists') { Log INFO "role assignment already exists" } else { throw } }

  # ---- 6) READ-BACK verification (REST GET) -------------------------------
  Log STEP "6) read-back verification (REST)"
  Assert "user reads back"        ([bool](Invoke-PimGraph -Path "/users/$userId").id)
  Assert "group reads back"       ([bool](Invoke-PimGraph -Path "/groups/$groupId").id)
  $members = @(Invoke-PimGraph -Path "/groups/$groupId/members?`$select=id" -All)
  Assert "group has the member"   ($members.id -contains $userId)
  $auMembers = @(Invoke-PimGraph -Path "/directory/administrativeUnits/$($a.id)/members?`$select=id" -All)
  Assert "AU has the group"       ($auMembers.id -contains $groupId)
  $ra = @(Invoke-PimArm -Path "$scope/providers/Microsoft.Authorization/roleAssignments?`$filter=principalId eq '$groupId'" -ApiVersion '2022-04-01' -All)
  Assert "Azure role assignment present" ($ra.Count -ge 1)

  # ---- 7) ENGINE context over REST sees the new objects -------------------
  Log STEP "7) Build-PimContext (REST) picks up the new live objects"
  Build-PimContext -Refresh | Out-Null
  Assert "context: PIM group appears in PimGroups"      (@($Global:PIM_Groups_Definitions_ID).DisplayName -contains $grpName)
  Assert "context: new admin appears in Admins filter"  (@($Global:Accounts_Definitions_ID).UserPrincipalName -contains $adminUpn)

  # ---- 8) DECISION CORE over the freshly-created group --------------------
  Log STEP "8) decision core over the new group"
  $row = [pscustomobject]@{ GroupName=$grpName; GroupTag='rest-test'; Workload='Entra-ID'; Owners=$adminUpn; AdministrativeUnitTag=$a.id }
  $f = Get-PimGroupFacets -Row $row
  Assert "facets: entra T1 L1"   ($f.service -eq 'entra' -and $f.tier -eq 1 -and $f.level -eq 1)
  Assert "owner recognized"      (Test-PimIsResourceOwner -Row $row -Identity $adminUpn)
  $helpdeskL2 = [pscustomobject]@{ identity='helpdesk@x'; services=@('entra'); tierMax=2; levelMax=2; capabilities=@('manage-indirect') }
  Assert "L2 helpdesk CANNOT manage more-privileged T1/L1 group" (-not (Test-PimPortalCanManageGroup -Profile $helpdeskL2 -Facets $f))
  $entraAdminL1 = [pscustomobject]@{ identity='entraadmin@x'; services=@('entra'); tierMax=1; levelMax=1; capabilities=@('manage-indirect') }
  Assert "T1/L1 entra admin CAN manage this T1/L1 group" (Test-PimPortalCanManageGroup -Profile $entraAdminL1 -Facets $f)

  # ---- 9) STILL module-free after all writes+reads ------------------------
  Assert "STILL no Graph/Az modules loaded" ((ModulesLoaded).Count -eq 0)
}
catch {
  Log ERROR "UNHANDLED: $($_.Exception.Message)"
  Log ERROR ("at: " + ($_.ScriptStackTrace -split "`n" | Select-Object -First 1))
}

# ---- log scan --------------------------------------------------------------
Log STEP "=== RESULT ==="
Log INFO ("assertions: {0} passed, {1} failed | log: {2} ERROR, {3} WARN" -f $script:pass,$script:fail,$script:errN,$script:warnN)
Write-Host ""
Write-Host ("RESULT: {0} passed / {1} failed ; {2} errors, {3} warnings in log" -f $script:pass,$script:fail,$script:errN,$script:warnN) -ForegroundColor ($(if($script:fail -or $script:errN){'Red'}else{'Green'}))
Write-Host ("log file: $logPath") -ForegroundColor DarkGray
if ($script:fail -or $script:errN) { exit 1 }
