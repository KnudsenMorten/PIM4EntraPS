<#
.SYNOPSIS
  Validates the PIM4EntraPS delegation ENGINE against the live lab objects
  provisioned by Provision-PimLab.ps1. Maps the live AU / users / groups /
  subscriptions / Power BI workspaces into the engine's data model, then exercises
  the REAL decision functions (approver routing, L2 approval, biz-owner-manages-
  external-consultant, helpdesk AU/level scoping, escalation layers).

  Pure engine logic over live identifiers -- no further tenant writes.
#>
[CmdletBinding()]
param([string]$StatePath)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests\live' }
if (-not $StatePath) { $StatePath = Join-Path $here 'pimlab-state.json' }
$shared = Resolve-Path "$here\..\..\engine\_shared"
. "$shared\PIM-ChangeQueue.ps1"
. "$shared\PIM-PortalAccess.ps1"
. "$shared\PIM-Approvals.ps1"

if (-not (Test-Path $StatePath)) { throw "State file not found: $StatePath (run Provision-PimLab.ps1 first)" }
$S = Get-Content $StatePath -Raw | ConvertFrom-Json
$dom = $S.upnDomain
function U($k){ "pimlab-$k@$dom" }
$ownerAzure   = U 'owner-azure'
$ownerPbi     = U 'owner-powerbi'
$helpdesk     = U 'admin-helpdesk'
$helpdeskMgr  = U 'admin-helpdeskmanager'
$consultant   = 'pimlab.consultant@contoso-external.example'
$sub1Scope    = $S.arm.($S.subs[0]).scope
$sub2Scope    = $S.arm.($S.subs[1]).scope
$pbiFinance   = $S.powerbi.'PIMLAB-Workspace-Finance'

# --- engine config (would live in SQL pim.Settings; seeded here) ------------
$global:PIM_NamingConventions = @{
  PawEnforcement   = $false   # opt-in, OFF by default (customer maturity)
  SupportFunctions = @{
    ITManager        = @($ownerAzure)            # escalation persona (acts as IT manager)
    PIMDelegationOwner = @($helpdeskMgr)
  }
  ApproverMatrix = @(
    # most-specific: Entra L2 helpdesk management -> the helpdesk MANAGER
    @{ workload='Entra-ID'; tier=2; level=2; plane='*'; approvers=@($helpdeskMgr); escalateTo=@('@ITManager'); slaHours=24 }
    # broader Entra service-owner layer (escalation target / also-approves)
    @{ workload='Entra-ID';                  approvers=@('@ITManager'); slaHours=48 }
    # Power BI workload owner approves Power BI
    @{ workload='PowerBI';                   approvers=@($ownerPbi); slaHours=24 }
    # Azure workload owner approves Azure
    @{ workload='Azure';                     approvers=@($ownerAzure); slaHours=24 }
  )
}

# --- definition rows (PIM groups as the engine sees them) -------------------
$rowHelpdesk = [pscustomobject]@{ GroupName='PIM-Entra-Helpdesk-L2-T2-USER-ID'; GroupTag='helpdesk-l2'; Workload='Entra-ID'; Owners=$helpdeskMgr; AdministrativeUnitTag=$S.auId }
$rowPbi      = [pscustomobject]@{ GroupName='PIM-PBI-WorkspaceContributor-L1-T1-APP-ID'; GroupTag='pbi-contrib'; Workload='PowerBI'; Owners=$ownerPbi; PermissionScope=$pbiFinance }
$rowAzRes    = [pscustomobject]@{ GroupName='PIM-AzRes-ResourceOwner-L1-T1-APP-RES'; GroupTag='azres-owner'; Workload='Azure'; Owners=$ownerAzure; PermissionScope=$sub1Scope }
# a high-priv group the helpdesk must NOT touch
$rowGA       = [pscustomobject]@{ GroupName='PIM-Entra-GlobalAdmin-L0-T0-USER-ID'; GroupTag='ga-l0'; Workload='Entra-ID'; Owners='' }

# --- portal-admin profiles (delegated GUI managers) ------------------------
$profHelpdesk = [pscustomobject]@{ identity=$helpdesk; services=@('entra'); tierMax=2; levelMax=2; capabilities=@('manage-indirect','assign') }
$profOwnerPbi = [pscustomobject]@{ identity=$ownerPbi; services=@('workload'); tierMax=1; levelMax=1; capabilities=@('manage-indirect','assign-admin','enable-consultants','approve-assignment','access-review'); managedAdmins=@($consultant) }
$profOwnerAz  = [pscustomobject]@{ identity=$ownerAzure; services=@('azure'); tierMax=1; levelMax=1; scopes=@($sub1Scope,$sub2Scope); capabilities=@('manage-indirect','assign-admin','enable-consultants','approve-assignment','access-review'); managedAdmins=@($consultant) }

# --- assertion harness ------------------------------------------------------
$script:pass=0; $script:fail=0
function Assert($name,$cond){ if($cond){ $script:pass++; Write-Host ("  PASS  {0}" -f $name) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL  {0}" -f $name) -ForegroundColor Red } }

Write-Host "`n=== PIM4EntraPS LIVE delegation engine validation ===" -ForegroundColor Cyan
Write-Host "tenant domain $dom | subs $($S.subs -join ', ')" -ForegroundColor DarkGray

Write-Host "`n[A] Naming-grammar facet parsing (live group names)" -ForegroundColor Cyan
$fH = Get-PimGroupFacets -Row $rowHelpdesk
$fP = Get-PimGroupFacets -Row $rowPbi
$fA = Get-PimGroupFacets -Row $rowAzRes
Assert "helpdesk -> service=entra tier=2 level=2"      ($fH.service -eq 'entra' -and $fH.tier -eq 2 -and $fH.level -eq 2)
Assert "powerbi  -> service=workload tier=1 level=1"   ($fP.service -eq 'workload' -and $fP.tier -eq 1 -and $fP.level -eq 1)
Assert "azres    -> service=azure scope=lab RG"        ($fA.service -eq 'azure' -and $fA.scope -eq $sub1Scope)

Write-Host "`n[B] Approver routing (workload x tier x level)" -ForegroundColor Cyan
$primHelpdesk = Get-PimApproversForResource -Facets $fH -Row $rowHelpdesk
$primPbi      = Get-PimApproversForResource -Facets $fP -Row $rowPbi
$primAz       = Get-PimApproversForResource -Facets $fA -Row $rowAzRes
Assert "L2 helpdesk routes to helpdesk MANAGER"        ($primHelpdesk -contains $helpdeskMgr)
Assert "Power BI routes to Power BI owner"             ($primPbi -contains $ownerPbi)
Assert "Azure routes to Azure owner"                  ($primAz -contains $ownerAzure)

Write-Host "`n[C] L2 management approval flow (helpdesk manager approves)" -ForegroundColor Cyan
$req = New-PimApprovalRequest -Requestor $helpdesk -TargetAdmin $helpdesk -GroupTag 'helpdesk-l2' -Justification 'activate L2 helpdesk'
$canMgr  = Test-PimCanApprove -Identity $helpdeskMgr -Row $rowHelpdesk -Facets $fH -Matrix $global:PIM_NamingConventions.ApproverMatrix
$canPbi  = Test-PimCanApprove -Identity $ownerPbi   -Row $rowHelpdesk -Facets $fH -Matrix $global:PIM_NamingConventions.ApproverMatrix
Assert "helpdesk MANAGER can approve L2 mgmt"          ($canMgr -eq $true)
Assert "Power BI owner CANNOT approve Entra L2"        ($canPbi -eq $false)
$dec = Resolve-PimApprovalDecision -Request $req -Approver $helpdeskMgr -Decision approve -CanApprove $canMgr
Assert "approval -> status approved + change queued"   ($dec.ok -and $dec.status -eq 'approved' -and $dec.change)

Write-Host "`n[D] Business owner manages EXTERNAL consultant + access" -ForegroundColor Cyan
Assert "PBI owner is resource owner of PBI workload"   (Test-PimIsResourceOwner -Row $rowPbi -Identity $ownerPbi)
Assert "PBI owner can enable/disable the consultant"   (Test-PimPortalCanEnableConsultant -Profile $profOwnerPbi -AdminName $consultant)
Assert "PBI owner can assign perms to the consultant"  (Test-PimPortalCanAssignAdmin -Profile $profOwnerPbi -AdminName $consultant)
Assert "PBI owner can MANAGE the PBI group"            (Test-PimPortalCanManageGroup -Profile $profOwnerPbi -Facets $fP)
Assert "Azure owner can enable the consultant"         (Test-PimPortalCanEnableConsultant -Profile $profOwnerAz -AdminName $consultant)
Assert "Azure owner can manage AzRes within scope"     (Test-PimPortalCanManageGroup -Profile $profOwnerAz -Facets $fA)
# cross-workload isolation: PBI owner must NOT manage Azure resources
Assert "PBI owner CANNOT manage Azure workload group"  (-not (Test-PimPortalCanManageGroup -Profile $profOwnerPbi -Facets $fA))
# scope isolation: an Azure group OUTSIDE the owner's delegated scopes is invisible
$fOut = Get-PimGroupFacets -Row ([pscustomobject]@{ GroupName='PIM-AzRes-ResourceOwner-L1-T1-APP-RES'; Workload='Azure'; PermissionScope='/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/other' })
Assert "Azure owner CANNOT see RG outside delegated scope" (-not (Test-PimPortalCanManageGroup -Profile $profOwnerAz -Facets $fOut))

Write-Host "`n[E] Helpdesk (L2) AU + level scoping" -ForegroundColor Cyan
Assert "helpdesk can manage its L2 Entra group"        (Test-PimPortalCanManageGroup -Profile $profHelpdesk -Facets $fH)
Assert "helpdesk CANNOT manage T0/L0 Global Admin"     (-not (Test-PimPortalCanManageGroup -Profile $profHelpdesk -Facets (Get-PimGroupFacets -Row $rowGA)))
Assert "helpdesk CANNOT manage Power BI (service gate)" (-not (Test-PimPortalCanManageGroup -Profile $profHelpdesk -Facets $fP))
Assert "helpdesk CANNOT manage Azure (service gate)"    (-not (Test-PimPortalCanManageGroup -Profile $profHelpdesk -Facets $fA))

Write-Host "`n[F] Layered approval + escalation (the layers ARE escalation points)" -ForegroundColor Cyan
$layers = @(Get-PimApproverLayers -Facets $fH -Row $rowHelpdesk -Matrix $global:PIM_NamingConventions.ApproverMatrix)
Assert "two approver layers for L2 helpdesk"           ($layers.Count -ge 2)
Assert "layer 0 = helpdesk manager (most specific)"    ($layers[0].approvers -contains $helpdeskMgr)
Assert "layer 1 escalates to IT manager persona"       ($layers[1].approvers -contains $ownerAzure)
$now = [datetime]::UtcNow
$reqOld = [pscustomobject]@{ requestedUtc = $now.AddHours(-30).ToString('o'); status='pending' }
$escNow = Get-PimEscalationTargetForRequest -Request $reqOld -Facets $fH -NowUtc $now -Row $rowHelpdesk -Matrix $global:PIM_NamingConventions.ApproverMatrix -SlaHours 24
Assert "aged 30h request escalates past layer 0"       ($escNow.isEscalated -and $escNow.layerIndex -ge 1)

Write-Host "`n[G] PAW gate is OPT-IN (off by default; tight is optional)" -ForegroundColor Cyan
Assert "default (no enforcement): T0 group manageable" (Test-PimPawAllowed -Tier 0 -Plane 'CP' -Level 0)
Assert "enforced + no PAW: T0 blocked"                 (-not (Test-PimPawAllowed -Tier 0 -Plane 'CP' -Level 0 -Enforce $true))
Assert "enforced + L0 PAW: T0 allowed"                 (Test-PimPawAllowed -Tier 0 -Plane 'CP' -Level 0 -RequestPawLevel 0 -Enforce $true)

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $script:pass,$script:fail) -ForegroundColor ($(if($script:fail){'Red'}else{'Green'}))
if ($script:fail) { exit 1 }
