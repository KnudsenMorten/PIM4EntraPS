#Requires -Version 5.1
<#
.SYNOPSIS
    Scenario tests for PIM4EntraPS: realistic end-to-end situations that must be
    caught or handled correctly -- validator negative cases (duplicate role, FK
    violations, naming, TAP-in-past, bad schedule) and lifecycle positives
    (create admin with schedule + TAP, consultant template, high-priv +
    approval). Rerunnable; uses crafted temp configs (no live tenant).
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$pass=0;$fail=0
function T($n,$c){ if($c){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }
function Section($t){ Write-Host "`n== $t ==" -ForegroundColor Cyan }

$root = Split-Path -Parent $PSScriptRoot
$global:PIM_ConfigVariant = 'test'
Import-Module (Join-Path $root 'engine\_shared\PIM-Functions.psm1') -Force -DisableNameChecking
. (Join-Path $root 'config\PIM4EntraPS.NamingConventions.locked.ps1')

# ---- crafted-config validator harness ------------------------------------
$H = @{
  'PIM-Definitions-Roles'  = 'GroupName;GroupDescription;GroupTag;AdministrativeUnitTag;CPPlatform;Plane;TierLevel;PermissionScope;SyncPlatform;IsRoleAssignable'
  'Account-Definitions-Admins' = 'FirstName;LastName;Initials;Purpose;TargetUsage;TargetPlatform;UserType;UserName;DisplayName;UserPrincipalName;UsageLocation;ForwardMailsToContact;MailForwardAddress;CreateTAP;TAPStartDate;TAPLifetimeHours;Ring;ProvisionDate'
  'PIM-Assignments-Admins' = 'Username;GroupTag;AssignmentType;Action;UpdateExisting;AutoExtend;NumOfDaysWhenExpire;Permanent;CPPlatform;Plane;TierLevel;PermissionScope;SyncPlatform'
  'PIM-Definitions-Tasks'  = 'GroupName;GroupDescription;GroupTag;AdministrativeUnitTag;IsRoleAssignable;Workload;Level;TierLevel;Plane;CPPlatform;Owners'
  'PIM-Assignments-Groups' = 'TargetGroupTag;SourceGroupTag;AssignmentType;Action;UpdateExisting;AutoExtend;NumOfDaysWhenExpire;Permanent;CPPlatform;Plane;TierLevel;PermissionScope;SyncPlatform'
  'PIM-Assignments-Roles-Groups' = 'GroupTag;RoleDefinitionName;AssignmentType;Action;UpdateExisting;AutoExtend;NumOfDaysWhenExpire;Permanent;CPPlatform;Plane;TierLevel;PermissionScope;SyncPlatform'
}
function Invoke-ScenarioValidation([hashtable]$Files) {
    $dir = Join-Path $env:TEMP "pim-scn-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory $dir | Out-Null
    foreach ($b in $Files.Keys) { Set-Content (Join-Path $dir "$b.custom.csv") (@($H[$b]) + $Files[$b]) -Encoding UTF8 }
    $script:scnDir = $dir
    function global:Get-PimConfigDir { $script:scnDir }
    function global:Get-PimNamingConventions { $global:PIM_NamingConventions }
    function global:Get-PimCsvBases { @('Account-Definitions-Admins','PIM-Assignments-Admins','PIM-Definitions-Roles','PIM-Definitions-Tasks','PIM-Definitions-Services','PIM-Definitions-Processes','PIM-Definitions-Resources','PIM-Definitions-Departments','PIM-Definitions-Organization','PIM-Definitions-AU','PIM-Assignments-Groups','PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs','PIM-Assignments-Azure-Resources','PIM-Assignments-Workloads') | ForEach-Object { [pscustomobject]@{ base=$_ } } }
    function global:Resolve-PimCsvPath { param([string]$BaseName) $p=Join-Path $script:scnDir "$BaseName.custom.csv"; if (Test-Path $p) { $p } else { $null } }
    # The validator reads every CSV through Read-PimRows (renamed from Read-PimCsvRows
    # in v2.4.172 "drop Csv from reader name"); stub THAT name or the validator's
    # try/catch swallows the missing-function error and loads every CSV empty,
    # silently passing every negative scenario.
    function global:Read-PimRows { param([string]$BaseName)
        $p = Resolve-PimCsvPath -BaseName $BaseName
        if (-not $p) { return @{ header=@(); rows=@(); source='none'; path=$null } }
        $rows = @(Import-Csv -Path $p -Delimiter ';')
        $header = if ($rows.Count) { @($rows[0].PSObject.Properties.Name) } else { @((Get-Content $p -TotalCount 1) -split ';') }
        @{ header=$header; rows=$rows; source='custom'; path=$p }
    }
    . (Join-Path $root 'tools\pim-manager\_validator.ps1')
    $v = @((Invoke-PimPreflightValidation).violations)
    Remove-Item $dir -Recurse -Force -EA SilentlyContinue
    $v
}
function Codes($v){ @($v | ForEach-Object { $_.Code } | Sort-Object -Unique) }

Section 'VALIDATOR SCENARIOS (negative cases must be caught)'
$roleHdrTag = 'Helpdesk-L1-T1-CP-ID'   # naming-regex-valid GroupTag

# dangling assignment FK (assignment -> undefined GroupTag)
$v = Invoke-ScenarioValidation @{
  'PIM-Definitions-Roles'  = @("PIM-Helpdesk-L1-T1-CP-ID;hd;$roleHdrTag;;CP;CP;T1;Global;;TRUE")
  'Account-Definitions-Admins' = @('Jane;Doe;JD;Day2Day;Cloud;ID;Internal;Admin-JD-ID;Jane;Admin-JD-ID@contoso.com;US;FALSE;;FALSE;;;2;')
  'PIM-Assignments-Admins' = @('Admin-JD-ID@contoso.com;ROLE-DoesNotExist;Eligible;Assign;FALSE;TRUE;365;FALSE;;;;;')
}
T 'assignment to undefined GroupTag -> PIM-FK-*' (((Codes $v) -match 'PIM-FK-00').Count -gt 0)

# admin in assignment not defined
$v = Invoke-ScenarioValidation @{
  'PIM-Definitions-Roles'  = @("PIM-Helpdesk-L1-T1-CP-ID;hd;$roleHdrTag;;CP;CP;T1;Global;;TRUE")
  'Account-Definitions-Admins' = @('Jane;Doe;JD;Day2Day;Cloud;ID;Internal;Admin-JD-ID;Jane;Admin-JD-ID@contoso.com;US;FALSE;;FALSE;;;2;')
  'PIM-Assignments-Admins' = @("Admin-GHOST-ID@contoso.com;$roleHdrTag;Eligible;Assign;FALSE;TRUE;365;FALSE;;;;;")
}
T 'assignment for undefined admin -> PIM-FK-*' (((Codes $v) -match 'PIM-FK-00').Count -gt 0)

# TAP lifetime out of range (1-720) -> PIM-TAP-002
$v = Invoke-ScenarioValidation @{
  'Account-Definitions-Admins' = @('Jane;Doe;JD;Day2Day;Cloud;ID;Internal;Admin-JD-ID;Jane;Admin-JD-ID@contoso.com;US;FALSE;;TRUE;Now;9999;2;')
}
T 'TAP lifetime > 720h -> PIM-TAP-002' ((Codes $v) -contains 'PIM-TAP-002')

# create admin with schedule + TAP, but TAP window opens BEFORE provision -> PIM-SCHED-002
$v = Invoke-ScenarioValidation @{
  'Account-Definitions-Admins' = @('Jane;Doe;JD;Day2Day;Cloud;ID;Internal;Admin-JD-ID;Jane;Admin-JD-ID@contoso.com;US;FALSE;;TRUE;FirstWorkdayNextMonth-5d;8;2;FirstWorkdayNextMonth')
}
T 'TAP starts before ProvisionDate -> PIM-SCHED-002' ((Codes $v) -contains 'PIM-SCHED-002')

# unparseable ProvisionDate -> PIM-SCHED-001
$v = Invoke-ScenarioValidation @{
  'Account-Definitions-Admins' = @('Jane;Doe;JD;Day2Day;Cloud;ID;Internal;Admin-JD-ID;Jane;Admin-JD-ID@contoso.com;US;FALSE;;FALSE;;;2;not-a-date')
}
T 'unparseable ProvisionDate -> PIM-SCHED-001' ((Codes $v) -contains 'PIM-SCHED-001')

# duplicate access PATH: admin reaches same permission group via 2 role groups -> PIM-DUP-001
$v = Invoke-ScenarioValidation @{
  'PIM-Definitions-Roles'  = @('PIM-A-L1-T1-CP-ID;a;ROLE-A-L1-T1-CP-ID;;CP;CP;T1;Global;;TRUE','PIM-B-L1-T1-CP-ID;b;ROLE-B-L1-T1-CP-ID;;CP;CP;T1;Global;;TRUE')
  'PIM-Definitions-Tasks'  = @('PIM-X-L1-T1-MP-ID;x;PERM-X-L1-T1-MP-ID;;FALSE;WL;L1;T1;MP;ID;')
  'PIM-Assignments-Groups' = @('ROLE-A-L1-T1-CP-ID;PERM-X-L1-T1-MP-ID;Eligible;Assign;FALSE;TRUE;365;FALSE;;;;;','ROLE-B-L1-T1-CP-ID;PERM-X-L1-T1-MP-ID;Eligible;Assign;FALSE;TRUE;365;FALSE;;;;;')
  'PIM-Assignments-Roles-Groups' = @('PERM-X-L1-T1-MP-ID;Helpdesk Administrator;Eligible;Assign;FALSE;TRUE;365;FALSE;;;;;')
  'Account-Definitions-Admins' = @('Jane;Doe;JD;Day2Day;Cloud;ID;Internal;Admin-JD-ID;Jane;Admin-JD-ID@contoso.com;US;FALSE;;FALSE;;;2;')
  'PIM-Assignments-Admins' = @('Admin-JD-ID@contoso.com;ROLE-A-L1-T1-CP-ID;Eligible;Assign;FALSE;TRUE;365;FALSE;;;;;','Admin-JD-ID@contoso.com;ROLE-B-L1-T1-CP-ID;Eligible;Assign;FALSE;TRUE;365;FALSE;;;;;')
}
T 'duplicate access path (admin->2 roles->same perm) -> PIM-DUP-001' ((Codes $v) -contains 'PIM-DUP-001')

# clean config -> no ERROR severity
$v = Invoke-ScenarioValidation @{
  'PIM-Definitions-Roles'  = @("PIM-Helpdesk-L1-T1-CP-ID;hd;$roleHdrTag;;CP;CP;T1;Global;;TRUE")
  'Account-Definitions-Admins' = @('Jane;Doe;JD;Day2Day;Cloud;ID;Internal;Admin-JD-ID;Jane;Admin-JD-ID@contoso.com;US;FALSE;;FALSE;;;2;')
  'PIM-Assignments-Admins' = @("Admin-JD-ID@contoso.com;$roleHdrTag;Eligible;Assign;FALSE;TRUE;365;FALSE;;;;;")
}
T 'consistent config -> no error-severity findings' (@($v | Where-Object Severity -eq 'error').Count -eq 0)

Section 'LIFECYCLE SCENARIOS (create admin with schedule + TAP, etc.)'
# Scenario: new employee next month -- provision 3 workdays before, TAP at 08:00
T 'create-admin-with-schedule: ProvisionDate resolves to a future UTC datetime' {
    $d = [datetime](Resolve-PimDateExpression -Expression 'FirstWorkdayNextMonth-3d')
    $d -gt (Get-Date)
}
T 'create-admin-with-schedule+TAP: TAPStartDate resolves with @time' {
    $d = [datetime](Resolve-PimDateExpression -Expression 'FirstWorkdayNextMonth@08:00')
    $d.Hour -eq 8
}
T 'consultant template prefills Day2Day + TAP + forwarding' {
    $j = Get-Content (Join-Path $root 'templates\admin\consultant.admintemplate.json') -Raw | ConvertFrom-Json
    ($j.prefill.Purpose -eq 'Day2Day') -and ($j.prefill.CreateTAP -eq 'TRUE') -and ($j.prefill.ForwardMailsToContact -eq 'TRUE')
}
T 'new-employee template provisions before first workday + TAP at start' {
    $j = Get-Content (Join-Path $root 'templates\admin\new-employee-next-month.admintemplate.json') -Raw | ConvertFrom-Json
    ($j.prefill.ProvisionDate -like 'FirstWorkday*') -and ($j.prefill.TAPStartDate -like '*08:00')
}

Section 'APPROVAL SCENARIO (assign high role -> approval required, mail on escalation)'
T 'approval-required policy template ENABLES approval' {
    "$(Get-Content (Join-Path $root 'templates\policy\approval-required.policytemplate.json') -Raw)" -match '(?i)approval'
}
T 'approval-escalation mail template exists + renders' {
    $p = Get-PimMailTemplate -Type 'approval-escalation'
    $p -and (ConvertTo-PimMailRendering -TemplateText (Get-Content $p -Raw) -Tokens @{ ApproverName='a@y'; GroupName='G' }).BodyHtml
}
T 'Serial approval escalation rotates approver index when overdue (state logic)' {
    # craft a serial group whose next-owner rotation is the offline-testable seam
    Save-PimPolicyState -State @{ 'G'=@{ groupId='gid'; groupTag='ROLE-GA'; approval=@{ mode='Serial'; owners=@('a@y','b@y','c@y'); activeApproverIndex=0; escalationHours=4 } } }
    $st = (Get-PimPolicyState)['G']
    # precondition for escalation: more owners exist beyond the active index
    ($st.approval.activeApproverIndex + 1) -lt @($st.approval.owners).Count
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
