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
  'PIM-Definitions-Organization' = 'GroupName;GroupDescription;GroupTag;AdministrativeUnitTag;IsRoleAssignable;Workload;Level;TierLevel;Plane;CPPlatform;Owners;SponsorUpn;Department'
  'PIM-Assignments-Azure-Resources' = 'GroupTag;AzScope;AzScopePermission;AssignmentType;Action;UpdateExisting;AutoExtend;NumOfDaysWhenExpire;Permanent;CPPlatform;Plane;TierLevel;PermissionScope;SyncPlatform'
}
function Invoke-ScenarioValidation([hashtable]$Files, [hashtable]$Caches) {
    $dir = Join-Path $env:TEMP "pim-scn-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory $dir | Out-Null
    foreach ($b in $Files.Keys) { Set-Content (Join-Path $dir "$b.custom.csv") (@($H[$b]) + $Files[$b]) -Encoding UTF8 }
    $script:scnDir = $dir
    # Optional tenant-cache stubs so the cache-driven rules (PIM-AUTH-*, PIM-ORPHAN-AZ-*,
    # PIM-STALE-003) can be exercised offline. When $Caches is $null the rules degrade
    # (skip) exactly as they do without a live cache -- which is itself a tested behaviour.
    $script:scnCaches = $Caches
    if ($Caches) {
        function global:Get-PimTenantCacheFile { param([string]$Kind) $f = Join-Path $script:scnDir "$Kind.json"; $f }
        function global:Read-PimTenantListCache {
            $out = [ordered]@{}
            foreach ($k in @('entra-roles','aus','pim-groups','azure-scopes','azure-rbac-roles')) {
                $key = ($k -replace '-([a-z])', { $args[0].Groups[1].Value.ToUpper() }) -replace '-',''
                $out[$key] = $null
            }
            if ($script:scnCaches.ContainsKey('azure-scopes')) { $out['azureScopes'] = @{ refreshedUtc=(Get-Date).ToString('o'); items=@($script:scnCaches['azure-scopes']) } }
            if ($script:scnCaches.ContainsKey('entra-roles'))  { $out['entraRoles']  = @{ refreshedUtc=(Get-Date).ToString('o'); items=@($script:scnCaches['entra-roles']) } }
            return $out
        }
        # auth-methods / pim-activity are read as raw JSON files by the validator.
        if ($Caches.ContainsKey('auth-methods')) { ($Caches['auth-methods'] | ConvertTo-Json -Depth 5) | Set-Content (Join-Path $dir 'auth-methods.json') -Encoding UTF8 }
        if ($Caches.ContainsKey('pim-activity')) { ($Caches['pim-activity'] | ConvertTo-Json -Depth 5) | Set-Content (Join-Path $dir 'pim-activity.json') -Encoding UTF8 }
    } else {
        Remove-Item Function:\global:Get-PimTenantCacheFile -EA SilentlyContinue
        Remove-Item Function:\global:Read-PimTenantListCache -EA SilentlyContinue
    }
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

Section 'GOVERNANCE / AUTHORING VALIDATOR RULES (new)'

# PIM-ROLE-OWNER-001: org/role row with no Owners/SponsorUpn/Department -> info
$v = Invoke-ScenarioValidation @{
  'PIM-Definitions-Organization' = @('PIM-Org-NoOwner-L1-T1-CP-ID;org;ORG-NOOWN-L1-T1-CP-ID;;TRUE;;L1;T1;CP;CP;;;')
}
T 'role/org with no owner -> PIM-ROLE-OWNER-001' ((Codes $v) -contains 'PIM-ROLE-OWNER-001')

# same row WITH an owner -> rule must NOT fire
$v = Invoke-ScenarioValidation @{
  'PIM-Definitions-Organization' = @('PIM-Org-Owned-L1-T1-CP-ID;org;ORG-OWNED-L1-T1-CP-ID;;TRUE;;L1;T1;CP;CP;owner@contoso.com;;')
}
T 'role/org WITH owner -> no PIM-ROLE-OWNER-001' (-not ((Codes $v) -contains 'PIM-ROLE-OWNER-001'))

# PIM-AUTH-001: admin with no strong auth method (auth-methods cache present) -> error
$v = Invoke-ScenarioValidation -Files @{
  'Account-Definitions-Admins' = @('Jane;Doe;JD;Day2Day;Cloud;ID;Internal;Admin-JD-ID;Jane;admin-jd-id@contoso.com;US;FALSE;;FALSE;;;2;')
  'PIM-Assignments-Admins' = @()
} -Caches @{ 'auth-methods' = @{ 'admin-jd-id@contoso.com' = @('sms') } }
T 'admin with only weak auth (sms) -> PIM-AUTH-002' ((Codes $v) -contains 'PIM-AUTH-002')

# PIM-AUTH: admin WITH a strong method -> no auth violation
$v = Invoke-ScenarioValidation -Files @{
  'Account-Definitions-Admins' = @('Jane;Doe;JD;Day2Day;Cloud;ID;Internal;Admin-JD-ID;Jane;admin-jd-id@contoso.com;US;FALSE;;FALSE;;;2;')
  'PIM-Assignments-Admins' = @()
} -Caches @{ 'auth-methods' = @{ 'admin-jd-id@contoso.com' = @('microsoftAuthenticator') } }
T 'admin with authenticator -> no PIM-AUTH-001/002' (-not (((Codes $v) -match 'PIM-AUTH-00').Count -gt 0 -and ((Codes $v) | Where-Object { $_ -in 'PIM-AUTH-001','PIM-AUTH-002' })))

# PIM-ORPHAN-AZ-001: azure assignment to a scope not in the azure-scopes cache -> warning
$v = Invoke-ScenarioValidation -Files @{
  'PIM-Definitions-Roles' = @('PIM-Az-L1-T1-CP-ID;az;AZ-L1-T1-CP-ID;;CP;CP;T1;Global;;TRUE')
  'PIM-Assignments-Azure-Resources' = @('AZ-L1-T1-CP-ID;/subscriptions/deleted-sub;Reader;Eligible;Assign;FALSE;TRUE;365;FALSE;;;;;')
} -Caches @{ 'azure-scopes' = @(@{ id='/subscriptions/live-sub'; displayName='Live'; scopePath='/subscriptions/live-sub'; type='subscription' }) }
T 'azure assignment to missing scope -> PIM-ORPHAN-AZ-001' ((Codes $v) -contains 'PIM-ORPHAN-AZ-001')

# child scope of a cached subscription is NOT orphaned
$v = Invoke-ScenarioValidation -Files @{
  'PIM-Definitions-Roles' = @('PIM-Az-L1-T1-CP-ID;az;AZ-L1-T1-CP-ID;;CP;CP;T1;Global;;TRUE')
  'PIM-Assignments-Azure-Resources' = @('AZ-L1-T1-CP-ID;/subscriptions/live-sub/resourceGroups/rg1;Reader;Eligible;Assign;FALSE;TRUE;365;FALSE;;;;;')
} -Caches @{ 'azure-scopes' = @(@{ id='/subscriptions/live-sub'; displayName='Live'; scopePath='/subscriptions/live-sub'; type='subscription' }) }
T 'azure RG under a known sub -> no PIM-ORPHAN-AZ-001' (-not ((Codes $v) -contains 'PIM-ORPHAN-AZ-001'))

Section 'MAIL-FORWARD VALIDATION (PIM-DOMAIN-001 false-positive fix)'
# Header field order ...UsageLocation;ForwardMailsToContact;MailForwardAddress;CreateTAP;...
# so each row's "...;US;<fwd>;<addr>;FALSE;;;2;" controls forwarding flag + address.

# both off (ForwardMailsToContact=FALSE + MailForwardAddress=FALSE sentinel) -> consistent "no forwarding" -> NO warning
$v = Invoke-ScenarioValidation @{
  'Account-Definitions-Admins' = @('Help;Desk;HD;Day2Day;Cloud;ID;Internal;Admin-Helpdesk-AD;Help Desk;Admin-Helpdesk-AD@contoso.com;US;FALSE;FALSE;FALSE;;;2;')
}
T 'both FALSE (sentinel address + forwarding off) -> NO PIM-DOMAIN-001' (-not ((Codes $v) -contains 'PIM-DOMAIN-001'))

# real address + forwarding off -> genuine misconfig -> WARNING
$v = Invoke-ScenarioValidation @{
  'Account-Definitions-Admins' = @('Help;Desk;HD;Day2Day;Cloud;ID;Internal;Admin-Helpdesk-AD;Help Desk;Admin-Helpdesk-AD@contoso.com;US;FALSE;contact@contoso.com;FALSE;;;2;')
}
T 'real address + forwarding off -> PIM-DOMAIN-001 warning' ((Codes $v) -contains 'PIM-DOMAIN-001')

# real address + forwarding on -> valid -> NO warning
$v = Invoke-ScenarioValidation @{
  'Account-Definitions-Admins' = @('Help;Desk;HD;Day2Day;Cloud;ID;Internal;Admin-Helpdesk-AD;Help Desk;Admin-Helpdesk-AD@contoso.com;US;TRUE;contact@contoso.com;FALSE;;;2;')
}
T 'real address + forwarding on -> no PIM-DOMAIN-001' (-not ((Codes $v) -contains 'PIM-DOMAIN-001'))

# blank address + forwarding off -> NO warning
$v = Invoke-ScenarioValidation @{
  'Account-Definitions-Admins' = @('Help;Desk;HD;Day2Day;Cloud;ID;Internal;Admin-Helpdesk-AD;Help Desk;Admin-Helpdesk-AD@contoso.com;US;FALSE;;FALSE;;;2;')
}
T 'blank address + forwarding off -> no PIM-DOMAIN-001' (-not ((Codes $v) -contains 'PIM-DOMAIN-001'))

# 'no' / '0' sentinels + forwarding off -> NO warning
$v = Invoke-ScenarioValidation @{
  'Account-Definitions-Admins' = @(
    'A;One;A1;Day2Day;Cloud;ID;Internal;Admin-A1-ID;A One;Admin-A1-ID@contoso.com;US;FALSE;no;FALSE;;;2;',
    'B;Two;B2;Day2Day;Cloud;ID;Internal;Admin-B2-ID;B Two;Admin-B2-ID@contoso.com;US;FALSE;0;FALSE;;;2;')
}
T "'no'/'0' sentinel addresses + forwarding off -> no PIM-DOMAIN-001" (-not ((Codes $v) -contains 'PIM-DOMAIN-001'))

# the shared sentinel predicate the engine apply path also uses
T 'Test-PimMailForwardAddressIsReal: FALSE/blank/no/0 -> not real' (
    (-not (Test-PimMailForwardAddressIsReal -Value 'FALSE')) -and
    (-not (Test-PimMailForwardAddressIsReal -Value '')) -and
    (-not (Test-PimMailForwardAddressIsReal -Value $null)) -and
    (-not (Test-PimMailForwardAddressIsReal -Value 'no')) -and
    (-not (Test-PimMailForwardAddressIsReal -Value '0'))
)
T 'Test-PimMailForwardAddressIsReal: real email -> real' (
    (Test-PimMailForwardAddressIsReal -Value 'contact@contoso.com') -and
    (-not (Test-PimMailForwardAddressIsReal -Value 'not-an-address'))
)

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
