#Requires -Version 5.1
<#
.SYNOPSIS
    Offline tests for the § 17 naming-convention helpers/validation and the § 18
    v1 -> v2 (group-centric) migration planner. Pure, no live tenant.
.DESCRIPTION
    Exercised both stand-alone (powershell.exe -File) and as a child process of the
    Pester job (PIM.Tests.ps1 'Naming + v1->v2 migration' block). Exits 0 on all-pass,
    1 on any failure. Asserts:
      * Resolve-PimAdminName / Resolve-PimGroupName / Resolve-PimResourceGroup grammar
      * Test-PimAdminName / Test-PimGroupName validation (Day2Day vs HighPriv, canonical
        vs simple group shapes, separator is '-')
      * Import-PimV1Baseline reads a v1 CSV and a Custom-Policies.ps1-style PS data file
      * ConvertTo-PimV2MigrationPlan maps direct user->role into the group-centric model
        (one group per role, group->role bindings, admin->group memberships, dedupe)
      * the planner is non-destructive (source file untouched, no Entra/SQL writes)
.EXAMPLE
    powershell -NoProfile -File tests\Test-PimNamingMigration.ps1
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-Naming.ps1')
. (Join-Path $root 'engine\_shared\PIM-Migration.ps1')

$script:Pass = 0; $script:Fail = 0
function Assert([bool]$Cond, [string]$Msg) {
    if ($Cond) { $script:Pass++; Write-Host "  [+] $Msg" -ForegroundColor Green }
    else       { $script:Fail++; Write-Host "  [-] $Msg" -ForegroundColor Red }
}
function AssertEq($Expected, $Actual, [string]$Msg) {
    Assert ("$Expected" -eq "$Actual") ("$Msg (expected '$Expected', got '$Actual')")
}

# --- ensure a clean, known convention (don't depend on a sourced custom config) ---
$global:PIM_NamingConventions = $null

Write-Host "`n== Naming helpers (§ 17) ==" -ForegroundColor Cyan
# Admin name = {AdminTypePrefix} + Admin-{Initial} + {Platform}, rendered LOWER-CASE.
# Default admin-type internal-adminuser -> NO prefix; default env entra -> -ID suffix.
# Operator examples: internal -> 'admin-mok-id'; high-priv -> 'admin-mok-l0-t0-id'.
AssertEq 'admin-mok-id'        (Resolve-PimAdminName -Owner 'mok')                         'day-2-day internal Entra renders admin-mok-id (lower-case, no prefix, -id)'
AssertEq 'admin-jdo-id'        (Resolve-PimAdminName -Owner 'JDO')                         'owner case is lower-cased in the rendered name'
# --- admin-type PREFIX: internal = none, external-adminuser = x-, external-guest = NONE ---
AssertEq 'admin-jdo-id'        (Resolve-PimAdminName -Owner 'jdo' -AdminType 'internal-adminuser') 'internal-adminuser -> NO prefix'
AssertEq 'x-admin-vnd-id'      (Resolve-PimAdminName -Owner 'vnd' -AdminType 'external-adminuser') 'external-adminuser -> x- prefix'
AssertEq 'admin-gst-id'        (Resolve-PimAdminName -Owner 'gst' -AdminType 'external-guest')     'external-guest -> NO prefix (default empty)'
# --- environment SUFFIX: entra = -ID, ad = -AD (NOT always -ID) ---
AssertEq 'admin-jdo-id'        (Resolve-PimAdminName -Owner 'jdo' -Environment 'entra')     'Entra environment -> -id suffix'
AssertEq 'admin-jdo-ad'        (Resolve-PimAdminName -Owner 'jdo' -Environment 'ad')        'AD environment -> -ad suffix (driven by environment)'
AssertEq 'x-admin-vnd-ad'      (Resolve-PimAdminName -Owner 'vnd' -AdminType 'external-adminuser' -Environment 'ad') 'external-adminuser AD -> x-admin-...-ad'
# --- high-priv carries L0-T0; default HighPriv pattern has NO prefix; suffix driven ---
AssertEq 'admin-mok-l0-t0-id'  (Resolve-PimAdminName -Owner 'mok' -HighPriv)                'high-priv internal Entra renders admin-mok-l0-t0-id'
AssertEq 'admin-skr-l0-t0-ad'  (Resolve-PimAdminName -Owner 'skr' -Environment 'ad' -HighPriv) 'high-priv AD carries L0-T0 + -ad'
AssertEq 'admin-skr-l0-t0-ad'  (Resolve-PimAdminName -Owner 'skr' -Platform 'AD' -HighPriv)    'high-priv: -Platform AD back-compat alias still works'
# --- "Admins" not "candidates": prefix/suffix resolvers + no literal "candidate" ---
AssertEq ''                    (Get-PimAdminTypePrefix -AdminType 'internal-adminuser') 'internal prefix is empty'
AssertEq ''                    (Get-PimAdminTypePrefix -AdminType 'external-guest')     'external-guest prefix is empty (default)'
AssertEq 'x-'                  (Get-PimAdminTypePrefix -AdminType 'external')           'external alias -> x- prefix'
AssertEq '-ID'                 (Get-PimEnvironmentSuffix -Environment 'entra')          'entra suffix -ID'
AssertEq '-AD'                 (Get-PimEnvironmentSuffix -Environment 'ad')             'ad suffix -AD'
Assert ((Resolve-PimAdminName -Owner 'x') -notmatch 'candidate') 'admin name has no "candidate" text'
AssertEq 'PIM-Helpdesk-IT'     (Resolve-PimGroupName -Role 'Helpdesk' -Department 'IT')    'group name simple shape'
AssertEq 'PIM-Helpdesk'        (Resolve-PimGroupName -Role 'Helpdesk')                     'group name with blank dept collapses trailing dash'
AssertEq 'PIM-User-Admin-AU-Users' (Resolve-PimGroupName -Role 'User Admin' -AdminUnit 'Users') 'AU subset group name'
# Resource group follows the full PIM convention (mixed case preserved).
AssertEq 'PIM-AzDevOps-OrgCollectionAdministrators-L2-T1-WDP-ID' `
         (Resolve-PimResourceGroup -Tier 1 -Workload 'AzDevOps' -Scope 'OrgCollectionAdministrators' -Permission '' -Level 2 -Plane 'WDP' -Platform 'ID') `
         'resource group name follows full PIM convention (PIM-{Workload}-{Scope}-{Permission}-L{Level}-T{Tier}-{Plane}-{Platform})'
# separator must be '-' never '_' / adm_ / PIM_
Assert ((Resolve-PimAdminName -Owner 'x') -notmatch '_')  'admin name has no underscore'
Assert ((Resolve-PimGroupName -Role 'x')  -notmatch 'PIM_') 'group name has no PIM_ literal'

# UPN-suffix branch (suffix appended AFTER the prefix+core+env-suffix name)
$global:PIM_NamingConventions = @{ AdminAccountUpnSuffix = 'contoso.com' }
AssertEq 'admin-jdo-id@contoso.com' (Resolve-PimAdminName -Owner 'jdo') 'admin name honours UPN suffix (after env suffix)'
$global:PIM_NamingConventions = $null

# Configurable prefix/suffix maps override the shipped defaults.
$global:PIM_NamingConventions = @{ AdminTypePrefixes = @{ 'external-adminuser' = 'ext-' }; EnvironmentSuffixes = @{ 'ad' = '-LEGACY' } }
AssertEq 'ext-admin-vnd-id'    (Resolve-PimAdminName -Owner 'vnd' -AdminType 'external-adminuser')  'custom prefix map honoured (ext-)'
AssertEq 'admin-jdo-legacy'    (Resolve-PimAdminName -Owner 'jdo' -Environment 'ad')                'custom env suffix map honoured (-LEGACY)'
$global:PIM_NamingConventions = $null

Write-Host "`n== Naming validation (§ 17) ==" -ForegroundColor Cyan
Assert (Test-PimAdminName -Name 'Admin-JDO-ID' -Purpose 'Day2Day')        'Day2Day internal Entra name passes'
Assert (Test-PimAdminName -Name 'x-Admin-VND-AD' -Purpose 'Day2Day')      'Day2Day external-adminuser AD name (x- prefix, -AD suffix) passes'
Assert (Test-PimAdminName -Name 'Admin-GST-ID' -Purpose 'Day2Day')        'Day2Day external-guest Entra name (no prefix) passes'
Assert (-not (Test-PimAdminName -Name 'z-Admin-JDO-ID' -Purpose 'Day2Day')) 'wrong prefix (z-) rejected'
Assert (-not (Test-PimAdminName -Name 'Admin-JDO-XX' -Purpose 'Day2Day'))  'wrong env suffix (-XX) rejected'
Assert (-not (Test-PimAdminName -Name 'Admin-JDO-ID' -Purpose 'HighPriv')) 'Day2Day name fails HighPriv check'
Assert (Test-PimAdminName -Name 'Admin-SKR-L0-T0-AD' -Purpose 'HighPriv')  'HighPriv AD name passes HighPriv check'
Assert (Test-PimAdminName -Name 'Admin-MOK-L0-T0-ID' -Purpose 'HighPriv') 'HighPriv internal Entra name passes'
Assert (Test-PimAdminName -Name 'Admin-JDO-ID@contoso.com' -Purpose 'Day2Day') 'UPN local part validated'
Assert (-not (Test-PimAdminName -Name 'jdoe' -Purpose 'Day2Day'))          'non-conforming admin name rejected'
Assert (Test-PimGroupName -Name 'PIM-Entra-ID-UserAdmin-L1-T0-CP-ID')      'canonical group grammar passes'
Assert (Test-PimGroupName -Name 'PIM-Helpdesk-IT')                         'simple group shape passes'
Assert (Test-PimGroupName -Name 'PIM-Helpdesk')                            'simple group shape w/o dept passes'
Assert (-not (Test-PimGroupName -Name 'totally bogus name!!'))             'bogus group name rejected'

# strict tag regex override wins
$global:PIM_NamingConventions = @{ PimGroupTagRegex = '^ROLE-[A-Za-z]+$' }
Assert (Test-PimGroupName -Name 'ROLE-Helpdesk')           'strict tag regex accepts a matching tag'
Assert (-not (Test-PimGroupName -Name 'PIM-Helpdesk-IT'))  'strict tag regex rejects a non-matching name'
$global:PIM_NamingConventions = $null

Write-Host "`n== v1 -> v2 migration (§ 18) ==" -ForegroundColor Cyan
$dir = Join-Path $env:TEMP ('pimmig-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $dir | Out-Null
try {
    $csv = Join-Path $dir 'v1.csv'
    @(
        'UserPrincipalName;RoleName;AssignmentType;Scope'
        'admin-jdo@contoso.com;Global Administrator;Eligible;/'
        'admin-jdo@contoso.com;User Administrator;Active;AU:Users'
        'admin-skr@contoso.com;Helpdesk Administrator;Eligible;/'
        'admin-skr@contoso.com;Global Administrator;Eligible;/'
        'admin-jdo@contoso.com;Global Administrator;Eligible;/'   # duplicate -> collapsed
    ) | Set-Content -LiteralPath $csv

    $before = (Get-Item $csv).LastWriteTimeUtc
    $v1 = Import-PimV1Baseline -Path $csv
    AssertEq 5 (@($v1).Count) 'v1 CSV rows read'

    $plan = ConvertTo-PimV2MigrationPlan -V1Rows $v1
    AssertEq 3 $plan.DistinctRoleCount        'distinct roles -> 3 groups (GA, UserAdmin, Helpdesk)'
    AssertEq 2 (@($plan.DistinctAdmins).Count) 'distinct admins -> 2'
    # jdo: GA + UserAdmin (GA dup collapsed) = 2 ; skr: Helpdesk + GA = 2 ; total 4
    AssertEq 4 (@($plan.AdminAssignments).Count) 'admin->group memberships -> 4 (dup collapsed)'
    AssertEq 3 (@($plan.RolesGroups).Count)      'group->role bindings -> 3'
    Assert (@($plan.Warnings).Count -ge 1)       'collapsed duplicate raised a warning'
    # every proposed group has a PIM- name + ROLE- tag
    foreach ($g in @($plan.Definitions)) {
        Assert ("$($g.GroupName)" -like 'PIM-*')   "group '$($g.GroupName)' uses PIM- prefix"
        Assert ("$($g.GroupTag)"  -like 'ROLE-*')  "group tag '$($g.GroupTag)' uses ROLE- prefix"
    }
    # GA active/eligible mapping: jdo's GA rows are Eligible -> Eligible
    $ga = @($plan.RolesGroups | Where-Object { $_.RoleDefinitionName -eq 'Global Administrator' })[0]
    AssertEq 'Eligible' $ga.AssignmentType 'Eligible v1 type maps to Eligible'
    $ua = @($plan.RolesGroups | Where-Object { $_.RoleDefinitionName -eq 'User Administrator' })[0]
    AssertEq 'Active' $ua.AssignmentType 'Active v1 type maps to Active'

    # non-destructive: source file unchanged
    AssertEq $before (Get-Item $csv).LastWriteTimeUtc 'v1 source file untouched (read-only)'

    # report renders + names the proposal explicitly
    $rpt = Format-PimMigrationReport -Plan $plan
    Assert ($rpt -match 'PROPOSAL, no writes performed') 'report flags proposal/no-writes'
    Assert ($rpt -match 'PIM-Definitions-Roles')         'report references the v2 target entity'

    # Custom-Policies.ps1 source
    $ps1 = Join-Path $dir 'Custom-Policies.ps1'
    @(
        '$Custom_Policies = @('
        '  [pscustomobject]@{ User = "admin-aaa@contoso.com"; Role = "Security Administrator"; Type = "Eligible" }'
        '  [pscustomobject]@{ User = "admin-bbb@contoso.com"; Role = "Exchange Administrator";  Type = "Active" }'
        ')'
    ) | Set-Content -LiteralPath $ps1
    $v1b  = Import-PimV1Baseline -Path $ps1
    AssertEq 2 (@($v1b).Count) 'Custom-Policies.ps1 rows harvested'
    $planB = ConvertTo-PimV2MigrationPlan -V1Rows $v1b
    AssertEq 2 $planB.DistinctRoleCount         'PS1 source -> 2 role groups'
    AssertEq 2 (@($planB.AdminAssignments).Count) 'PS1 source -> 2 memberships'

    # Invoke-PimV1Migration convenience surfaces the report on the object
    $one = Invoke-PimV1Migration -Path $csv
    Assert ([bool]$one.Report)     'Invoke-PimV1Migration attaches a Report'
    AssertEq $csv $one.SourcePath  'Invoke-PimV1Migration records SourcePath'
}
finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("`nRESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail) { 'Red' } else { 'Green' })
if ($script:Fail) { exit 1 } else { exit 0 }
