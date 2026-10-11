#Requires -Version 5.1
<#
.SYNOPSIS
  PIM REQUIREMENTS 98.5 -- the SAMPLE CONFIGURATION of the live demo environment: one made-up company, the common
  departments and made-up admin accounts, as REAL PIM Manager definitions (owner 2026-10-11: "demo: you are free to
  configure samples - make up a company and make common dept and make up sampe admins").

.DESCRIPTION
  Not the synthetic DISPLAY dataset of REQUIREMENTS 100.68 (b) (that one lives in its own SQL schema and is never read
  by the engine). THESE rows are ordinary definitions in pim.Rows: once they are committed the engine creates the
  matching Entra objects (admin accounts, groups, assignments) on its next run. That is intended on the demo tenant and
  is exactly why tools/setup/Set-PimDemoSamples.ps1 refuses anywhere else (the caller's demo-environment proof).

  THE MODEL (Get-PimDemoSampleModel, PURE and deterministic): the fictional company "Quillmere", 8 departments, 14 admin
  accounts in three tiers, 6 job-function groups, 8 department groups, 1 organization group, 10 Entra-role permission
  groups and 41 delegation rows (who gets which group, which group holds which permission group, which permission
  group holds which Entra role). Every row has the shape the Manager's own wizards write.

  HOW THE ROWS ARE WRITTEN (Invoke-PimDemoSampleChange): through the store's own upsert-only, transactional, journaled
  writer (Merge-PimSqlEntityRows, the one the supported importer uses) under a change-journal context with Source
  'demo-samples' -- never a private INSERT. A key the store already holds is NEVER overwritten (kept + reported), so a
  second run adds nothing. Before any write: the caller's demo proof, the model's own safety rules
  (Test-PimDemoSampleModel) and the Manager's pre-flight validator over the state the write would produce.

  HOW A SAMPLE ROW IS RECOGNISED (the marker): the change journal. A row is "a sample row" when the LATEST journal row
  of its (Entity, Key) has Source 'demo-samples' and is an Add / Modify. A row a person changed afterwards (its latest
  journal row is theirs) is no longer a sample row and is left alone. -Remove deletes exactly those rows, journaled as
  Remove under the same source, assignments first and definitions last.

  SAFETY RULES of the model (enforced, not only promised -- Test-PimDemoSampleModel): no Global Administrator,
  Privileged Role Administrator or Privileged Authentication Administrator; no direct role assignment; no Azure
  delegation; no setting; no row that disables, removes or offboards anything (every admin Enabled, every Action Assign,
  no Lifecycle / AutoDisableDate); only the entities listed in Get-PimDemoSampleEntityOrder.

  Windows PowerShell 5.1 and pwsh 7. ASCII only. No module, no az.
#>

$script:PimDemoSampleSource = 'demo-samples'
$script:PimDemoSampleCompany = 'Quillmere'
$script:PimDemoSampleEntityOrder = @(
    'Account-Definitions-Companies', 'PIM-Definitions-Departments', 'PIM-Definitions-Organization', 'PIM-Definitions-Roles',
    'PIM-Definitions-Tasks', 'PIM-Definitions-Services', 'Account-Definitions-Admins',
    'PIM-Assignments-Roles-Groups', 'PIM-Assignments-Groups', 'PIM-Assignments-Admins'
)
# Every entity the Manager's validator reads (the grid's entity list, Open-PimManager.ps1 $script:PimCsvBases).
# tests/Test-PimDemoSamples.ps1 keeps the two lists identical.
$script:PimDemoSampleValidatorBases = @(
    'Account-Definitions-Admins', 'Account-Definitions-Companies', 'PIM-Definitions-Roles', 'PIM-Definitions-Tasks',
    'PIM-Definitions-Services', 'PIM-Definitions-Processes', 'PIM-Definitions-Resources', 'PIM-Definitions-Departments',
    'PIM-Definitions-Organization', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg', 'PIM-Definitions-AU',
    'PIM-Assignments-Admins', 'PIM-Assignments-Groups', 'PIM-Assignments-Roles-Groups', 'PIM-Assignments-Roles-AUs',
    'PIM-Assignments-Azure-Resources', 'PIM-Assignments-Workloads'
)
# Roles a sample must never hold (each can make itself Global Administrator).
$script:PimDemoSampleForbiddenRoles = @('Global Administrator', 'Company Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator')

function Get-PimDemoSampleSource { $script:PimDemoSampleSource }
function Get-PimDemoSampleEntityOrder { @($script:PimDemoSampleEntityOrder) }
function Get-PimDemoSampleValidatorBases { @($script:PimDemoSampleValidatorBases) }
function Get-PimDemoSampleForbiddenRoles { @($script:PimDemoSampleForbiddenRoles) }

function New-PimDemoSampleRow {
    <# PURE. One row object from an ordered map (columns in the map's order). Built member by member: the same on 5.1 and 7. #>
    param([Parameter(Mandatory, Position = 0)][System.Collections.IDictionary]$Map)
    $o = New-Object psobject
    foreach ($k in @($Map.Keys)) { Add-Member -InputObject $o -NotePropertyName "$k" -NotePropertyValue $Map[$k] }
    return $o
}

function Get-PimDemoSampleModel {
    <#
      PURE, deterministic. The sample configuration for -Domain (the tenant's own verified domain; never hard-coded here).
      -DepartmentOwnerUpn: one or more EXISTING accounts of the tenant that own the departments (given in rotation over
      the 8 departments). They are the owners of the groups AND the recipients of the engine's mail about the
      department's admin accounts (new-admin notice, Temporary Access Pass) -- so they must be real mailboxes the
      operator chose, never invented ones.
      Returns { source; company; domain; owners[]; departments[]; admins[]; groups[]; entities (entity -> rows, in apply
      order); counts; engineObjects }.
    #>
    param([Parameter(Mandatory)][string]$Domain, [Parameter(Mandatory)][string[]]$DepartmentOwnerUpn, [string]$UsageLocation = 'US')
    $dom = "$Domain".Trim().ToLowerInvariant()
    if ($dom -notmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$') { throw "Get-PimDemoSampleModel: -Domain '$Domain' is not a domain name (expected e.g. demo.example.com)." }
    $owners = @($DepartmentOwnerUpn | ForEach-Object { "$_" -split '[|;,]' } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    if (-not $owners.Count) { throw 'Get-PimDemoSampleModel: -DepartmentOwnerUpn needs at least one existing account (user@domain).' }
    foreach ($o in $owners) { if ($o -notmatch '^[^@\s|;,]+@[^@\s|;,]+\.[^@\s|;,]+$') { throw "Get-PimDemoSampleModel: -DepartmentOwnerUpn '$o' is not a user principal name (user@domain)." } }
    $loc = "$UsageLocation".Trim().ToUpperInvariant()
    if ($loc -notmatch '^[A-Z]{2}$') { throw "Get-PimDemoSampleModel: -UsageLocation '$UsageLocation' is not a two-letter country code." }
    $company = $script:PimDemoSampleCompany

    # ---- departments: name, short tag, description ---------------------------------------------------------------
    $deptSpec = @(
        @('IT', 'IT', 'Information technology'),
        @('Finance', 'Finance', 'Finance and accounting'),
        @('HR', 'HR', 'Human resources'),
        @('Sales', 'Sales', 'Sales'),
        @('Marketing', 'Marketing', 'Marketing and communications'),
        @('Operations', 'Operations', 'Operations and logistics'),
        @('Legal', 'Legal', 'Legal and compliance'),
        @('Customer Support', 'CustomerSupport', 'Customer support')
    )
    $departments = New-Object System.Collections.Generic.List[object]
    $ownerOf = @{}
    for ($i = 0; $i -lt $deptSpec.Count; $i++) {
        $d = $deptSpec[$i]; $own = $owners[$i % $owners.Count]
        $ownerOf[$d[0]] = $own
        $departments.Add((New-PimDemoSampleRow ([ordered]@{ name = $d[0]; short = $d[1]; description = $d[2]; owner = $own; groupTag = "DEPT-$($d[1])"; groupName = "PIM-DEPT-$($d[1])" })))
    }
    $itOwner = $ownerOf['IT']

    $deptRows = New-Object System.Collections.Generic.List[object]
    foreach ($d in $departments) {
        # the owner row: the shape Access > Departments & owners saves (Save-PimManagerDepartments)
        $deptRows.Add((New-PimDemoSampleRow ([ordered]@{ Department = $d.name; Owners = $d.owner; Contact = ''; Notes = "$company sample department" })))
    }
    foreach ($d in $departments) {
        # the department's own group: the direct-group wizard, type department. Owners are repeated on the group row so
        # the department's owner is the same whichever of its two rows a reader meets first.
        $deptRows.Add((New-PimDemoSampleRow ([ordered]@{ Department = $d.name; GroupName = $d.groupName; GroupDescription = "$($d.description) -- department group ($company sample)"; GroupTag = $d.groupTag
            AdministrativeUnitTag = ''; IsRoleAssignable = 'FALSE'; TierLevel = 'T2'; Plane = ''; CPPlatform = ''; Owners = $d.owner; PolicyTemplate = '' })))
    }

    # ---- the company -------------------------------------------------------------------------------------------------
    $companyRows = @((New-PimDemoSampleRow ([ordered]@{ Company = $company; Type = 'Internal'; Contacts = ''; SponsorDepartment = 'IT'; ReviewCadenceDays = ''; Notes = 'Fictional sample company of the live demo' })))

    # ---- organization group ------------------------------------------------------------------------------------------
    $orgTag = "ORG-$company"
    $orgRows = @((New-PimDemoSampleRow ([ordered]@{ GroupName = "PIM-ORG-$company"; GroupDescription = "$company administration leads ($company sample)"; GroupTag = $orgTag; AdministrativeUnitTag = ''
        IsRoleAssignable = 'FALSE'; TierLevel = 'T1'; Plane = ''; CPPlatform = ''; Owners = $itOwner; PolicyTemplate = '' })))

    # ---- Entra-role permission groups (the permission wizard's shape): entity, name segment, Entra role ------------
    $permSpec = @(
        @('PIM-Definitions-Tasks', 'UserAdministrator', 'User Administrator'),
        @('PIM-Definitions-Tasks', 'HelpdeskAdministrator', 'Helpdesk Administrator'),
        @('PIM-Definitions-Tasks', 'GroupsAdministrator', 'Groups Administrator'),
        @('PIM-Definitions-Tasks', 'LicenseAdministrator', 'License Administrator'),
        @('PIM-Definitions-Tasks', 'BillingAdministrator', 'Billing Administrator'),
        @('PIM-Definitions-Tasks', 'ReportsReader', 'Reports Reader'),
        @('PIM-Definitions-Tasks', 'SecurityReader', 'Security Reader'),
        @('PIM-Definitions-Services', 'ExchangeAdministrator', 'Exchange Administrator'),
        @('PIM-Definitions-Services', 'IntuneAdministrator', 'Intune Administrator'),
        @('PIM-Definitions-Services', 'SecurityAdministrator', 'Security Administrator')
    )
    $permTag = @{}
    $taskRows = New-Object System.Collections.Generic.List[object]; $serviceRows = New-Object System.Collections.Generic.List[object]
    $roleGroupRows = New-Object System.Collections.Generic.List[object]
    foreach ($p in $permSpec) {
        $tag = "Entra-ID-$($p[1])-L1-T0-CP-ID"
        $permTag[$p[1]] = $tag
        $def = New-PimDemoSampleRow ([ordered]@{ GroupName = "PIM-$tag"; GroupDescription = "$($p[2]) ($company sample)"; GroupTag = $tag; AdministrativeUnitTag = ''; IsRoleAssignable = 'TRUE'
            Workload = 'Entra-ID'; Level = 'L1'; TierLevel = 'T0'; Plane = 'CP'; CPPlatform = 'ID'; Owners = $itOwner; PolicyTemplate = '' })
        if ($p[0] -eq 'PIM-Definitions-Tasks') { $taskRows.Add($def) } else { $serviceRows.Add($def) }
        $roleGroupRows.Add((New-PimDemoSampleRow ([ordered]@{ GroupTag = $tag; RoleDefinitionName = $p[2]; AssignmentType = 'Eligible'; Action = 'Assign'; UpdateExisting = 'FALSE'; AutoExtend = 'TRUE'
            NumOfDaysWhenExpire = '365'; Permanent = 'FALSE'; CPPlatform = 'ID'; Plane = 'CP'; TierLevel = 'T0'; PermissionScope = 'Global'; SyncPlatform = '' })))
    }

    # ---- job-function groups: tag, department, tier, description, permission groups, days, auto-extend -------------
    # Role-assignable, because each is nested (eligible) into role-assignable Entra-role groups.
    # (plain strings only: the permission groups are a comma-separated list)
    $roleSpec = @(
        @('ITOperations', 'IT', 'T1', 'IT operations engineers', 'UserAdministrator,GroupsAdministrator,IntuneAdministrator,ExchangeAdministrator', '365', 'TRUE'),
        @('ServiceDesk', 'IT', 'T2', 'Service desk agents', 'HelpdeskAdministrator', '365', 'TRUE'),
        @('SecurityOperations', 'IT', 'T0', 'Security operations (time-limited: renewed every 90 days)', 'SecurityAdministrator', '90', 'FALSE'),
        @('SecurityReview', 'Legal', 'T1', 'Compliance and security review', 'SecurityReader,ReportsReader', '365', 'TRUE'),
        @('FinanceSystems', 'Finance', 'T1', 'Finance systems and billing', 'BillingAdministrator,ReportsReader', '365', 'TRUE'),
        @('PeopleOnboarding', 'HR', 'T1', 'Joiners and leavers: licences', 'LicenseAdministrator', '365', 'TRUE')
    )
    $roleRows = New-Object System.Collections.Generic.List[object]; $nestRows = New-Object System.Collections.Generic.List[object]
    $roleTier = @{}
    foreach ($r in $roleSpec) {
        $tag = "ROLE-$($r[0])"
        $dShort = ''; foreach ($dd in $departments) { if ("$($dd.name)" -eq "$($r[1])") { $dShort = "$($dd.short)" } }
        $roleTier[$tag] = $r[2]
        $roleRows.Add((New-PimDemoSampleRow ([ordered]@{ GroupName = "PIM-$tag-$dShort"; GroupDescription = "$($r[3]) ($company sample)"; GroupTag = $tag; AdministrativeUnitTag = ''; CPPlatform = ''; Plane = ''
            TierLevel = $r[2]; PermissionScope = ''; SyncPlatform = ''; IsRoleAssignable = 'TRUE'; Owners = ''; SponsorUpn = ''; Department = $r[1]; PolicyTemplate = '' })))
        foreach ($seg in @("$($r[4])" -split ',')) {
            $nestRows.Add((New-PimDemoSampleRow ([ordered]@{ TargetGroupTag = $tag; SourceGroupTag = $permTag[$seg]; AssignmentType = 'Eligible'; Action = 'Assign'; UpdateExisting = 'FALSE'; AutoExtend = $r[6]
                NumOfDaysWhenExpire = $r[5]; Permanent = 'FALSE'; CPPlatform = ''; Plane = ''; TierLevel = $r[2]; PermissionScope = ''; SyncPlatform = '' })))
        }
    }

    # ---- admin accounts: first, last, initials, tier, department, assignments 'group tag:type:days:auto-extend;...' --
    $adminSpec = @(
        @('Avery', 'Ashdown', 'AAS', 'T0', 'IT', 'ROLE-SecurityOperations:Eligible:90:FALSE'),
        @('Morgan', 'Kestrel', 'MKE', 'T0', 'IT', 'ROLE-SecurityOperations:Eligible:90:FALSE'),
        @('Jordan', 'Briarwood', 'JBR', 'T1', 'IT', "ROLE-ITOperations:Eligible:365:TRUE;${orgTag}:Active:365:TRUE"),
        @('Casey', 'Coldwater', 'CCO', 'T1', 'IT', 'ROLE-ITOperations:Eligible:365:TRUE'),
        @('Riley', 'Dunmore', 'RDU', 'T1', 'Finance', 'ROLE-FinanceSystems:Eligible:365:TRUE'),
        @('Quinn', 'Eastlake', 'QEA', 'T1', 'HR', 'ROLE-PeopleOnboarding:Eligible:365:TRUE;DEPT-HR:Active:365:TRUE'),
        @('Harper', 'Fairholm', 'HFA', 'T1', 'Legal', 'ROLE-SecurityReview:Eligible:365:TRUE;DEPT-Legal:Active:365:TRUE'),
        @('Rowan', 'Greyfield', 'RGR', 'T1', 'Operations', "DEPT-Operations:Active:365:TRUE;${orgTag}:Active:365:TRUE"),
        @('Sage', 'Hartwell', 'SHA', 'T1', 'Sales', 'DEPT-Sales:Active:365:TRUE'),
        @('Taylor', 'Ironside', 'TIR', 'T2', 'IT', 'ROLE-ServiceDesk:Eligible:365:TRUE;DEPT-IT:Active:365:TRUE'),
        @('Emery', 'Larkspur', 'ELA', 'T2', 'Customer Support', 'ROLE-ServiceDesk:Eligible:30:FALSE;DEPT-CustomerSupport:Active:365:TRUE'),
        @('Finley', 'Merrow', 'FME', 'T2', 'Customer Support', 'ROLE-ServiceDesk:Eligible:365:TRUE'),
        @('Blake', 'Northcott', 'BNO', 'T2', 'Marketing', 'DEPT-Marketing:Active:365:TRUE'),
        @('Dana', 'Oakhurst', 'DOA', 'T2', 'Finance', 'DEPT-Finance:Active:365:TRUE')
    )
    $adminRows = New-Object System.Collections.Generic.List[object]; $adminAssignRows = New-Object System.Collections.Generic.List[object]
    $admins = New-Object System.Collections.Generic.List[object]
    $groupTier = @{}; foreach ($k in $roleTier.Keys) { $groupTier[$k] = $roleTier[$k] }
    foreach ($d in $departments) { $groupTier[$d.groupTag] = 'T2' }
    $groupTier[$orgTag] = 'T1'
    foreach ($a in $adminSpec) {
        $high = ($a[3] -eq 'T0')
        $purpose = if ($high) { 'HighPriv' } else { 'Day2Day' }
        # the shipped naming convention (Resolve-PimAdminName): admin-<initials>-id, high-privilege admin-<initials>-l0-t0-id
        $userName = if ($high) { ('admin-{0}-l0-t0-id' -f $a[2].ToLowerInvariant()) } else { ('admin-{0}-id' -f $a[2].ToLowerInvariant()) }
        $upn = "$userName@$dom"
        $display = if ($high) { "$($a[0]) $($a[1]) (Admin, Cloud, ID, L0, T0)" } else { "$($a[0]) $($a[1]) (Admin, Cloud, ID)" }
        $adminRows.Add((New-PimDemoSampleRow ([ordered]@{ FirstName = $a[0]; LastName = $a[1]; Initials = $a[2]; Purpose = $purpose; TargetUsage = 'Cloud'; TargetPlatform = 'ID'
            UserType = 'Internal'; AdminType = 'internal-adminuser'; UserName = $userName; DisplayName = $display; UserPrincipalName = $upn; UsageLocation = $loc; Company = $company
            Department = $a[4]; Environment = 'entra'; CreateTAP = 'TRUE'; AccountStatus = 'Enabled'; ManagementMode = 'local' })))
        $adminGroups =New-Object System.Collections.Generic.List[string]
        foreach ($spec in @("$($a[5])" -split ';')) {
            $g = @($spec -split ':')
            $adminGroups.Add("$($g[0])")
            $adminAssignRows.Add((New-PimDemoSampleRow ([ordered]@{ Username = $upn; GroupTag = "$($g[0])"; AssignmentType = "$($g[1])"; Action = 'Assign'; UpdateExisting = 'FALSE'; AutoExtend = "$($g[3])"
                NumOfDaysWhenExpire = "$($g[2])"; Permanent = 'FALSE'; CPPlatform = ''; Plane = ''; TierLevel = "$($groupTier["$($g[0])"])"; PermissionScope = ''; SyncPlatform = '' })))
        }
        $admins.Add((New-PimDemoSampleRow ([ordered]@{ name = "$($a[0]) $($a[1])"; initials = $a[2]; tier = $a[3]; department = $a[4]; userName = $userName; userPrincipalName = $upn; groups = @($adminGroups.ToArray()) })))
    }

    $entities = [ordered]@{}
    $entities['Account-Definitions-Companies'] = @($companyRows)
    $entities['PIM-Definitions-Departments'] = @($deptRows.ToArray())
    $entities['PIM-Definitions-Organization'] = @($orgRows)
    $entities['PIM-Definitions-Roles'] = @($roleRows.ToArray())
    $entities['PIM-Definitions-Tasks'] = @($taskRows.ToArray())
    $entities['PIM-Definitions-Services'] = @($serviceRows.ToArray())
    $entities['Account-Definitions-Admins'] = @($adminRows.ToArray())
    $entities['PIM-Assignments-Roles-Groups'] = @($roleGroupRows.ToArray())
    $entities['PIM-Assignments-Groups'] = @($nestRows.ToArray())
    $entities['PIM-Assignments-Admins'] = @($adminAssignRows.ToArray())

    $groups = New-Object System.Collections.Generic.List[object]
    foreach ($e in @('PIM-Definitions-Departments', 'PIM-Definitions-Organization', 'PIM-Definitions-Roles', 'PIM-Definitions-Tasks', 'PIM-Definitions-Services')) {
        foreach ($r in @($entities[$e])) { if ("$($r.GroupTag)".Trim()) { $isRa = ("$($r.IsRoleAssignable)" -eq 'TRUE'); $groups.Add((New-PimDemoSampleRow ([ordered]@{ entity = $e; tag = "$($r.GroupTag)"; name = "$($r.GroupName)"; roleAssignable = $isRa }))) } }
    }
    $total = 0; foreach ($e in $entities.Keys) { $total += @($entities[$e]).Count }
    $delegations = $roleGroupRows.Count + $nestRows.Count + $adminAssignRows.Count
    $timeLimited = @(@($nestRows.ToArray()) + @($adminAssignRows.ToArray()) | Where-Object { "$($_.AutoExtend)" -eq 'FALSE' }).Count
    $counts = [ordered]@{ companies = 1; departments = $departments.Count; admins = $admins.Count; groups = $groups.Count; roleAssignableGroups = @($groups | Where-Object { $_.roleAssignable }).Count
        entraRoles = $roleGroupRows.Count; delegationRows = $delegations; timeLimited = $timeLimited; rows = $total }
    # What the engine creates in the tenant from these rows, said once for the plan, the docs and the report.
    $engineObjects = @(
        ("{0} admin accounts (user accounts '{1}' and '{2}' @{3}), each with a Temporary Access Pass that is mailed -- with a new-admin notice -- to the owner(s) of its department" -f $admins.Count, 'admin-<initials>-id', 'admin-<initials>-l0-t0-id', $dom),
        ("{0} security groups: {1} department groups (PIM-DEPT-*), 1 organization group (PIM-ORG-{2}), {3} job-function groups (PIM-ROLE-*, role-assignable) and {4} Entra-role permission groups (PIM-Entra-ID-*, role-assignable), owned by the department owners given" -f $groups.Count, $departments.Count, $company, $roleRows.Count, $roleGroupRows.Count),
        ("{0} eligible Entra role assignments, one per permission group: {1}" -f $roleGroupRows.Count, ((@($roleGroupRows.ToArray()) | ForEach-Object { "$($_.RoleDefinitionName)" }) -join ', ')),
        ("{0} eligible group-in-group memberships (job-function group -> permission group), 1 of them for 90 days without auto-renewal" -f $nestRows.Count),
        ("{0} admin memberships: {1} eligible in a job-function group ({2} time-limited, no auto-renewal) and {3} active in a department / organization group" -f $adminAssignRows.Count, @($adminAssignRows.ToArray() | Where-Object { $_.AssignmentType -eq 'Eligible' }).Count, @($adminAssignRows.ToArray() | Where-Object { $_.AutoExtend -eq 'FALSE' }).Count, @($adminAssignRows.ToArray() | Where-Object { $_.AssignmentType -eq 'Active' }).Count)
    )
    return [pscustomobject][ordered]@{ source = $script:PimDemoSampleSource; company = $company; domain = $dom; owners = @($owners); departments = @($departments.ToArray()); admins = @($admins.ToArray())
        groups = @($groups.ToArray()); entities = $entities; counts = $counts; engineObjects = @($engineObjects) }
}

function Get-PimDemoSampleRowLabel {
    <# PURE. A short human name for one sample row (the plan prints it). #>
    param([Parameter(Mandatory)][string]$Entity, [Parameter(Mandatory)][object]$Row)
    $g = { param($n) $p = $Row.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { "$($p.Value)" } else { '' } }
    switch ($Entity) {
        'Account-Definitions-Companies' { return (& $g 'Company') }
        'Account-Definitions-Admins'    { return ("{0} {1} ({2})" -f (& $g 'FirstName'), (& $g 'LastName'), (& $g 'UserName')) }
        'PIM-Definitions-Departments'   { if ((& $g 'GroupTag')) { return (& $g 'GroupName') }; return ("{0} (owner {1})" -f (& $g 'Department'), (& $g 'Owners')) }
        'PIM-Assignments-Admins'        { return ("{0} -> {1} ({2}, {3} days)" -f ((& $g 'Username') -replace '@.*$', ''), (& $g 'GroupTag'), (& $g 'AssignmentType'), (& $g 'NumOfDaysWhenExpire')) }
        'PIM-Assignments-Groups'        { return ("{0} -> {1} ({2}, {3} days)" -f (& $g 'TargetGroupTag'), (& $g 'SourceGroupTag'), (& $g 'AssignmentType'), (& $g 'NumOfDaysWhenExpire')) }
        'PIM-Assignments-Roles-Groups'  { return ("{0} -> {1}" -f (& $g 'GroupTag'), (& $g 'RoleDefinitionName')) }
        default                         { return (& $g 'GroupName') }
    }
}

function Test-PimDemoSampleModel {
    <#
      PURE. The model's own rules, checked before any write (and by the tests): only the sample entities; every row has
      a store key (Get-PimStoreRowKey) and no two rows share one; no forbidden role; no direct role / Azure / workload
      row; nothing that disables, removes or offboards; every reference resolves inside the model (group tags, admins,
      departments); every account is in -Domain. Returns { ok; problems[] }.
    #>
    param([Parameter(Mandatory)][object]$Model)
    $bad = New-Object System.Collections.Generic.List[string]
    $allowed = @($script:PimDemoSampleEntityOrder)
    $ents = $Model.entities
    $names = @($ents.Keys)
    foreach ($e in $names) { if ($allowed -notcontains "$e") { $bad.Add("entity '$e' is not a sample entity") } }
    if (-not $names.Count) { $bad.Add('the model has no rows') }
    $val = { param($r, $n) $p = $r.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { "$($p.Value)".Trim() } else { '' } }
    $tags = @{}; $upns = @{}; $depts = @{}
    foreach ($e in $names) {
        $rows = @($ents[$e])
        foreach ($r in $rows) {
            if ($null -eq $r) { $bad.Add("${e}: a null row"); continue }
            $k = Get-PimStoreRowKey -Base $e -Row $r
            if (-not $k) { $bad.Add("${e}: a row has no store key") }
            foreach ($c in @('Lifecycle', 'AutoDisableDate', 'OffboardDate', 'ProvisionDate', 'StatusChangeCode', 'Replicate', 'Ring', 'Target')) { if ((& $val $r $c)) { $bad.Add("${e} '$k': column $c must stay blank in a sample") } }
            $act = (& $val $r 'Action'); if ($act -and $act -ne 'Assign') { $bad.Add("${e} '$k': Action '$act' (a sample only assigns)") }
            $role = (& $val $r 'RoleDefinitionName')
            if ($role -and (@($script:PimDemoSampleForbiddenRoles | ForEach-Object { $_.ToLowerInvariant() }) -contains $role.ToLowerInvariant())) { $bad.Add("${e} '$k': the role '$role' is never part of a sample") }
            if ($e -like 'PIM-Definitions-*') { $t = (& $val $r 'GroupTag'); if ($t) { if ($tags.ContainsKey($t.ToLowerInvariant())) { $bad.Add("group tag '$t' is defined twice") }; $tags[$t.ToLowerInvariant()] = $r } }
            if ($e -eq 'PIM-Definitions-Departments' -and -not (& $val $r 'GroupTag')) { $depts[(& $val $r 'Department').ToLowerInvariant()] = $true; if (-not (& $val $r 'Owners')) { $bad.Add("department '$k' has no owner") } }
            if ($e -eq 'Account-Definitions-Admins') {
                $u = (& $val $r 'UserPrincipalName').ToLowerInvariant()
                if (-not $u.EndsWith("@$($Model.domain)")) { $bad.Add("admin '$k' is not in the domain $($Model.domain)") }
                if ((& $val $r 'AccountStatus') -ne 'Enabled') { $bad.Add("admin '$k': AccountStatus must be Enabled") }
                if ($u) { $upns[$u] = $true }
            }
        }
        foreach ($dup in @(Get-PimDuplicateStoreKeys -Base $e -Rows $rows)) { $bad.Add("${e}: store key '$($dup.key)' is used by $($dup.count) rows") }
    }
    foreach ($e in $names) {
        foreach ($r in @($ents[$e])) {
            if ($null -eq $r) { continue }
            if ($e -like 'PIM-Assignments-*') { foreach ($c in @('GroupTag', 'TargetGroupTag', 'SourceGroupTag')) { $t = (& $val $r $c); if ($t -and -not $tags.ContainsKey($t.ToLowerInvariant())) { $bad.Add("${e}: $c '$t' is not a group of the sample") } } }
            if ($e -eq 'PIM-Assignments-Admins') { $u = (& $val $r 'Username').ToLowerInvariant(); if (-not $upns.ContainsKey($u)) { $bad.Add("${e}: '$u' is not an admin of the sample") } }
            if ($e -eq 'PIM-Assignments-Roles-Groups') { $t = (& $val $r 'GroupTag'); if ($t -and $tags.ContainsKey($t.ToLowerInvariant()) -and "$($tags[$t.ToLowerInvariant()].IsRoleAssignable)" -ne 'TRUE') { $bad.Add("${e}: '$t' holds an Entra role but is not role-assignable") } }
            if ($e -eq 'PIM-Assignments-Groups' -or $e -eq 'PIM-Assignments-Admins') {
                # Entra refuses an ACTIVE membership in a role-assignable group (the validator's PIM-RA-002).
                $c = if ($e -eq 'PIM-Assignments-Groups') { (& $val $r 'SourceGroupTag') } else { (& $val $r 'GroupTag') }
                if ($c -and $tags.ContainsKey($c.ToLowerInvariant()) -and "$($tags[$c.ToLowerInvariant()].IsRoleAssignable)" -eq 'TRUE' -and (& $val $r 'AssignmentType') -ne 'Eligible') { $bad.Add("${e}: an Active membership in the role-assignable group '$c'") }
            }
            $d = (& $val $r 'Department')
            if ($d -and $e -ne 'PIM-Definitions-Departments' -and -not $depts.ContainsKey($d.ToLowerInvariant())) { $bad.Add("${e}: department '$d' is not a department of the sample") }
        }
    }
    return [pscustomobject]@{ ok = ($bad.Count -eq 0); problems = @($bad.ToArray()) }
}

function Get-PimDemoSampleApplyPlan {
    <#
      PURE. What applying -Model would do to a store that holds -Existing (@{ entity = @( @{ key; row } ) }): per entity
      add (the store lacks the key) / present (the store holds the same row) / kept (the store holds the key with OTHER
      content -- never overwritten). Decided by the store's own Get-PimSqlMergePlan -OnKeyConflict KeepExisting.
    #>
    param([Parameter(Mandatory)][object]$Model, [hashtable]$Existing = @{})
    $per = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($script:PimDemoSampleEntityOrder)) {
        if (-not $Model.entities.Contains($e)) { continue }
        $have = if ($Existing.ContainsKey($e)) { @($Existing[$e]) } else { @() }
        $p = Get-PimSqlMergePlan -Base $e -Rows @($Model.entities[$e]) -Existing $have -OnKeyConflict KeepExisting
        $per.Add([pscustomobject][ordered]@{ entity = $e; add = @($p.add); present = @($p.unchanged); kept = @($p.kept); skippedNoKey = [int]$p.skippedNoKey; collapsed = [int]$p.collapsed })
    }
    $sum = { param($n) $t = 0; foreach ($x in $per) { $t += @($x.$n).Count }; $t }
    return [pscustomobject][ordered]@{ entities = @($per.ToArray()); add = (& $sum 'add'); present = (& $sum 'present'); kept = (& $sum 'kept') }
}

function Test-PimDemoSampleJournalRowIsSample {
    <# PURE. -History: one store row's journal rows, oldest first. A sample row = its LATEST journal row is an Add / Modify with Source 'demo-samples'. #>
    param([AllowNull()][object[]]$History)
    $h = @(@($History) | Where-Object { $null -ne $_ })
    if (-not $h.Count) { return $false }
    $last = $h[-1]
    return ("$($last.Source)".Trim() -eq $script:PimDemoSampleSource -and "$($last.Op)".Trim() -in @('Add', 'Modify'))
}

function Get-PimDemoSampleRemovePlan {
    <#
      PURE. Which stored rows -Remove takes away: of the (entity, key) pairs the journal ever saw under the sample source
      (-Refs @( @{ entity; key } )), those that are STILL stored (-Existing) and whose latest journal row is the sample's
      (-History 'entity|key' lower -> rows oldest first). A row someone changed afterwards is kept and reported; a row
      already gone is skipped. Assignments first, definitions last.
    #>
    param([object[]]$Refs = @(), [hashtable]$Existing = @{}, [hashtable]$History = @{})
    $byEntity = @{}
    foreach ($r in @($Refs)) {
        if ($null -eq $r) { continue }
        $e = "$($r.entity)".Trim(); $k = "$($r.key)".Trim()
        if (-not $e -or -not $k) { continue }
        if (-not $byEntity.ContainsKey($e)) { $byEntity[$e] = New-Object System.Collections.Generic.List[string] }
        if ($byEntity[$e] -notcontains $k) { $byEntity[$e].Add($k) }
    }
    $order = New-Object System.Collections.Generic.List[string]
    $known = @($script:PimDemoSampleEntityOrder); [array]::Reverse($known)
    foreach ($e in $known) { if ($byEntity.ContainsKey($e)) { $order.Add($e) } }
    foreach ($e in @($byEntity.Keys | Sort-Object)) { if ($order -notcontains $e) { $order.Insert(0, $e) } }   # an entity an older sample used: before the definitions
    $per = New-Object System.Collections.Generic.List[object]
    foreach ($e in $order) {
        $stored = @{}
        if ($Existing.ContainsKey($e)) { foreach ($x in @($Existing[$e])) { if ($null -ne $x -and "$($x.key)") { $stored["$($x.key)".ToLowerInvariant()] = $x } } }
        $remove = New-Object System.Collections.Generic.List[object]; $changed = New-Object System.Collections.Generic.List[object]; $gone = 0
        foreach ($k in @($byEntity[$e] | Sort-Object)) {
            if (-not $stored.ContainsKey($k.ToLowerInvariant())) { $gone++; continue }
            $hk = ("{0}|{1}" -f $e, $k).ToLowerInvariant()
            $hist = if ($History.ContainsKey($hk)) { @($History[$hk]) } else { @() }
            if (Test-PimDemoSampleJournalRowIsSample -History $hist) { $remove.Add($stored[$k.ToLowerInvariant()]) }
            else { $changed.Add([pscustomobject]@{ key = "$($stored[$k.ToLowerInvariant()].key)"; by = $(if ($hist.Count) { "$($hist[-1].InitiatedBy) ($($hist[-1].Source))" } else { 'unknown' }) }) }
        }
        $per.Add([pscustomobject][ordered]@{ entity = $e; remove = @($remove.ToArray()); changed = @($changed.ToArray()); gone = $gone })
    }
    $nr = 0; $nc = 0; foreach ($x in $per) { $nr += @($x.remove).Count; $nc += @($x.changed).Count }
    return [pscustomobject][ordered]@{ entities = @($per.ToArray()); remove = $nr; changed = $nc }
}

function Get-PimDemoSampleValidationErrors {
    <#
      Runs the Manager's own pre-flight validator (tools/pim-manager/_validator.ps1 Invoke-PimPreflightValidation) over
      the state a write would produce: every entity's stored rows (-ReadRows { param($entity) } -> rows) with -Pending
      (@{ entity = rows }) replacing the entities it names. The validator's host functions are defined HERE, for this
      call only. Returns the ERROR-severity findings as @( @{ code; entity; message; signature } ). Throws when the
      validator cannot run (the caller then writes nothing).
    #>
    param([Parameter(Mandatory)][string]$ValidatorPath, [Parameter(Mandatory)][scriptblock]$ReadRows, [hashtable]$Pending = @{}, [hashtable]$Naming = @{})
    if (-not (Test-Path -LiteralPath $ValidatorPath)) { throw "the Manager's validator was not found at $ValidatorPath" }
    $script:__pimDemoSampleReadRows = $ReadRows
    $script:__pimDemoSampleNaming = $Naming
    function Get-PimCsvBases { return , @($script:PimDemoSampleValidatorBases | ForEach-Object { [pscustomobject]@{ base = $_ } }) }
    function Get-PimNamingConventions { return $script:__pimDemoSampleNaming }
    function Read-PimRows {
        param([Parameter(Position = 0)][string]$BaseName, [switch]$NoScope)
        $rows = @(& $script:__pimDemoSampleReadRows $BaseName)
        $hdr = if ($rows.Count) { @($rows[0].PSObject.Properties.Name) } else { @() }
        return @{ header = $hdr; rows = $rows; source = 'sql'; path = "sql:$BaseName" }
    }
    . $ValidatorPath
    $res = Invoke-PimPreflightValidation -PendingRows $Pending
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($v in @($res.violations)) {
        if ($null -eq $v -or "$($v.Severity)" -ne 'error') { continue }
        $out.Add([pscustomobject][ordered]@{ code = "$($v.Code)"; entity = "$($v.Csv)"; message = "$($v.Message)"; signature = ("{0}|{1}|{2}" -f "$($v.Code)", "$($v.Csv)", "$($v.Message)") })
    }
    return @($out.ToArray())
}

function Remove-PimDemoSampleStoreRows {
    <#
      Deletes the given rows of ONE entity in ONE transaction through the store's set-based journaled writer
      (Invoke-PimSqlEntityRowBatchTx): -Rows @( @{ key; json } ) where json is the stored JSON the plan saw. A row whose
      stored JSON is no longer that (someone changed it since the plan) is NOT deleted. Returns { removed; skipped }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity, [AllowEmptyCollection()][object[]]$Rows = @())
    $want = @($Rows | Where-Object { $null -ne $_ -and "$($_.key)" })
    if (-not $want.Count) { return [pscustomobject]@{ removed = 0; skipped = 0 } }
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    $tx = $null
    try {
        $c.Open(); $tx = $c.BeginTransaction()
        $cmd = $c.CreateCommand(); $cmd.Transaction = $tx
        $cmd.CommandText = 'SELECT [Key], DataJson FROM pim.Rows WITH (UPDLOCK, HOLDLOCK) WHERE Entity=@e'
        [void]$cmd.Parameters.AddWithValue('@e', $Entity)
        $now = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
        $rd = $cmd.ExecuteReader()
        try { while ($rd.Read()) { $now["$($rd.GetValue(0))"] = @{ key = "$($rd.GetValue(0))"; json = $(if ($rd.IsDBNull(1)) { '' } else { "$($rd.GetValue(1))" }) } } } finally { $rd.Close() }
        $items = New-Object System.Collections.Generic.List[object]; $skipped = 0
        foreach ($w in $want) {
            if (-not $now.ContainsKey("$($w.key)")) { $skipped++; continue }
            $cur = $now["$($w.key)"]
            if (-not [string]::Equals("$($cur.json)", "$($w.json)", [StringComparison]::Ordinal)) { $skipped++; continue }
            $items.Add([ordered]@{ k = "$($cur.key)"; op = 'Remove'; d = $null; b = "$($cur.json)" })
        }
        if ($items.Count) { [void](Invoke-PimSqlEntityRowBatchTx -Connection $c -Transaction $tx -Entity $Entity -Items @($items.ToArray())) }
        $tx.Commit(); $tx = $null
        return [pscustomobject]@{ removed = $items.Count; skipped = $skipped }
    } catch {
        if ($tx) { try { $tx.Rollback() } catch { Write-Warning "  [sql] transaction rollback failed: $($_.Exception.Message)" } }
        throw
    } finally {
        if ($c) { $c.Close(); $c.Dispose() }
    }
}

function New-PimDemoSampleSqlStore {
    <#
      The store operations Invoke-PimDemoSampleChange uses, over the real SQL store -- each one a store / journal library
      function, none a private write. (The tests hand in an in-memory store with the same operations.)
      Every operation is called with the store itself first:
        ReadRows   store, entity                 -> @( @{ key; row; json } )
        SampleRefs store                         -> @( @{ entity; key } ) every row the journal ever saw under the sample source
        History    store, refs                   -> 'entity|key' (lower) -> journal rows oldest first (THROWS when unreadable)
        Merge      store, entity, rows           -> Merge-PimSqlEntityRows -OnKeyConflict KeepExisting (add only, journaled)
        Remove     store, entity, @(@{key;json}) -> Remove-PimDemoSampleStoreRows (journaled)
        Audit      store, action, target, after  -> Write-PimSqlAuditEvent
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$Actor = '')
    # No closures: every operation receives the store itself as its first argument (a closure would run in its own
    # module scope and would not see the store functions a setup script dot-sourced into ITS scope).
    return @{
        ConnectionString = $ConnectionString
        Actor      = $(if ("$Actor".Trim()) { "$Actor".Trim() } else { 'setup' })
        ReadRows   = {
            param($s, $entity)
            $o = New-Object System.Collections.Generic.List[object]
            foreach ($r in @(Invoke-PimSqlQuery -ConnectionString $s.ConnectionString -Sql 'SELECT [Key], DataJson FROM pim.Rows WHERE Entity = @e ORDER BY [Key]' -Parameters @{ e = "$entity" })) {
                $j = "$($r.DataJson)"
                $o.Add(@{ key = "$($r.Key)"; json = $j; row = $(if ($j.Trim()) { $j | ConvertFrom-Json } else { [pscustomobject]@{} }) })
            }
            return @($o.ToArray())   # callers wrap in @(): no leading comma, or an empty result would arrive as one (empty) element
        }
        SampleRefs = {
            param($s)
            $o = New-Object System.Collections.Generic.List[object]
            foreach ($r in @(Invoke-PimSqlQuery -ConnectionString $s.ConnectionString -Sql 'SELECT DISTINCT Entity, [Key] FROM pim.CommitJournal WHERE Source = @s' -Parameters @{ s = (Get-PimDemoSampleSource) })) { $o.Add(@{ entity = "$($r.Entity)"; key = "$($r.Key)" }) }
            return @($o.ToArray())   # callers wrap in @(): no leading comma, or an empty result would arrive as one (empty) element
        }
        History    = { param($s, $refs) return (Get-PimCommitJournalKeyHistory -ConnectionString $s.ConnectionString -Refs @($refs)) }
        Merge      = { param($s, $entity, $rows) return (Merge-PimSqlEntityRows -ConnectionString $s.ConnectionString -Entity "$entity" -Base "$entity" -Rows @($rows) -OnKeyConflict KeepExisting) }
        Remove     = { param($s, $entity, $rows) return (Remove-PimDemoSampleStoreRows -ConnectionString $s.ConnectionString -Entity "$entity" -Rows @($rows)) }
        Audit      = { param($s, $action, $target, $after) Write-PimSqlAuditEvent -ConnectionString $s.ConnectionString -Actor "$($s.Actor)" -ActorSource 'setup' -Action "$action" -Target "$target" -After $after }
    }
}

function Invoke-PimDemoSampleChange {
    <#
      The plan and -- with -Apply -- the change.
        -Action Apply : REFUSED (throw, nothing read or written) unless -Eligibility (the caller's demo-environment proof,
                        Get-PimDemoModeEligibility's result) allows it. Then: the model's own rules; the stored rows;
                        the plan; the Manager's validator over the result (-Validate { param($pending) } -> the error
                        findings it would have, minus the ones the store has today; any NEW error refuses). With -Apply
                        each entity's missing rows are written through Store.Merge in definition-before-assignment
                        order under ONE change-journal commit (Source 'demo-samples'), audited, and read back.
        -Action Remove: allowed anywhere -- it only deletes rows the journal says are the sample's own (and a customer
                        environment has none, because Apply is refused there). Assignments first, definitions last.
      Returns { action; applied; commitId; source; plan (lines); entities[]; added / present / kept / removed / changed }.
    #>
    param([Parameter(Mandatory)][ValidateSet('Apply', 'Remove')][string]$Action, [Parameter(Mandatory)][hashtable]$Store, [object]$Model = $null,
          [object]$Eligibility = $null, [switch]$Apply, [scriptblock]$Validate = $null, [string]$Actor = '')
    $src = $script:PimDemoSampleSource
    $lines = New-Object System.Collections.Generic.List[string]
    $who = if ("$Actor".Trim()) { "$Actor".Trim() } else { 'setup' }
    if ($Action -eq 'Apply') {
        if ($null -eq $Eligibility -or -not $Eligibility.allowed) {
            $r = if ($Eligibility) { @($Eligibility.reasons) -join '; ' } else { 'the environment was not checked' }
            throw "REFUSED: the sample configuration is allowed only on the demo environment -- $r. Nothing was written."
        }
        if ($null -eq $Model) { throw 'REFUSED: no sample model was given. Nothing was written.' }
        $chk = Test-PimDemoSampleModel -Model $Model
        if (-not $chk.ok) { throw ("REFUSED: the sample model breaks its own rules -- {0}. Nothing was written." -f (@($chk.problems | Select-Object -First 5) -join '; ')) }
        $existing = @{}
        foreach ($e in @($Model.entities.Keys)) { $existing["$e"] = @(& $Store.ReadRows $Store "$e") }
        $plan = Get-PimDemoSampleApplyPlan -Model $Model -Existing $existing
        foreach ($p in $plan.entities) {
            $lines.Add(("{0}: add {1}, already there {2}, kept as they are (same key, other content) {3}" -f $p.entity, @($p.add).Count, @($p.present).Count, @($p.kept).Count))
            foreach ($x in @($p.add)) { $lines.Add(("    + {0}" -f (Get-PimDemoSampleRowLabel -Entity $p.entity -Row $x.row))) }
            foreach ($x in @($p.kept)) { $lines.Add(("    = kept: '{0}' is already in the store with other content -- not changed" -f $x.key)) }
            if ($p.skippedNoKey -or $p.collapsed) { throw "REFUSED: $($p.entity) has $($p.skippedNoKey) row(s) without a key and $($p.collapsed) sharing one. Nothing was written." }
        }
        if ($Validate -and $plan.add -gt 0) {
            $pending = @{}
            foreach ($p in $plan.entities) {
                if (-not @($p.add).Count) { continue }
                $pending[$p.entity] = @(@($existing[$p.entity] | ForEach-Object { $_.row }) + @($p.add | ForEach-Object { $_.row }))
            }
            $before = @{}; foreach ($v in @(& $Validate @{})) { $before["$($v.signature)"] = $true }
            $new = @(@(& $Validate $pending) | Where-Object { -not $before.ContainsKey("$($_.signature)") })
            if ($new.Count) {
                throw ("REFUSED: the Manager's validator finds {0} error(s) the sample rows would add -- {1}. Nothing was written." -f $new.Count, (@($new | Select-Object -First 5 | ForEach-Object { "$($_.code) [$($_.entity)] $($_.message)" }) -join ' | '))
            }
            $lines.Add('validated: the Manager''s pre-flight validator finds no new error in the result')
        }
        $commitId = [guid]::NewGuid().ToString('N')
        $added = 0
        if ($Apply -and $plan.add -gt 0) {
            $ctx = New-PimCommitJournalContext -CommitId $commitId -Source $src -InitiatedBy $who
            $prev = Set-PimCommitJournalContext -Context $ctx
            try {
                foreach ($p in $plan.entities) {
                    if (-not @($p.add).Count) { continue }
                    $m = & $Store.Merge $Store $p.entity @($p.add | ForEach-Object { $_.row })
                    $added += [int]$m.added
                }
            } finally { [void](Set-PimCommitJournalContext -Context $prev) }
            # read back: every planned row is stored now
            $missing = New-Object System.Collections.Generic.List[string]
            foreach ($p in $plan.entities) {
                if (-not @($p.add).Count) { continue }
                $have = @{}; foreach ($x in @(& $Store.ReadRows $Store $p.entity)) { $have["$($x.key)".ToLowerInvariant()] = $true }
                foreach ($x in @($p.add)) { if (-not $have.ContainsKey("$($x.key)".ToLowerInvariant())) { $missing.Add("$($p.entity) '$($x.key)'") } }
            }
            if ($missing.Count) { throw ("read-back FAILED: {0} sample row(s) are not in the store: {1}" -f $missing.Count, (@($missing | Select-Object -First 5) -join ', ')) }
            try { & $Store.Audit $Store 'demo-samples.apply' $src ([ordered]@{ commitId = $commitId; company = "$($Model.company)"; domain = "$($Model.domain)"; added = $added; present = $plan.present; kept = $plan.kept; counts = $Model.counts }) }
            catch { Write-Warning "audit 'demo-samples.apply' could not be written: $($_.Exception.Message)" }
        }
        return [pscustomobject][ordered]@{ action = 'Apply'; applied = [bool]$Apply; commitId = $(if ($Apply -and $plan.add -gt 0) { $commitId } else { '' }); source = $src; plan = @($lines.ToArray())
            entities = @($plan.entities); toAdd = $plan.add; added = $added; present = $plan.present; kept = $plan.kept; removed = 0; changed = 0 }
    }

    # ---- Remove ------------------------------------------------------------------------------------------------------
    $refs = @(& $Store.SampleRefs $Store)
    $existing = @{}
    foreach ($e in @($refs | ForEach-Object { "$($_.entity)" } | Sort-Object -Unique)) { $existing[$e] = @(& $Store.ReadRows $Store $e) }
    $history = if ($refs.Count) { & $Store.History $Store $refs } else { @{} }   # throws when the journal cannot be read: then nothing is removed
    if ($null -eq $history) { $history = @{} }
    $plan = Get-PimDemoSampleRemovePlan -Refs $refs -Existing $existing -History $history
    foreach ($p in $plan.entities) {
        $lines.Add(("{0}: remove {1}, changed by someone since (left alone) {2}, already gone {3}" -f $p.entity, @($p.remove).Count, @($p.changed).Count, $p.gone))
        foreach ($x in @($p.remove)) { $lines.Add(("    - {0}" -f $x.key)) }
        foreach ($x in @($p.changed)) { $lines.Add(("    = left alone: '{0}' was last changed by {1}" -f $x.key, $x.by)) }
    }
    if (-not $plan.entities.Count) { $lines.Add('no sample row is recorded in the change journal of this store -- nothing to remove') }
    $commitId = [guid]::NewGuid().ToString('N')
    $removed = 0
    if ($Apply -and $plan.remove -gt 0) {
        $ctx = New-PimCommitJournalContext -CommitId $commitId -Source $src -InitiatedBy $who
        $prev = Set-PimCommitJournalContext -Context $ctx
        try {
            foreach ($p in $plan.entities) {
                if (-not @($p.remove).Count) { continue }
                $m = & $Store.Remove $Store $p.entity @($p.remove | ForEach-Object { @{ key = "$($_.key)"; json = "$($_.json)" } })
                $removed += [int]$m.removed
            }
        } finally { [void](Set-PimCommitJournalContext -Context $prev) }
        try { & $Store.Audit $Store 'demo-samples.remove' $src ([ordered]@{ commitId = $commitId; removed = $removed; leftAlone = $plan.changed }) }
        catch { Write-Warning "audit 'demo-samples.remove' could not be written: $($_.Exception.Message)" }
    }
    return [pscustomobject][ordered]@{ action = 'Remove'; applied = [bool]$Apply; commitId = $(if ($Apply -and $plan.remove -gt 0) { $commitId } else { '' }); source = $src; plan = @($lines.ToArray())
        entities = @($plan.entities); toRemove = $plan.remove; added = 0; present = 0; kept = 0; removed = $removed; changed = $plan.changed }
}
