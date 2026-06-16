#Requires -Version 5.1
<#
.SYNOPSIS
    Seeded-data proof for the Delegation Map's PERMISSIONS & TARGETS column
    (REQUIREMENTS.md GUI). Renders the Manager from a TEMP config seeded with
    real delegation rows and asserts the column-3 targets are populated with the
    structured fields the GUI needs (short label + full scope path / AU /
    workload for the tooltip + click-to-expand). HARD RULE: no dead views --
    this drives the REAL Build-PimGraphData and inspects the REAL rendered HTML.

    Two halves:
      A. STATIC ASSERTIONS over pim-manager.html -- the column container, the
         breakdown renderer, and the per-kind grouping exist + are wired into
         the detail panel for a selected capability/permission group.
      B. SEEDED RENDER -- builds a temp config (definitions + the 3 target
         assignment files with known rows incl. a FULL Azure scope path),
         registers it as a Manager instance, renders -StaticHtml, then parses
         the embedded PIM_DATA and asserts the enriched target nodes.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$mgrDir   = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\pim-manager'
$htmlPath = Join-Path $mgrDir 'pim-manager.html'
$srvPath  = Join-Path $mgrDir 'Open-PimManager.ps1'
T 'pim-manager.html present'    (Test-Path -LiteralPath $htmlPath)
T 'Open-PimManager.ps1 present' (Test-Path -LiteralPath $srvPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

$html = [System.IO.File]::ReadAllText($htmlPath)

# --- A. Static assertions: the column is wired, not a dead view ---------------
T 'col3 container present (mapCol3)'              ($html -match 'id="mapCol3"')
T 'col3 header is PERMISSIONS & TARGETS'         ($html -match 'Permissions &amp; Targets')
T 'col3 sub-header lists Entra / AU / Azure'     ($html -match 'Entra &middot; AU &middot; Azure')
T 'breakdown renderer defined (mapTargetBreakdown)' ($html -match 'function mapTargetBreakdown\(')
T 'breakdown groups Entra ID roles'              ($html -match "'entra-role': 'Entra ID roles'")
T 'breakdown groups AU-scoped roles'             ($html -match "'au-role': 'AU-scoped roles'")
T 'breakdown groups Azure RBAC @ scope'          ($html -match "'az-resource': 'Azure RBAC @ scope'")
T 'breakdown chips carry full detail (data-full)'($html -match 'data-full=')
T 'breakdown chips have click-to-expand'         ($html -match "classList.toggle\('exp'\)")
T 'detail panel calls the breakdown'             ($html -match 'mapTargetBreakdown\(m, down\)')
# Backend enrichment of the synthetic target nodes.
$srv = [System.IO.File]::ReadAllText($srvPath)
T 'backend carries roleName on entra-role'   ($srv -match "roleName = .\$\(\`$r.RoleDefinitionName\)")
T 'backend carries auTag on au-role'         ($srv -match 'auTag = ')
T 'backend carries full scopePath on az'     ($srv -match 'scopePath = ')
T 'backend humanises the Azure scope'        ($srv -match '\$azScopeMeta')

# --- B. Seeded render: real data -> populated, enriched column-3 targets -------
$seedRoot = Join-Path ([IO.Path]::GetTempPath()) ("pim-pt-seed-{0}" -f ([Guid]::NewGuid().ToString('N').Substring(0, 8)))
$cfgDir   = Join-Path $seedRoot 'config'
$outDir   = Join-Path $seedRoot 'output'
New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$utf8 = New-Object System.Text.UTF8Encoding($false)
function Write-Seed($name, $lines) { [System.IO.File]::WriteAllText((Join-Path $cfgDir "$name.custom.csv"), (($lines -join "`r`n") + "`r`n"), $utf8) }

# A capability bundle (Services group) granting all three target kinds, plus an
# AU definition and a role group that nests the bundle and the admin who reaches it.
Write-Seed 'Account-Definitions-Admins' @(
    'FirstName;LastName;Initials;Purpose;TargetUsage;TargetPlatform;UserType;UserName;DisplayName;UserPrincipalName;UsageLocation;ForwardMailsToContact;MailForwardAddress;CreateTAP;TAPStartDate;Ring',
    'Pat;Ops;PO;HighPriv;;ID;Member;adm-L0-T0-pat;Pat Ops (admin);adm-pat@seed.test;US;FALSE;;FALSE;;'
)
Write-Seed 'PIM-Definitions-Roles' @(
    'GroupName;GroupDescription;GroupTag;AdministrativeUnitTag;CPPlatform;Plane;TierLevel;PermissionScope;SyncPlatform;IsRoleAssignable',
    'Identity Admin role;Identity admin;ROLE-IdentityAdmin;;ID;CP;T0;Global;;TRUE'
)
Write-Seed 'PIM-Definitions-Services' @(
    'GroupName;GroupDescription;GroupTag;AdministrativeUnitTag;IsRoleAssignable;Workload;Level;TierLevel;Plane;CPPlatform;Owners',
    'Entra ID service;Entra ID admins;SRV-EntraID;;TRUE;EntraID;L1;T0;CP;ID;owner@seed.test'
)
Write-Seed 'PIM-Definitions-AU' @(
    'AUDisplayName;AUDescription;AdministrativeUnitTag;Workload;Level;TierLevel;Visibility',
    'Standard users AU;Standard users;AU-Users-Standard;Users;L1;T2;Public'
)
Write-Seed 'PIM-Assignments-Admins' @(
    'Username;GroupTag;AssignmentType;Action;UpdateExisting;AutoExtend;NumOfDaysWhenExpire;Permanent;CPPlatform;Plane;TierLevel;PermissionScope;SyncPlatform',
    'adm-pat@seed.test;ROLE-IdentityAdmin;Eligible;Assign;FALSE;TRUE;90;FALSE;ID;CP;T0;Global;'
)
Write-Seed 'PIM-Assignments-Groups' @(
    'TargetGroupTag;SourceGroupTag;AssignmentType;Action;UpdateExisting;AutoExtend;NumOfDaysWhenExpire;Permanent;CPPlatform;Plane;TierLevel;PermissionScope;SyncPlatform',
    'ROLE-IdentityAdmin;SRV-EntraID;Eligible;Assign;FALSE;TRUE;90;FALSE;ID;CP;T0;Global;'
)
Write-Seed 'PIM-Assignments-Roles-Groups' @(
    'GroupTag;RoleDefinitionName;AssignmentType;Action;UpdateExisting;AutoExtend;NumOfDaysWhenExpire;Permanent;CPPlatform;Plane;TierLevel;PermissionScope;SyncPlatform',
    'SRV-EntraID;Global Administrator;Eligible;Assign;FALSE;TRUE;90;FALSE;ID;CP;T0;Global;'
)
Write-Seed 'PIM-Assignments-Roles-AUs' @(
    'GroupTag;AdministrativeUnitTag;RoleDefinitionName;AssignmentType;Action;UpdateExisting;AutoExtend;NumOfDaysWhenExpire;Permanent;CPPlatform;Plane;TierLevel;PermissionScope;SyncPlatform',
    'SRV-EntraID;AU-Users-Standard;User Administrator;Active;Assign;FALSE;TRUE;365;FALSE;ID;CP;T2;Scoped;'
)
$azScope = '/providers/Microsoft.Management/managementGroups/mg-platform-identity'
Write-Seed 'PIM-Assignments-Azure-Resources' @(
    'GroupTag;AzScope;AzScopePermission;AssignmentType;Action;UpdateExisting;AutoExtend;NumOfDaysWhenExpire;Permanent;CPPlatform;Plane;TierLevel;PermissionScope;SyncPlatform',
    ('SRV-EntraID;{0};Owner;Active;Assign;FALSE;TRUE;90;FALSE;ID;MP;T1;Scoped;' -f $azScope)
)

# Render the seeded config via -ConfigRoot (ad-hoc instance). This drives the
# REAL Build-PimGraphData over the seeded rows and bakes PIM_DATA into the HTML.
$outHtml = Join-Path $seedRoot 'render.html'
try {
    $stdout = Join-Path $seedRoot 'render.out'
    $p = Start-Process powershell.exe -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$srvPath`"",
        '-StaticHtml', '-NoLaunch', '-ConfigRoot', "`"$cfgDir`"", '-OutHtml', "`"$outHtml`""
    ) -RedirectStandardOutput $stdout -RedirectStandardError "$stdout.err" -PassThru -WindowStyle Hidden -Wait
    T 'static render exited 0' ($p.ExitCode -eq 0)
    T 'rendered HTML produced'  (Test-Path -LiteralPath $outHtml)

    if (Test-Path -LiteralPath $outHtml) {
        $rendered = [System.IO.File]::ReadAllText($outHtml)
        # Extract the injected PIM_DATA JSON object: let PIM_DATA = { ... };
        $mtc = [regex]::Match($rendered, 'let PIM_DATA = (\{.*?\});\r?\n', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        T 'PIM_DATA injected into rendered HTML' ($mtc.Success)
        if ($mtc.Success) {
            $data = $mtc.Groups[1].Value | ConvertFrom-Json
            $nodes = @($data.nodes)
            $entra = @($nodes | Where-Object { $_.kind -eq 'entra-role' })
            $au    = @($nodes | Where-Object { $_.kind -eq 'au-role' })
            $az    = @($nodes | Where-Object { $_.kind -eq 'az-resource' })
            T 'column-3 has Entra role target(s)'    (@($entra).Count -ge 1)
            T 'column-3 has AU-scoped role target(s)'(@($au).Count -ge 1)
            T 'column-3 has Azure RBAC target(s)'    (@($az).Count -ge 1)

            $ga = $entra | Where-Object { "$($_.roleName)" -eq 'Global Administrator' } | Select-Object -First 1
            T 'Entra target carries roleName' ($ga -and "$($ga.roleName)" -eq 'Global Administrator')

            $ua = $au | Where-Object { "$($_.auTag)" -eq 'AU-Users-Standard' } | Select-Object -First 1
            T 'AU target carries roleName + auTag' ($ua -and "$($ua.roleName)" -eq 'User Administrator' -and "$($ua.auTag)" -eq 'AU-Users-Standard')

            $own = $az | Where-Object { "$($_.roleName)" -eq 'Owner' } | Select-Object -First 1
            T 'Azure target carries FULL scopePath' ($own -and "$($own.scopePath)" -eq $azScope)
            T 'Azure target humanised scopeType=Management group' ($own -and "$($own.scopeType)" -eq 'Management group')
            T 'Azure target short label = mg name' ($own -and "$($own.scopeShort)" -eq 'mg-platform-identity')

            # The selected capability bundle (SRV-EntraID) must REACH all three.
            $edges = @($data.edges)
            $fromBundle = @($edges | Where-Object { "$($_.source)" -eq 'group:SRV-EntraID' })
            T 'bundle edges reach entra/au/az targets' (
                @($fromBundle | Where-Object { "$($_.target)" -like 'entra-role:*' }).Count -ge 1 -and
                @($fromBundle | Where-Object { "$($_.target)" -like 'au-role:*' }).Count -ge 1 -and
                @($fromBundle | Where-Object { "$($_.target)" -like 'az-res:*' }).Count -ge 1
            )
        }
    } else {
        Get-Content $stdout, "$stdout.err" -ErrorAction SilentlyContinue | Select-Object -Last 12 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }
} finally {
    Remove-Item -LiteralPath $seedRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
