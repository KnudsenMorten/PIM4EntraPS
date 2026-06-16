#Requires -Version 5.1
<#
.SYNOPSIS
    Seeded-data proof for the Delegation Map's TRANSITIVE REACH model
    (Open-PimManager.ps1 Build-PimGraphData + pim-manager.html buildMapModel /
    mapBfs). Guards the "person -> role groups -> bundles -> Entra/AU/Azure/
    workload" reach against OVER-REPORTING and DUPLICATION.

    Root cause this test locks down: PIM-Assignments-Groups records
    "SourceGroupTag becomes a MEMBER of TargetGroupTag" (engine GroupMembers
    provider). On the 4-column board reach must flow strictly left->right
    (role group col1 -> permission group col2 -> targets col3). A group->group
    nesting edge that points sideways/backwards (e.g. a high-priv role group
    nested into a lower role group) MUST NOT propagate the nested group's own
    grants up to everyone in the parent -- doing so inflated the reach and made
    the same AU-scoped role appear across many AUs a person never actually
    reaches. The fix orients every group-nest reach hop by COLUMN and drops
    same-column nests; this test asserts the corrected, deterministic reach.

    HARD RULE: no dead views -- drives the REAL Build-PimGraphData and replicates
    the REAL buildMapModel/mapBfs reach rules, then asserts the deduped reach set.

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

# --- A. Static assertions: the column-orientation reach guard is present -------
T 'reach builder orients group nests by column (addReach)' ($html -match 'const addReach =')
T 'same-column group nest is dropped from reach'           ($html -match 'same-column nesting is not a reach hop')
T 'group-to-group reach is column-oriented'                ($html -match "addReach\(e, e\.kind === 'group-to-group'\)")
T 'pending group nests routed through the same guard'      ($html -match 'addReach\(e, !!isNest\)')

# --- Reach replication (mirrors buildMapModel + mapBfs reach rules) ------------
function Get-Col($node) {
    if (-not $node) { return -1 }
    switch ($node.kind) {
        'admin'            { return 0 }
        'role-group'       { return 1 }
        'permission-group' { return 2 }
        'entra-role'       { return 3 }
        'au-role'          { return 3 }
        'az-resource'      { return 3 }
        default            { return -1 }
    }
}
function Build-Reach($data) {
    $byId = @{}; foreach ($n in $data.nodes) { $byId[$n.id] = $n }
    $fwd = @{}
    foreach ($e in $data.edges) {
        if ($e.cosmetic -or $e.kind -eq 'au-to-au-role') { continue }
        $cs = Get-Col $byId[$e.source]; $ct = Get-Col $byId[$e.target]
        if ($cs -lt 0 -or $ct -lt 0) { continue }
        $sId = $e.source; $tId = $e.target
        if ($e.kind -eq 'group-to-group') {
            if ($cs -eq $ct) { continue }                       # same-column nest = not a reach hop
            if ($cs -gt $ct) { $sId = $e.target; $tId = $e.source }  # orient lower->higher col
        }
        if (-not $fwd.ContainsKey($sId)) { $fwd[$sId] = New-Object System.Collections.ArrayList }
        [void]$fwd[$sId].Add($tId)
    }
    return @{ byId = $byId; fwd = $fwd }
}
function Get-Down($model, $startId) {
    $seen = @{}; $seen[$startId] = $true
    $q = New-Object System.Collections.Queue; $q.Enqueue($startId)
    while ($q.Count) {
        $cur = $q.Dequeue()
        if ($model.fwd.ContainsKey($cur)) {
            foreach ($nx in $model.fwd[$cur]) { if (-not $seen.ContainsKey($nx)) { $seen[$nx] = $true; $q.Enqueue($nx) } }
        }
    }
    return $seen.Keys
}
function Count-Kind($model, $ids, $kind) { @($ids | Where-Object { $model.byId.ContainsKey($_) -and $model.byId[$_].kind -eq $kind }).Count }

# --- Render a seeded config through the REAL Build-PimGraphData ----------------
$utf8 = New-Object System.Text.UTF8Encoding($false)
function Render-Seed($seedFiles) {
    $seedRoot = Join-Path ([IO.Path]::GetTempPath()) ("pim-reach-{0}" -f ([Guid]::NewGuid().ToString('N').Substring(0, 8)))
    $cfgDir   = Join-Path $seedRoot 'config'
    New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
    foreach ($name in $seedFiles.Keys) {
        [System.IO.File]::WriteAllText((Join-Path $cfgDir "$name.custom.csv"), (($seedFiles[$name] -join "`r`n") + "`r`n"), $utf8)
    }
    $outHtml = Join-Path $seedRoot 'render.html'
    $stdout  = Join-Path $seedRoot 'render.out'
    try {
        $p = Start-Process powershell.exe -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$srvPath`"",
            '-StaticHtml', '-NoLaunch', '-ConfigRoot', "`"$cfgDir`"", '-OutHtml', "`"$outHtml`""
        ) -RedirectStandardOutput $stdout -RedirectStandardError "$stdout.err" -PassThru -WindowStyle Hidden -Wait
        if ($p.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $outHtml)) {
            Get-Content $stdout, "$stdout.err" -ErrorAction SilentlyContinue | Select-Object -Last 12 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
            return $null
        }
        $rendered = [System.IO.File]::ReadAllText($outHtml)
        $mtc = [regex]::Match($rendered, 'let PIM_DATA = (\{.*?\});\r?\n', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if (-not $mtc.Success) { return $null }
        return ($mtc.Groups[1].Value | ConvertFrom-Json)
    } finally {
        Remove-Item -LiteralPath $seedRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# === Fixture 1: OVER-REACH guard ==============================================
# Helpdesk admin is assigned ONLY to ROLE-Helpdesk (real reach = 1 AU-scoped
# role: Helpdesk Administrator @ AU-Users-Standard). A high-priv role group
# ROLE-IdentityAdmin is (mis)nested as a Source INTO ROLE-Helpdesk. The buggy
# Target->Source forward edge let the Helpdesk person inherit EVERY AU-scoped
# role of ROLE-IdentityAdmin (4 total, across AUs they never reach). The fix
# must report exactly the 1 real AU-scoped role and NOT reach ROLE-IdentityAdmin.
$overReach = @{
    'Account-Definitions-Admins' = @(
        'FirstName;LastName;Initials;Purpose;TargetPlatform;UserType;UserName;DisplayName;UserPrincipalName;UsageLocation',
        'Help;Desk;HD;Day2Day;ID;Member;adm-helpdesk;Helpdesk (Admin, Cloud, ID);adm-helpdesk@seed.test;US'
    )
    'PIM-Definitions-Roles' = @(
        'GroupName;GroupDescription;GroupTag;TierLevel;Level',
        'Helpdesk role;Helpdesk;ROLE-Helpdesk;T2;L2',
        'Identity Admin role;Id admin;ROLE-IdentityAdmin;T0;L0'
    )
    'PIM-Definitions-AU' = @(
        'AUDisplayName;AUDescription;AdministrativeUnitTag;TierLevel',
        'Std users;std;AU-Users-Standard;T2',
        'Priv admins;priv;AU-Admins-Privileged;T0',
        'Corp devices;dev;AU-Devices-Corp;T2'
    )
    'PIM-Assignments-Admins' = @(
        'Username;GroupTag;AssignmentType;Action',
        'adm-helpdesk@seed.test;ROLE-Helpdesk;Active;Assign'
    )
    'PIM-Assignments-Groups' = @(
        'TargetGroupTag;SourceGroupTag;AssignmentType;Action',
        'ROLE-Helpdesk;ROLE-IdentityAdmin;Eligible;Assign'
    )
    'PIM-Assignments-Roles-AUs' = @(
        'GroupTag;AdministrativeUnitTag;RoleDefinitionName;AssignmentType;Action',
        'ROLE-Helpdesk;AU-Users-Standard;Helpdesk Administrator;Active;Assign',
        'ROLE-IdentityAdmin;AU-Admins-Privileged;User Administrator;Active;Assign',
        'ROLE-IdentityAdmin;AU-Admins-Privileged;Privileged Authentication Administrator;Active;Assign',
        'ROLE-IdentityAdmin;AU-Devices-Corp;Cloud Device Administrator;Active;Assign'
    )
    'PIM-Assignments-Roles-Groups'    = @('GroupTag;RoleDefinitionName;AssignmentType;Action')
    'PIM-Assignments-Azure-Resources' = @('GroupTag;AzScope;AzScopePermission;AssignmentType;Action')
}

Write-Host "`n-- Fixture 1: over-reach guard (Helpdesk must NOT inherit nested high-priv role group) --" -ForegroundColor Cyan
$d1 = Render-Seed $overReach
T 'fixture-1 rendered' ($null -ne $d1)
if ($d1) {
    $m1 = Build-Reach $d1
    $down = @(Get-Down $m1 'adm-helpdesk@seed.test')
    $au   = @($down | Where-Object { $m1.byId.ContainsKey($_) -and $m1.byId[$_].kind -eq 'au-role' })
    T 'reaches exactly 1 role group (ROLE-Helpdesk, not the nested ROLE-IdentityAdmin)' ((Count-Kind $m1 $down 'role-group') -eq 1)
    T 'role group reached is ROLE-Helpdesk' ($down -contains 'group:ROLE-Helpdesk' -and -not ($down -contains 'group:ROLE-IdentityAdmin'))
    T 'reaches exactly 1 AU-scoped role (no inflation)' ($au.Count -eq 1)
    T 'the 1 AU role is Helpdesk Administrator @ AU-Users-Standard' ($au -contains 'au-role:AU-Users-Standard:Helpdesk Administrator')
    T 'does NOT reach the privileged AU roles' (
        -not ($au -contains 'au-role:AU-Admins-Privileged:User Administrator') -and
        -not ($au -contains 'au-role:AU-Admins-Privileged:Privileged Authentication Administrator') -and
        -not ($au -contains 'au-role:AU-Devices-Corp:Cloud Device Administrator')
    )
    # de-dup: the reached AU-role set has no duplicate ids
    T 'AU-role reach set is deduped (distinct ids)' ($au.Count -eq (@($au | Select-Object -Unique).Count))
}

# === Fixture 2: canonical nesting still reaches (no under-reporting) ===========
# Engine-canonical direction: the ROLE group is the SOURCE nested INTO a
# permission group (Target) that holds the Entra role. Admin in the role group
# MUST still reach that Entra role through the bundle.
$canonical = @{
    'Account-Definitions-Admins' = @(
        'FirstName;LastName;Initials;Purpose;TargetPlatform;UserType;UserName;DisplayName;UserPrincipalName;UsageLocation',
        'Sec;Lead;SL;HighPriv;ID;Member;adm-seclead;Security Lead (Admin, ID);adm-seclead@seed.test;US'
    )
    'PIM-Definitions-Roles' = @(
        'GroupName;GroupDescription;GroupTag;TierLevel;Level',
        'Security lead;Sec;ROLE-SecurityLead;T0;L0'
    )
    'PIM-Definitions-Services' = @(
        'GroupName;GroupDescription;GroupTag;TierLevel;Level',
        'Entra GA bundle;GA;Entra-ID-GlobalAdministrator-L0;T0;L0'
    )
    'PIM-Definitions-AU'      = @('AUDisplayName;AUDescription;AdministrativeUnitTag;TierLevel')
    'PIM-Assignments-Admins'  = @(
        'Username;GroupTag;AssignmentType;Action',
        'adm-seclead@seed.test;ROLE-SecurityLead;Eligible;Assign'
    )
    'PIM-Assignments-Groups' = @(
        'TargetGroupTag;SourceGroupTag;AssignmentType;Action',
        'Entra-ID-GlobalAdministrator-L0;ROLE-SecurityLead;Eligible;Assign'
    )
    'PIM-Assignments-Roles-AUs'    = @('GroupTag;AdministrativeUnitTag;RoleDefinitionName;AssignmentType;Action')
    'PIM-Assignments-Roles-Groups' = @(
        'GroupTag;RoleDefinitionName;AssignmentType;Action',
        'Entra-ID-GlobalAdministrator-L0;Global Administrator;Eligible;Assign'
    )
    'PIM-Assignments-Azure-Resources' = @('GroupTag;AzScope;AzScopePermission;AssignmentType;Action')
}

Write-Host "`n-- Fixture 2: canonical nesting (role group SOURCE -> permission group TARGET) still reaches --" -ForegroundColor Cyan
$d2 = Render-Seed $canonical
T 'fixture-2 rendered' ($null -ne $d2)
if ($d2) {
    $m2 = Build-Reach $d2
    $down2 = @(Get-Down $m2 'adm-seclead@seed.test')
    T 'reaches the permission-group bundle' ((Count-Kind $m2 $down2 'permission-group') -eq 1)
    T 'reaches exactly 1 Entra role (Global Administrator)' (
        (Count-Kind $m2 $down2 'entra-role') -eq 1 -and ($down2 -contains 'entra-role:Global Administrator')
    )
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
