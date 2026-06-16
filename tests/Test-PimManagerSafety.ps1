#Requires -Version 5.1
<#
.SYNOPSIS
    Regression proofs for three PIM Manager safety/correctness fixes:

      H1  Delegation Map renders EMPTY on Excel-saved (quote-wrapped) CSVs.
          Read-PimRows split the header with -split ';' which KEEPS the double
          quotes Excel adds ("UserPrincipalName"), while Import-Csv strips them
          -- so every field read back blank and Build-PimGraphData skipped every
          admin (empty map). Fix strips surrounding quotes from header tokens so
          quoted and unquoted CSVs parse identically. Proof: render a QUOTED
          fixture through the REAL Build-PimGraphData and assert nodes/edges/
          admins > 0 (map non-empty), matching an unquoted render.

      L1  Validate post-action toasts don't render -- the JS targeted #vResults
          but the element id is #valResults. Static assertion over the HTML.

      SAFETY  Maintenance bulk-revoke guard (interim, incident-driven): break-
          glass accounts excluded, large batches need an explicit count
          confirmation, a what-if/preview lists exactly what will be revoked, and
          every revoke is audited. The pure planner Get-PimRevokeGuardPlan (+
          Test-PimRowIsBreakGlass / Get-PimBreakGlassIdentifiers) is extracted
          IN-PROC and exercised directly.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$solRoot  = Split-Path -Parent $PSScriptRoot
$mgrDir   = Join-Path $solRoot 'tools\pim-manager'
$htmlPath = Join-Path $mgrDir 'pim-manager.html'
$srvPath  = Join-Path $mgrDir 'Open-PimManager.ps1'
T 'pim-manager.html present'    (Test-Path -LiteralPath $htmlPath)
T 'Open-PimManager.ps1 present' (Test-Path -LiteralPath $srvPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

$src  = [System.IO.File]::ReadAllText($srvPath)
$html = [System.IO.File]::ReadAllText($htmlPath)

# ===========================================================================
# L1 -- Validate post-action toasts target the REAL element id (#valResults)
# ===========================================================================
Write-Host "`n-- L1: Validate toast element id --" -ForegroundColor Cyan
T 'no stale #vResults reference remains in the GUI'        (-not ($html -match "getElementById\('vResults'\)"))
T 'fix/overrule toasts target the real #valResults id'    (([regex]::Matches($html, "getElementById\('valResults'\)")).Count -ge 3)
T 'the #valResults container element actually exists'      ($html -match "id=`"valResults`"")

# ===========================================================================
# H1 -- quoted (Excel-style) CSV headers parse identically to unquoted, so the
# Delegation Map is NOT empty. Render BOTH through the REAL Build-PimGraphData.
# ===========================================================================
Write-Host "`n-- H1: quoted CSV header -> non-empty Delegation Map --" -ForegroundColor Cyan

$utf8 = New-Object System.Text.UTF8Encoding($false)
function Render-Seed($seedFiles) {
    $seedRoot = Join-Path ([IO.Path]::GetTempPath()) ("pim-safety-{0}" -f ([Guid]::NewGuid().ToString('N').Substring(0, 8)))
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

# Two admins assigned to a role group; the role group holds an Entra role bundle.
# A minimal but COMPLETE delegation chain so nodes + edges are both non-empty.
$rowsByBase = @{
    'Account-Definitions-Admins' = @(
        'FirstName;LastName;Initials;Purpose;TargetPlatform;UserType;UserName;DisplayName;UserPrincipalName;UsageLocation',
        'Ada;Admin;AA;HighPriv;ID;Member;adm-ada-L0-T0;Ada (Admin, ID);adm-ada@seed.test;US',
        'Bo;Operator;BO;Day2Day;ID;Member;adm-bo;Bo (Admin, ID);adm-bo@seed.test;US'
    )
    'PIM-Definitions-Roles' = @(
        'GroupName;GroupDescription;GroupTag;TierLevel;Level',
        'Security lead;Sec;ROLE-SecurityLead;T0;L0'
    )
    'PIM-Definitions-Services' = @(
        'GroupName;GroupDescription;GroupTag;TierLevel;Level',
        'Entra GA bundle;GA;Entra-ID-GlobalAdministrator-L0;T0;L0'
    )
    'PIM-Assignments-Admins' = @(
        'Username;GroupTag;AssignmentType;Action',
        'adm-ada@seed.test;ROLE-SecurityLead;Eligible;Assign',
        'adm-bo@seed.test;ROLE-SecurityLead;Eligible;Assign'
    )
    'PIM-Assignments-Groups' = @(
        'TargetGroupTag;SourceGroupTag;AssignmentType;Action',
        'Entra-ID-GlobalAdministrator-L0;ROLE-SecurityLead;Eligible;Assign'
    )
    'PIM-Assignments-Roles-Groups' = @(
        'GroupTag;RoleDefinitionName;AssignmentType;Action',
        'Entra-ID-GlobalAdministrator-L0;Global Administrator;Eligible;Assign'
    )
}

# Quote EVERY field of EVERY line, exactly as Excel "CSV (semicolon)" does.
function Quote-AllFields($lines) {
    return @($lines | ForEach-Object {
        (($_ -split ';') | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }) -join ';'
    })
}

$unquoted = @{}; foreach ($k in $rowsByBase.Keys) { $unquoted[$k] = $rowsByBase[$k] }
$quoted   = @{}; foreach ($k in $rowsByBase.Keys) { $quoted[$k]   = Quote-AllFields $rowsByBase[$k] }

$dU = Render-Seed $unquoted
$dQ = Render-Seed $quoted
T 'unquoted fixture rendered' ($null -ne $dU)
T 'quoted (Excel) fixture rendered' ($null -ne $dQ)

if ($dU -and $dQ) {
    $admU = @($dU.nodes | Where-Object { $_.kind -eq 'admin' })
    $admQ = @($dQ.nodes | Where-Object { $_.kind -eq 'admin' })
    T 'BASELINE: unquoted render has 2 admin nodes' ($admU.Count -eq 2)
    T 'QUOTED render has the SAME 2 admin nodes (not blanked out)' ($admQ.Count -eq 2)
    T 'QUOTED render: admin UPNs survived (not empty)' (
        ($admQ.id -contains 'adm-ada@seed.test') -and ($admQ.id -contains 'adm-bo@seed.test')
    )
    T 'QUOTED render: Delegation Map nodes are non-empty' (@($dQ.nodes).Count -gt 0)
    T 'QUOTED render: Delegation Map edges are non-empty' (@($dQ.edges).Count -gt 0)
    T 'QUOTED render matches unquoted node count (parse parity)' (@($dQ.nodes).Count -eq @($dU.nodes).Count)
    T 'QUOTED render matches unquoted edge count (parse parity)' (@($dQ.edges).Count -eq @($dU.edges).Count)
    # The Purpose marker still resolves from the quoted UserName (L0/T0).
    $ada = @($admQ | Where-Object { $_.id -eq 'adm-ada@seed.test' })
    T 'QUOTED render: HighPriv purpose still derived from quoted UserName marker' (
        $ada.Count -eq 1 -and "$($ada[0].purpose)" -eq 'HighPriv'
    )
}

# ===========================================================================
# SAFETY -- bulk-revoke guard (pure planner, extracted IN-PROC)
# ===========================================================================
Write-Host "`n-- SAFETY: bulk-revoke guard (break-glass / what-if / count-confirm / audit) --" -ForegroundColor Cyan

foreach ($fn in 'Get-PimBreakGlassIdentifiers','Test-PimRowIsBreakGlass','Get-PimRevokeGuardPlan') {
    $m = [regex]::Match($src, ("function {0}[\s\S]*?\n\}}\r?\n" -f [regex]::Escape($fn)))
    T "$fn function is present" ($m.Success)
    if ($m.Success) { Invoke-Expression $m.Value }
}

# Build a deterministic set of revoke rows.
function New-Row($id, $principal, $type) { [pscustomobject]@{ id = $id; principal = $principal; principalId = ("oid-$id"); type = $type } }
$rows = @(
    New-Row 'r1' 'breakglass1@seed.test' 'entra-role'   # protected by UPN
    New-Row 'r2' 'normal-a@seed.test'     'entra-role'
    New-Row 'r3' 'normal-b@seed.test'     'azure-rbac'
    New-Row 'r4' 'normal-c@seed.test'     'pim-for-groups'
)
$bgByOid = New-Row 'r5' 'normal-d@seed.test' 'entra-role'   # protected by object id (oid-r5)

# Configure break-glass: one UPN + one object id.
$global:PIM_BreakGlassAccounts = @('breakglass1@seed.test', 'oid-r5')
try {
    $ids = Get-PimBreakGlassIdentifiers
    T 'break-glass identifiers parsed + lowercased' ($ids -contains 'breakglass1@seed.test' -and $ids -contains 'oid-r5')

    T 'Test-PimRowIsBreakGlass matches by UPN'        (Test-PimRowIsBreakGlass -Row $rows[0] -Identifiers $ids)
    T 'Test-PimRowIsBreakGlass matches by object id'  (Test-PimRowIsBreakGlass -Row $bgByOid -Identifiers $ids)
    T 'Test-PimRowIsBreakGlass rejects a normal row'  (-not (Test-PimRowIsBreakGlass -Row $rows[1] -Identifiers $ids))

    # (b) EXCLUSION: break-glass rows are skipped + reported, never revoked.
    $plan = Get-PimRevokeGuardPlan -Rows ($rows + $bgByOid)
    T 'break-glass accounts are EXCLUDED from toRevoke' (
        -not (@($plan.toRevoke).principal -contains 'breakglass1@seed.test') -and
        -not (@($plan.toRevoke).principal -contains 'normal-d@seed.test')
    )
    T 'excluded break-glass accounts are REPORTED in skipped' ($plan.skippedCount -eq 2)
    T 'toRevoke holds exactly the 3 normal rows' ($plan.toRevokeCount -eq 3)

    # (c) LARGE-BATCH count-confirmation. Default threshold = 5.
    $big = @(); for ($i = 0; $i -lt 7; $i++) { $big += New-Row "b$i" "normal-$i@seed.test" 'entra-role' }
    $pBigNoConfirm = Get-PimRevokeGuardPlan -Rows $big
    T 'batch over threshold REQUIRES confirmation'                ($pBigNoConfirm.confirmRequired)
    T 'over-threshold batch with NO confirmCount is NOT satisfied' (-not $pBigNoConfirm.confirmSatisfied)
    $pBigWrong = Get-PimRevokeGuardPlan -Rows $big -ConfirmCount 99
    T 'over-threshold batch with WRONG confirmCount is NOT satisfied' (-not $pBigWrong.confirmSatisfied)
    $pBigRight = Get-PimRevokeGuardPlan -Rows $big -ConfirmCount 7
    T 'over-threshold batch with EXACT confirmCount is satisfied'  ($pBigRight.confirmSatisfied)

    # confirmCount must match the POST-EXCLUSION count, not the raw selection.
    $bigWithBg = $big + (New-Row 'bgX' 'breakglass1@seed.test' 'entra-role')
    $pMix = Get-PimRevokeGuardPlan -Rows $bigWithBg -ConfirmCount 8
    T 'confirmCount of raw selection (incl. break-glass) does NOT satisfy' (-not $pMix.confirmSatisfied)
    $pMixOk = Get-PimRevokeGuardPlan -Rows $bigWithBg -ConfirmCount 7
    T 'confirmCount of the post-exclusion total satisfies'                ($pMixOk.confirmSatisfied -and $pMixOk.toRevokeCount -eq 7)

    # Small batches need no confirmation.
    $pSmall = Get-PimRevokeGuardPlan -Rows @($rows[1], $rows[2])
    T 'small batch (<= threshold) needs no confirmation' (-not $pSmall.confirmRequired -and $pSmall.confirmSatisfied)

    # (d) WHAT-IF: the plan is a pure preview (no execution side effects) and
    # lists exactly the rows that would be revoked + those skipped.
    T 'what-if plan reports total / toRevoke / skipped consistently' (
        $plan.total -eq 5 -and ($plan.toRevokeCount + $plan.skippedCount) -eq $plan.total
    )
} finally {
    Remove-Variable -Name PIM_BreakGlassAccounts -Scope Global -ErrorAction SilentlyContinue
}

# (b') With NO break-glass configured, nothing is excluded.
$planNone = Get-PimRevokeGuardPlan -Rows $rows
T 'no break-glass configured -> nothing excluded' ($planNone.skippedCount -eq 0 -and $planNone.toRevokeCount -eq 4)

# (a) AUDIT: the /api/revoke handler writes an audit event per revoke + per skip.
T 'handler audits every revoke (revoke.active-assignment)' (
    $src -match "Write-PimManagerAuditEvent\s+-Action\s+'revoke\.active-assignment'"
)
T 'handler audits skipped break-glass (revoke.skipped.break-glass)' (
    $src -match "Write-PimManagerAuditEvent\s+-Action\s+'revoke\.skipped\.break-glass'"
)
T 'handler refuses an over-threshold batch without confirmCount (409)' (
    ($src -match '\$plan\.confirmRequired\s+-and\s+-not\s+\$plan\.confirmSatisfied') -and ($src -match 'return 409')
)
T 'handler supports a preview (what-if) that never executes' (
    ($src -match 'if\s*\(\$preview\)') -and ($src -match 'preview\s*=\s*\$true')
)
T 'handler only revokes the guarded subset (plan.toRevoke), not the raw rows' (
    $src -match '\$rowsToRevoke\s*=\s*@\(\$plan\.toRevoke\)'
)

# GUI calls preview first + sends confirmCount on large batches.
T 'GUI calls the preview/what-if before committing' ($html -match "preview:\s*true")
T 'GUI sends confirmCount on confirmed large batches' ($html -match 'payload\.confirmCount\s*=')
T 'GUI gates the danger confirm on typing the exact count' ($html -match 'function showRevokeConfirm')

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
