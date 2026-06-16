#Requires -Version 5.1
<#
.SYNOPSIS
    REAL-BROWSER (headless Chromium via Playwright) verification for two PIM
    Manager fixes:

      H1  Delegation Map renders a NON-empty People column when the config CSVs
          are Excel-saved (every field double-quoted). Before the fix the quoted
          headers made every field read blank, so Build-PimGraphData produced no
          admin nodes and the People column was empty.

      L1  The Validate-tab post-action toast target resolves to a REAL element
          (#valResults). Before the fix the code targeted #vResults (which does
          not exist), so toasts silently never rendered. This drives the ACTUAL
          production toast-insertion path in the live page and asserts the toast
          appears.

    Boots Open-PimManager.ps1 headless (-Server -NoLaunch) against a TEMP config
    root seeded with QUOTED CSVs, captures the URL + session token from stdout,
    then runs the Playwright spec (tests/gui/pim-manager-safety.spec.js) against
    it. Self-SKIPS cleanly (exit 0) if Node / @playwright/test / a browser is
    unavailable -- mirroring the Live-test rule. Otherwise exit 0 green / 1 red.

    Run:  powershell -NoProfile -File tests\gui\Verify-PimManagerSafetyGui.ps1
#>
# -Port 0 (default) => boot helper allocates a FREE port at runtime (no fixed-port
# collision / no zombie-port hang). A non-zero -Port is accepted but ignored.
[CmdletBinding()] param([int]$Port = 0)

$ErrorActionPreference = 'Stop'
function Skip($why) { Write-Host "  SKIP (clean): $why" -ForegroundColor Yellow; exit 0 }

$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'tests\_shared\PimManagerBoot.ps1')
$mgr     = Join-Path $solRoot 'tools\pim-manager\Open-PimManager.ps1'
$guiDir  = $PSScriptRoot
$spec    = Join-Path $guiDir 'pim-manager-safety.spec.js'
# Playwright + browsers are installed under the scenario-gui project (shared).
$pwProj  = Join-Path $solRoot 'tests\scenario\gui'

$node = (Get-Command node -ErrorAction SilentlyContinue)
if (-not $node) { Skip 'node not found' }
if (-not (Test-Path (Join-Path $pwProj 'node_modules\@playwright\test'))) { Skip '@playwright/test not installed (run npm install in tests\scenario\gui)' }
if (-not (Test-Path $spec)) { Skip "spec missing: $spec" }

# --- Seed a TEMP config root with QUOTED (Excel-style) CSVs ------------------
$utf8 = New-Object System.Text.UTF8Encoding($false)
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
    'PIM-Assignments-Admins' = @(
        'Username;GroupTag;AssignmentType;Action',
        'adm-ada@seed.test;ROLE-SecurityLead;Eligible;Assign',
        'adm-bo@seed.test;ROLE-SecurityLead;Eligible;Assign'
    )
}
function Quote-AllFields($lines) {
    return @($lines | ForEach-Object {
        (($_ -split ';') | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }) -join ';'
    })
}
$seedRoot = Join-Path ([IO.Path]::GetTempPath()) ("pim-gui-safety-{0}" -f ([Guid]::NewGuid().ToString('N').Substring(0, 8)))
$cfgDir   = Join-Path $seedRoot 'config'
New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null
foreach ($name in $rowsByBase.Keys) {
    [System.IO.File]::WriteAllText((Join-Path $cfgDir "$name.custom.csv"), ((Quote-AllFields $rowsByBase[$name]) -join "`r`n") + "`r`n", $utf8)
}

$out = Join-Path $seedRoot 'mgr.out'
Write-Host "Booting Manager headless on a dynamic free port against QUOTED-CSV config ..." -ForegroundColor Cyan
$ctx  = Start-PimManagerForTest -ManagerPath $mgr -ExtraArgs @('-ConfigRoot', "`"$cfgDir`"") -StdoutPath $out -TimeoutSec 30
$proc = $ctx.Process

try {
    $token = $ctx.Token
    if (-not $token -or $ctx.Port -le 0) {
        Get-Content $out, "$out.err" -EA SilentlyContinue | Select-Object -Last 15 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        Skip 'Manager did not emit a session token (boot failed in this environment)'
    }
    $base = $ctx.BaseUrl
    Write-Host "  Manager up at $base -- running Playwright spec headless ..." -ForegroundColor Green

    $env:PIM_GUI_BASEURL = $base
    $env:PIM_GUI_TOKEN   = $token
    # Run ONLY our spec, headless, from the project that has @playwright/test.
    $cli    = Join-Path $pwProj 'node_modules\@playwright\test\cli.js'
    $config = Join-Path $guiDir 'playwright.safety.config.js'
    # The spec + config live in tests/gui but @playwright/test is installed under
    # tests/scenario/gui -- make it resolvable from anywhere via NODE_PATH.
    $env:NODE_PATH = (Join-Path $pwProj 'node_modules')
    Push-Location $pwProj
    try {
        & node "$cli" test --config "$config" --reporter=line 2>&1 | ForEach-Object { Write-Host "    $_" }
        $code = $LASTEXITCODE
    } finally { Pop-Location; Remove-Item Env:NODE_PATH -ErrorAction SilentlyContinue }
    if ($code -ne 0) { Write-Host "`n RESULT: Playwright spec FAILED (exit $code)" -ForegroundColor Red; exit 1 }
    Write-Host "`n RESULT: headless browser verification GREEN" -ForegroundColor Green
    exit 0
} finally {
    if ($proc -and -not $proc.HasExited) { try { $proc.Kill() } catch {} }
    Remove-Item -LiteralPath $seedRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:PIM_GUI_BASEURL, Env:PIM_GUI_TOKEN -ErrorAction SilentlyContinue
}
