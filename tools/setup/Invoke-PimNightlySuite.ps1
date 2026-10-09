#Requires -Version 5.1
<#
.SYNOPSIS
    NIGHTLY FULL SUITE (PIM REQUIREMENTS 100.20; framework DOCS/REQUIREMENTS.md 12.1 SPEED RULE item 2): the whole offline
    suite on origin/main, on the test VM, every night; a red night becomes a FIX REQUEST for the next morning.

.DESCRIPTION
    The fast release gate (Release-PimFix.ps1) runs only what a fix touches, so the full suite moves OFF the critical path:
    "the full suite runs nightly on main; a red nightly is fixed the next morning and blocks the next ring-2 promotion,
    not ring-1 hotfixes" (owner 2026-10-09).

      1. git fetch origin main in -SourceRepo, then a DETACHED git worktree of origin/main in <WorkRoot>\tree-<stamp>
         (never a checkout, reset or branch switch in the source tree -- other sessions work in it);
      2. run-pim-suite-vm.ps1 -Repo <that worktree> -Lane nightly (the full Run-AllPimTests.ps1 on the test VM, never on
         this machine), waiting on its suite.done;
      3. the verdict -> <WorkRoot>\last-nightly.json (commit, exit, red suites, log, minutes); RED -> one entry appended
         to <WorkRoot>\fix-requests.jsonl (id, utc, commit, red suites, log path, status 'open') -- the next session's
         first job (and the reason a ring-2 promotion waits);
      4. the worktree is removed (git worktree remove --force), the logs are kept (-KeepDays, default 14).
    -WhatIf prints the plan. Scheduled by Register-PimFastReleaseTasks.ps1 (a task DEFINITION -- creating it is the
    operator's step). No PowerShell modules.
.EXAMPLE
    .\tools\setup\Invoke-PimNightlySuite.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SourceRepo = '',
    [string]$WorkRoot = $(Join-Path $env:ProgramData 'pim\nightly'),
    [string]$VmRunner = 'C:\ProgramData\pim\ops\run-pim-suite-vm.ps1',
    [string]$Lane = 'nightly',
    [ValidateRange(1, 32)][int]$Throttle = 16,
    [ValidateRange(1, 12)][int]$Hours = 3,
    [ValidateRange(1, 365)][int]$KeepDays = 14
)
$ErrorActionPreference = 'Stop'
$sol = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $SourceRepo) { $SourceRepo = Split-Path (Split-Path $sol -Parent) -Parent }
$stamp = (Get-Date).ToString('yyyyMMdd-HHmm')
$tree = Join-Path $WorkRoot "tree-$stamp"
$outDir = Join-Path $WorkRoot "run-$stamp"
$fixFile = Join-Path $WorkRoot 'fix-requests.jsonl'
$clock = [Diagnostics.Stopwatch]::StartNew()
function RepoGit { $ErrorActionPreference = 'Continue'; $o = & git.exe -C $SourceRepo @args 2>&1; $script:GitExit = $LASTEXITCODE; return $o }
function Get-PimNightlyRedSuites([string[]]$Log) {
    # Run-AllPimTests: "-- Test-X.ps1 FAILED -- exit 1, ..." ; Pester fan-out: "[-] Test-X.ps1 exits 0" ; a -Tests run: "##### X exit 1"
    $r = New-Object System.Collections.Generic.List[string]
    foreach ($l in $Log) {
        $t = "$l" -replace '\x1b\[[0-9;]*m', ''
        if ($t -match '--\s+(\S+\.ps1)\s+FAILED') { $n = $Matches[1] -replace '\.ps1$', ''; if (-not $r.Contains($n)) { $r.Add($n) } }
        elseif ($t -match '\[-\]\s+(\S+\.ps1)\s+exits 0') { $n = $Matches[1] -replace '\.ps1$', ''; if (-not $r.Contains($n)) { $r.Add($n) } }
        elseif ($t -match '^##### (\S+) exit [1-9]') { if (-not $r.Contains($Matches[1])) { $r.Add($Matches[1]) } }
    }
    return @($r)
}

Write-Host "PIM NIGHTLY FULL SUITE -- origin/main of $SourceRepo on the test VM (lane $Lane)" -ForegroundColor Magenta
Write-Host "  > git -C $SourceRepo fetch origin main"
Write-Host "  > git -C $SourceRepo worktree add --detach $tree origin/main"
Write-Host "  > pwsh -NoProfile -File $VmRunner -Repo $tree -Lane $Lane -Throttle $Throttle -Hours $Hours -WithProfile -OutDir $outDir"
Write-Host "  > red -> append a fix request to $fixFile ; verdict -> $(Join-Path $WorkRoot 'last-nightly.json')"
Write-Host "  > git -C $SourceRepo worktree remove --force $tree"
if (-not $PSCmdlet.ShouldProcess($SourceRepo, 'nightly full suite on origin/main (test VM)')) { exit 0 }

New-Item -ItemType Directory -Force -Path $WorkRoot, $outDir | Out-Null
[void](RepoGit fetch origin main); if ($script:GitExit) { throw 'git fetch origin main failed' }
$commit = "$(RepoGit rev-parse origin/main)".Trim()
[void](RepoGit worktree add --detach $tree origin/main); if ($script:GitExit) { throw "git worktree add $tree failed" }
$code = 'error'; $red = @()
try {
    & pwsh -NoProfile -File $VmRunner -Repo $tree -Lane $Lane -Throttle $Throttle -Hours $Hours -WithProfile -OutDir $outDir | Out-Host
    $code = if (Test-Path (Join-Path $outDir 'suite.done')) { (Get-Content (Join-Path $outDir 'suite.done') -Raw).Trim() } else { 'missing' }
    $log = if (Test-Path (Join-Path $outDir 'suite.log')) { Get-Content (Join-Path $outDir 'suite.log') } else { @() }
    $red = @(Get-PimNightlyRedSuites $log)
} finally {
    [void](RepoGit worktree remove --force $tree)
    if (Test-Path -LiteralPath $tree) { Remove-Item -LiteralPath $tree -Recurse -Force -ErrorAction SilentlyContinue }
}
$verdict = [ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); commit = $commit; exit = $code; green = ($code -eq '0')
                       red = @($red); log = (Join-Path $outDir 'suite.log'); minutes = [Math]::Round($clock.Elapsed.TotalMinutes, 1) }
[IO.File]::WriteAllText((Join-Path $WorkRoot 'last-nightly.json'), ($verdict | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
if ($code -ne '0') {
    $fr = [ordered]@{ id = "nightly-$stamp"; utc = $verdict.utc; source = 'nightly full suite'; status = 'open'; commit = $commit
                      red = @($red); exit = $code; log = $verdict.log
                      ask = 'fix the red suites first thing; a red nightly blocks the next promotion to ring 2 (not fixes to ring 1)' }
    [IO.File]::AppendAllText($fixFile, (($fr | ConvertTo-Json -Depth 4 -Compress) + "`n"), [Text.UTF8Encoding]::new($false))
    Write-Host ("NIGHTLY RED on {0}: {1} -- fix request {2} in {3}" -f $commit.Substring(0, [Math]::Min(10, $commit.Length)), $(if ($red.Count) { $red -join ', ' } else { "exit $code" }), $fr.id, $fixFile) -ForegroundColor Red
} else {
    Write-Host ("NIGHTLY GREEN on {0} in {1} min" -f $commit, $verdict.minutes) -ForegroundColor Green
}
# keep the logs for -KeepDays
Get-ChildItem -LiteralPath $WorkRoot -Directory -Filter 'run-*' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepDays) } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
if ($code -ne '0') { exit 1 }
exit 0
