#Requires -Version 5.1
<#
.SYNOPSIS
    TEST-09 -- the deployed-vs-merged drift check (tools/setup/Test-PimDeployedVersionDrift.ps1).

    On 2026-08-06 the hosted Manager was found running a 7-week-old image that did not
    contain the SEC-01 security fix, while §33 recorded that fix as closed. Nothing
    surfaced it: every gate we had validates a DEPLOYMENT, and the failure mode here is
    the ABSENCE of one. This suite covers the pure decision core of the check that closes
    that gap.

    The assertions that matter most are the ones proving it does NOT report green when it
    could not actually determine the answer -- an empty app list, an unparseable tag.
    "Checked nothing" must never read as "all good" (BUG-09 is exactly that bug, one
    layer up, in the deploy script).

    Offline. No az, no network.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $solRoot 'engine\_shared\PIM-DateSafe.ps1')
$checker = Join-Path $solRoot 'tools\setup\Test-PimDeployedVersionDrift.ps1'
Assert "the drift checker exists" (Test-Path -LiteralPath $checker)
if (-not (Test-Path -LiteralPath $checker)) { Write-Host "`n RESULT: $pass passed, $fail failed" -ForegroundColor Red; exit 1 }
. $checker   # dot-source: the script returns before touching az

Write-Host "=== PIM deployed-version drift (TEST-09) ===" -ForegroundColor Cyan

# --- tag parsing --------------------------------------------------------------
Assert "parses a normal image ref"          ((Get-PimImageTag -Image 'acr.azurecr.io/pim-manager:2.4.238') -eq '2.4.238')
Assert "parses a bare repo:tag"             ((Get-PimImageTag -Image 'pim-manager:1.0.0') -eq '1.0.0')
Assert "no tag -> '' (implicit latest)"     ((Get-PimImageTag -Image 'acr.azurecr.io/pim-manager') -eq '')
Assert "empty/null -> ''"                   (((Get-PimImageTag -Image '') -eq '') -and ((Get-PimImageTag -Image $null) -eq ''))
# a registry PORT must not be mistaken for a tag -- that would silently compare 'v1' wrong
Assert "a registry port is not read as a tag" ((Get-PimImageTag -Image 'localhost:5000/pim-manager') -eq '')
Assert "port + real tag still parses the tag" ((Get-PimImageTag -Image 'localhost:5000/pim-manager:2.4.238') -eq '2.4.238')

$now = [datetime]::SpecifyKind([datetime]'2026-08-06T00:00:00', [System.DateTimeKind]::Utc)
function D($app, $tag, $daysOld) {
    [pscustomobject]@{ app = $app; image = "acr.azurecr.io/pim-manager:$tag"; revision = "$app--0001"
                       createdUtc = $now.AddDays(-1 * $daysOld).ToString('o') }
}

# --- the happy path -----------------------------------------------------------
$r = Get-PimVersionDriftReport -Expected '2.4.238' -Deployed @(D 'a' '2.4.238' 1; D 'b' '2.4.238' 2) -NowUtc $now
Assert "all matching -> ok"                 ($r.ok -and $r.drifted.Count -eq 0 -and $r.rows.Count -eq 2)

# --- THE incident this exists for ---------------------------------------------
$r = Get-PimVersionDriftReport -Expected '2.4.238' -Deployed @(
        D 'ca-pim-manager' '2.4.238' 1
        D 'ca-pim-engine'  '2.4.230' 48
        D 'ca-pim-scheduler' '2.4.230' 48) -NowUtc $now
Assert "the real incident shape is DRIFT, not ok" (-not $r.ok)
Assert "  ...both stale workers are named"        ($r.drifted.Count -eq 2 -and (@($r.drifted | ForEach-Object { $_.app }) -contains 'ca-pim-engine'))
Assert "  ...and the current app is NOT flagged"  (@($r.drifted | ForEach-Object { $_.app }) -notcontains 'ca-pim-manager')

# --- "could not determine" must NEVER be ok -----------------------------------
$r = Get-PimVersionDriftReport -Expected '2.4.238' -Deployed @() -NowUtc $now
Assert "an EMPTY app list is NOT ok (checked nothing != all good)" (-not $r.ok)

$r = Get-PimVersionDriftReport -Expected '2.4.238' -Deployed @(
        [pscustomobject]@{ app = 'x'; image = 'acr.azurecr.io/pim-manager'; revision = 'r'; createdUtc = '' }) -NowUtc $now
Assert "an unparseable tag is UNKNOWN, not ok"    ((-not $r.ok) -and $r.unknown.Count -eq 1)
Assert "  ...and unknown is not counted as drift" ($r.drifted.Count -eq 0)

# --- age check ----------------------------------------------------------------
$r = Get-PimVersionDriftReport -Expected '2.4.238' -Deployed @(D 'a' '2.4.238' 60) -MaxAgeDays 45 -NowUtc $now
Assert "right tag but a 60-day-old revision -> STALE" ((-not $r.ok) -and $r.stale.Count -eq 1)
$r = Get-PimVersionDriftReport -Expected '2.4.238' -Deployed @(D 'a' '2.4.238' 60) -MaxAgeDays 0 -NowUtc $now
Assert "MaxAgeDays=0 disables the age check"          ($r.ok)
$r = Get-PimVersionDriftReport -Expected '2.4.238' -Deployed @(
        [pscustomobject]@{ app='a'; image='acr.azurecr.io/pim-manager:2.4.238'; revision='r'; createdUtc='' }) -NowUtc $now
Assert "a missing createdUtc does not fabricate an age" ($r.ok -and ($null -eq $r.rows[0].ageDays))

# --- drift beats stale in the reported status ---------------------------------
$r = Get-PimVersionDriftReport -Expected '2.4.238' -Deployed @(D 'a' '2.4.230' 99) -MaxAgeDays 45 -NowUtc $now
Assert "a wrong tag reports DRIFT (not merely stale)" ($r.drifted.Count -eq 1 -and $r.stale.Count -eq 0)

# --- the design constraint that makes this check meaningful -------------------
# If this ever runs FROM the deploy path it inherits the exact blind spot it closes:
# a deploy that never happens runs no gate. Assert it is not wired into the deployer.
$upd = Join-Path $solRoot 'tools\setup\Update-PimContainers.ps1'
if (Test-Path -LiteralPath $upd) {
    $updText = [System.IO.File]::ReadAllText($upd)
    Assert "the drift check is NOT invoked from the deploy path (it must be scheduled)" `
        ($updText -notmatch 'Test-PimDeployedVersionDrift')
}
$chk = [System.IO.File]::ReadAllText($checker)
Assert "the checker documents WHY it must be scheduled, not deploy-triggered" ($chk -match 'SCHEDULE')
Assert "the checker distinguishes 'could not check' (exit 2) from 'no drift' (exit 0)" `
    (($chk -match 'exit 2') -and ($chk -match 'CANNOT CHECK'))

Write-Host ""
Write-Host ("PIM version drift (TEST-09): {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
