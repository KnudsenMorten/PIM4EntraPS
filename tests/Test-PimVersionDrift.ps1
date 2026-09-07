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


# --- TEST-09b: a DIGEST is not a tag, and an AMBIENT subscription is not this fleet -------------
# 🔴 Both defects were found on 2026-08-30 trying to answer "is prod on latest?" -- the one
# question this gate exists for -- and it could not.
#
# (a) An image pinned as `repo@sha256:f25b...` was parsed by splitting on the last ':', so the
#     gate reported the DIGEST HEX as the running "tag": a 64-char string printed where a version
#     belongs, then compared to 2.4.252 and called DRIFT. The verdict was right, which is exactly
#     why nobody noticed -- a gate whose output is unreadable is one nobody reads.
Assert "a DIGEST-pinned image yields no tag (not the hex)" (
    (Get-PimImageTag -Image 'acrpimmfnpr.azurecr.io/pim-manager@sha256:f25ba6e48fbadf96f24aebc38da0f775c99f8027bc240953edd02d10f787e023') -eq '')
Assert "  ...and a normal tag still parses (the fix is narrow)" (
    (Get-PimImageTag -Image 'acr.azurecr.io/pim-manager:2.4.251') -eq '2.4.251')

# (b) With no tag to parse, the caller may resolve the digest against the registry. The pure core
#     accepts that resolved tag -- and MUST NOT let it override a tag the image really carries,
#     or a stale cache entry could silently rewrite a correct answer.
$digestImg = 'acr.azurecr.io/pim-manager@sha256:abc123'
$rowsResolved = (Get-PimVersionDriftReport -Expected '2.4.252' -Deployed @(
    [pscustomobject]@{ app='ca-pim-manager'; image=$digestImg; revision='r1'; createdUtc=''; resolvedTag='2.4.251' })).rows
Assert "a resolved digest tag is used when the image carries none" ("$($rowsResolved[0].tag)" -eq '2.4.251')
Assert "  ...and it reports DRIFT against the expected version" ("$($rowsResolved[0].status)" -eq 'drift')
$rowsBoth = (Get-PimVersionDriftReport -Expected '2.4.252' -Deployed @(
    [pscustomobject]@{ app='x'; image='acr/pim-manager:2.4.252'; revision='r'; createdUtc=''; resolvedTag='9.9.9' })).rows
Assert "  ...but a REAL tag always wins over a resolved one" ("$($rowsBoth[0].tag)" -eq '2.4.252' -and "$($rowsBoth[0].status)" -eq 'ok')
# 🔒 'unknown' must stay REACHABLE. An admitted gap beats an invented version -- if resolution
# fails, the gate says so rather than guessing.
$rowsNone = (Get-PimVersionDriftReport -Expected '2.4.252' -Deployed @(
    [pscustomobject]@{ app='y'; image=$digestImg; revision='r'; createdUtc=''; resolvedTag='' })).rows
Assert "  ...and an unresolvable digest is UNKNOWN, never a pass" (
    "$($rowsNone[0].status)" -eq 'unknown' -and -not (Get-PimVersionDriftReport -Expected '2.4.252' -Deployed @(
        [pscustomobject]@{ app='y'; image=$digestImg; revision='r'; createdUtc=''; resolvedTag='' })).ok)

# (c) EVERY az call must be SUBSCRIPTION-SCOPED. This gate ran against the ambient default, and on
#     a machine logged into two directories that is a coin flip -- on mgmt1 it lands on a different
#     company's subscription, so the gate queried the wrong tenant and found nothing. Same family
#     as SEC-12: an ambient identity standing in for an explicit one.
$chkSrc  = Get-Content -LiteralPath $checker -Raw
$chkCode = (($chkSrc -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
Assert "the checker accepts -SubscriptionId" ($chkCode -match '\$SubscriptionId')
# 🪤 Comment-stripped, because this file argues about subscriptions at length and an assertion
# reading prose would be satisfied by its own documentation.
$azCalls  = @([regex]::Matches($chkCode, '&\s+az\s+containerapp[^\r\n]*'))
$unscoped = @($azCalls | Where-Object { $_.Value -notmatch '@subArgs' })
Assert "  ...and EVERY containerapp call is scoped with @subArgs" ($azCalls.Count -ge 3 -and $unscoped.Count -eq 0)
Assert "  ...including the ACR lookup used to resolve a digest" ($chkCode -match 'acr manifest list-metadata[^\r\n]*@SubArgs')
# (d) Container app JOBS drift too. A fleet check that reads only apps can report "no drift" while
#     the tick job runs last month's engine -- BUG-09's shape, one resource type over.
# 🪤 THE FIRST VERSION OF THIS ASSERT COULD NOT FAIL, and only the negative run showed it: it
# checked that `$Jobs` and `containerapp job show` EXIST in the file. Deleting the line that adds
# jobs to the work list left both in place -- parameter declared, branch present, and no job ever
# read. Declared-but-not-wired, which is this codebase's most expensive recurring defect. Assert
# the WIRING: jobs must actually reach $targets.
Assert "the checker also reads container app JOBS" (
    $chkCode -match '\$Jobs' -and $chkCode -match 'containerapp job show' -and
    $chkCode -match '\$targets\s*\+=\s*,@\{\s*name\s*=\s*\$j')
Write-Host ""
Write-Host ("PIM version drift (TEST-09): {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
