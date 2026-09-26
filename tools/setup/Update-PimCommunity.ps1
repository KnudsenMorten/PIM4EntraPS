#Requires -Version 5.1
<#
.SYNOPSIS
    Keep a COMMUNITY (free) installation on the latest release: pull it from GitHub, then re-run the
    deploy with the parameters the last successful deploy saved.

.DESCRIPTION
    The community edition has no in-cloud updater (that needs the published release feed of a Pro
    subscription), so it updates on your schedule, from GitHub. This is that update, as one command
    (operator 2026-09-26: "update ... setup scripts so community version runs latest version").

      1. FETCH the clone's upstream and say which version it would move to (VERSION here -> VERSION there).
      2. With -Apply: PULL it, fast-forward only. A clone with local changes to tracked files is REFUSED --
         a merge in a deploy tree is a decision for you, not for an updater.
      3. RE-RUN Invoke-PimDeployAll.ps1 with the saved profile (see _PimDeployProfile.ps1). Every step that is
         already current is skipped; the schema is upgraded additively before the new version rolls, and a
         failed health check rolls the Manager back. Without -Apply the deploy prints its plan only.

    The profile is written by a successful `Invoke-PimDeployAll.ps1 ... -Apply` (it prints where). No profile
    yet? Run step 3 of the README once with -Apply, then use this.

.PARAMETER TenantId
    Which saved profile to use when there is more than one on this machine.
.PARAMETER ProfilePath
    A profile file to use directly.
.PARAMETER SkipPull
    Re-run the deploy on the code you already have (no fetch, no pull).
.PARAMETER Apply
    Pull and deploy. Without it nothing changes: the target version is reported and the deploy plan printed.

.EXAMPLE
    .\tools\setup\Update-PimCommunity.ps1            # what would change
    .\tools\setup\Update-PimCommunity.ps1 -Apply     # update to the latest release
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$ProfilePath,
    [switch]$SkipPull,
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimDeployProfile.ps1')
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# --- which profile -----------------------------------------------------------------------------------
if (-not "$ProfilePath".Trim()) {
    $dir = Get-PimDeployProfileDir
    $all = @(if (Test-Path $dir) { Get-ChildItem -Path $dir -Filter '*.json' -File })
    if ("$TenantId".Trim()) { $all = @($all | Where-Object { $_.Name -like "$($TenantId.Trim())-*" }) }
    if (-not $all.Count) { throw "no deploy profile found in $dir$(if ($TenantId) { " for tenant $TenantId" }). Run README step 3 (Invoke-PimDeployAll.ps1 ... -Apply) once; it saves the profile this updater re-uses." }
    if ($all.Count -gt 1) { throw "more than one deploy profile in ${dir}: $(@($all.Name) -join ', ') -- pick one with -TenantId or -ProfilePath" }
    $ProfilePath = $all[0].FullName
}
$prof = Read-PimDeployProfile -Path $ProfilePath
Write-Host "deploy profile : $ProfilePath (saved $($prof.savedUtc), deployed version $($prof.version))" -ForegroundColor Cyan
if (@($prof.omitted).Count) { Write-Host "not in the profile (they carry a secret): $(@($prof.omitted) -join ', ') -- this updater cannot supply them" -ForegroundColor Yellow }

# --- the code ------------------------------------------------------------------------------------------
function Get-PimLocalVersion { $f = Join-Path $solRoot 'VERSION'; if (Test-Path $f) { "$(Get-Content $f -Raw)".Trim() } else { '' } }
$before = Get-PimLocalVersion
if ($SkipPull) {
    Write-Host "code           : $before (no pull -- -SkipPull)" -ForegroundColor DarkGray
} else {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'git is not installed -- it is needed to fetch the latest release (or pass -SkipPull)' }
    $inside = "$(& git -C $solRoot rev-parse --is-inside-work-tree 2>$null)".Trim()
    if ($inside -ne 'true') { throw "$solRoot is not a git clone -- get the code with 'git clone' (README step 1), or pass -SkipPull" }
    & git -C $solRoot fetch --quiet 2>&1 | Out-Host
    if ($LASTEXITCODE) { throw "git fetch failed (exit $LASTEXITCODE)" }
    $upstream = "$(& git -C $solRoot rev-parse --abbrev-ref '@{u}' 2>$null)".Trim()
    if (-not $upstream) { throw 'this branch has no upstream to update from -- check out the default branch of the GitHub clone' }
    $remoteVer = "$(& git -C $solRoot show '@{u}:./VERSION' 2>$null)".Trim()
    $behind = [int]"$(& git -C $solRoot rev-list --count 'HEAD..@{u}' 2>$null)".Trim()
    if (-not $behind) {
        Write-Host "code           : $before -- already the latest on $upstream" -ForegroundColor Green
    } else {
        Write-Host "code           : $before -> $remoteVer ($behind commit(s) on $upstream)" -ForegroundColor Green
        $dirty = @(& git -C $solRoot status --porcelain --untracked-files=no)
        if ($dirty.Count) { throw "this clone has local changes to tracked files -- refusing to update over them:`n  $($dirty -join "`n  ")" }
        if ($Apply) {
            & git -C $solRoot pull --ff-only --quiet 2>&1 | Out-Host
            if ($LASTEXITCODE) { throw "git pull --ff-only failed (exit $LASTEXITCODE) -- the clone has diverged from $upstream; resolve it yourself" }
            $after = Get-PimLocalVersion
            Write-Host "pulled         : now $after" -ForegroundColor Green
        } else {
            Write-Host "                 (plan only: nothing pulled; the plan below is for the code you have now -- re-run with -Apply)" -ForegroundColor DarkYellow
        }
    }
}

# --- the deploy ----------------------------------------------------------------------------------------
$deployArgs = $prof.parameters
if ($Apply) { $deployArgs['Apply'] = $true }
$global:LASTEXITCODE = 0
& (Join-Path $PSScriptRoot 'Invoke-PimDeployAll.ps1') @deployArgs
# The deploy's own verdict is the update's verdict (an unverified or failed deploy is not a success).
exit $LASTEXITCODE
