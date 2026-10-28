#Requires -Version 5.1

<#
.SYNOPSIS
    Updates a PIM Manager installation by hand: it reads Invardia's signed release for this edition and ring, verifies it exactly as the in-cloud updater does, and only with -Apply downloads the release, checks its size and SHA-256, and deploys it with the parameters the last successful deploy saved.

.DESCRIPTION
    Two ways to update, the same for Pro and Community: the in-cloud updater (the default -- it runs at night) or this
    command, for an installation whose owner keeps the updater off (deploy with -SkipUpdater) and updates on their own
    schedule. Both check the same things before anything changes.

      1. READ the signed release: Community -- Invardia's Community channel (anonymous); Pro -- the licence feed
         (-InstallKey + -LicencePath). VERIFY it: signature by an update key built into this version, product, kind,
         ring, a sequence not lower than the last one applied here (no replay), a release that asks for a manual step or
         a newer starting version is held, and a major jump is refused (-AllowMajor takes a planned one).
      2. With -Apply: DOWNLOAD the release archive and check its size and SHA-256 against the signed manifest, unpack it
         into a new folder next to this one (PIM4EntraPS-<version>), and check its VERSION.
      3. RUN that release's own Invoke-PimDeployAll.ps1 with the saved profile (see _PimDeployProfile.ps1). Every step that
         is already current is skipped; the schema is upgraded additively before the new version rolls, and a failed health
         check rolls the Manager back. Without -Apply the deploy prints its plan only.

    The profile is written by a successful `Invoke-PimDeployAll.ps1 ... -Apply` (it prints where). No profile
    yet? Run toolssetupInvoke-PimDeployAll.ps1 ... -Apply once (the first install), then use this.

.PARAMETER TenantId
    Which saved profile to use when there is more than one on this machine.
.PARAMETER ProfilePath
    A profile file to use directly.
.PARAMETER SkipPull
    Re-run the deploy on the code you already have (no release is read or downloaded).
.PARAMETER Apply
    Download the verified release and deploy it. Without it nothing changes: the target version is reported and the deploy
    plan printed. -WhatIf wins over -Apply: nothing is downloaded and the deploy runs as a -WhatIf plan.
.PARAMETER Edition
    Community (default: Invardia's anonymous Community channel) or Pro (the licence feed: needs -InstallKey and -LicencePath).
.PARAMETER Ring
    The release ring to follow (default 3, the public release; the Community channel serves rings 2 and 3).
.PARAMETER InstallKey
    Pro only: this installation's Invardia install key (Settings > Licence).
.PARAMETER LicencePath
    Pro only: the Invardia-issued licence file.
.PARAMETER BaseUrl
    Invardia's address, when not https://invardia.com.
.PARAMETER AllowMajor
    Take a MAJOR version jump on purpose (refused otherwise, framework PUB-8).
.PARAMETER DeployArgs
    Extra parameters for the release's deploy (a hashtable) -- for a parameter a newer release added. Never saved.
.PARAMETER AcceptBaselineChange
    Accept a new version that changes the policy baseline. The update refuses such a version and names this switch;
    give it for that one run when the change is intended. It is never saved into the profile.
.PARAMETER StepRunner
    Test seam only (tests\script-docs): handed to Invoke-PimDeployAll.ps1 -StepRunner.

.EXAMPLE
    .\tools\setup\Update-PimCommunity.ps1            # what would change
    .\tools\setup\Update-PimCommunity.ps1 -Apply     # update to the latest release

.LINK
    https://invardia.com/docs/pim/scripts/Update-PimCommunity/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$TenantId,
    [string]$ProfilePath,
    [switch]$SkipPull,
    [switch]$Apply,
    [switch]$AcceptBaselineChange,
    [ValidateSet('Community', 'Pro')][string]$Edition = 'Community',
    [ValidateRange(0, 3)][int]$Ring = 3,
    [string]$InstallKey,
    [string]$LicencePath,
    [string]$BaseUrl = '',
    [switch]$AllowMajor,
    [hashtable]$DeployArgs,
    # --- test seam (tests\script-docs\Update-PimCommunity.case.ps1) ---
    [scriptblock]$StepRunner
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimDeployProfile.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$null = Start-PimScriptRun -Script 'Update-PimCommunity'
$script:updRc = 0
try {
# -WhatIf wins over -Apply: nothing is fetched, nothing is pulled, the deploy prints its plan only.
$whatIfOnly = [bool]$WhatIfPreference
if ($Apply -and -not $PSCmdlet.ShouldProcess($solRoot, 'download the verified signed release and deploy it')) { $Apply = $false }

# --- which profile -----------------------------------------------------------------------------------
if (-not "$ProfilePath".Trim()) {
    $dir = Get-PimDeployProfileDir
    $all = @(if (Test-Path $dir) { Get-ChildItem -Path $dir -Filter '*.json' -File })
    if ("$TenantId".Trim()) { $all = @($all | Where-Object { $_.Name -like "$($TenantId.Trim())-*" }) }
    if (-not $all.Count) { throw "no deploy profile found in $dir$(if ($TenantId) { " for tenant $TenantId" }). Run the first install (toolssetupInvoke-PimDeployAll.ps1 ... -Apply) once; it saves the profile this updater re-uses." }
    if ($all.Count -gt 1) { throw "more than one deploy profile in ${dir}: $(@($all.Name) -join ', ') -- pick one with -TenantId or -ProfilePath" }
    $ProfilePath = $all[0].FullName
}
$prof = Read-PimDeployProfile -Path $ProfilePath
Write-Host "deploy profile : $ProfilePath (saved $($prof.savedUtc), deployed version $($prof.version))" -ForegroundColor Cyan
if (@($prof.omitted).Count) { Write-Host "not in the profile (they carry a secret): $(@($prof.omitted) -join ', ') -- this updater cannot supply them" -ForegroundColor Yellow }

# --- the code: the SIGNED release, never a bare git pull ----------------------------------------------------
# COMMUNITY-INCLOUD-UPDATER (owner 2026-10-28): this manual command is a real choice ("i like the manual update as backup ...
# just in case that customers dont trust the update mechanism for security reason"), so it checks EXACTLY what the in-cloud
# updater checks -- Invardia's signed manifest (signature by an embedded key, product, kind, ring, sequence, minFromVersion,
# manualStep, major jump), then the archive's size + SHA-256 -- and deploys from the VERIFIED archive. Community: the
# anonymous Community channel; Pro: the licence feed (-InstallKey + -LicencePath). It used to trust 'git pull'.
function Get-PimLocalVersion { param([string]$Root = $solRoot) $f = Join-Path $Root 'VERSION'; if (Test-Path $f) { "$(Get-Content $f -Raw)".Trim() } else { '' } }
$before = Get-PimLocalVersion
$deployScript = Join-Path $PSScriptRoot 'Invoke-PimDeployAll.ps1'
$seqFile = "$ProfilePath.update-sequence.json"   # the manual path's own replay watermark, next to the profile
$pendingSeq = $null
if ($SkipPull) {
    Write-Host "code           : $before (no pull -- -SkipPull)" -ForegroundColor DarkGray
} else {
    . (Join-Path $solRoot 'engine\_shared\PIM-InvardiaUpdate.ps1')
    $kind = $(if ($Edition -eq 'Pro') { 'code' } else { 'community' })
    $applied = 0
    try { if (Test-Path -LiteralPath $seqFile) { $sj = Get-Content -Raw -LiteralPath $seqFile | ConvertFrom-Json; $k = "$kind-r$Ring"; if ($sj.PSObject.Properties[$k]) { $applied = [int]$sj.$k } } } catch { $applied = 0 }
    if ($Edition -eq 'Pro') {
        if (-not "$InstallKey".Trim() -or -not "$LicencePath".Trim()) { throw 'Pro: -InstallKey and -LicencePath are needed to read the signed Pro release feed (Settings > Licence shows the install key)' }
        . (Join-Path $solRoot 'engine\_shared\PIM-LicenceRequest.ps1')
        $lic = ConvertTo-PimInvardiaLicenceText -Value (Get-Content -Raw -LiteralPath $LicencePath)
        $p = Invoke-PimInvardiaManifestPull -Http { param($m, $u, $b, $h) Invoke-PimLicenceHttp -Method $m -Url $u -Body $b -Headers $h } -BaseUrl $BaseUrl -InstallKey $InstallKey -LicenceText $lic -Ring $Ring
    } else {
        $p = Invoke-PimInvardiaCommunityPull -BaseUrl $BaseUrl -Ring $Ring
    }
    if ($p.status -eq 204) {
        Write-Host "code           : $before -- $($p.reason)" -ForegroundColor Green
    } elseif ($p.status -ne 200) {
        throw "the signed release could not be read: $($p.reason)"
    } else {
        $v = Test-PimInvardiaManifest -Response $p.body -Kind $kind -AppliedSequence $applied -RunningVersion $before -Ring $Ring
        if (-not $v.ok) { throw "the release was REFUSED -- nothing changed: $($v.reason)" }
        if ($v.hold) { throw "the release is HELD -- nothing changed: $($v.reason)" }
        Write-Host "signed release : $($v.reason) -- verified (signature, product, kind, ring, sequence)" -ForegroundColor Green
        $cmp = $(if ($before) { Compare-PimReleaseVersion $v.version $before } else { 1 })
        if ($cmp -le 0) {
            Write-Host "code           : $before -- already the latest the ring approves ($($v.version))" -ForegroundColor Green
        } else {
            $mj = Test-PimUpdateMajorJump -RunningVersion $before -Target $v.version -AllowMajor:$AllowMajor
            if (-not $mj.ok) { throw $mj.reason }
            Write-Host "code           : $before -> $($v.version)" -ForegroundColor Green
            if ($Apply -and -not $whatIfOnly) {
                $dest = Join-Path (Split-Path -Parent $solRoot) ("PIM4EntraPS-{0}" -f $v.version)
                if (Test-Path -LiteralPath $dest) { throw "$dest already exists -- remove it (or run that release's own Update-PimCommunity.ps1)" }
                $zip = Join-Path ([IO.Path]::GetTempPath()) ("pim-release-{0}.zip" -f $v.version)
                $d = Save-PimInvardiaArchive -Url $v.downloadUrl -OutFile $zip -ExpectedSha256 $v.sha256 -ExpectedSize $v.size
                if (-not $d.ok) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue; throw "the archive was REFUSED -- nothing changed: $($d.reason)" }
                Write-Host "archive        : $($d.bytes) bytes, size + SHA-256 match the signed manifest" -ForegroundColor Green
                $stage = Join-Path ([IO.Path]::GetTempPath()) ("pim-release-{0}-{1}" -f $v.version, ([guid]::NewGuid().ToString('N').Substring(0, 6)))
                try {
                    Expand-Archive -LiteralPath $zip -DestinationPath $stage -Force
                    # Community zip = the release tree at its root; Pro zip = pim-manager-src-<v>/SOLUTIONS/PIM4EntraPS
                    $tree = $stage
                    $proTree = Join-Path $stage ("pim-manager-src-{0}\SOLUTIONS\PIM4EntraPS" -f $v.version)
                    if (Test-Path -LiteralPath (Join-Path $proTree 'VERSION')) { $tree = $proTree }
                    elseif (-not (Test-Path -LiteralPath (Join-Path $tree 'VERSION'))) {
                        $tops = @(Get-ChildItem -LiteralPath $stage -Directory); if ($tops.Count -eq 1) { $tree = $tops[0].FullName }
                    }
                    $inVer = Get-PimLocalVersion -Root $tree
                    if ($inVer -ne $v.version) { throw "the archive holds version '$inVer', the signed manifest says $($v.version) -- refused" }
                    Move-Item -LiteralPath $tree -Destination $dest
                } finally {
                    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
                }
                Write-Host "verified tree  : $dest (run future updates from there)" -ForegroundColor Green
                # G6: the NEW release's own deploy runs -- it knows the parameters that release added.
                $deployScript = Join-Path $dest 'tools\setup\Invoke-PimDeployAll.ps1'
                $pendingSeq = @{ key = "$kind-r$Ring"; value = [int]$v.sequence }
            } else {
                Write-Host "                 (plan only: nothing downloaded; the plan below is for the code you have now -- re-run with -Apply)" -ForegroundColor DarkYellow
            }
        }
    }
}

# --- the deploy ----------------------------------------------------------------------------------------
$deployArgs = $prof.parameters
if ($Apply) { $deployArgs['Apply'] = $true }
if ($whatIfOnly) { $deployArgs['WhatIf'] = $true }
if ($StepRunner) { $deployArgs['StepRunner'] = $StepRunner }
# COMMUNITY-TEST-ENV G1: the update's refusal of a policy-baseline change names -AcceptBaselineChange -- passed on, one run only
# (never saved into the profile).
if ($AcceptBaselineChange) { $deployArgs['AcceptBaselineChange'] = $true }
# G6: any parameter a NEWER release's deploy added, passed through as given (never saved into the profile).
if ($DeployArgs) { foreach ($k in @($DeployArgs.Keys)) { $deployArgs[$k] = $DeployArgs[$k] } }
$global:LASTEXITCODE = 0
& $deployScript @deployArgs
$script:updRc = $LASTEXITCODE
# The sequence this run applied becomes the manual path's replay watermark -- only after a deploy that succeeded.
if ($pendingSeq -and $script:updRc -eq 0) {
    try {
        $sj = [ordered]@{}; if (Test-Path -LiteralPath $seqFile) { $o = Get-Content -Raw -LiteralPath $seqFile | ConvertFrom-Json; foreach ($pp in $o.PSObject.Properties) { $sj[$pp.Name] = $pp.Value } }
        $sj[$pendingSeq.key] = $pendingSeq.value
        [IO.File]::WriteAllText($seqFile, ($sj | ConvertTo-Json -Compress))
    } catch { Write-Warning "the applied sequence was not recorded ($($_.Exception.Message)) -- the same release is simply seen again next time" }
}
} finally { Stop-PimScriptRun -Script 'Update-PimCommunity' }
# The deploy's own verdict is the update's verdict (an unverified or failed deploy is not a success):
# exit $LASTEXITCODE of the deploy, carried past the finally that closes the transcript.
exit $script:updRc
