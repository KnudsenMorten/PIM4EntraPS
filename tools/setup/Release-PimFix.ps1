#Requires -Version 5.1
<#
.SYNOPSIS
    FAST RELEASE PATH (PIM REQUIREMENTS 100.20; framework DOCS/REQUIREMENTS.md 12.1 SPEED RULE): one fix, from the
    working tree to RING 1, in one command -- gate on the test VM, version bump, commit + push + tags, Invardia ring 1,
    the support-script / documentation hand-overs -- with the time of every step. It never touches ring 2.

.DESCRIPTION
    Owner 2026-10-09: "it is simply taking too long whenever i want simple things fixed. customer is frustrated and i am
    loosing business ... it is a disater". Target: a one-line fix released to ring 1 in <= 15 min, the gate <= 10 min.

      1 preconditions  on main, origin/main not ahead (git fetch), the tree holds only this fix (+ the bump files)
      2 gate           tests\Get-PimAffectedSuites.ps1 (the GATE answer: core set + the fix's own suites + the GUI harnesses
                       of the touched page sections) -> run-pim-suite-vm.ps1 -Tests 'gate=...' -Lane gate on the test VM:
                       parallel, PowerShell 7 only, a time per suite. RED stops the release. -FullGate runs the full suite
                       instead (a feature release). Never on this machine.
      3 bump           VERSION, tools\setup\install-parameters.json "version", sync\release-map.json PIM internal.1 AND .2,
                       RELEASENOTES.md (one line: -Notes) -- text surgery, formatting kept
      4 commit + push  explicit paths only (never a wildcard add), push, git ls-remote == HEAD ("Changes must be made through a pull
                       request" is not a failure), the tags PIM4EntraPS-<v> + PIM4EntraPS-v<v>, pushed and read back
      5 publish        Publish-PimInvardiaRelease.ps1 -Ring 1 -Apply (a 409 versionExists -> -Promote to ring 1)
      6 hand-over      every tools\setup\Build-Pim*.ps1 hand-over builder present (support scripts; settings docs, the security
                       pack and the setup catalog share <HandoverRoot>\docs) into <HandoverRoot>\<kind>\pim-manager\<v>
      7 timing         the table of step times against the 15 / 10 min targets
    After ring 1 rolls, tools\setup\Invoke-PimPostRollSmoke.ps1 (scheduled -IfChanged by Register-PimFastReleaseTasks.ps1)
    smokes the hosted Manager and rolls it back to the last-good image on red -- the safety net that makes a small gate
    acceptable. The full suite runs nightly (Invoke-PimNightlySuite.ps1).

    -WhatIf plans EVERY step with its exact command and writes nothing: no fetch, no VM, no file, no commit, no publish.
    Stops at the first red; -From <n> resumes at step n (the version is then read from VERSION when step 3 is done).
    The publisher identity (tenant, Key Vault) comes from -PublisherTenantId / -KeyVault / -KeyVaultSubscription or the
    JSON -ConfigFile (keys publisherTenantId, keyVault, keyVaultSubscription, azureConfigDir) -- never from this file.
.EXAMPLE
    .\tools\setup\Release-PimFix.ps1 -Notes 'Get Started no longer hides the mail step' -WhatIf
.EXAMPLE
    .\tools\setup\Release-PimFix.ps1 -Notes 'Get Started no longer hides the mail step' -ConfigFile C:\ProgramData\pim\ops\release-fix.json
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Version = '',                              # default: the next patch of VERSION
    [Parameter(Mandatory)][string]$Notes,               # one line for RELEASENOTES + the commit message
    [ValidateSet(1)][int]$Ring = 1,                     # ring 1 ONLY -- ring 2 moves on the owner's typed words, elsewhere
    [string[]]$Files = @(),                             # the fix's files (repo-relative); default: what differs from origin/main
    [ValidateRange(1, 7)][int]$From = 1,
    [switch]$FullGate,
    [string]$Repo = '',
    [string]$VmRunner = 'C:\ProgramData\pim\ops\run-pim-suite-vm.ps1',
    [string]$Lane = 'gate',                             # a RELEASE lane on the test VM: never waits, AboveNormal priority
    [string]$OutRoot = $(Join-Path $env:ProgramData 'pim\logs\release-fix'),
    [string]$HandoverRoot = $(Join-Path $env:ProgramData 'Invardia\handover'),
    [string]$ConfigFile = $(Join-Path $env:ProgramData 'pim\ops\release-fix.json'),
    [string]$PublisherTenantId = '',
    [string]$KeyVault = '',
    [string]$KeyVaultSubscription = '',
    [string]$AzureConfigDir = ''
)
$ErrorActionPreference = 'Stop'
$plan = [bool]$WhatIfPreference
$sol = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not $Repo) { $Repo = Split-Path (Split-Path $sol -Parent) -Parent }
$Files = @($Files | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() -replace '\\', '/' } | Where-Object { $_ })
$BumpFiles = @('SOLUTIONS/PIM4EntraPS/VERSION', 'SOLUTIONS/PIM4EntraPS/tools/setup/install-parameters.json', 'sync/release-map.json', 'SOLUTIONS/PIM4EntraPS/RELEASENOTES.md')
$clock = [Diagnostics.Stopwatch]::StartNew()
$times = New-Object System.Collections.Generic.List[object]
$script:StepClock = $null; $script:StepName = ''
function El([TimeSpan]$t) { '{0:00}:{1:00}' -f [int][Math]::Floor($t.TotalMinutes), $t.Seconds }
function Close-Step { if ($script:StepClock) { $times.Add([pscustomobject]@{ Step = $script:StepName; Seconds = [Math]::Round($script:StepClock.Elapsed.TotalSeconds, 1) }); Write-Host ("    step done in {0}" -f (El $script:StepClock.Elapsed)) -ForegroundColor DarkGray; $script:StepClock = $null } }
function Step([int]$n, [string]$title) {
    Close-Step
    $script:CurStep = $n; $script:StepName = "$n $title"; $script:StepClock = [Diagnostics.Stopwatch]::StartNew()
    Write-Host ("`n[{0}/7] {1}   (+{2} total)" -f $n, $title, (El $clock.Elapsed)) -ForegroundColor Cyan
}
function Red([string]$m) {
    Close-Step
    Write-Host "`nRED: $m" -ForegroundColor Red
    Write-Host ("Stopped after {0}. Fix it, then re-run with -From {1}." -f (El $clock.Elapsed), $script:CurStep) -ForegroundColor Red
    exit 1
}
function Show([string]$cmd) { Write-Host "    > $cmd" -ForegroundColor $(if ($plan) { 'Yellow' } else { 'DarkGray' }) }
# NOT named "Git": a function Git calling git resolves to ITSELF (PowerShell names are case-insensitive) and recurses
function RepoGit { $ErrorActionPreference = 'Continue'; $o = & git.exe -C $Repo @args 2>&1; $script:GitExit = $LASTEXITCODE; return $o }

# ---- configuration (never real identifiers in this file) ------------------------------------------------------------
$cfg = $null
if ($ConfigFile -and (Test-Path -LiteralPath $ConfigFile)) { try { $cfg = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json } catch { throw "-ConfigFile ${ConfigFile}: not JSON ($($_.Exception.Message))" } }
if ($cfg) {
    if (-not $PublisherTenantId -and $cfg.publisherTenantId) { $PublisherTenantId = "$($cfg.publisherTenantId)" }
    if (-not $KeyVault -and $cfg.keyVault) { $KeyVault = "$($cfg.keyVault)" }
    if (-not $KeyVaultSubscription -and $cfg.keyVaultSubscription) { $KeyVaultSubscription = "$($cfg.keyVaultSubscription)" }
    if (-not $AzureConfigDir -and $cfg.azureConfigDir) { $AzureConfigDir = "$($cfg.azureConfigDir)" }
}

# ---- the version -----------------------------------------------------------------------------------------------------
$verFile = Join-Path $sol 'VERSION'
$cur = (Get-Content -LiteralPath $verFile -Raw).Trim()
if (-not $Version) {
    if ($From -ge 4) { $Version = $cur }
    elseif ($cur -match '^(\d+)\.(\d+)\.(\d+)$') { $Version = '{0}.{1}.{2}' -f $Matches[1], $Matches[2], ([int]$Matches[3] + 1) }
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "no release version (VERSION='$cur', -Version '$Version')" }
$Notes = ("$Notes" -replace '[\r\n]+', ' ').Trim()
if (-not $Notes) { throw '-Notes: one line for RELEASENOTES and the commit message' }
$runDir = Join-Path $OutRoot $Version
$vmOut = Join-Path $runDir 'gate'

Write-Host ("PIM FAST RELEASE -- {0} -> ring 1 (VERSION now {1}){2}" -f $Version, $cur, $(if ($plan) { '   *** -WhatIf: a PLAN, nothing is changed ***' } else { '' })) -ForegroundColor Magenta
Write-Host "  notes     : $Notes"
Write-Host "  repo      : $Repo"
Write-Host "  ring      : 1 only (ring 2 is never touched by this command)"
Write-Host ("  gate      : {0}" -f $(if ($FullGate) { 'the FULL suite (-FullGate)' } else { "affected suites, PowerShell 7, lane '$Lane'" }))
if (-not $plan -and $From -le 5 -and -not $PublisherTenantId) { throw "the Invardia publish needs -PublisherTenantId (or publisherTenantId in $ConfigFile)" }

# =====================================================================================================================
if ($From -le 1) {
    Step 1 'preconditions: main, origin/main not ahead, only this fix in the tree'
    Show "git -C $Repo rev-parse --abbrev-ref HEAD   (must be main)"
    $br = "$(RepoGit rev-parse --abbrev-ref HEAD)".Trim()
    Write-Host "    branch: $br"
    if (-not $plan -and $br -ne 'main') { Red "the repo is on '$br', not main" }
    Show "git -C $Repo fetch origin main ; git rev-list --count HEAD..origin/main   (must be 0)"
    if (-not $plan) { [void](RepoGit fetch origin main); if ($script:GitExit) { Red 'git fetch failed' } }
    $behind = "$(RepoGit rev-list --count HEAD..origin/main)".Trim()
    Write-Host ("    origin/main ahead of HEAD by: {0}{1}" -f $behind, $(if ($plan) { ' (last fetch; -WhatIf does not fetch)' } else { '' }))
    if (-not $plan -and $behind -ne '0') { Red "origin/main is $behind commit(s) ahead -- pull --ff-only and re-run" }
    $dirty = @(RepoGit status --porcelain | Where-Object { "$_" -match '^[ MADRCU?!]{2} ' } | ForEach-Object { ("$_".Substring(3)).Trim('"') -replace '\\', '/' } | ForEach-Object { if ($_ -match ' -> ') { ($_ -split ' -> ')[-1] } else { $_ } })
    $ahead = @(RepoGit diff --name-only origin/main...HEAD | ForEach-Object { "$_".Trim() } | Where-Object { $_ -and $_ -notmatch '^(warning|fatal):' })
    if (-not $Files.Count) { $Files = @(@($dirty) + @($ahead) | Where-Object { $BumpFiles -notcontains $_ } | Sort-Object -Unique) }
    Write-Host ("    the fix: {0}" -f $(if ($Files.Count) { $Files -join ', ' } else { '(nothing changed)' }))
    $extra = @($dirty | Where-Object { $Files -notcontains $_ -and $BumpFiles -notcontains $_ })
    if ($extra.Count) { if ($plan) { Write-Host "    !! not part of this fix (a real run refuses): $($extra -join ', ')" -ForegroundColor Yellow } else { Red "the tree holds files that are not this fix: $($extra -join ', ') -- another session may be live; release from a clean tree" } }
    if (-not $plan -and -not $Files.Count) { Red 'there is no change to release' }
    if ($Files.Count -gt 5) { Write-Host "    note: $($Files.Count) files -- the SPEED RULE is ONE fix per release" -ForegroundColor Yellow }
}

# =====================================================================================================================
if ($From -le 2) {
    Step 2 'gate on the test VM (never on this machine)'
    $selector = Join-Path $sol 'tests\Get-PimAffectedSuites.ps1'
    $gateList = ''
    if ($FullGate) {
        Show "pwsh -NoProfile -File $VmRunner -Lane $Lane -Repo $Repo -OutDir $vmOut   (the full suite)"
    } else {
        $selArgs = @('-NoProfile', '-File', $selector, '-Json')
        if ($Files.Count) { $selArgs += @('-Files', ($Files -join ',')) } else { $selArgs += @('-Range', 'origin/main...HEAD') }
        Show ("pwsh " + ($selArgs -join ' ') + '   (the GATE answer; read-only)')
        $selOut = & pwsh @selArgs | Out-String
        if ($LASTEXITCODE) { Red 'the suite selector failed' }
        $sel = $selOut | ConvertFrom-Json
        $gateList = "$($sel.GateList)"
        foreach ($f in @($sel.Files)) { Write-Host ("      {0} [{1}] -> {2}" -f $f.Path, $f.Class, (@($f.Suites) -join ', ')) }
        Write-Host ("    {0} suite(s){1}: {2}" -f @($sel.Suites).Count, $(if (@($sel.GuiHarnesses).Count) { " (GUI harnesses: $(@($sel.GuiHarnesses) -join ', '))" } else { '' }), $sel.List)
        if (-not $gateList -or $gateList -eq 'gate=') { Red 'the selector returned no gate' }
        Show "pwsh -NoProfile -File $VmRunner -Tests '$gateList' -Lane $Lane -Hours 1 -Repo $Repo -OutDir $vmOut   (waits; reads $vmOut\suite.done)"
    }
    if (-not $plan) {
        if (-not (Test-Path -LiteralPath $VmRunner)) { Red "no VM runner at $VmRunner (offline tests never run on this machine)" }
        New-Item -ItemType Directory -Force -Path $vmOut | Out-Null
        $t0 = [Diagnostics.Stopwatch]::StartNew()
        if ($FullGate) { & pwsh -NoProfile -File $VmRunner -Lane $Lane -Repo $Repo -OutDir $vmOut -Hours 2 | Out-Host }
        else { & pwsh -NoProfile -File $VmRunner -Tests $gateList -Lane $Lane -Hours 1 -Repo $Repo -OutDir $vmOut | Out-Host }
        $done = if (Test-Path "$vmOut\suite.done") { (Get-Content "$vmOut\suite.done" -Raw).Trim() } else { 'missing' }
        $log = if (Test-Path "$vmOut\suite.log") { Get-Content "$vmOut\suite.log" } else { @() }
        $reds = @($log | Where-Object { $_ -match '^##### (\S+) exit ([1-9]\d*)$' } | ForEach-Object { $Matches[1] } | Where-Object { $_ -notlike 'gate=*' })
        $gt = @($log | Where-Object { $_ -match '^\s+[\d.]+s  exit ' })
        if ($gt.Count) { Write-Host '    suite times on the VM:'; $gt | Select-Object -First 15 | ForEach-Object { Write-Host "    $_" } }
        Write-Host ("    VM: done={0} in {1}; red: {2}" -f $done, (El $t0.Elapsed), $(if ($reds.Count) { $reds -join ', ' } else { 'none' }))
        if ($done -ne '0') { Red "the gate is red on the VM ($vmOut\suite.log): $($reds -join ', ')" }
    }
}

# =====================================================================================================================
if ($From -le 3) {
    Step 3 "version bump $cur -> $Version (+ RELEASENOTES)"
    $ip = Join-Path $sol 'tools\setup\install-parameters.json'
    $rm = Join-Path $Repo 'sync\release-map.json'
    $rn = Join-Path $sol 'RELEASENOTES.md'
    Show "VERSION = $Version"
    Show "install-parameters.json: `"version`": `"$Version`""
    Show "sync/release-map.json: PIM4EntraPS internal 1.version AND 2.version = $Version (promotedUtc = now)"
    Show "RELEASENOTES.md: '## $Version -- $(Get-Date -Format yyyy-MM-dd)' + '- $Notes' under '<!-- next release entry goes here -->'"
    if (-not $plan) {
        $utf8 = [Text.UTF8Encoding]::new($false)
        [IO.File]::WriteAllText($verFile, "$Version`n", $utf8)
        $t = [IO.File]::ReadAllText($ip)
        $first = [regex]::Match($t, '"version"\s*:\s*"[^"]+"')
        if (-not $first.Success) { Red 'install-parameters.json has no "version"' }
        [IO.File]::WriteAllText($ip, $t.Substring(0, $first.Index) + ('"version": "' + $Version + '"') + $t.Substring($first.Index + $first.Length), $utf8)
        $m = [IO.File]::ReadAllText($rm)
        $pm = [regex]::Match($m, '"PIM4EntraPS":\s*\{\s*"internal"')
        if (-not $pm.Success) { Red 'sync/release-map.json: no PIM4EntraPS internal channel' }
        $pi = $pm.Index
        $end = $m.IndexOf('"3":', $pi); if ($end -lt 0) { Red 'sync/release-map.json: no ring 3 after the PIM channel (layout changed -- bump by hand)' }
        $blk = $m.Substring($pi, $end - $pi)
        $now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $blk = [regex]::Replace($blk, '("(?:1|2)":\s*\{\s*"version":\s*")[^"]+(",\s*"promotedUtc":\s*")[^"]+(")', { param($x) $x.Groups[1].Value + $Version + $x.Groups[2].Value + $now + $x.Groups[3].Value })
        $n = ([regex]::Matches($blk, '"(1|2)":\s*\{\s*"version":\s*"' + [regex]::Escape($Version) + '"')).Count
        if ($n -ne 2) { Red "sync/release-map.json: bumped $n of the 2 PIM ring entries (1 and 2) -- check the layout" }
        [IO.File]::WriteAllText($rm, $m.Substring(0, $pi) + $blk + $m.Substring($end), $utf8)
        $r = [IO.File]::ReadAllText($rn)
        if ($r -notmatch [regex]::Escape("## $Version ")) {
            $mark = '<!-- next release entry goes here -->'
            if (-not $r.Contains($mark)) { Red 'RELEASENOTES.md: no "<!-- next release entry goes here -->" marker' }
            [IO.File]::WriteAllText($rn, $r.Replace($mark, "$mark`n## $Version -- $(Get-Date -Format yyyy-MM-dd)`n`n- $Notes`n"), $utf8)
        }
        $back = (Get-Content -LiteralPath $verFile -Raw).Trim(); $ipBack = ([IO.File]::ReadAllText($ip) | ConvertFrom-Json).version
        Write-Host "    read back: VERSION=$back install-parameters=$ipBack release-map PIM 1+2=$Version"
        if ($back -ne $Version -or $ipBack -ne $Version) { Red 'the bump did not read back' }
    }
}

# =====================================================================================================================
if ($From -le 4) {
    Step 4 'commit explicit paths -> push -> ls-remote -> tags'
    $paths = @(@($Files) + $BumpFiles | Sort-Object -Unique)
    foreach ($p in $paths) { Show "git -C $Repo add -- $p" }
    Show "git -C $Repo diff --cached --name-only   (exactly those paths, nothing else)"
    $msg = "release(PIM) v$Version -- $Notes"
    Show "git -C $Repo commit -F <msg>   ('$msg')"
    Show "git -C $Repo push origin main ; git ls-remote origin refs/heads/main == HEAD"
    Show "git -C $Repo tag PIM4EntraPS-$Version ; tag PIM4EntraPS-v$Version ; git push origin both ; ls-remote each"
    if (-not $plan) {
        foreach ($p in $paths) { if (Test-Path -LiteralPath (Join-Path $Repo $p)) { [void](RepoGit add -- $p); if ($script:GitExit) { Red "git add $p failed" } } }
        $staged = @(RepoGit diff --cached --name-only | ForEach-Object { "$_".Trim() } | Where-Object { $_ -and $_ -notmatch '^(warning|hint):' })
        $other = @($staged | Where-Object { $paths -notcontains $_ })
        if ($other.Count) { Red "staged files that are not this release: $($other -join ', ') (unstage them BY PATH; never git reset)" }
        if ($staged.Count) {
            $mf = [IO.Path]::GetTempFileName(); [IO.File]::WriteAllText($mf, $msg, [Text.UTF8Encoding]::new($false))
            try { [void](RepoGit commit -F $mf); if ($script:GitExit) { Red 'git commit failed (a hook?) -- fix it, never --no-verify' } } finally { Remove-Item $mf -Force }
        } else { Write-Host '    nothing staged -- already committed' }
        $head = "$(RepoGit rev-parse HEAD)".Trim()
        RepoGit push origin main | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
        $remote = "$((@(RepoGit ls-remote origin refs/heads/main) | Where-Object { "$_" -match '^[0-9a-f]{40}\s' } | Select-Object -First 1) -split '\s+' | Select-Object -First 1)".Trim()
        Write-Host "    HEAD $head / origin main $remote"
        if ($remote -ne $head) { Red "the push did not land (origin main = $remote, HEAD = $head)" }
        foreach ($tg in "PIM4EntraPS-$Version", "PIM4EntraPS-v$Version") {
            $have = "$(RepoGit rev-parse -q --verify "refs/tags/$tg")".Trim()
            if (-not $have) { [void](RepoGit tag $tg $head); if ($script:GitExit) { Red "git tag $tg failed" } }
            elseif ("$(RepoGit rev-parse "$tg^{commit}")".Trim() -ne $head) { Red "tag $tg already exists on another commit -- never move a published tag" }
        }
        [void](RepoGit push origin "PIM4EntraPS-$Version" "PIM4EntraPS-v$Version")
        foreach ($tg in "PIM4EntraPS-$Version", "PIM4EntraPS-v$Version") { if (-not "$(@(RepoGit ls-remote origin "refs/tags/$tg") | Where-Object { "$_" -match '^[0-9a-f]{40}\s' })".Trim()) { Red "tag $tg is not on origin" } }
        Write-Host "    pushed $head + tags PIM4EntraPS-$Version, PIM4EntraPS-v$Version"
    }
}

# =====================================================================================================================
if ($From -le 5) {
    Step 5 'publish: Invardia ring 1'
    $pub = Join-Path $sol 'tools\setup\Publish-PimInvardiaRelease.ps1'
    $pubArgs = @{ Version = $Version; Ring = $Ring; TenantId = $(if ($PublisherTenantId) { $PublisherTenantId } else { '<publisher tenant>' }); Apply = $true }
    if ($KeyVault) { $pubArgs['KeyVault'] = $KeyVault }
    if ($KeyVaultSubscription) { $pubArgs['KeyVaultSubscription'] = $KeyVaultSubscription }
    if ($Ring -ne 1) { Red 'ring 1 only' }
    Show ("{0}pwsh -NoProfile -File {1} -Version {2} -Ring 1 -TenantId {3}{4}{5} -Apply   (409 versionExists -> the same with -Promote)" -f $(if ($AzureConfigDir) { "`$env:AZURE_CONFIG_DIR='$AzureConfigDir'; " } else { '' }), $pub, $Version, $pubArgs.TenantId, $(if ($KeyVault) { " -KeyVault $KeyVault" } else { '' }), $(if ($KeyVaultSubscription) { " -KeyVaultSubscription $KeyVaultSubscription" } else { '' }))
    if (-not $plan) {
        $prevCfg = $env:AZURE_CONFIG_DIR
        if ($AzureConfigDir) { $env:AZURE_CONFIG_DIR = $AzureConfigDir }
        try {
            $o = & $pub @pubArgs 2>&1; $c = $LASTEXITCODE
            $o | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
            if ($c -and ("$o" -match 'versionExists|409')) {
                Write-Host '    already published -- releasing it to ring 1 (-Promote)' -ForegroundColor Yellow
                $o = & $pub @pubArgs -Promote 2>&1; $c = $LASTEXITCODE; $o | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
            }
        } finally { $env:AZURE_CONFIG_DIR = $prevCfg }
        if ($c) { Red "Invardia publish ring 1 failed (exit $c)" }
    }
}

# =====================================================================================================================
if ($From -le 6) {
    Step 6 'hand-overs: support scripts, settings docs, security pack (each builder that exists)'
    $kinds = [ordered]@{ 'Build-PimSupportScripts.ps1' = 'support-scripts'; 'Build-PimSettingsDocs.ps1' = 'docs'; 'Build-PimSettingDocs.ps1' = 'docs'; 'Build-PimSecurityPack.ps1' = 'docs'; 'Build-PimSetupCatalog.ps1' = 'docs' }
    # 100.30: the settings docs, the security pack and the setup catalog share ONE folder, <HandoverRoot>\docs\pim-manager\<v>,
    # and each builder (re)writes that folder's ONE SHA256SUMS.txt over every file in it (tools\setup\_PimHandoverSums.ps1).
    $builders = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'Build-Pim*.ps1' -File | Where-Object { $kinds.Contains($_.Name) -or $_.Name -match '(?i)Setting|Security' })
    if (-not $builders.Count) { Write-Host '    no hand-over builder in this tree' -ForegroundColor Yellow }
    foreach ($b in $builders) {
        $kind = if ($kinds.Contains($b.Name)) { $kinds[$b.Name] } else { ($b.BaseName -replace '^Build-Pim', '' -creplace '([a-z])([A-Z])', '$1-$2').ToLowerInvariant() }
        $dest = Join-Path $HandoverRoot "$kind\pim-manager\$Version"
        $hasOut = $false; try { $hasOut = (Get-Command $b.FullName -ErrorAction Stop).Parameters.ContainsKey('OutDir') } catch { }
        Show ("pwsh -NoProfile -File {0}{1}" -f $b.FullName, $(if ($hasOut) { " -OutDir $dest" } else { '' }))
        if (-not $plan) {
            if ($hasOut) { & pwsh -NoProfile -File $b.FullName -OutDir $dest | Out-Host } else { & pwsh -NoProfile -File $b.FullName | Out-Host }
            if ($LASTEXITCODE) { Red "$($b.Name) failed (exit $LASTEXITCODE)" }
        }
    }
}

# =====================================================================================================================
Step 7 'timing'
Close-Step
$total = $clock.Elapsed
$gateS = (@($times | Where-Object { $_.Step -like '2 *' }) | Measure-Object Seconds -Sum).Sum
Write-Host ''
$times | ForEach-Object { Write-Host ("    {0,7:N1}s  {1}" -f $_.Seconds, $_.Step) }
Write-Host ("    total {0} (target <= 15:00); gate {1:N0}s (target <= 600s){2}" -f (El $total), $gateS, $(if ($plan) { ' -- PLAN times, nothing ran' } else { '' })) -ForegroundColor $(if ($total.TotalMinutes -le 15) { 'Green' } else { 'Yellow' })
Write-Host ("`n{0} {1} to ring 1. Ring 2 is not touched. The post-roll smoke (Invoke-PimPostRollSmoke.ps1) guards the roll in ring 1." -f $(if ($plan) { 'PLAN for' } else { 'RELEASED' }), $Version) -ForegroundColor Green
exit 0
