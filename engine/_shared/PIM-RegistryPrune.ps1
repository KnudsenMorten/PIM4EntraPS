#Requires -Version 7.0
<#
.SYNOPSIS
    IMAGE-PRUNE (framework IMAGE-PATCH-1, owner decision 2026-11-12): after a SUCCESSFUL update that read back healthy,
    the install's OWN container registry keeps only the current release's image and the one previous release's image,
    per PIM repository. Every other manifest is deleted.

.DESCRIPTION
    Why: the registry's vulnerability scan reads every stored image, so images of old releases keep reporting old CVEs
    at the install long after it stopped running them. Rollback = one version down (the previous image stays); an older
    rollback rebuilds the image from its source.

    WHAT IS KEPT, per repository (Get-PimRegistryPrunePlan, PURE):
      * every manifest carrying a version tag >= the CURRENT version (the current one, and anything newer -- a newer tag
        is a build of the next version and is never ours to delete before it runs);
      * every manifest carrying the PREVIOUS version's tag (the highest version tag below the current one, sorted as
        versions: 3.1.10 > 3.1.9);
      * every digest a container app / job of this install RUNS, or its PIM_UPDATE_LAST_GOOD names (re-read right before
        deleting) -- listed in the report with who uses it;
      * the platform child manifests of a KEPT multi-platform image (an image index) -- listed as "child of <tag>";
      * a manifest whose registry lock forbids deleting it -- listed as "kept: locked", never unlocked.
    An UNTAGGED manifest that is none of these goes, whatever its age (3.1.15).
    Everything else is deleted, by digest, over the registry's data plane (DELETE /v2/<repo>/manifests/<digest>).

    NEVER: another registry (only the login server of the install's own Manager image), a repository PIM does not push
    (only the Manager's repository and the sign-in front's), a repository whose current version tag is not there, or
    anything when the identity has no delete right (soft skip with one plain line). The function never throws.

    Test seam: $global:PIM_RegistryPruneRest = { param($Op, $LoginServer, $Repository, $Arg) ... } with
      Op 'token'     -> @{ token = '...'; actions = @('pull','delete') }
      Op 'manifests' -> the manifest objects of the repository (digest, tags, createdTime, lastUpdateTime, mediaType,
                        changeableAttributes.deleteEnabled); $null = the repository does not exist
      Op 'children'  -> the child digests of the image index $Arg
      Op 'delete'    -> deletes manifest $Arg
#>

# The only job / app setting whose image value counts as "in use" (the watchdog starts it). Never a pin such as
# PIM_UPDATE_TARGET_IMAGE: that is a request, not a running image.
$script:PimRegistryPruneImageSettings = @('PIM_UPDATE_LAST_GOOD')

$script:PimRegistryPruneIndexTypes = @(
    'application/vnd.docker.distribution.manifest.list.v2+json',
    'application/vnd.oci.image.index.v1+json')

function ConvertTo-PimRegistryPruneVersion {
    <# PURE. '3.1.13' / 'v3.1.13' / '3.1.7.1' -> [version]; anything else (latest, a digest, 2.4.295-rc) -> $null. #>
    param([AllowEmptyString()][AllowNull()][string]$Tag)
    $t = "$Tag".Trim()
    if ($t -match '^[vV]?(?<v>\d+(\.\d+){1,3})$') { try { return [version]$Matches['v'] } catch { return $null } }
    return $null
}

function Get-PimRegistryPruneTime {
    <# PURE. The manifest's time (lastUpdateTime, else createdTime) as UTC, or $null. #>
    param($Manifest)
    foreach ($p in 'lastUpdateTime', 'createdTime') {
        $v = $Manifest.$p
        if ($v -is [datetime]) { return $v.ToUniversalTime() }
        if ("$v".Trim()) { try { return ([datetimeoffset]::Parse("$v", [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } catch { } }
    }
    return $null
}

function Get-PimRegistryPrunePlan {
    <#
      PURE. Which manifests of ONE repository stay and which go.
        -Manifests       the repository's manifests (digest, tags, times, mediaType, changeableAttributes)
        -CurrentVersion  the version this install runs now (the Manager repository: the version the update rolled to)
        -LiveDigests     digests a live app / job / job setting names -- always kept
        -LiveBy          @{ <digest> = '<app/job that uses it>' } -- the reason named in the report (3.1.15)
        -Children        @{ <index digest> = @(<child digest>, ...) } for kept image indexes
      Returns @{ ok; reason; current; previous; keep = @(@{digest; tags; why; extra}); delete = @(@{digest; tags; why});
                 total; indexes = @(<kept index digests>) }. ok = $false = delete NOTHING (reason says why).
      extra = $true for a keep beyond current / previous / newer (live-used, locked, child) -- each is listed in the report.
      3.1.15 (live 3.1.14 on the build host: 21 untagged build leftovers survived): an UNTAGGED manifest goes unless a live
      app / job uses that exact digest or it is a platform child of a KEPT index -- there is no age rule any more.
    #>
    param([object[]]$Manifests = @(), [AllowEmptyString()][string]$CurrentVersion = '', [string[]]$LiveDigests = @(),
          [hashtable]$LiveBy = @{}, [hashtable]$Children = @{})
    $all = @($Manifests | Where-Object { $_ -and "$($_.digest)".Trim() })
    $res = @{ ok = $false; reason = ''; current = "$CurrentVersion".Trim(); previous = ''; keep = @(); delete = @(); total = $all.Count; indexes = @() }
    $cur = ConvertTo-PimRegistryPruneVersion -Tag $CurrentVersion
    if (-not $cur) { $res.reason = "the current version ('$CurrentVersion') is not a version -- nothing deleted"; return $res }
    $hasCur = $false; $prev = $null
    foreach ($m in $all) {
        foreach ($t in @($m.tags)) {
            $v = ConvertTo-PimRegistryPruneVersion -Tag "$t"
            if (-not $v) { continue }
            if ($v -eq $cur) { $hasCur = $true }
            elseif ($v -lt $cur -and (-not $prev -or $v -gt $prev)) { $prev = $v }
        }
    }
    if (-not $hasCur) { $res.reason = "the current version's tag $cur is not in the repository -- nothing deleted"; return $res }
    $res.previous = if ($prev) { "$prev" } else { '' }

    $live = @{}; foreach ($d in @($LiveDigests) + @($LiveBy.Keys)) { if ("$d".Trim()) { $live["$d".Trim().ToLowerInvariant()] = $true } }
    $by = @{}; foreach ($k in @($LiveBy.Keys)) { if ("$k".Trim()) { $by["$k".Trim().ToLowerInvariant()] = "$($LiveBy[$k])" } }
    $why = [ordered]@{}; $extra = @{}
    foreach ($m in $all) {
        $dg = "$($m.digest)".Trim().ToLowerInvariant()
        $vs = @(@($m.tags) | ForEach-Object { ConvertTo-PimRegistryPruneVersion -Tag "$_" } | Where-Object { $_ })
        if (@($vs | Where-Object { $_ -eq $cur }).Count) { $why[$dg] = 'current release' }
        elseif (@($vs | Where-Object { $_ -gt $cur }).Count) { $why[$dg] = 'newer than the current release' }
        elseif ($prev -and @($vs | Where-Object { $_ -eq $prev }).Count) { $why[$dg] = 'previous release' }
        elseif ($live.ContainsKey($dg)) { $why[$dg] = 'live-used by ' + $(if ("$($by[$dg])".Trim()) { "$($by[$dg])" } else { 'a live container or job' }); $extra[$dg] = $true }
        elseif ($m.changeableAttributes -and $m.changeableAttributes.PSObject.Properties['deleteEnabled'] -and $m.changeableAttributes.deleteEnabled -eq $false) { $why[$dg] = 'kept: locked (delete disabled in the registry; not unlocked)'; $extra[$dg] = $true }
    }
    # The platform children of a KEPT image index stay with it (a multi-platform image is the index + its platform manifests).
    foreach ($dg in @($why.Keys)) {
        $m = @($all | Where-Object { "$($_.digest)".Trim().ToLowerInvariant() -eq $dg })[0]
        if ($m -and "$($m.mediaType)" -in $script:PimRegistryPruneIndexTypes) { $res.indexes += $dg }
        $label = if ($m -and @($m.tags).Count) { (@($m.tags) -join ', ') } else { $dg }
        foreach ($c in @($Children[$dg])) { $ck = "$c".Trim().ToLowerInvariant(); if ($ck -and -not $why.Contains($ck)) { $why[$ck] = "child of $label"; $extra[$ck] = $true } }
    }
    # Everything else goes: an older release, and EVERY untagged manifest no live app / job uses and no kept index holds.
    foreach ($m in $all) {
        $dg = "$($m.digest)".Trim().ToLowerInvariant()
        $tags = @(@($m.tags) | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
        if ($why.Contains($dg)) { $res.keep += @{ digest = "$($m.digest)"; tags = $tags; why = $why[$dg]; extra = [bool]$extra[$dg] }; continue }
        if (-not $tags.Count) { $res.delete += @{ digest = "$($m.digest)"; tags = @(); why = 'untagged, not in use' }; continue }
        $res.delete += @{ digest = "$($m.digest)"; tags = $tags; why = 'an older release' }
    }
    $res.ok = $true
    $res.reason = "current $cur, previous $(if ($prev) { $prev } else { '(none)' })"
    return $res
}

function Test-PimRegistryPruneDue {
    <#
      PURE. May this run prune? Only after a SUCCESSFUL, not-held update whose Manager READ BACK on the target image.
      Returns @{ due; reason }.
    #>
    param([AllowEmptyString()][string]$Outcome = '', [object]$Healthy = $null, [bool]$Held = $false,
          [AllowEmptyString()][string]$ManagerImage = '', [AllowEmptyString()][string]$TargetImage = '',
          [string[]]$JobsNotRolled = @(), [AllowEmptyString()][string]$Disable = '')
    if ("$Disable".Trim() -eq '1') { return @{ due = $false; reason = 'switched off on this install (PIM_UPDATE_NO_PRUNE=1)' } }
    if ($Held) { return @{ due = $false; reason = 'the install is held -- nothing pruned' } }
    if ("$Outcome" -ne 'ok') { return @{ due = $false; reason = "the update did not succeed ($Outcome) -- nothing pruned" } }
    if ($Healthy -eq $false) { return @{ due = $false; reason = 'the Manager was not healthy after the roll -- nothing pruned' } }
    if (@($JobsNotRolled | Where-Object { "$_".Trim() }).Count) { return @{ due = $false; reason = 'not every job is on the new build -- nothing pruned' } }
    $t = "$TargetImage".Trim(); $m = "$ManagerImage".Trim()
    if (-not $t) { return @{ due = $false; reason = 'no target image -- nothing pruned' } }
    if (-not $m) { return @{ due = $false; reason = 'the Manager image did not read back -- nothing pruned' } }
    if ($m -ine $t) { return @{ due = $false; reason = "the Manager reads back on $m, not $t -- nothing pruned" } }
    return @{ due = $true; reason = "the Manager reads back on $t" }
}

function Get-PimRegistryLiveImages {
    <#
      PURE. Every image reference the given container apps / jobs RUN: each container and init container image, plus the
      ONE setting that names an image the platform may start -- PIM_UPDATE_LAST_GOOD (the updater's last-known-good image
      the watchdog falls back to).
      3.1.15 (live 3.1.14 on the build host): ANY image-shaped setting counted as "in use" -- a stale pin such as
      PIM_UPDATE_TARGET_IMAGE (ignored by a ring-managed updater) held an old release and, through it, every untagged
      manifest since. Only what really runs, or may be started by the watchdog, counts now.
      -WithSource: @{ image; by } objects, by = '<resource> (container <name>)' / '<resource> setting PIM_UPDATE_LAST_GOOD'.
    #>
    param([object[]]$Resources = @(), [AllowEmptyString()][string]$LoginServer = '', [switch]$WithSource)
    $out = New-Object System.Collections.Generic.List[object]
    $ls = "$LoginServer".Trim().ToLowerInvariant()
    foreach ($r in @($Resources | Where-Object { $_ })) {
        $tpl = $r.properties.template
        $rn = "$($r.name)".Trim(); if (-not $rn) { $rn = 'an app or job' }
        foreach ($c in @(@($tpl.containers) + @($tpl.initContainers) | Where-Object { $_ })) {
            if ("$($c.image)".Trim()) { $out.Add(@{ image = "$($c.image)".Trim(); by = "$rn (container $($c.name))" }) }
            if ($ls) {
                foreach ($e in @($c.env | Where-Object { $_ -and "$($_.name)" -in $script:PimRegistryPruneImageSettings })) {
                    $v = "$($e.value)".Trim()
                    if ($v -and $v.ToLowerInvariant().StartsWith("$ls/")) { $out.Add(@{ image = $v; by = "$rn setting $($e.name)" }) }
                }
            }
        }
    }
    if ($WithSource) { return @($out.ToArray()) }
    return @($out.ToArray() | ForEach-Object { $_.image } | Select-Object -Unique)
}

function Invoke-PimRegistryPruneRest {
    <# The registry data plane (or the test seam). See the file header for the operations. #>
    param([Parameter(Mandatory)][string]$Op, [Parameter(Mandatory)][string]$LoginServer, [string]$Repository = '', [string]$Arg = '')
    if ($global:PIM_RegistryPruneRest) { return (& $global:PIM_RegistryPruneRest $Op $LoginServer $Repository $Arg) }
    switch ($Op) {
        'token' {
            $aad = Get-PimRestToken -Resource 'arm'
            $body = @{ grant_type = 'access_token'; service = $LoginServer; access_token = "$aad" }
            try { $tid = Get-PimTokenTenantId -Token "$aad"; if ($tid) { $body['tenant'] = $tid } } catch { }
            $ex = Invoke-RestMethod -Method POST -Uri "https://$LoginServer/oauth2/exchange" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body $body
            $tk = Invoke-RestMethod -Method POST -Uri "https://$LoginServer/oauth2/token" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body @{
                grant_type = 'refresh_token'; service = $LoginServer; scope = "repository:$Repository`:pull,delete"; refresh_token = "$($ex.refresh_token)" }
            $acc = "$($tk.access_token)"
            return @{ token = $acc; actions = @(Get-PimRegistryTokenActions -Token $acc -Repository $Repository) }
        }
        'manifests' {
            $h = @{ Authorization = "Bearer $script:PimRegistryPruneToken" }
            $list = New-Object System.Collections.Generic.List[object]; $last = ''
            for ($page = 0; $page -lt 50; $page++) {
                $u = "https://$LoginServer/acr/v1/$Repository/_manifests?n=1000" + $(if ($last) { "&last=$([uri]::EscapeDataString($last))" } else { '' })
                try { $r = Invoke-RestMethod -Method GET -Uri $u -Headers $h -TimeoutSec 60 }
                catch { $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }; if ($code -eq 404) { return $null }; throw }
                $ms = @(@($r.manifests) | Where-Object { $_ })
                foreach ($m in $ms) { $list.Add($m) }
                if ($ms.Count -lt 1000) { break }
                $last = "$($ms[-1].digest)"
            }
            return , @($list.ToArray())
        }
        'children' {
            $h = @{ Authorization = "Bearer $script:PimRegistryPruneToken"; Accept = ($script:PimRegistryPruneIndexTypes -join ', ') }
            $r = Invoke-RestMethod -Method GET -Uri "https://$LoginServer/v2/$Repository/manifests/$Arg" -Headers $h -TimeoutSec 60
            return @(@($r.manifests) | ForEach-Object { "$($_.digest)" } | Where-Object { $_ })
        }
        'delete' {
            # A platform child is removed by the registry together with its deleted index: its own DELETE then answers 404 --
            # already gone, not a failure.
            try { [void](Invoke-RestMethod -Method DELETE -Uri "https://$LoginServer/v2/$Repository/manifests/$Arg" -Headers @{ Authorization = "Bearer $script:PimRegistryPruneToken" } -TimeoutSec 60) }
            catch { $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }; if ($code -eq 404) { return 'gone' }; throw }
            return $true
        }
    }
}

function Get-PimRegistryTokenActions {
    <# PURE. The actions a registry access token grants on -Repository (its 'access' claim). @() when unreadable. #>
    param([AllowEmptyString()][string]$Token, [string]$Repository)
    try {
        $p = "$Token".Split('.')[1].Replace('-', '+').Replace('_', '/')
        switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
        $c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
        return @(@($c.access) | Where-Object { "$($_.type)" -eq 'repository' -and "$($_.name)" -eq $Repository } | ForEach-Object { @($_.actions) } | ForEach-Object { "$_" })
    } catch { return @() }
}

function Invoke-PimRegistryPrune {
    <#
      The whole prune for ONE install. NEVER throws. Returns @{ ran; skipped; reason; planOnly; kept; total; deleted;
      failed; repos = @(@{ repository; ok; reason; total; kept; deleted; failed; left; plan }); line; lines }.
        -LoginServer        the install's own registry (from the Manager's image) -- the ONLY registry touched
        -ManagerRepository  the Manager's repository; its current version = -TargetVersion
        -Repositories       the other PIM repositories (signin-front); their current version = the highest version a
                            live image of that repository names (none = that repository is left alone)
        -ReadLiveImages     { } -> image references in use NOW; called right before the deletes of each repository
                            (a failed read = nothing deleted)
        -PlanOnly           decide and report, delete nothing
    #>
    param([AllowEmptyString()][string]$LoginServer = '', [AllowEmptyString()][string]$ManagerRepository = '',
          [AllowEmptyString()][string]$TargetVersion = '', [string[]]$Repositories = @(),
          [Parameter(Mandatory)][scriptblock]$ReadLiveImages, [switch]$PlanOnly)
    $res = @{ ran = $false; skipped = $true; reason = ''; planOnly = [bool]$PlanOnly; kept = 0; total = 0; deleted = 0; failed = 0; repos = @(); line = ''; lines = @() }
    $ls = "$LoginServer".Trim().ToLowerInvariant()
    if (-not $ls -or -not "$ManagerRepository".Trim()) {
        $res.reason = "registry: not pruned -- this install's registry is not known"; $res.line = $res.reason; $res.lines = @($res.line); return $res
    }
    $repos = @(@("$ManagerRepository".Trim()) + @($Repositories | ForEach-Object { "$_".Trim() }) | Where-Object { $_ } | Select-Object -Unique)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($repo in $repos) {
        $rr = @{ repository = $repo; ok = $false; reason = ''; total = 0; kept = 0; deleted = 0; failed = 0; left = -1; plan = $null }
        try {
            $tok = Invoke-PimRegistryPruneRest -Op 'token' -LoginServer $ls -Repository $repo
            if (-not $tok -or @($tok.actions) -notcontains 'delete') {
                # Soft skip: no delete right on the registry yet. Nothing in any repository is touched.
                $noRight = "registry: not pruned -- this updater's identity has no delete right on its registry yet (Contributor on the registry gives it; the update job setup grants it)"
                if (-not @($res.repos).Count) { $res.reason = $noRight; $res.line = $noRight; $res.lines = @($noRight); return $res }
                $rr.reason = 'no delete right on it -- nothing deleted'; $res.repos += $rr; continue
            }
            $script:PimRegistryPruneToken = "$($tok.token)"
            $ms = Invoke-PimRegistryPruneRest -Op 'manifests' -LoginServer $ls -Repository $repo
            if ($null -eq $ms) { $rr.reason = 'not in this registry'; $res.repos += $rr; continue }
            $ms = @($ms | Where-Object { $_ })
            $rr.total = $ms.Count
            # The live images, re-read NOW (right before anything is deleted). A failed read = nothing deleted.
            # Each item is an image string or @{ image; by } (who uses it -- named in the report).
            $liveImgs = @(& $ReadLiveImages)
            $liveDigests = New-Object System.Collections.Generic.List[string]; $liveVersions = @(); $liveBy = @{}
            foreach ($item in $liveImgs) {
                $img = if ($item -is [hashtable] -or ($item -and $item.PSObject.Properties['image'])) { "$($item.image)" } else { "$item" }
                $who = if ($item -is [hashtable] -or ($item -and $item.PSObject.Properties['by'])) { "$($item.by)".Trim() } else { '' }
                $ref = Split-PimImageReference -Image "$img"
                if (-not $ref -or "$($ref.loginServer)".ToLowerInvariant() -ne $ls -or "$($ref.repository)" -ne $repo) { continue }
                $hit = @()
                if ("$($ref.digest)".Trim()) { $hit += "$($ref.digest)".Trim() }
                if ("$($ref.tag)".Trim()) {
                    foreach ($m in @($ms | Where-Object { @($_.tags) -contains "$($ref.tag)" })) { $hit += "$($m.digest)" }
                    $lv = ConvertTo-PimRegistryPruneVersion -Tag "$($ref.tag)"; if ($lv) { $liveVersions += $lv }
                }
                foreach ($h in $hit) {
                    $liveDigests.Add($h); $hk = $h.ToLowerInvariant()
                    if ($who) { $liveBy[$hk] = if ($liveBy[$hk]) { "$($liveBy[$hk]), $who" } else { $who } }
                    elseif (-not $liveBy.ContainsKey($hk)) { $liveBy[$hk] = '' }
                }
                foreach ($m in @($ms | Where-Object { "$($_.digest)" -eq "$($ref.digest)" })) {
                    foreach ($t in @($m.tags)) { $lv = ConvertTo-PimRegistryPruneVersion -Tag "$t"; if ($lv) { $liveVersions += $lv } }
                }
            }
            $curV = ''
            if ($repo -eq "$ManagerRepository".Trim()) { $curV = "$TargetVersion".Trim() }
            elseif ($liveVersions.Count) { $curV = "$(@($liveVersions | Sort-Object -Descending)[0])" }
            if (-not $curV) { $rr.reason = 'no live image names a version of it -- nothing deleted'; $res.repos += $rr; continue }
            $plan = Get-PimRegistryPrunePlan -Manifests $ms -CurrentVersion $curV -LiveDigests @($liveDigests.ToArray()) -LiveBy $liveBy
            if ($plan.ok -and @($plan.indexes).Count) {
                $kids = @{}
                foreach ($ix in @($plan.indexes)) { $kids[$ix] = @(Invoke-PimRegistryPruneRest -Op 'children' -LoginServer $ls -Repository $repo -Arg $ix) }
                $plan = Get-PimRegistryPrunePlan -Manifests $ms -CurrentVersion $curV -LiveDigests @($liveDigests.ToArray()) -LiveBy $liveBy -Children $kids
            }
            $rr.plan = $plan
            if (-not $plan.ok) { $rr.reason = $plan.reason; $rr.kept = $rr.total; $res.repos += $rr; continue }
            $rr.kept = @($plan.keep).Count
            if (-not $PlanOnly) {
                foreach ($d in @($plan.delete)) {
                    try { [void](Invoke-PimRegistryPruneRest -Op 'delete' -LoginServer $ls -Repository $repo -Arg "$($d.digest)"); $rr.deleted++ }
                    catch { $rr.failed++ }
                }
                # 3.1.15 (d): kept / deleted are the READ-BACK numbers -- a platform child removed with its deleted index is
                # neither counted as kept nor twice as deleted. Not readable = the planned numbers, said so.
                try { $after = Invoke-PimRegistryPruneRest -Op 'manifests' -LoginServer $ls -Repository $repo; $rr.left = @($after | Where-Object { $_ }).Count } catch { $rr.left = -1 }
                if ($rr.left -ge 0) { $rr.kept = $rr.left; $rr.deleted = [Math]::Max(0, $rr.total - $rr.left) }
            }
            $rr.ok = $true; $rr.reason = $plan.reason
        } catch {
            $rr.reason = "could not be read or pruned ($((("$($_.Exception.Message)") -split "`n")[0])) -- the update is not affected"
        }
        $res.repos += $rr
    }
    $res.ran = $true; $res.skipped = $false
    foreach ($rr in $res.repos) {
        $res.total += [int]$rr.total
        if ($rr.ok) {
            $res.kept += [int]$rr.kept; $res.deleted += [int]$rr.deleted; $res.failed += [int]$rr.failed
            $planDel = @($rr.plan.delete).Count
            $l = if ($PlanOnly) { "registry (plan only): $($rr.repository) -- would keep $($rr.kept) of $($rr.total) images, would delete $planDel ($($rr.reason))" }
                 else { "registry: $($rr.repository) -- kept $($rr.kept) of $($rr.total) images; deleted $($rr.deleted)" + $(if ($rr.failed) { "; $($rr.failed) could not be deleted (tried again next update)" } else { '' }) + $(if ($rr.left -ge 0) { " (read back)" } else { ' (planned; not read back)' }) + " ($($rr.reason))" }
            $lines.Add($l)
            # 3.1.15 (c): every keep beyond current / previous / newer is listed with its reason.
            foreach ($k in @($rr.plan.keep | Where-Object { $_.extra })) {
                $name = if (@($k.tags).Count) { (@($k.tags) -join ', ') } else { "untagged $("$($k.digest)".Substring(0, [Math]::Min(19, "$($k.digest)".Length)))" }
                $lines.Add("registry: $($rr.repository) -- kept $name -- $($k.why)")
            }
        } elseif ("$($rr.reason)" -ne 'not in this registry') {
            $lines.Add("registry: $($rr.repository) -- $($rr.reason)")
        }
    }
    $res.lines = @($lines.ToArray())
    $res.line = if ($PlanOnly) { "registry (plan only): would keep $($res.kept) of $($res.total) images" } else { "registry: kept $($res.kept) of $($res.total) images; deleted $($res.deleted)" }
    $res.reason = $res.line
    return $res
}
