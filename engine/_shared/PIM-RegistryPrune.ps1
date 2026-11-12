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
          [hashtable]$LiveBy = @{}, [hashtable]$Children = @{},
          # IMAGE-PRUNE CONTRACT point 2: what ran BEFORE this update (read before the roll) + the durable record of the
          # previous release, as digests of this repository; kept as 'previous release (recorded)'. With
          # -RequirePreviousRecord and -PreviousRecorded:$false = delete NOTHING (the previous release is not recorded).
          [string[]]$PreviousDigests = @(), [bool]$PreviousRecorded = $true, [switch]$RequirePreviousRecord,
          # point 2 (Invardia 2026-11-12): @{ <referrer digest> = '<what it refers to>' } -- the OCI referrers (attestations,
          # signatures) of kept images, transitively; kept and counted with the child manifests.
          [hashtable]$Referrers = @{})
    $all = @($Manifests | Where-Object { $_ -and "$($_.digest)".Trim() })
    $res = @{ ok = $false; reason = ''; current = "$CurrentVersion".Trim(); previous = ''; keep = @(); delete = @(); total = $all.Count; indexes = @() }
    if ($RequirePreviousRecord -and -not $PreviousRecorded) { $res.reason = 'the previous release is not recorded (what ran before this update could not be read) -- nothing deleted'; return $res }
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
    $prevRec = @{}; foreach ($d in @($PreviousDigests)) { if ("$d".Trim()) { $prevRec["$d".Trim().ToLowerInvariant()] = $true } }
    $why = [ordered]@{}; $extra = @{}
    foreach ($m in $all) {
        $dg = "$($m.digest)".Trim().ToLowerInvariant()
        $vs = @(@($m.tags) | ForEach-Object { ConvertTo-PimRegistryPruneVersion -Tag "$_" } | Where-Object { $_ })
        if (@($vs | Where-Object { $_ -eq $cur }).Count) { $why[$dg] = 'current release' }
        elseif (@($vs | Where-Object { $_ -gt $cur }).Count) { $why[$dg] = 'newer than the current release' }
        elseif ($prevRec.ContainsKey($dg)) { $why[$dg] = 'previous release (recorded: ran before this update)'; if (-not ($prev -and @($vs | Where-Object { $_ -eq $prev }).Count)) { $extra[$dg] = $true } }
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
    foreach ($rk in @($Referrers.Keys)) { $rd = "$rk".Trim().ToLowerInvariant(); if ($rd -and -not $why.Contains($rd)) { $why[$rd] = "referrer of $($Referrers[$rk])"; $extra[$rd] = $true } }
    # Everything else goes: an older release, and EVERY untagged manifest no live app / job uses and no kept index holds.
    foreach ($m in $all) {
        $dg = "$($m.digest)".Trim().ToLowerInvariant()
        $tags = @(@($m.tags) | Where-Object { "$_".Trim() } | ForEach-Object { "$_" })
        if ($why.Contains($dg)) { $res.keep += @{ digest = "$($m.digest)"; tags = $tags; why = $why[$dg]; extra = [bool]$extra[$dg]; child = [bool]("$($why[$dg])" -like 'child of *' -or "$($why[$dg])" -like 'referrer of *') }; continue }
        if (-not $tags.Count) { $res.delete += @{ digest = "$($m.digest)"; tags = @(); why = 'untagged, not in use' }; continue }
        $res.delete += @{ digest = "$($m.digest)"; tags = $tags; why = 'an older release' }
    }
    $res.ok = $true
    $res.reason = "current $cur, previous $(if ($prev) { $prev } else { '(none)' })"
    return $res
}

function Get-PimRegistryPruneSwitch {
    <#
      PURE. IMAGE-PRUNE CONTRACT point 1: the switch PIM_Updater_ImagePrune (framework default ON). off / 0 / false / no = off.
      The old PIM_UPDATE_NO_PRUNE=1 (3.1.14-3.1.17) still switches it off. Returns @{ on; reason }.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Value = '', [AllowEmptyString()][AllowNull()][string]$LegacyNoPrune = '')
    # FAIL SAFE (review 2026-11-12): ON only for unset / on / 1 / true / yes -- any other value (off, disabled, a typo) = OFF.
    $v = "$Value".Trim()
    if ($v -and $v -notmatch '^(?i)(on|1|true|yes)$') { return @{ on = $false; reason = "switched off on this install (PIM_Updater_ImagePrune=$v)" } }
    if ("$LegacyNoPrune".Trim() -eq '1') { return @{ on = $false; reason = 'switched off on this install (PIM_UPDATE_NO_PRUNE=1)' } }
    return @{ on = $true; reason = 'on (PIM_Updater_ImagePrune, default on)' }
}

function Get-PimRegistryPruneSwitchValue {
    <# The switch's value from the process environment, name matched WITHOUT case (Linux names are case-sensitive). Never throws. #>
    try {
        foreach ($e in [Environment]::GetEnvironmentVariables().GetEnumerator()) { if ("$($e.Key)" -ieq 'PIM_Updater_ImagePrune') { return "$($e.Value)" } }
    } catch { }
    return ''
}

function Test-PimRegistryPruneDue {
    <#
      PURE. May this run prune? Only after a SUCCESSFUL, not-held update whose Manager READ BACK on the target image.
      Returns @{ due; reason }. -Switch = PIM_Updater_ImagePrune (contract point 1); -Disable = the old PIM_UPDATE_NO_PRUNE.
    #>
    param([AllowEmptyString()][string]$Outcome = '', [object]$Healthy = $null, [bool]$Held = $false,
          [AllowEmptyString()][string]$ManagerImage = '', [AllowEmptyString()][string]$TargetImage = '',
          [string[]]$JobsNotRolled = @(), [AllowEmptyString()][string]$Disable = '', [AllowEmptyString()][string]$Switch = '')
    $sw = Get-PimRegistryPruneSwitch -Value $Switch -LegacyNoPrune $Disable
    if (-not $sw.on) { return @{ due = $false; reason = "$($sw.reason) -- nothing deleted" } }
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

function Get-PimRegistryPruneResources {
    <#
      IMAGE-PRUNE CONTRACT point 2 (review 2026-11-12): every app and job of the install, PLUS the ACTIVE revisions of an app
      that runs in MULTIPLE revision mode (in single mode the one active revision is the app's template). -Arm: seam
      ( { param($path) } -> the listed objects ). A revision list that cannot be read THROWS -- the caller then deletes nothing.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [scriptblock]$Arm = $null,
          [string]$ApiVersion = '2024-03-01')
    if (-not $Arm) { $Arm = { param($p) @(Invoke-PimArm -Method GET -Path $p -ApiVersion $ApiVersion -All) } }
    $base = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App"
    $apps = @(& $Arm "$base/containerApps" | Where-Object { $_ })
    $jobs = @(& $Arm "$base/jobs" | Where-Object { $_ })
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($a in $apps) { $out.Add($a) }
    foreach ($j in $jobs) { $out.Add($j) }
    foreach ($a in $apps) {
        $mode = "$($a.properties.configuration.activeRevisionsMode)".Trim()
        if (-not $mode -or $mode -ieq 'Single') { continue }
        $revs = $null
        for ($try = 1; $try -le 2 -and $null -eq $revs; $try++) {
            try { $revs = @(& $Arm "$($a.id)/revisions" | Where-Object { $_ }) }
            catch { if ($try -ge 2 -or "$($_.Exception.Message)" -notmatch '(?i)PaginationTokenExpired|pagination token') { throw } }
        }
        foreach ($r in @($revs | Where-Object { $_.properties.active })) {
            $out.Add([pscustomobject]@{ name = "$($a.name) revision $($r.name)"; properties = $r.properties })
        }
    }
    return @($out.ToArray())
}

function ConvertFrom-PimRegistryBody {
    <#
      PURE. A registry answer as an object, whatever shape it arrived in (Invardia 2026-11-12, from EPS's read-back): a
      vendor media type (application/vnd.oci.image.index.v1+json) is NOT parsed by Invoke-RestMethod -- it hands back a
      byte[] or a string. Bytes -> UTF-8 text -> JSON; text -> JSON; an object as it is; empty / unparsable -> $null.
    #>
    param([AllowNull()][object]$Body)
    if ($null -eq $Body) { return $null }
    $txt = $null
    if ($Body -is [byte[]]) { $txt = [Text.Encoding]::UTF8.GetString($Body) }
    elseif ($Body -is [string]) { $txt = $Body }
    else { return $Body }
    $txt = "$txt".Trim([char]0xFEFF, ' ', "`r", "`n", "`t")
    if (-not $txt) { return $null }
    try { return ($txt | ConvertFrom-Json) } catch { return $null }
}

function Invoke-PimRegistryPruneRest {
    <# The registry data plane (or the test seam). See the file header for the operations. #>
    param([Parameter(Mandatory)][string]$Op, [Parameter(Mandatory)][string]$LoginServer, [string]$Repository = '', [string]$Arg = '')
    # 3.1.19: the seam returns what the REAL op returns -- 'manifests' is ONE object (the array, `return , @(...)` below), so a
    # caller that pipes it gets one item. 3.1.18 tests went through `return (& seam)`, which unrolled it, and missed the
    # read-back bug the first live run at internal showed ("1 left", every kept image "missing", 2026-11-12 21:24Z).
    if ($global:PIM_RegistryPruneRest) {
        $seamOut = (& $global:PIM_RegistryPruneRest $Op $LoginServer $Repository $Arg)
        if ($Op -eq 'manifests' -and $null -ne $seamOut) { return , @($seamOut) }
        return $seamOut
    }
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
            $r = ConvertFrom-PimRegistryBody (Invoke-RestMethod -Method GET -Uri "https://$LoginServer/v2/$Repository/manifests/$Arg" -Headers $h -TimeoutSec 60)
            return @(@($r.manifests) | ForEach-Object { "$($_.digest)" } | Where-Object { $_ })
        }
        'referrers' {
            # IMAGE-PRUNE CONTRACT point 2 (Invardia 2026-11-12, from EPS's read-back): the OCI referrers of $Arg (manifests whose
            # `subject` is $Arg -- Defender MDVM attestations, notary signatures). 200 + an empty index = none; any error THROWS
            # (the caller then deletes nothing in that repository).
            $h = @{ Authorization = "Bearer $script:PimRegistryPruneToken"; Accept = 'application/vnd.oci.image.index.v1+json' }
            $r = ConvertFrom-PimRegistryBody (Invoke-RestMethod -Method GET -Uri "https://$LoginServer/v2/$Repository/referrers/$Arg" -Headers $h -TimeoutSec 60)
            if ($null -eq $r) { throw "the referrers of $Arg answered no readable body" }
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

function Get-PimRegistryPruneMaxDeletes { <# PURE. LITERAL. Contract point 6: at most this many deletes per update; the rest waits (said). #> return 200 }

function Invoke-PimRegistryPrune {
    <#
      The whole prune for ONE install. NEVER throws. Returns @{ ran; skipped; reason; planOnly; kept; total; deleted;
      failed; children; locked; warnings; backlog; repos = @(@{ repository; ok; reason; total; kept; children; locked;
      deleted; failed; left; missing; plan }); line; lines }.
        -LoginServer        the install's own registry (from the Manager's image) -- the ONLY registry touched
        -ManagerRepository  the Manager's repository; its current version = -TargetVersion
        -Repositories       the other PIM repositories (signin-front); their current version = the highest version a
                            live image of that repository names (none = that repository is left alone)
        -ReadLiveImages     { } -> image references in use NOW; called right before the deletes of each repository
                            (a failed read = nothing deleted)
        -PlanOnly           decide and report, delete nothing
      IMAGE-PRUNE CONTRACT (framework IMAGE-PATCH-1, Invardia 2026-11-12) -- what the updater always passes:
        -PreviousImages     point 2: the image references that ran BEFORE this update (read before the roll) + the durable
                            record of the previous release. -RequirePreviousRecord: $null / none = delete NOTHING.
        -OwnRegistry        point 3: { param($loginServer) } -> $true only when that registry sits in the install's OWN
                            resource group. Passed and not $true (or it throws) = delete NOTHING.
        -ReleaseRecord      point 5: { } writes the release record; called BEFORE the first delete. It fails = delete NOTHING.
        -Log                point 5: { param($line) } -- every line is handed over AT ONCE, never held to the end.
        -Progress           point 5: { param($state) } -- the running totals after each repository (the update record).
        -Beat               point 4: { } -- called at every registry call, at most once per -BeatSeconds; a failing
                            beat never stops the clean-up.
        -MaxDeletes         point 6: at most this many deletes in this update; the rest waits for the next (said).
    #>
    param([AllowEmptyString()][string]$LoginServer = '', [AllowEmptyString()][string]$ManagerRepository = '',
          [AllowEmptyString()][string]$TargetVersion = '', [string[]]$Repositories = @(),
          [Parameter(Mandatory)][scriptblock]$ReadLiveImages, [switch]$PlanOnly,
          [AllowNull()][object[]]$PreviousImages = $null, [switch]$RequirePreviousRecord,
          [scriptblock]$OwnRegistry = $null, [scriptblock]$ReleaseRecord = $null,
          [scriptblock]$Log = $null, [scriptblock]$Progress = $null, [scriptblock]$Beat = $null,
          [ValidateRange(5, 600)][int]$BeatSeconds = 50, [int]$MaxDeletes = -1)
    $res = @{ ran = $false; skipped = $true; reason = ''; planOnly = [bool]$PlanOnly; kept = 0; total = 0; deleted = 0; failed = 0
              children = 0; locked = 0; warnings = 0; backlog = 0; repos = @(); line = ''; lines = @() }
    $lines = New-Object System.Collections.Generic.List[string]
    $say = { param($l) $lines.Add("$l"); if ($Log) { try { & $Log "$l" } catch { } } }
    $script:PimRegistryPruneLastBeat = [datetime]::MinValue
    $beatNow = {
        if (-not $Beat) { return }
        try { if (([datetime]::UtcNow - $script:PimRegistryPruneLastBeat).TotalSeconds -ge $BeatSeconds) { $script:PimRegistryPruneLastBeat = [datetime]::UtcNow; & $Beat } } catch { }
    }
    $stop = { param($why) $res.reason = "$why"; $res.line = "$why"; & $say "$why"; $res.lines = @($lines.ToArray()); return $res }
    if ($MaxDeletes -lt 0) { $MaxDeletes = Get-PimRegistryPruneMaxDeletes }
    $ls = "$LoginServer".Trim().ToLowerInvariant()
    if (-not $ls -or -not "$ManagerRepository".Trim()) { return (& $stop "registry: not pruned -- this install's registry is not known") }
    # point 3: the install's OWN registry, in its own resource group
    if ($OwnRegistry) {
        $own = $false; $ownErr = ''
        try { & $beatNow; $own = [bool](& $OwnRegistry $ls) } catch { $ownErr = ((("$($_.Exception.Message)") -split "`n")[0]) }
        if (-not $own) { return (& $stop ("registry: not pruned -- $ls is not confirmed in this install's own resource group" + $(if ($ownErr) { " ($ownErr)" } else { '' }) + ' -- nothing deleted')) }
    }
    # point 2: what ran before this update must be recorded
    $prevRefs = @()
    if ($null -ne $PreviousImages) { $prevRefs = @($PreviousImages | ForEach-Object { if ($_ -is [hashtable] -or ($_ -and $_.PSObject.Properties['image'])) { "$($_.image)" } else { "$_" } } | Where-Object { "$_".Trim() }) }
    if ($RequirePreviousRecord -and $prevRefs.Count -eq 0) { return (& $stop 'registry: not pruned -- the previous release is not recorded (what ran before this update could not be read) -- nothing deleted') }
    # point 5: the release record BEFORE the first delete
    if ($ReleaseRecord -and -not $PlanOnly) {
        try { & $beatNow; & $ReleaseRecord; & $beatNow; & $say "registry: release record written before the clean-up ($TargetVersion; previous: $($prevRefs.Count) image reference(s))" }
        catch { return (& $stop "registry: not pruned -- the release record could not be written ($((("$($_.Exception.Message)") -split "`n")[0])) -- nothing deleted") }
    }
    $repos = @(@("$ManagerRepository".Trim()) + @($Repositories | ForEach-Object { "$_".Trim() }) | Where-Object { $_ } | Select-Object -Unique)
    $budget = [Math]::Max(0, $MaxDeletes)
    $tellProgress = {
        if (-not $Progress) { return }
        & $beatNow
        try { & $Progress ([ordered]@{ inProgress = $true; total = [int](@($res.repos | ForEach-Object { [int]$_.total }) | Measure-Object -Sum).Sum
                                       deleted = [int](@($res.repos | ForEach-Object { [int]$_.deleted }) | Measure-Object -Sum).Sum; lines = @($lines.ToArray()) }) } catch { }
    }
    foreach ($repo in $repos) {
        $rr = @{ repository = $repo; ok = $false; reason = ''; total = 0; kept = 0; children = 0; locked = 0; deleted = 0; failed = 0; left = -1; missing = @(); backlog = 0; plan = $null }
        try {
            & $beatNow
            $tok = Invoke-PimRegistryPruneRest -Op 'token' -LoginServer $ls -Repository $repo
            if (-not $tok -or @($tok.actions) -notcontains 'delete') {
                # Soft skip: no delete right on the registry yet. Nothing in any repository is touched.
                $noRight = "registry: not pruned -- this updater's identity has no delete right on its registry yet (Contributor on the registry gives it; the update job setup grants it)"
                if (-not @($res.repos).Count) { return (& $stop $noRight) }
                $rr.reason = 'no delete right on it -- nothing deleted'; & $say "registry: $repo -- $($rr.reason)"; $res.repos += $rr; continue
            }
            $script:PimRegistryPruneToken = "$($tok.token)"
            & $beatNow
            $ms = Invoke-PimRegistryPruneRest -Op 'manifests' -LoginServer $ls -Repository $repo
            if ($null -eq $ms) { $rr.reason = 'not in this registry'; $res.repos += $rr; continue }
            $ms = @($ms | Where-Object { $_ })
            $rr.total = $ms.Count
            # The live images, re-read NOW (right before anything is deleted). A failed read = nothing deleted.
            # Each item is an image string or @{ image; by } (who uses it -- named in the report).
            & $beatNow
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
            # point 2: the previous release's digests in THIS repository (by digest, or by the tag they carried)
            $prevDigests = @()
            foreach ($p in $prevRefs) {
                $ref = Split-PimImageReference -Image "$p"
                if (-not $ref -or "$($ref.loginServer)".ToLowerInvariant() -ne $ls -or "$($ref.repository)" -ne $repo) { continue }
                if ("$($ref.digest)".Trim()) { $prevDigests += "$($ref.digest)".Trim() }
                if ("$($ref.tag)".Trim()) { foreach ($m in @($ms | Where-Object { @($_.tags) -contains "$($ref.tag)" })) { $prevDigests += "$($m.digest)" } }
            }
            $curV = ''
            if ($repo -eq "$ManagerRepository".Trim()) { $curV = "$TargetVersion".Trim() }
            elseif ($liveVersions.Count) { $curV = "$(@($liveVersions | Sort-Object -Descending)[0])" }
            if (-not $curV) { $rr.reason = 'no live image names a version of it -- nothing deleted'; & $say "registry: $repo -- $($rr.reason)"; $res.repos += $rr; continue }
            # review 2026-11-12 (1): "recorded" is per REPOSITORY -- a repository the pre-roll read names nothing of deletes nothing
            $planArgs = @{ Manifests = $ms; CurrentVersion = $curV; LiveDigests = @($liveDigests.ToArray()); LiveBy = $liveBy; PreviousDigests = $prevDigests
                           PreviousRecorded = ($prevDigests.Count -gt 0); RequirePreviousRecord = [bool]$RequirePreviousRecord }
            $plan = Get-PimRegistryPrunePlan @planArgs
            if ($plan.ok -and @($plan.indexes).Count) {
                $kids = @{}; $emptyIx = @()
                foreach ($ix in @($plan.indexes)) {
                    & $beatNow
                    $kids[$ix] = @(Invoke-PimRegistryPruneRest -Op 'children' -LoginServer $ls -Repository $repo -Arg $ix | Where-Object { "$_".Trim() })
                    if ($kids[$ix].Count -eq 0) { $emptyIx += $ix }
                }
                # review 2026-11-12 (7): a KEPT image index whose platform list came back EMPTY is an image that cannot be read --
                # its platform manifests would look like untagged leftovers. Keep everything in this repository.
                if ($emptyIx.Count) {
                    $plan = @{ ok = $false; reason = "the platform list of the kept image index $("$($emptyIx[0])".Substring(0, [Math]::Min(19, "$($emptyIx[0])".Length))) could not be read -- nothing deleted"; keep = @(); delete = @(); indexes = @() }
                } else {
                    $plan = Get-PimRegistryPrunePlan @planArgs -Children $kids
                }
                $planArgs['Children'] = $kids
            }
            # point 2 (Invardia 2026-11-12, EPS read-back): every REFERRER of a kept image, TRANSITIVELY (a Defender MDVM
            # attestation of an image, the notary signature over that attestation). A referrers read that fails = nothing
            # deleted in this repository; more than 500 reads = nothing deleted (said).
            if ($plan.ok) {
                $refs = @{}; $seen = @{}; $queue = New-Object System.Collections.Generic.Queue[object]
                $nameOf = @{}; foreach ($k in @($plan.keep)) { $kd = "$($k.digest)".Trim().ToLowerInvariant(); $nameOf[$kd] = $(if (@($k.tags).Count) { @($k.tags) -join ', ' } else { $kd.Substring(0, [Math]::Min(19, $kd.Length)) }); $queue.Enqueue($kd) }
                $reads = 0; $refErr = ''
                while ($queue.Count -and -not $refErr) {
                    $d = $queue.Dequeue(); if ($seen.ContainsKey($d)) { continue }; $seen[$d] = $true
                    if (++$reads -gt 500) { $refErr = 'more than 500 referrer reads'; break }
                    try {
                        & $beatNow
                        foreach ($rd in @(Invoke-PimRegistryPruneRest -Op 'referrers' -LoginServer $ls -Repository $repo -Arg $d | Where-Object { "$_".Trim() })) {
                            $rk = "$rd".Trim().ToLowerInvariant()
                            if (-not $refs.ContainsKey($rk)) { $refs[$rk] = "$($nameOf[$d])"; $nameOf[$rk] = "a referrer of $($nameOf[$d])"; $queue.Enqueue($rk) }
                        }
                    } catch { $refErr = ((("$($_.Exception.Message)") -split "`n")[0]) }
                }
                if ($refErr) { $plan = @{ ok = $false; reason = "the referrers (attestations / signatures) of the kept images could not be read ($refErr) -- nothing deleted"; keep = @(); delete = @(); indexes = @() } }
                elseif ($refs.Count) { $plan = Get-PimRegistryPrunePlan @planArgs -Referrers $refs }
            }
            $rr.plan = $plan
            if (-not $plan.ok) { $rr.reason = $plan.reason; $rr.kept = $rr.total; & $say "registry: $repo -- $($rr.total) images, nothing deleted ($($plan.reason))"; $res.repos += $rr; continue }
            $keepAll = @($plan.keep)
            $rr.children = @($keepAll | Where-Object { $_.child }).Count
            $rr.locked = @($keepAll | Where-Object { "$($_.why)" -like 'kept: locked*' }).Count
            $rr.kept = $keepAll.Count - $rr.children
            $toDelete = @($plan.delete)
            $now = @($toDelete | Select-Object -First $budget)
            $rr.backlog = $toDelete.Count - $now.Count
            # point 5: the BEFORE line, at once
            & $say ("registry: $repo -- $($rr.total) images, $($rr.kept) kept" + $(if ($rr.children) { " (+ $($rr.children) child manifest(s) of kept images)" } else { '' }) +
                    $(if ($rr.locked) { ", $($rr.locked) locked" } else { '' }) + ", $($toDelete.Count) to delete" + $(if ($PlanOnly) { ' (plan only)' } else { '' }) +
                    $(if ($rr.backlog) { "; $($now.Count) now, $($rr.backlog) wait for the next update (a large backlog spans updates)" } else { '' }) + " ($($plan.reason))")
            foreach ($k in @($keepAll | Where-Object { $_.extra -and -not $_.child })) {
                $name = if (@($k.tags).Count) { (@($k.tags) -join ', ') } else { "untagged $("$($k.digest)".Substring(0, [Math]::Min(19, "$($k.digest)".Length)))" }
                & $say "registry: $repo -- kept $name -- $($k.why)"
            }
            if (-not $PlanOnly) {
                $done = 0
                foreach ($d in $now) {
                    & $beatNow
                    try { [void](Invoke-PimRegistryPruneRest -Op 'delete' -LoginServer $ls -Repository $repo -Arg "$($d.digest)"); $done++ }
                    catch { $rr.failed++ }
                }
                $budget = [Math]::Max(0, $budget - $now.Count)
                $rr.deleted = $done
                # 3.1.15 (d): deleted / left are the READ-BACK numbers. Not readable = the planned numbers, said so.
                $afterDg = $null
                # 3.1.19: the same unwrap as the first read (the op returns the array as ONE object; piping it straight into
                # Where-Object counted 1 and named every kept image missing -- live at internal 3.1.18)
                try { & $beatNow; $after = Invoke-PimRegistryPruneRest -Op 'manifests' -LoginServer $ls -Repository $repo; $after = @(@($after) | Where-Object { $_ }); $rr.left = $after.Count; $afterDg = @{}; foreach ($a in $after) { $afterDg["$($a.digest)".Trim().ToLowerInvariant()] = $true } } catch { $rr.left = -1 }
                if ($rr.left -ge 0) { $rr.deleted = [Math]::Max(0, $rr.total - $rr.left) }
                if ($null -ne $afterDg) {
                    foreach ($k in $keepAll) { if (-not $afterDg.ContainsKey("$($k.digest)".Trim().ToLowerInvariant())) { $rr.missing += $k } }
                }
                # point 5: the AFTER line, at once
                & $say ("registry: $repo -- $($rr.deleted) deleted, " + $(if ($rr.left -ge 0) { "$($rr.left) left (read back)" } else { 'left not read back (planned numbers)' }) +
                        $(if ($rr.failed) { "; $($rr.failed) could not be deleted (tried again next update)" } else { '' }) + $(if ($rr.locked) { "; $($rr.locked) locked (kept)" } else { '' }))
                foreach ($k in @($rr.missing)) {
                    $name = if (@($k.tags).Count) { (@($k.tags) -join ', ') } else { "$($k.digest)" }
                    & $say "WARNING: registry: $repo -- the kept image $name ($($k.why)) is missing after the clean-up"
                }
            }
            $rr.ok = $true; $rr.reason = $plan.reason
        } catch {
            $rr.reason = "could not be read or pruned ($((("$($_.Exception.Message)") -split "`n")[0])) -- what was not deleted yet is kept; the update is not affected"
            & $say "registry: $repo -- $($rr.reason)"
        }
        $res.repos += $rr
        & $tellProgress
    }
    $res.ran = $true; $res.skipped = $false
    foreach ($rr in $res.repos) {
        $res.total += [int]$rr.total
        if ($rr.ok) {
            $res.kept += [int]$rr.kept; $res.children += [int]$rr.children; $res.locked += [int]$rr.locked
            $res.deleted += [int]$rr.deleted; $res.failed += [int]$rr.failed; $res.warnings += @($rr.missing).Count; $res.backlog += [int]$rr.backlog
        } else {
            $res.kept += [int]$rr.total   # review 2026-11-12 (5): a repository left alone keeps every image it has
        }
    }
    $res.line = if ($PlanOnly) { "registry (plan only): would keep $($res.kept) of $($res.total) images" }
                else { "registry: kept $($res.kept) of $($res.total) images" + $(if ($res.children) { " (+ $($res.children) child manifest(s))" } else { '' }) + "; deleted $($res.deleted)" +
                       $(if ($res.failed) { "; $($res.failed) failed" } else { '' }) + $(if ($res.backlog) { "; $($res.backlog) wait for the next update" } else { '' }) +
                       $(if ($res.warnings) { "; WARNING: $($res.warnings) kept image(s) missing" } else { '' }) }
    & $say $res.line
    $res.reason = $res.line
    $res.lines = @($lines.ToArray())
    return $res
}
