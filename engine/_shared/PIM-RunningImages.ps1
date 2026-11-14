#Requires -Version 7.0
<#
.SYNOPSIS
    SEC-LANE-1 (framework, owner 2026-11-14: "patched" = what RUNS, read back per install): the images this install's container
    apps and jobs run NOW, each with its digest and .NET version -- the updater records them (pim.Settings 'UpdateState'
    .runningImages) and the heartbeat sends them as Update.runningImages (Invardia heartbeatstate.ts, commit 2e20fb60).
    The install reports itself, so a private registry nobody outside can read (403) is read back too.

.DESCRIPTION
    Get-PimRunningImages        PURE with seams: every container of every app / job -> { component; repo; digest; dotnet; readUtc }.
                                component = the app / job name, or "<name>.<container>" when the container is named otherwise
                                (the Manager app runs the Manager AND the sign-in front). -Resolve { param($image) } returns
                                @{ digest = 'sha256:...'; dotnet = 'x.y.z' } (or $null = not readable: that component is sent
                                without digest / dotnet, never a guess).
    Resolve-PimRegistryImage    the real resolver: the install's own registry over its data plane (the job's managed identity,
                                AAD token exchange, pull scope): a tag -> its digest (acr/v1 _tags), the manifest -> the config
                                -> ASPNET_VERSION (else DOTNET_VERSION). A digest reference reads the config only. Cached per run.
    No module, no az CLI.
#>

function Split-PimRunningImageRef {
    <# PURE. 'login/repo/path:tag@sha256:...' -> @{ loginServer; repository; tag; digest } (any part may be ''). #>
    param([AllowEmptyString()][string]$Image)
    $img = "$Image".Trim()
    $dg = ''; $at = $img.IndexOf('@')
    if ($at -ge 0) { $dg = $img.Substring($at + 1); $img = $img.Substring(0, $at) }
    $slash = $img.IndexOf('/')
    $ls = ''; $rest = $img
    if ($slash -gt 0 -and ($img.Substring(0, $slash) -match '[.:]' -or $img.Substring(0, $slash) -eq 'localhost')) { $ls = $img.Substring(0, $slash); $rest = $img.Substring($slash + 1) }
    $tag = ''; $colon = $rest.LastIndexOf(':')
    if ($colon -gt 0) { $tag = $rest.Substring($colon + 1); $rest = $rest.Substring(0, $colon) }
    return @{ loginServer = $ls.ToLowerInvariant(); repository = $rest.ToLowerInvariant(); tag = $tag; digest = $dg.ToLowerInvariant() }
}

function Get-PimRunningImages {
    param([object[]]$Resources = @(), [scriptblock]$Resolve = $null, [datetime]$NowUtc = [datetime]::UtcNow, [int]$Max = 40)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $read = $NowUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    foreach ($r in @($Resources | Where-Object { $_ })) {
        $rn = "$($r.name)".Trim().ToLowerInvariant()
        if (-not $rn) { continue }
        foreach ($c in @($r.properties.template.containers | Where-Object { $_ -and "$($_.image)".Trim() })) {
            $cn = "$($c.name)".Trim().ToLowerInvariant()
            $comp = if (-not $cn -or $cn -eq $rn) { $rn } else { "$rn.$cn" }
            if ($comp -notmatch '^[a-z0-9][a-z0-9._-]{0,79}$' -or $seen.ContainsKey($comp)) { continue }
            $seen[$comp] = $true
            $ref = Split-PimRunningImageRef -Image "$($c.image)"
            $item = [ordered]@{ component = $comp }
            if ($ref.repository -match '^[a-z0-9][a-z0-9._/-]{0,79}$') { $item['repo'] = $ref.repository }
            $res = $null
            if ($Resolve) { try { $res = & $Resolve "$($c.image)".Trim() } catch { $res = $null } }
            $dg = if ($res -and "$($res.digest)" -match '^sha256:[0-9a-f]{64}$') { "$($res.digest)" } elseif ($ref.digest -match '^sha256:[0-9a-f]{64}$') { $ref.digest } else { '' }
            if ($dg) { $item['digest'] = $dg }
            if ($res -and "$($res.dotnet)" -match '^\d+\.\d+\.\d+$') { $item['dotnet'] = "$($res.dotnet)" }
            $item['readUtc'] = $read
            $out.Add([pscustomobject]$item)
            if ($out.Count -ge $Max) { return @($out.ToArray()) }
        }
    }
    return @($out.ToArray())
}

function Resolve-PimRegistryImage {
    <# The install's own registry (the managed identity), one image reference -> @{ digest; dotnet }. Throws on a read error. #>
    param([Parameter(Mandatory)][string]$Image)
    if (-not $script:PimRunningImageCache) { $script:PimRunningImageCache = @{} }
    if ($script:PimRunningImageCache.ContainsKey($Image)) { return $script:PimRunningImageCache[$Image] }
    $ref = Split-PimRunningImageRef -Image $Image
    if (-not $ref.loginServer -or $ref.loginServer -notlike '*.azurecr.io') { throw "not an Azure registry image: $Image" }
    $ls = $ref.loginServer; $repo = $ref.repository
    if (-not $script:PimRunningImageRefresh) { $script:PimRunningImageRefresh = @{} }
    if (-not $script:PimRunningImageRefresh.ContainsKey($ls)) {
        $aad = Get-PimRestToken -Resource 'arm'
        $body = @{ grant_type = 'access_token'; service = $ls; access_token = "$aad" }
        try { $tid = Get-PimTokenTenantId -Token "$aad"; if ($tid) { $body['tenant'] = $tid } } catch { }
        $script:PimRunningImageRefresh[$ls] = "$((Invoke-RestMethod -Method POST -Uri "https://$ls/oauth2/exchange" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body $body).refresh_token)"
    }
    $tk = "$((Invoke-RestMethod -Method POST -Uri "https://$ls/oauth2/token" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body @{
        grant_type = 'refresh_token'; service = $ls; scope = "repository:$($repo):pull,metadata_read"; refresh_token = $script:PimRunningImageRefresh[$ls] }).access_token)"
    $h = @{ Authorization = "Bearer $tk"; Accept = 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json' }
    $dg = $ref.digest
    if (-not $dg) {
        if (-not $ref.tag) { throw "no tag and no digest: $Image" }
        $dg = "$((Invoke-RestMethod -Method GET -Uri "https://$ls/acr/v1/$repo/_tags/$($ref.tag)" -Headers $h -TimeoutSec 60).tag.digest)".ToLowerInvariant()
    }
    $dotnet = ''
    try {
        # a vendor media type comes back as bytes / text, not parsed (ConvertFrom-PimRegistryBody, PIM-RegistryPrune.ps1)
        $man = Invoke-RestMethod -Method GET -Uri "https://$ls/v2/$repo/manifests/$dg" -Headers $h -TimeoutSec 60
        if ($man -is [byte[]]) { $man = [Text.Encoding]::UTF8.GetString($man) }
        if ($man -is [string]) { $man = $man | ConvertFrom-Json }
        $cfg = Invoke-RestMethod -Method GET -Uri "https://$ls/v2/$repo/blobs/$($man.config.digest)" -Headers @{ Authorization = "Bearer $tk" } -TimeoutSec 60
        if ($cfg -is [byte[]]) { $cfg = [Text.Encoding]::UTF8.GetString($cfg) }
        if ($cfg -is [string]) { $cfg = $cfg | ConvertFrom-Json }
        $envs = @($cfg.config.Env)
        $v = @($envs | Where-Object { "$_" -like 'ASPNET_VERSION=*' }) + @($envs | Where-Object { "$_" -like 'DOTNET_VERSION=*' })
        if ($v.Count) { $dotnet = ("$($v[0])" -split '=', 2)[1] }
    } catch { $dotnet = '' }
    $res = @{ digest = $dg; dotnet = $dotnet }
    $script:PimRunningImageCache[$Image] = $res
    return $res
}
