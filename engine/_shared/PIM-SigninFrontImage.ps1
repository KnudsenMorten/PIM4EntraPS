#Requires -Version 5.1
<#
.SYNOPSIS
    CR7 / framework DOCS/REQUIREMENTS.md 12.11g -- the IMAGE STEP for the shared web sign-in front (FRAMEWORK/signin-front),
    built by an install's OWN updater in its OWN registry, at the component version PIM pins. PIM docs/REQUIREMENTS.md 100.168.

.DESCRIPTION
    The two-container Manager revision (12.11g item 2) needs an image 'signin-front:<pinned version>' in the install's
    registry. Nothing else builds it, and an install may have no build host and no contact (framework 12.23 P9) -- so the
    updater builds it the way it already builds the Manager (section 55): the signed source archive carries
    FRAMEWORK/signin-front (src + VERSION) next to the solution, and the registry builds it over the same four ARM/HTTPS
    calls (PIM-AcrBuild.ps1).

    [!] OPT-IN, AND OTHERWISE ABSENT. Only an install that
          * runs behind the front: the Manager app carries PIM_HOSTED_AUTH_LAYER=signin-front, or
          * was prepared for the move: the updater job carries PIM_BUILD_SIGNIN_FRONT=1 (Set-PimManagerSigninFront.ps1
            sets it before it moves an environment)
        builds the front image. Every other install: no extra build, no extra call, not one extra line in the log --
        the decision (Get-PimSigninFrontOptIn) reads only the Manager app object the updater has already read and its
        own environment.
    [!] A FAILED FRONT BUILD NEVER FAILS THE MANAGER UPDATE. It is reported plainly; the Manager keeps running as before
        (a Manager behind the front keeps its current front image; one not yet moved simply cannot be moved yet).
    [!] ALREADY THERE = NO REBUILD: the version this updater recorded (PIM_SIGNIN_FRONT_BUILT), else the front image the
        Manager already runs, else the registry's own tag list (data plane) -- in that order, the first that answers.

    The front's build context is the archive's FRAMEWORK/signin-front/src re-rooted (its Dockerfile does `COPY
    SigninFront.csproj .` -- the context root must be src), written as a fresh .tar.gz with .NET only (no tar binary).
    The component is built ONLY when the archive's FRAMEWORK/signin-front/VERSION is the version the archive's solution
    pins (tools/pim-manager/signin-front.version) -- never a component the release did not pin.

.NOTES
    PS 5.1 + 7, no modules. Pure functions are tested offline (tests/Test-PimSigninFront.ps1, section IMG); the I/O is
    injected (-Build / -TagCheck / -Record) so the whole step runs with no registry at all.
#>

$script:PimSigninFrontRepository = 'signin-front'
$script:PimSigninFrontContainerName = 'signin-front'
$script:PimSigninFrontSrcPrefix = 'FRAMEWORK/signin-front/src/'
$script:PimSigninFrontVersionEntry = 'FRAMEWORK/signin-front/VERSION'
$script:PimSigninFrontPinEntry = 'SOLUTIONS/PIM4EntraPS/tools/pim-manager/signin-front.version'

function Test-PimSigninFrontVersionText {
    <# PURE. A component version is three dotted numbers -- nothing else is ever used as an image tag. #>
    param([AllowEmptyString()][string]$Text)
    return ("$Text".Trim() -match '^[0-9]+\.[0-9]+\.[0-9]+$')
}

function Get-PimSigninFrontPinnedVersion {
    <# The version THIS tree pins (tools/pim-manager/signin-front.version), '' when absent or not a version. #>
    param([Parameter(Mandatory)][string]$SolutionRoot)
    $f = Join-Path $SolutionRoot 'tools\pim-manager\signin-front.version'
    if (-not (Test-Path -LiteralPath $f)) { return '' }
    $v = "$(Get-Content -LiteralPath $f -Raw -ErrorAction SilentlyContinue)".Trim()
    if (Test-PimSigninFrontVersionText $v) { return $v }
    return ''
}

function Test-PimSigninFrontFlagOn {
    <# PURE. PIM_BUILD_SIGNIN_FRONT: 1 / true / yes / on = on; anything else (unset included) = off. #>
    param([AllowEmptyString()][AllowNull()][string]$Value)
    return ("$Value".Trim() -match '^(?i)(1|true|yes|on)$')
}

function Get-PimSignInLayer {
    <#
      PURE. Framework 8.17 SignIn (agreed SI + PIM + Invardia 2026-10-20): the web app's sign-in layer, read from the RUNNING
      app, never from a config file. -App = the Manager container app (ARM), -AuthConfig = its authConfigs/current (ARM) and
      -AuthRead = that read answered (a missing auth config is $null with -AuthRead $true = no Easy Auth).
        a container named 'signin-front'           -> layer 'signin-front', version = its image tag up to the first '-'
                                                      (signin-front:1.2.1-src-<hash> -> '1.2.1'; no tag = $null)
        else authConfigs/current platform.enabled  -> 'easyauth' (version $null)
        else                                       -> 'none'     (an OPEN web app is reported, never left out)
      No app, or the auth config was not read on an app without the front = $null (not known -- never a guess).
      @{ layer; version; checkedUtc }
    #>
    param([AllowNull()][object]$App, [AllowNull()][object]$AuthConfig = $null, [bool]$AuthRead = $false, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $App -or $null -eq $App.properties) { return $null }
    $ts = $NowUtc.ToUniversalTime().ToString('o')
    $fr = @(@($App.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -eq 'signin-front' })
    if ($fr.Count) {
        $img = "$($fr[0].image)"
        $tag = if ($img -match ':([^:/@]+)$') { $Matches[1] } else { '' }
        $ver = (($tag -split '-')[0]).Trim()
        return [ordered]@{ layer = 'signin-front'; version = $(if ($ver) { $ver } else { $null }); checkedUtc = $ts }
    }
    if (-not $AuthRead) { return $null }
    $on = $false
    if ($AuthConfig -and $AuthConfig.properties -and $AuthConfig.properties.platform) { $on = ("$($AuthConfig.properties.platform.enabled)" -match '^(?i)true$') }
    return [ordered]@{ layer = $(if ($on) { 'easyauth' } else { 'none' }); version = $null; checkedUtc = $ts }
}

function Get-PimSigninFrontOptIn {
    <#
      PURE. Does this install build the front image? From the Manager app object ALREADY READ (-App, may be $null) and the
      updater's own PIM_BUILD_SIGNIN_FRONT (-BuildFlag). @{ optIn; behindFront; flag; reason }.
        behindFront = a container of the Manager carries PIM_HOSTED_AUTH_LAYER=signin-front (the switch of 12.11g item 2)
        optIn       = behindFront OR the flag is on
    #>
    param([AllowNull()][object]$App, [AllowEmptyString()][AllowNull()][string]$BuildFlag = '')
    $behind = $false
    if ($App -and $App.properties -and $App.properties.template) {
        foreach ($c in @($App.properties.template.containers)) {
            if (-not $c) { continue }
            foreach ($e in @($c.env)) {
                if ($e -and "$($e.name)" -eq 'PIM_HOSTED_AUTH_LAYER' -and "$($e.value)".Trim() -ieq 'signin-front') { $behind = $true }
            }
        }
    }
    $flag = Test-PimSigninFrontFlagOn $BuildFlag
    $why = if ($behind) { 'the Manager runs behind the sign-in front (PIM_HOSTED_AUTH_LAYER=signin-front)' }
           elseif ($flag) { 'this updater carries PIM_BUILD_SIGNIN_FRONT=1 (prepared for the move to the sign-in front)' }
           else { 'not opted in (no PIM_HOSTED_AUTH_LAYER=signin-front on the Manager, no PIM_BUILD_SIGNIN_FRONT=1 here)' }
    return @{ optIn = ($behind -or $flag); behindFront = $behind; flag = $flag; reason = $why }
}

function Resolve-PimManagerContainerName {
    <#
      PURE. Which container of the Manager app IS the Manager? -Configured (PIM_ManagerContainerName) wins. Otherwise ''
      (= "the single container", today's rule) -- EXCEPT a two-container revision with the sign-in front: then the one
      container that is not 'signin-front'. Without this an updater behind the front cannot read its own registry and
      refuses to roll ("cannot tell which of 2 containers").
    #>
    param([AllowNull()][object]$App, [AllowEmptyString()][string]$Configured = '')
    if ("$Configured".Trim()) { return "$Configured".Trim() }
    if (-not $App -or -not $App.properties -or -not $App.properties.template) { return '' }
    $cs = @(@($App.properties.template.containers) | Where-Object { $_ })
    if ($cs.Count -lt 2) { return '' }
    if (-not @($cs | Where-Object { "$($_.name)" -eq $script:PimSigninFrontContainerName }).Count) { return '' }
    $others = @($cs | Where-Object { "$($_.name)" -ne $script:PimSigninFrontContainerName })
    if ($others.Count -eq 1) { return "$($others[0].name)" }
    return ''
}

function Get-PimSigninFrontCurrentImage {
    <# PURE. The image the Manager's 'signin-front' container runs now ('' when there is none). #>
    param([AllowNull()][object]$App)
    if (-not $App -or -not $App.properties -or -not $App.properties.template) { return '' }
    $c = @(@($App.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -eq $script:PimSigninFrontContainerName }) | Select-Object -First 1
    if ($c) { return "$($c.image)".Trim() }
    return ''
}

function Test-PimSigninFrontStateReady {
    <#
      PURE. May the front container move to -Version? Front 1.3.0 (framework 12.11g item 9) REFUSES TO START without its state
      settings (SIGNIN_SQL_SERVER, SIGNIN_SQL_DATABASE, SIGNIN_KEYVAULT_KEY_ID) -- moving an install's front to 1.3.0+ before
      they are on its container would take the sign-in down. Below 1.3.0, or with all three set: ok. Returns @{ ok; reason }.
    #>
    param([AllowNull()][object]$App, [AllowEmptyString()][string]$Version)
    if (-not (Test-PimSigninFrontVersionText $Version)) { return @{ ok = $true; reason = 'no front version' } }
    if ([version]"$Version".Trim() -lt [version]'1.3.0') { return @{ ok = $true; reason = "front $Version needs no state settings" } }
    $c = $null
    if ($App -and $App.properties -and $App.properties.template) {
        $c = @(@($App.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -eq $script:PimSigninFrontContainerName }) | Select-Object -First 1
    }
    if (-not $c) { return @{ ok = $false; reason = 'no signin-front container' } }
    $missing = @('SIGNIN_SQL_SERVER', 'SIGNIN_SQL_DATABASE', 'SIGNIN_KEYVAULT_KEY_ID' | Where-Object {
        $n = $_; -not @(@($c.env) | Where-Object { $_ -and "$($_.name)" -eq $n -and "$($_.value)".Trim() }).Count })
    if ($missing.Count) { return @{ ok = $false; reason = "front $Version needs $($missing -join ', ') on its container first (Set-PimSigninFrontState)" } }
    return @{ ok = $true; reason = 'state settings present' }
}

function Get-PimSigninFrontImageRef {
    <# PURE. <login server>/signin-front:<version> -- '' when either part is missing. #>
    param([AllowEmptyString()][string]$LoginServer, [AllowEmptyString()][string]$Version)
    if (-not "$LoginServer".Trim() -or -not (Test-PimSigninFrontVersionText $Version)) { return '' }
    return ("$("$LoginServer".Trim())/$($script:PimSigninFrontRepository)" + ':' + "$Version".Trim())
}

function Get-PimSigninFrontImageDecision {
    <#
      PURE. Build the front image, or is it already there? @{ action = none | present | build | check; reason }.
        none     not opted in, or no version to build
        present  the version this updater recorded (-Built) IS the wanted one, or the Manager's front already runs it
                 (-CurrentImage equals -WantedImage)
        check    unknown yet -- ask the registry (Test-PimSigninFrontImagePresent), then decide again with -TagPresent
        build    -TagPresent is $false, or the registry could not be asked (-TagPresent 'unknown') -- a rebuild of an
                 existing tag is harmless (layers cached), a missing image is not
    #>
    param([bool]$OptIn, [AllowEmptyString()][string]$Wanted = '', [AllowEmptyString()][string]$Built = '',
          [AllowEmptyString()][string]$CurrentImage = '', [AllowEmptyString()][string]$WantedImage = '',
          [AllowEmptyString()][string]$TagPresent = '')
    if (-not $OptIn) { return @{ action = 'none'; reason = 'not opted in' } }
    if (-not (Test-PimSigninFrontVersionText $Wanted)) { return @{ action = 'none'; reason = 'no pinned sign-in front version to build' } }
    if ("$Built".Trim() -eq "$Wanted".Trim()) { return @{ action = 'present'; reason = "signin-front:$Wanted was built here already (PIM_SIGNIN_FRONT_BUILT)" } }
    if ("$WantedImage".Trim() -and "$CurrentImage".Trim() -eq "$WantedImage".Trim()) { return @{ action = 'present'; reason = "the Manager's front already runs $WantedImage" } }
    switch ("$TagPresent".Trim().ToLowerInvariant()) {
        'true'    { return @{ action = 'present'; reason = "signin-front:$Wanted is already in the registry" } }
        'false'   { return @{ action = 'build'; reason = "signin-front:$Wanted is not in the registry" } }
        'unknown' { return @{ action = 'build'; reason = "the registry's tags could not be read -- building signin-front:$Wanted (a rebuild of an existing tag is harmless)" } }
        default   { return @{ action = 'check'; reason = "is signin-front:$Wanted in the registry?" } }
    }
}

# ---- tar.gz, .NET only ------------------------------------------------------------------------------------------------

function Read-PimTarGzFiles {
    <#
      Regular files from a .tar.gz whose names start with one of -Prefixes, with their bytes. .NET only (no tar binary:
      GNU tar on PATH reads 'C:' as a remote host). Understands ustar names (prefix + name), a pax 'x' header's path=,
      a GNU 'L' long name, and skips pax global headers ('g' -- git archive writes one with the commit id).
      Returns @{ ok; files = ordered @{ name -> byte[] }; reason }.
    #>
    param([Parameter(Mandatory)][string]$Path, [string[]]$Prefixes = @(''), [int]$MaxEntries = 50000, [int64]$MaxFileBytes = 16MB)
    $files = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) { return @{ ok = $false; files = $files; reason = "no archive at '$Path'" } }
    $fs = $null; $gz = $null
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
        $readExact = {
            param([int64]$n)
            $buf = New-Object byte[] $n
            $off = 0
            while ($off -lt $n) {
                $got = $gz.Read($buf, $off, [int]([Math]::Min([int64]1048576, $n - $off)))
                if ($got -le 0) { break }
                $off += $got
            }
            if ($off -lt $n) { return $null }
            return ,$buf
        }
        $nextName = ''
        for ($i = 0; $i -lt $MaxEntries; $i++) {
            $hdr = & $readExact 512
            if ($null -eq $hdr -or $hdr[0] -eq 0) { break }
            $name = [System.Text.Encoding]::ASCII.GetString($hdr, 0, 100).Split([char]0)[0]
            $magic = [System.Text.Encoding]::ASCII.GetString($hdr, 257, 5)
            if ($magic -eq 'ustar') {
                $pre = [System.Text.Encoding]::ASCII.GetString($hdr, 345, 155).Split([char]0)[0]
                if ($pre) { $name = "$pre/$name" }
            }
            $oct = [System.Text.Encoding]::ASCII.GetString($hdr, 124, 12).Trim([char]0, ' ')
            $size = [int64]0
            if ($oct -match '^[0-7]+$') { $size = [Convert]::ToInt64($oct, 8) }
            $type = [char]$hdr[156]
            $padded = [int64]([Math]::Ceiling($size / 512.0) * 512)
            $want = $false
            if ($type -eq [char]'x' -or $type -eq [char]'L') { $want = $true }
            elseif ($type -eq [char]'0' -or $type -eq [char]0) {
                $eff = if ($nextName) { $nextName } else { $name }
                foreach ($p in $Prefixes) { if ($eff.StartsWith("$p", [StringComparison]::Ordinal)) { $want = $true; break } }
            }
            if ($want -and $size -gt $MaxFileBytes) { return @{ ok = $false; files = $files; reason = "an entry of $size bytes is larger than this reader takes" } }
            $data = $null
            if ($padded -gt 0) {
                if ($want) {
                    $blk = & $readExact $padded
                    if ($null -eq $blk) { return @{ ok = $false; files = $files; reason = 'the archive ends inside an entry (truncated)' } }
                    $data = New-Object byte[] $size
                    [Array]::Copy($blk, 0, $data, 0, $size)
                } else {
                    $left = $padded
                    while ($left -gt 0) {
                        $chunk = [int64]([Math]::Min([int64]1048576, $left))
                        $blk = & $readExact $chunk
                        if ($null -eq $blk) { return @{ ok = $false; files = $files; reason = 'the archive ends inside an entry (truncated)' } }
                        $left -= $chunk
                    }
                }
            } elseif ($want) { $data = New-Object byte[] 0 }
            if ($type -eq [char]'x') {
                # pax extended header: "<len> key=value\n" records; path= names the NEXT entry
                $txt = [System.Text.Encoding]::UTF8.GetString($data)
                foreach ($rec in ($txt -split "`n")) { if ($rec -match '^\d+ path=(.*)$') { $nextName = $Matches[1] } }
                continue
            }
            if ($type -eq [char]'L') { $nextName = [System.Text.Encoding]::UTF8.GetString($data).Split([char]0)[0]; continue }
            if ($type -eq [char]'0' -or $type -eq [char]0) {
                $eff = if ($nextName) { $nextName } else { $name }
                if ($want) { $files[$eff] = $data }
            }
            $nextName = ''
        }
        return @{ ok = $true; files = $files; reason = '' }
    } catch {
        return @{ ok = $false; files = $files; reason = "the archive could not be read: $($_.Exception.Message)" }
    } finally {
        if ($gz) { $gz.Dispose() }
        if ($fs) { $fs.Dispose() }
    }
}

function Write-PimTarGz {
    <#
      Write -Files (ordered name -> byte[]) as a ustar .tar.gz. Names are relative, '/'-separated, at most 100 characters
      (a longer one is refused -- the front's src has none). Mode 0644, mtime 0 (the same input gives the same bytes).
    #>
    param([Parameter(Mandatory)][string]$OutFile, [Parameter(Mandatory)][System.Collections.IDictionary]$Files)
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $fs = [System.IO.File]::Create($OutFile)
    try {
        $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Compress)
        try {
            foreach ($k in @($Files.Keys)) {
                $name = "$k"
                if ($name -match '[^\x20-\x7e]') { throw "Write-PimTarGz: the entry name '$name' is not ASCII" }
                # ustar: name (100) + prefix (155), split at a '/'. Longer than that is refused (never truncated).
                $pre = ''
                if ($name.Length -gt 100) {
                    $cut = -1
                    for ($j = $name.Length - 1; $j -gt 0; $j--) { if ($name[$j] -eq '/' -and $j -le 155 -and ($name.Length - $j - 1) -le 100 -and ($name.Length - $j - 1) -gt 0) { $cut = $j; break } }
                    if ($cut -lt 0) { throw "Write-PimTarGz: the entry name '$name' is too long for a ustar header" }
                    $pre = $name.Substring(0, $cut); $name = $name.Substring($cut + 1)
                }
                $nb = [System.Text.Encoding]::ASCII.GetBytes($name)
                $data = [byte[]]$Files[$k]
                if ($null -eq $data) { $data = New-Object byte[] 0 }
                $h = New-Object byte[] 512
                [Array]::Copy($nb, 0, $h, 0, $nb.Length)
                $put = { param([int]$at, [string]$s) $b = [System.Text.Encoding]::ASCII.GetBytes($s); [Array]::Copy($b, 0, $h, $at, $b.Length) }
                if ($pre) { & $put 345 $pre }
                & $put 100 "0000644`0"
                & $put 108 "0000000`0"
                & $put 116 "0000000`0"
                & $put 124 ([Convert]::ToString([int64]$data.Length, 8).PadLeft(11, '0') + "`0")
                & $put 136 ("00000000000" + "`0")
                & $put 148 '        '
                $h[156] = [byte][char]'0'
                & $put 257 "ustar`0"
                & $put 263 '00'
                $sum = 0
                foreach ($b in $h) { $sum += [int]$b }
                & $put 148 ([Convert]::ToString($sum, 8).PadLeft(6, '0') + "`0 ")
                $gz.Write($h, 0, 512)
                if ($data.Length) {
                    $gz.Write($data, 0, $data.Length)
                    $pad = (512 - ($data.Length % 512)) % 512
                    if ($pad) { $gz.Write((New-Object byte[] $pad), 0, $pad) }
                }
            }
            $end = New-Object byte[] 1024
            $gz.Write($end, 0, 1024)
        } finally { $gz.Dispose() }
    } finally { $fs.Dispose() }
}

function New-PimSigninFrontBuildContext {
    <#
      The front's build context from the PIM source archive (repo-root shaped .tar.gz): FRAMEWORK/signin-front/src/**
      re-rooted at the context root (its Dockerfile COPYs SigninFront.csproj from the root), written to -OutFile.
      Refused -- with the reason, never a guess:
        * no FRAMEWORK/signin-front/src/Dockerfile in the archive (a release packed before the front was carried)
        * no / unreadable FRAMEWORK/signin-front/VERSION, or no pin in the archive's solution
        * the archive's component VERSION is not the version the archive's solution pins
      @{ ok; path; version; pinned; component; files; reason }.
    #>
    param([Parameter(Mandatory)][string]$ArchivePath, [Parameter(Mandatory)][string]$OutFile)
    $res = @{ ok = $false; path = ''; version = ''; pinned = ''; component = ''; files = 0; reason = '' }
    $rd = Read-PimTarGzFiles -Path $ArchivePath -Prefixes @($script:PimSigninFrontSrcPrefix, $script:PimSigninFrontVersionEntry, $script:PimSigninFrontPinEntry)
    if (-not $rd.ok) { $res.reason = $rd.reason; return $res }
    $f = $rd.files
    if (-not $f.Contains($script:PimSigninFrontSrcPrefix + 'Dockerfile')) {
        $res.reason = 'the source archive carries no FRAMEWORK/signin-front/src (a release packed before the sign-in front was carried) -- nothing to build'
        return $res
    }
    $comp = if ($f.Contains($script:PimSigninFrontVersionEntry)) { [System.Text.Encoding]::UTF8.GetString($f[$script:PimSigninFrontVersionEntry]).Trim([char]0xFEFF).Trim() } else { '' }
    $pin = if ($f.Contains($script:PimSigninFrontPinEntry)) { [System.Text.Encoding]::UTF8.GetString($f[$script:PimSigninFrontPinEntry]).Trim([char]0xFEFF).Trim() } else { '' }
    $res.component = $comp; $res.pinned = $pin
    if (-not (Test-PimSigninFrontVersionText $comp)) { $res.reason = 'the source archive carries no readable FRAMEWORK/signin-front/VERSION'; return $res }
    if (-not (Test-PimSigninFrontVersionText $pin)) { $res.reason = 'the source archive pins no sign-in front version (tools/pim-manager/signin-front.version)'; return $res }
    if ($comp -ne $pin) { $res.reason = "the source archive carries component $comp, but this release pins $pin -- not built (only the pinned version is ever built)"; return $res }
    $ctx = [ordered]@{}
    foreach ($k in @($f.Keys)) {
        if (-not "$k".StartsWith($script:PimSigninFrontSrcPrefix, [StringComparison]::Ordinal)) { continue }
        $rel = "$k".Substring($script:PimSigninFrontSrcPrefix.Length)
        if (-not $rel -or $rel -match '(^|/)\.\.(/|$)' -or $rel.StartsWith('/')) { continue }
        if ($rel -match '^(bin|obj)/') { continue }
        $ctx[$rel] = $f[$k]
    }
    try { Write-PimTarGz -OutFile $OutFile -Files $ctx } catch { $res.reason = "the front's build context could not be written: $($_.Exception.Message)"; return $res }
    $res.ok = $true; $res.path = $OutFile; $res.version = $pin; $res.files = $ctx.Count; $res.reason = "signin-front $pin, $($ctx.Count) files"
    return $res
}

# ---- the registry -----------------------------------------------------------------------------------------------------

function Test-PimSigninFrontImagePresent {
    <#
      Is <repository>:<tag> in the registry? Over the registry's own data plane (/acr/v1/<repo>/_tags/<tag>) with the
      token the updater already has (the ARM token, exchanged for a repository-scoped registry token). NEVER throws.
      'true' | 'false' | 'unknown' (a private registry this process cannot reach, a refused exchange, ...).
      Test seam: $global:PIM_SigninFrontTagStub = { param($LoginServer, $Repository, $Tag) 'true' | 'false' | 'unknown' }.
    #>
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Tag, [string]$Repository = $script:PimSigninFrontRepository)
    if ($global:PIM_SigninFrontTagStub) { try { return "$(& $global:PIM_SigninFrontTagStub $LoginServer $Repository $Tag)" } catch { return 'unknown' } }
    try {
        $aad = Get-PimRestToken -Resource 'arm'
        $body = @{ grant_type = 'access_token'; service = $LoginServer; access_token = "$aad" }
        try {
            $p = "$aad".Split('.')[1].Replace('-', '+').Replace('_', '/')
            switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
            $tid = "$(([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json).tid)"
            if ($tid) { $body['tenant'] = $tid }
        } catch { }
        $ex = Invoke-RestMethod -Method POST -Uri "https://$LoginServer/oauth2/exchange" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body $body
        $tk = Invoke-RestMethod -Method POST -Uri "https://$LoginServer/oauth2/token" -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 -Body @{
            grant_type = 'refresh_token'; service = $LoginServer; scope = "repository:$Repository`:pull"; refresh_token = "$($ex.refresh_token)" }
        try {
            $r = Invoke-RestMethod -Method GET -Uri "https://$LoginServer/acr/v1/$Repository/_tags/$Tag" -Headers @{ Authorization = "Bearer $($tk.access_token)" } -TimeoutSec 60
            if ("$($r.tag.name)" -eq $Tag -or "$($r.tag.digest)".Trim()) { return 'true' }
            return 'unknown'
        } catch {
            $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            if ($code -eq 404) { return 'false' }
            return 'unknown'
        }
    } catch { return 'unknown' }
}

function Invoke-PimSigninFrontImageStep {
    <#
      The updater's whole front step for ONE run. NEVER throws and never exits: a failure is a result with a plain reason,
      and the Manager update goes on regardless. Returns @{ ok; action; built; version; image; reason; lines }.
        -Wanted        the version to have (the updater image's own pin; the archive's pin wins when an archive is given)
        -Built         PIM_SIGNIN_FRONT_BUILT (what this updater recorded)
        -CurrentImage  the Manager's front container image now ('' when not behind the front)
        -ArchivePath   the PIM source archive of this run ('' = none fetched: a 'build' then reports that it needs one)
        -Build         { param($ContextPath, $ImageName) } -> @{ ok; status; runId; seconds }   (default: Invoke-PimAcrRestBuild in
                       -SubscriptionId / -ResourceGroup / -RegistryName on -AgentPoolName, Dockerfile at the context root)
        -TagCheck      { param($LoginServer, $Tag) } -> 'true' | 'false' | 'unknown'            (default: Test-PimSigninFrontImagePresent)
        -Record        { param($Version) }   records PIM_SIGNIN_FRONT_BUILT on the updater job (a failure is a note)
    #>
    param([bool]$OptIn, [AllowEmptyString()][string]$Wanted = '', [AllowEmptyString()][string]$Built = '',
          [AllowEmptyString()][string]$CurrentImage = '', [AllowEmptyString()][string]$LoginServer = '',
          [AllowEmptyString()][string]$ArchivePath = '', [string]$WorkDir = ([IO.Path]::GetTempPath()),
          [scriptblock]$Build, [scriptblock]$TagCheck, [scriptblock]$Record,
          [string]$SubscriptionId = '', [string]$ResourceGroup = '', [string]$RegistryName = '', [string]$AgentPoolName = '', [scriptblock]$OnPoll)
    $lines = New-Object System.Collections.Generic.List[string]
    $out = @{ ok = $true; action = 'none'; built = $false; version = ''; image = ''; reason = ''; lines = $lines }
    try {
        if (-not $OptIn) { $out.reason = 'not opted in'; return $out }
        $ver = "$Wanted".Trim()
        $ctxRes = $null
        $ctxFile = Join-Path $WorkDir ("signin-front-ctx-{0}.tar.gz" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
        try {
            if ("$ArchivePath".Trim() -and (Test-Path -LiteralPath $ArchivePath)) {
                # The archive of the version being built names the version to build: its own pin, checked against its component.
                $ctxRes = New-PimSigninFrontBuildContext -ArchivePath $ArchivePath -OutFile $ctxFile
                if ("$($ctxRes.pinned)".Trim() -and (Test-PimSigninFrontVersionText "$($ctxRes.pinned)")) { $ver = "$($ctxRes.pinned)".Trim() }
            }
            $out.version = $ver
            $img = Get-PimSigninFrontImageRef -LoginServer $LoginServer -Version $ver
            $out.image = $img
            $d = Get-PimSigninFrontImageDecision -OptIn $true -Wanted $ver -Built $Built -CurrentImage $CurrentImage -WantedImage $img
            if ($d.action -eq 'check') {
                if (-not $img) { $d = @{ action = 'build'; reason = 'the registry could not be named -- the front cannot be checked' } }
                else {
                    $tp = 'unknown'
                    try { $tp = if ($TagCheck) { "$(& $TagCheck $LoginServer $ver)" } else { Test-PimSigninFrontImagePresent -LoginServer $LoginServer -Tag $ver } } catch { $tp = 'unknown' }
                    $d = Get-PimSigninFrontImageDecision -OptIn $true -Wanted $ver -Built $Built -CurrentImage $CurrentImage -WantedImage $img -TagPresent $tp
                }
            }
            $out.action = $d.action
            if ($d.action -eq 'none') { $out.reason = $d.reason; return $out }
            if ($d.action -eq 'present') {
                $out.reason = $d.reason
                $lines.Add("sign-in front image: $($d.reason) -- not rebuilt") | Out-Null
                if ("$Built".Trim() -ne $ver -and $Record) { try { & $Record $ver } catch { $lines.Add("  (could not record PIM_SIGNIN_FRONT_BUILT=$ver -- it is checked again next run: $($_.Exception.Message))") | Out-Null } }
                return $out
            }
            # build
            if (-not $img) { $out.ok = $false; $out.reason = 'the front image was NOT built: this environment''s registry is not known (read from the Manager''s image)'; $lines.Add("sign-in front image: $($out.reason)") | Out-Null; return $out }
            if (-not $ctxRes) {
                $out.ok = $false
                $out.reason = "the front image signin-front:$ver was NOT built: this run has no source archive to build it from (it is built by a run that fetches one)"
                $lines.Add("sign-in front image: $($out.reason)") | Out-Null
                return $out
            }
            if (-not $ctxRes.ok) {
                $out.ok = $false; $out.reason = "the front image was NOT built: $($ctxRes.reason)"
                $lines.Add("sign-in front image: $($out.reason)") | Out-Null
                return $out
            }
            $lines.Add("sign-in front image: building signin-front:$ver in the registry ($($d.reason); $($ctxRes.files) source files)") | Out-Null
            $b = $null
            try {
                $imgName = "$($script:PimSigninFrontRepository):$ver"
                if ($Build) { $b = & $Build $ctxFile $imgName }
                else {
                    # The same REST ACR build as the Manager (PIM-AcrBuild.ps1); the context's root holds the front's Dockerfile.
                    $b = Invoke-PimAcrRestBuild -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName `
                            -ContextPath $ctxFile -ImageNames @($imgName) -DockerFilePath 'Dockerfile' -AgentPoolName $AgentPoolName -OnPoll $OnPoll
                }
            } catch { $b = @{ ok = $false; status = "error: $($_.Exception.Message)"; seconds = 0; runId = '' } }
            if (-not $b -or -not $b.ok) {
                $st = if ($b) { "$($b.status)" } else { 'no answer' }
                $out.ok = $false
                $out.reason = "the front image signin-front:$ver was NOT built ($st) -- the Manager update is not affected; the next run tries again"
                $lines.Add("sign-in front image: $($out.reason)") | Out-Null
                return $out
            }
            $out.built = $true
            $out.reason = "built signin-front:$ver in $($b.seconds)s (run $($b.runId))"
            $lines.Add("sign-in front image: $($out.reason)") | Out-Null
            if ($Record) { try { & $Record $ver } catch { $lines.Add("  (could not record PIM_SIGNIN_FRONT_BUILT=$ver -- the next run checks the registry instead: $($_.Exception.Message))") | Out-Null } }
            return $out
        } finally { Remove-Item -LiteralPath $ctxFile -Force -ErrorAction SilentlyContinue }
    } catch {
        $out.ok = $false; $out.reason = "the front image step failed: $($_.Exception.Message) -- the Manager update is not affected"
        $lines.Add("sign-in front image: $($out.reason)") | Out-Null
        return $out
    }
}
