#Requires -Version 5.1
<#
.SYNOPSIS
    SEC-PKG-INTERNAL (2026-11-03) -- what a PIM Manager release PACKAGE must never carry, in ONE place.

.DESCRIPTION
    Two packers build the archives an install's updater (and, with PRO-PACKAGE-FROM-INVARDIA, a customer admin's PC) receives:
      * Publish-PimInvardiaRelease.ps1  pim-manager-src-<v>.zip, git archive of the release TAG (Invardia's update platform);
      * Publish-PimSourceArchive.ps1    pim-src-<v>.tar.gz, git archive of HEAD (or a tar of a synced tree).
    Both packed `.dockerignore SOLUTIONS/PIM4EntraPS` whole, so internal/ (real identifiers, install values, identities),
    CLAUDE.md, docs/REQUIREMENTS.md, docs/TESTS.md and tests/ (live harness values) rode along. The images were always clean
    (the Manager Dockerfile deletes tests/ internal/ docs/ before its final stage); the PACKAGE was not.

    THE RULE IS THE PUBLIC PUBLISH'S STRIP (.github/scripts/publish-stage.ps1 + solution.publish.json), copied here per the
    solution-isolation rule (never widen the shared stage script for one solution):
      * a FILE named CLAUDE.md, REQUIREMENTS.md or TESTS.md, at any depth;
      * a FOLDER named internal, logs, staging, demo or output (any case), at any depth;
      * an internal-only launcher (*.internal-vm.* / *.internal-azure.*);
      * PIM's own excludePaths + top-level strip: tests/ and solution.publish.json at the solution root.
    Nothing an install or the updater needs is among them: the Manager image deletes tests/ internal/ output/ itself, the
    installer and the updater run only engine/, tools/, sql/, config/, templates/, workloads/, vendor/ and VERSION, and every
    read of tests\live\* in shipped code is behind a Test-Path (the public Community release has never carried tests/).

      Get-PimReleaseExcludePathspecs  the git `:(exclude)` pathspecs for `git archive ... -- <paths> <these>`
      Test-PimReleaseInternalPath     PURE: is one archive entry (repo-relative) internal-only?
      Get-PimReleaseInternalEntries   PURE: the internal-only entries of a listing (the check step's refusal)
      Get-PimReleaseZipInternalEntries the same, read from a zip file (its entry names, optional top folder stripped)
      Test-PimReleaseZip              Publish-PimInvardiaRelease's whole "check the zip" step (shape + version + internal)
#>

$script:PimReleaseStripFileNames = @('CLAUDE.md', 'REQUIREMENTS.md', 'TESTS.md')
$script:PimReleaseStripDirNames = @('internal', 'logs', 'staging', 'demo', 'output')
$script:PimReleaseSolutionPrefix = 'SOLUTIONS/PIM4EntraPS'
# solution-root items PIM's own publish removes (solution.publish.json excludePaths 'tests' + the stage's top-level strip)
$script:PimReleaseSolutionRootStrip = @('tests', 'solution.publish.json')

function Get-PimReleaseExcludePathspecs {
    <#
      PURE. The `:(exclude)` pathspecs that keep every internal-only path out of `git archive <ref> -- <paths>`. glob + icase
      magic, so a name matches at any depth and in any case (the stage lowercases folder names before comparing). An exclude
      that matches nothing is not an error (only a POSITIVE pathspec must match), so an older tag packs the same way.
    #>
    param([string]$SolutionPrefix = $script:PimReleaseSolutionPrefix)
    $p = "$SolutionPrefix".Trim().TrimEnd('/')
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($d in $script:PimReleaseStripDirNames) { $out.Add(":(exclude,glob,icase)**/$d/**") }
    foreach ($f in $script:PimReleaseStripFileNames) { $out.Add(":(exclude,glob)**/$f") }
    $out.Add(':(exclude,glob)**/*.internal-vm.*')
    $out.Add(':(exclude,glob)**/*.internal-azure.*')
    $out.Add(":(exclude,glob)$p/tests/**")
    $out.Add(":(exclude)$p/solution.publish.json")
    return $out.ToArray()
}

function Test-PimReleaseInternalPath {
    <#
      PURE. -Path is one archive entry, repo-relative ('SOLUTIONS/PIM4EntraPS/internal/X.md', '.dockerignore'); '\' or '/'.
      $true when the public strip would remove it. A folder entry ('.../internal/') counts too.
    #>
    param([AllowEmptyString()][string]$Path, [string]$SolutionPrefix = $script:PimReleaseSolutionPrefix)
    $p = "$Path".Replace('\', '/').TrimStart('/')
    if (-not $p) { return $false }
    $isDir = $p.EndsWith('/')
    $segs = @($p.TrimEnd('/') -split '/' | Where-Object { $_ })
    if (-not $segs.Count) { return $false }
    $dirSegs = if ($isDir) { $segs } elseif ($segs.Count -gt 1) { $segs[0..($segs.Count - 2)] } else { @() }
    foreach ($s in $dirSegs) { if ($script:PimReleaseStripDirNames -contains $s.ToLowerInvariant()) { return $true } }
    $leaf = $segs[-1]
    if (-not $isDir -and ($script:PimReleaseStripFileNames -ccontains $leaf)) { return $true }
    if (-not $isDir -and $leaf -match '\.internal-(vm|azure)\.') { return $true }
    $pre = "$SolutionPrefix".Trim().TrimEnd('/') + '/'
    if ($p.StartsWith($pre, [StringComparison]::OrdinalIgnoreCase)) {
        $rel = $p.Substring($pre.Length)
        $first = @($rel -split '/')[0]
        if ($first -and ($script:PimReleaseSolutionRootStrip -contains $first.ToLowerInvariant())) {
            # tests/ is a folder; solution.publish.json is a file at the solution root only
            if ($first -ieq 'tests' -and ($rel -match '^(?i)tests(/|$)')) { return $true }
            if ($first -ieq 'solution.publish.json' -and $rel -ieq 'solution.publish.json') { return $true }
        }
    }
    return $false
}

function Get-PimReleaseInternalEntries {
    <# PURE. The entries of -Names (repo-relative after -StripTop is removed) that must not be in a release package. #>
    param([AllowEmptyCollection()][string[]]$Names = @(), [string]$StripTop = '', [string]$SolutionPrefix = $script:PimReleaseSolutionPrefix)
    $top = "$StripTop".Replace('\', '/').Trim().TrimEnd('/')
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($Names)) {
        $e = "$n".Replace('\', '/')
        $rel = $e
        if ($top -and $e.StartsWith("$top/", [StringComparison]::Ordinal)) { $rel = $e.Substring($top.Length + 1) }
        if (Test-PimReleaseInternalPath -Path $rel -SolutionPrefix $SolutionPrefix) { $out.Add($e) }
    }
    return $out.ToArray()
}

function Test-PimReleaseZip {
    <#
      Publish-PimInvardiaRelease's "check the zip" step (reads only): every entry under the ONE top folder
      pim-manager-src-<Version>/, its SOLUTIONS/PIM4EntraPS/VERSION says -Version, and NO internal-only path is in it
      (SEC-PKG-INTERNAL), and NO real identifier in the CONTENT of any text file (-Deny: Read-PimReleaseDenylist; none given =
      refused, fail closed). Returns @{ ok; reason; count; leaked; contentHits }. The caller refuses (removes the zip, sends
      nothing) on ok=$false. The reason names files and lines, never an identifier.
    #>
    param([Parameter(Mandatory)][string]$ZipPath, [Parameter(Mandatory)][string]$Version, [object[]]$Deny = @())
    $top = "pim-manager-src-$Version"
    $res = @{ ok = $false; reason = ''; count = 0; leaked = @(); contentHits = @() }
    if (-not ('System.IO.Compression.ZipFile' -as [type])) { Add-Type -AssemblyName System.IO.Compression.FileSystem }
    $z = $null
    try { $z = [System.IO.Compression.ZipFile]::OpenRead($ZipPath) } catch { $res.reason = "the release zip cannot be read: $($_.Exception.Message)"; return $res }
    try {
        $names = @($z.Entries | ForEach-Object { $_.FullName })
        $res.count = $names.Count
        $bad = @($names | Where-Object { -not "$_".StartsWith("$top/") })
        if ($bad.Count) { $res.reason = "the zip has entries outside $top/ (e.g. $($bad[0]))"; return $res }
        $ve = $z.Entries | Where-Object { $_.FullName -eq "$top/SOLUTIONS/PIM4EntraPS/VERSION" } | Select-Object -First 1
        if (-not $ve) { $res.reason = 'the zip carries no SOLUTIONS/PIM4EntraPS/VERSION'; return $res }
        $sr = New-Object System.IO.StreamReader($ve.Open()); try { $inner = $sr.ReadToEnd().Trim() } finally { $sr.Dispose() }
        if ($inner -ne $Version) { $res.reason = "VERSION inside the zip is '$inner', not $Version"; return $res }
        $leak = @(Get-PimReleaseInternalEntries -Names $names -StripTop $top)
        if ($leak.Count) {
            $res.leaked = $leak
            $res.reason = ("REFUSED: the release zip carries {0} internal-only path(s) (e.g. {1}) -- the internal notes, the backlog, the test document and the test suite never leave the repository" -f $leak.Count, (@($leak | Select-Object -First 3) -join ', '))
            return $res
        }
    } finally { $z.Dispose() }
    if (-not @($Deny).Count) { $res.reason = 'REFUSED: no private identifier list to scan the content against -- the package cannot be checked'; return $res }
    $ch = @(Get-PimReleaseZipContentHits -ZipPath $ZipPath -Deny $Deny -StripTop $top)
    if ($ch.Count) {
        $res.contentHits = $ch
        $res.reason = ("REFUSED: {0} file line(s) in the release zip carry a real identifier or a secret -- {1}{2}. Remove it from the source, commit, tag again." -f $ch.Count, (@($ch | Select-Object -First 5) -join '; '), $(if ($ch.Count -gt 5) { "; and $($ch.Count - 5) more" } else { '' }))
        return $res
    }
    $res.ok = $true
    return $res
}

# ---- CONTENT SCAN (framework 0 "Installer rules", item 7; 2026-11-03) -------------------------------------------------------
# A path rule cannot see a customer name in a comment, a release note or an ops script. So the check step ALSO reads every
# text file IN the package and refuses on a real identifier: PIM's own denylist (internal/REAL-IDENTIFIERS.md, the block
# Test-PimSourceSanitization.ps1 parses -- GUIDs, also by their unique first 8 hex; value: literals; word: / case: whole
# words) plus the secret shapes the public sanitization blocks (a private key block, a GitHub token). A finding names the
# FILE and LINE and the kind of entry -- NEVER the identifier itself (the refusal lands in logs and transcripts).
# FAILS CLOSED: no readable denylist = the package is refused (a scan that checks nothing is not a pass).
$script:PimReleaseTextExt = @('.ps1', '.psm1', '.psd1', '.json', '.sql', '.md', '.yml', '.yaml', '.xml', '.csv', '.txt', '.js', '.mjs', '.css', '.html',
                              '.htm', '.cs', '.csproj', '.bicep', '.sh', '.cmd', '.bat', '.config', '.props', '.targets', '.ini', '.toml', '.svg', '')
$script:PimReleaseSecretShapes = @(
    # a header WITH key material after it (64+ base64 characters): code that BUILDS a PEM ("-----BEGIN ...-----`n$b64") or a
    # redacted sample is not a key
    @{ kind = 'a private key block'; rx = '-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=\r\n]{64,}' }
    @{ kind = 'a GitHub token'; rx = '(?i)\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})' }
)

function Read-PimReleaseDenylist {
    <#
      The DENYLIST block of internal/REAL-IDENTIFIERS.md -> @( @{ n; kind = guid|guidhead|literal|word|case; value } ), parsed
      exactly as tests/Test-PimSourceSanitization.ps1 does (guid, value:, word:, case:). A GUID also yields its first 8 hex as a
      whole word (a truncated id -- "1234abcd-..." -- is caught too, as the public sanitization does). Throws when the file is
      missing or the block carries nothing (fail closed). -Text: the file's text (test seam).
    #>
    param([string]$Path = '', [string]$Text = '')
    if (-not "$Text") {
        if (-not "$Path".Trim() -or -not (Test-Path -LiteralPath $Path)) { throw "the private identifier list (internal\REAL-IDENTIFIERS.md) is not there ($Path) -- the package cannot be checked, so it is refused" }
        $Text = [IO.File]::ReadAllText($Path)
    }
    $out = New-Object System.Collections.Generic.List[object]
    $in = $false; $n = 0
    foreach ($line in ("$Text" -split "`r?`n")) {
        if ($line -match '^##\s*DENYLIST-BEGIN') { $in = $true; continue }
        if ($line -match '^##\s*DENYLIST-END') { $in = $false; continue }
        if (-not $in -or $line -match '^\s*<!--') { continue }
        $w = [regex]::Match($line, '^\s*(?<k>word|case):\s*(?<v>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:#.*)?$')
        if ($w.Success) {
            $v = $w.Groups['v'].Value.Trim().Trim('"', "'")
            if ($v.Length -ge 3) { $n++; $out.Add(@{ n = $n; kind = $w.Groups['k'].Value; value = $(if ($w.Groups['k'].Value -eq 'word') { $v.ToLowerInvariant() } else { $v }) }) }
            continue
        }
        $l = [regex]::Match($line, '^\s*value:\s*(?<v>.+?)\s*(?:#.*)?$')
        if ($l.Success) {
            $v = $l.Groups['v'].Value.Trim().Trim('"', "'")
            if ($v.Length -ge 5) { $n++; $out.Add(@{ n = $n; kind = 'literal'; value = $v.ToLowerInvariant() }) }
            continue
        }
        $g = [regex]::Match($line, '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
        if ($g.Success) {
            $n++
            $out.Add(@{ n = $n; kind = 'guid'; value = $g.Value.ToLowerInvariant() })
            $out.Add(@{ n = $n; kind = 'guidhead'; value = $g.Value.Substring(0, 8).ToLowerInvariant() })
        }
    }
    if (-not $out.Count) { throw 'the private identifier list carries no entry -- the package cannot be checked, so it is refused' }
    return $out.ToArray()
}

function Find-PimReleaseContentHits {
    <#
      PURE. -Text of one package file (-Name, for the finding) against -Deny (Read-PimReleaseDenylist) and the secret shapes.
      Returns "<name>:<line> -- <what kind of entry>" per hit (first hit per entry). The identifier is NEVER in the result.
    #>
    param([Parameter(Mandatory)][string]$Name, [AllowEmptyString()][string]$Text, [Parameter(Mandatory)][object[]]$Deny)
    $hits = New-Object System.Collections.Generic.List[string]
    if (-not $Text) { return $hits.ToArray() }
    $lineOf = { param([int]$i) ([regex]::Matches($Text.Substring(0, $i), "`n")).Count + 1 }
    $lower = $Text.ToLowerInvariant()
    $seen = @{}
    foreach ($d in $Deny) {
        if ($d.kind -eq 'guidhead' -and $seen.ContainsKey("$($d.n)")) { continue }   # the full id already named this file
        $idx = -1
        switch ($d.kind) {
            'guid'    { $idx = $lower.IndexOf($d.value) }
            'literal' { $idx = $lower.IndexOf($d.value) }
            default {
                # word (any case) / case (exact) / guidhead (the first 8 hex of a real id, as a word): whole word only
                $rx = $(if ($d.kind -eq 'case') { '' } else { '(?i)' }) + '(?<![A-Za-z0-9])' + [regex]::Escape($d.value) + '(?![A-Za-z0-9])'
                $m = [regex]::Match($Text, $rx); if ($m.Success) { $idx = $m.Index }
            }
        }
        if ($idx -ge 0) {
            $seen["$($d.n)"] = $true
            $what = switch ($d.kind) { 'guid' { 'a real tenant / subscription id' } 'guidhead' { 'the start of a real tenant / subscription id' } 'literal' { 'a real identifier' } default { 'a real customer / environment name' } }
            $hits.Add(("{0}:{1} -- {2} (denylist entry {3})" -f $Name, (& $lineOf $idx), $what, $d.n))
        }
    }
    foreach ($s in $script:PimReleaseSecretShapes) {
        $m = [regex]::Match($Text, $s.rx)
        if ($m.Success) { $hits.Add(("{0}:{1} -- {2}" -f $Name, (& $lineOf $m.Index), $s.kind)) }
    }
    return $hits.ToArray()
}

function Test-PimReleaseTextName {
    # PURE. Is this package entry a TEXT file the content scan reads? (by extension; no extension = Dockerfile, VERSION, LICENSE)
    param([string]$Name)
    $leaf = "$Name".Replace('\', '/').TrimEnd('/'); $leaf = $leaf.Substring($leaf.LastIndexOf('/') + 1)
    if (-not $leaf) { return $false }
    $ext = [IO.Path]::GetExtension($leaf).ToLowerInvariant()
    return ($script:PimReleaseTextExt -contains $ext)
}

function Get-PimReleaseZipContentHits {
    <# Every content hit in a zip's TEXT entries (Find-PimReleaseContentHits). -StripTop: the top folder, left out of the names. #>
    param([Parameter(Mandatory)][string]$ZipPath, [Parameter(Mandatory)][object[]]$Deny, [string]$StripTop = '', [int64]$MaxBytes = 8MB)
    if (-not ('System.IO.Compression.ZipFile' -as [type])) { Add-Type -AssemblyName System.IO.Compression.FileSystem }
    $hits = New-Object System.Collections.Generic.List[string]
    $z = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        foreach ($e in $z.Entries) {
            if ($e.FullName.EndsWith('/') -or $e.Length -gt $MaxBytes -or -not (Test-PimReleaseTextName -Name $e.FullName)) { continue }
            $name = $e.FullName; if ($StripTop -and $name.StartsWith("$StripTop/")) { $name = $name.Substring($StripTop.Length + 1) }
            $sr = New-Object System.IO.StreamReader($e.Open(), [Text.Encoding]::UTF8, $true)
            try { $t = $sr.ReadToEnd() } finally { $sr.Dispose() }
            foreach ($h in @(Find-PimReleaseContentHits -Name $name -Text $t -Deny $Deny)) { $hits.Add($h) }
        }
    } finally { $z.Dispose() }
    return $hits.ToArray()
}

function Get-PimReleaseTarGzContentHits {
    <#
      Every content hit in a .tar.gz's TEXT entries, read with .NET only (no tar binary): the full name (ustar prefix, pax
      path=, GNU long name), the content of a text entry up to -MaxBytes.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][object[]]$Deny, [int64]$MaxBytes = 8MB)
    $hits = New-Object System.Collections.Generic.List[string]
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $hdr = New-Object byte[] 512; $longName = $null
            $readN = { param([int64]$Count) $b = New-Object byte[] $Count; $r = 0; while ($r -lt $Count) { $k = $gz.Read($b, $r, [int][Math]::Min([int64]1048576, $Count - $r)); if ($k -le 0) { break }; $r += $k }; ,$b }
            while ($true) {
                $r = 0; while ($r -lt 512) { $k = $gz.Read($hdr, $r, 512 - $r); if ($k -le 0) { break }; $r += $k }
                if ($r -lt 512 -or $hdr[0] -eq 0) { break }
                $name = [Text.Encoding]::ASCII.GetString($hdr, 0, 100).TrimEnd([char]0, ' ')
                if ([Text.Encoding]::ASCII.GetString($hdr, 257, 6) -eq "ustar$([char]0)") { $pre = [Text.Encoding]::ASCII.GetString($hdr, 345, 155).TrimEnd([char]0, ' '); if ($pre) { $name = "$pre/$name" } }
                $type = [char]$hdr[156]
                $oct = [Text.Encoding]::ASCII.GetString($hdr, 124, 12).Trim([char]0, ' ')
                $size = [int64]0; if ($oct -match '^[0-7]+$') { $size = [Convert]::ToInt64($oct, 8) }
                $padded = [int64]([Math]::Ceiling($size / 512.0) * 512)
                $read = ($type -cin @([char]'x', [char]'L')) -or (($type -ceq [char]'0' -or $type -ceq [char]0) -and $size -le $MaxBytes)
                $data = if ($read -and $padded -gt 0) { & $readN $padded } else { $null }
                if (-not $read -and $padded -gt 0) { [void](& $readN $padded) }
                if ($type -ceq [char]'x') { $pm = [regex]::Match([Text.Encoding]::UTF8.GetString($data, 0, [int]$size), '(?m)^\d+ path=(?<p>[^\n]*)$'); if ($pm.Success) { $longName = $pm.Groups['p'].Value }; continue }
                if ($type -ceq [char]'L') { $longName = [Text.Encoding]::UTF8.GetString($data, 0, [int]$size).TrimEnd([char]0); continue }
                if ($longName) { $name = $longName; $longName = $null }
                if ($data -and (Test-PimReleaseTextName -Name $name)) {
                    $t = [Text.Encoding]::UTF8.GetString($data, 0, [int]$size)
                    foreach ($h in @(Find-PimReleaseContentHits -Name $name -Text $t -Deny $Deny)) { $hits.Add($h) }
                }
            }
        } finally { $gz.Dispose() }
    } finally { $fs.Dispose() }
    return $hits.ToArray()
}

function Get-PimReleaseZipInternalEntries {
    <# The internal-only entries of a zip file (-StripTop: its one top folder, e.g. 'pim-manager-src-3.0.24'). Reads only. #>
    param([Parameter(Mandatory)][string]$ZipPath, [string]$StripTop = '')
    if (-not ('System.IO.Compression.ZipFile' -as [type])) { Add-Type -AssemblyName System.IO.Compression.FileSystem }
    $z = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try { $names = @($z.Entries | ForEach-Object { $_.FullName }) } finally { $z.Dispose() }
    return @(Get-PimReleaseInternalEntries -Names $names -StripTop $StripTop)
}
