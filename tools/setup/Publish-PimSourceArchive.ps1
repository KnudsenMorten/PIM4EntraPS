#Requires -Version 5.1
<#
.SYNOPSIS
    Publish the build context for ONE version, so any environment can build that version itself. §55.

.DESCRIPTION
    The nightly updater in each environment fetches a source archive and asks its OWN registry to
    build it (§55). This produces that archive, and optionally uploads it with a read-only link.

    🔑 WHY THIS EXISTS RATHER THAN AN IMAGE FEED. Distributing IMAGES between registries needs a
    cross-tenant registry credential provisioned and rotated in every customer tenant. A read-only
    link to ONE object needs none. Nothing that can read the repository ever lands in a tenant we
    do not own.

    🪤 THE ARCHIVE IS REPO-ROOT SHAPED. The Dockerfile does `COPY SOLUTIONS/PIM4EntraPS`, so the
    context root must be the repository root -- exactly what Build-PimManagerImage has always
    uploaded (`git archive HEAD -- .dockerignore SOLUTIONS/PIM4EntraPS`). An archive with a single
    wrapping folder -- which is what a GitHub tag tarball gives you -- fails at COPY inside the
    registry, minutes in. -Verify checks the shape here, in seconds, before anyone can publish it.

.PARAMETER Version
    The version this archive is for. Defaults to the VERSION file in the tree being packed.

.PARAMETER OutDir
    Where to write <Repo>-<Version>.tar.gz. Defaults to the system temp folder.

.PARAMETER StorageAccount / -Container / -SubscriptionId
    Upload the archive and mint a read-only link. Omit to produce the file only.

.PARAMETER SasDays
    Lifetime of the read link (default 400). It must outlive the release, because an environment
    that has been offline for a month must still be able to fetch what it was approved for.

.EXAMPLE
    .\Publish-PimSourceArchive.ps1 -Verify
    Pack the current tree and prove the shape, without uploading anything.

.EXAMPLE
    .\Publish-PimSourceArchive.ps1 -StorageAccount <account> -Container pim-src -SubscriptionId <sub>
    Pack, upload, and print the URL template to configure environments with.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Version,
    [string]$OutDir,
    [string]$RepoRoot,
    [string]$StorageAccount,
    [string]$Container = 'pim-src',
    [string]$SubscriptionId,
    [int]$SasDays = 400,
    # 🔑 PER-CUSTOMER ISOLATION. Azure allows only FIVE stored access policies per container, so
    # "a policy per customer" needs a CONTAINER per customer -- containers are free and unlimited.
    # With one, revoking a single customer is deleting one policy; without one, the only lever is
    # fleet-wide. Costs an upload of the archive per customer (a few MB), which is the price of
    # being able to cut off one tenant without cutting off the rest.
    [string]$CustomerId,
    [string]$PolicyName = 'srcread',
    # Community editions (S2/S4) already publish their source publicly, so a credential here
    # protects nothing and is one more thing to rotate. Anonymous blob read removes it entirely.
    [switch]$PublicRead,
    [switch]$Verify,
    # SEC-23: the read link carries a SAS -- a credential -- so it is NEVER printed (it lands in
    # transcripts, CI logs and screenshots). -PassThru returns it as an OBJECT on the pipeline instead:
    #     $src = .\Publish-PimSourceArchive.ps1 ... -PassThru;  $src.SourceUrlTemplate
    # Captured into a variable it never reaches the console.
    [switch]$PassThru
)
if ("$CustomerId".Trim()) {
    # Container names: lowercase alphanumerics and dashes only.
    $cid = ("$CustomerId".Trim().ToLowerInvariant() -replace '[^a-z0-9-]', '-').Trim('-')
    if (-not $cid) { throw "Publish-PimSourceArchive: -CustomerId '$CustomerId' contains no usable characters." }
    $Container = "pim-src-$cid"
}
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
. (Join-Path $here '_PimAz.ps1')

function Hide-PimSourceUrlQuery {
    <#
      SEC-23. A URL with its query string (the SAS) replaced, and any stray sig= in free text withheld.
      Everything this script prints about the read link goes through here.
    #>
    param([AllowEmptyString()][string]$Text)
    $t = "$Text" -replace '(https://[^\s?"'']+)\?[^\s"'']*', '$1?<read-sas withheld>'
    return ($t -replace '(?i)(sig=)[^&\s"'']+', '$1<withheld>')
}

function Get-PimTarGzEntryNames {
    <#
      Entry names from a .tar.gz, read with .NET only -- no tar binary, no PATH dependency.
      A tar entry is a 512-byte header (name at offset 0, size as octal at 124) followed by the
      file content padded to 512. Enough to answer "is this archive repo-root shaped?".
    #>
    param([Parameter(Mandatory)][string]$Path, [int]$MaxEntries = 20000)
    $names = New-Object System.Collections.Generic.List[string]
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $hdr = New-Object byte[] 512
            while ($names.Count -lt $MaxEntries) {
                $read = 0
                while ($read -lt 512) {
                    $n = $gz.Read($hdr, $read, 512 - $read)
                    if ($n -le 0) { break }
                    $read += $n
                }
                if ($read -lt 512) { break }
                if ($hdr[0] -eq 0) { break }                       # the two zero blocks that end a tar
                $name = [System.Text.Encoding]::ASCII.GetString($hdr, 0, 100).TrimEnd([char]0, ' ')
                if ($name) { [void]$names.Add($name) }
                $oct = [System.Text.Encoding]::ASCII.GetString($hdr, 124, 12).Trim([char]0, ' ')
                $size = 0
                if ($oct -match '^[0-7]+$') { $size = [Convert]::ToInt64($oct, 8) }
                $skip = [int64]([Math]::Ceiling($size / 512.0) * 512)
                $buf = New-Object byte[] 8192
                while ($skip -gt 0) {
                    $want = [int][Math]::Min([int64]8192, $skip)
                    $got = $gz.Read($buf, 0, $want)
                    if ($got -le 0) { break }
                    $skip -= $got
                }
            }
        } finally { $gz.Dispose() }
    } finally { $fs.Dispose() }
    $names.ToArray()
}

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

# <repo>/SOLUTIONS/PIM4EntraPS/tools/setup -> four up is the repository root, the same derivation
# Build-PimManagerImage uses. Resolved from THIS FILE, never the working directory.
if (-not "$RepoRoot".Trim()) { $RepoRoot = (Resolve-Path (Join-Path $here '..\..\..\..')).Path }
$solRoot = Join-Path $RepoRoot 'SOLUTIONS\PIM4EntraPS'
if (-not (Test-Path -LiteralPath $solRoot)) { throw "Publish-PimSourceArchive: '$solRoot' not found -- -RepoRoot is not a repository root." }

if (-not "$Version".Trim()) {
    $vf = Join-Path $solRoot 'VERSION'
    if (-not (Test-Path -LiteralPath $vf)) { throw "Publish-PimSourceArchive: no -Version and no VERSION file at '$vf'." }
    $Version = (Get-Content -LiteralPath $vf -Raw).Trim()
}
if (-not "$OutDir".Trim()) { $OutDir = [IO.Path]::GetTempPath() }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$archive = Join-Path $OutDir ("pim-src-$Version.tar.gz")

Write-Host "`n=== PIM source archive ($Version) ===" -ForegroundColor Cyan
Note "repo root  $RepoRoot"
Note "archive    $archive"

# ---- 1. pack ------------------------------------------------------------------------------------
# 🔑 `git archive` OF HEAD, NOT A COPY OF THE DIRECTORY. A working tree carries build output,
# .custom.* customer files that are gitignored, and whatever another session left behind; HEAD
# carries what was committed. Build-PimManagerImage learned this already -- it tars HEAD for the
# same reason -- and a release artifact has even less business shipping an uncommitted tree.
Step 'pack the build context from HEAD'
$isRepo = Test-Path -LiteralPath (Join-Path $RepoRoot '.git')
if ($isRepo) {
    if ($PSCmdlet.ShouldProcess($archive, 'git archive HEAD')) {
        & git -C $RepoRoot archive --format=tar.gz -o $archive HEAD -- .dockerignore SOLUTIONS/PIM4EntraPS
        if ($LASTEXITCODE -ne 0) { throw "Publish-PimSourceArchive: git archive failed (exit $LASTEXITCODE)." }
    }
} else {
    # A synced/released tree is not a git clone. tar ships with Windows 10+ and every container base.
    Note 'not a git clone (a synced tree) -- packing the directory as-is'
    if ($PSCmdlet.ShouldProcess($archive, 'tar')) {
        # 🪤 Write to a RELATIVE name inside the repo root, then move. Handing tar an absolute
        # Windows path makes GNU tar read `C:` as a remote host (see the listing note below).
        Push-Location $RepoRoot
        try {
            $tmpName = "pim-src-$Version.tar.gz"
            & tar -czf $tmpName .dockerignore SOLUTIONS/PIM4EntraPS
            if ($LASTEXITCODE -ne 0) { throw "Publish-PimSourceArchive: tar failed (exit $LASTEXITCODE)." }
            Move-Item -LiteralPath (Join-Path $RepoRoot $tmpName) -Destination $archive -Force
        } finally { Pop-Location }
    }
}
if (-not $WhatIfPreference) {
    if (-not (Test-Path -LiteralPath $archive)) { throw "Publish-PimSourceArchive: no archive was produced." }
    Note ("packed {0:N0} bytes" -f (Get-Item -LiteralPath $archive).Length)
}

# ---- 2. verify the SHAPE ------------------------------------------------------------------------
# 🔴 THE ONE THING THAT MUST BE TRUE, CHECKED WHERE IT IS CHEAP. The registry discovers a wrong
# shape by failing `COPY SOLUTIONS/PIM4EntraPS` several minutes into a build, in a log nobody is
# watching, in a customer tenant. Listing the archive costs a second.
if ((-not $WhatIfPreference) -and ($Verify -or $StorageAccount)) {
    Step 'verify the archive is repo-root shaped'
    # 🪤 NOT `tar -tzf <path>`. GNU tar (the one Git for Windows puts on PATH) reads `C:\...` as a
    # REMOTE HOST spec and answers "Cannot connect to C: resolve failed", while the bsdtar that
    # ships in Windows handles it fine -- so the verification passed or failed depending on which
    # tar happened to be first in PATH. Measured 2026-09-10 on the very first run of this script.
    # Reading the tar headers directly has no such dependency and needs no external tool at all.
    $listing = @(Get-PimTarGzEntryNames -Path $archive)
    if (-not $listing.Count) { throw "Publish-PimSourceArchive: could not list '$archive'." }
    $hasDockerfile = @($listing | Where-Object { $_ -eq 'SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile' }).Count -gt 0
    if (-not $hasDockerfile) {
        $sample = ($listing | Select-Object -First 3) -join ', '
        throw ("Publish-PimSourceArchive: the archive is NOT repo-root shaped -- " +
               "'SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile' is not at its root (top entries: $sample). " +
               "The Dockerfile does COPY SOLUTIONS/PIM4EntraPS, so a wrapping folder fails the build.")
    }
    Note "verified: $($listing.Count) entries, Dockerfile at the expected path"
}

# ---- 3. upload + read link ----------------------------------------------------------------------
if ($StorageAccount -and -not $WhatIfPreference) {
    $subArgs = @(); if ("$SubscriptionId".Trim()) { $subArgs = @('--subscription', "$SubscriptionId".Trim()) }
    $blob = "pim-src-$Version.tar.gz"

    Step "upload $blob to $StorageAccount/$Container"
    # 🔑 THE KEY IS READ HERE AND NEVER LEAVES HERE. Reading it is a MANAGEMENT-plane call, which
    # the publishing identity can already make; what gets distributed is a read-only SAS to one
    # blob, never the key. This followed the pattern of the baseline SAS rotation (retired
    # 2026-09-18, SEC-27) for the same job -- data-plane operations against a freshly-created account otherwise need a separate
    # RBAC grant on the caller, and a publish step that fails until somebody grants a role by hand
    # is a publish step nobody runs.
    # 🪤 Never write the key to a log, a file, or a variable that outlives this call.
    $key = "$(az storage account keys list --account-name $StorageAccount @subArgs --query "[0].value" -o tsv 2>$null)".Trim()
    if (-not $key) { throw "Publish-PimSourceArchive: could not read a key for '$StorageAccount' -- the publishing identity needs management rights on it." }

    # -PublicRead: anonymous blob access, for editions whose source is public anyway. No token is
    # issued, so there is nothing to expire, leak or rotate -- the rotation question stops existing
    # rather than getting a better answer.
    $pubArgs = @(); if ($PublicRead) { $pubArgs = @('--public-access', 'blob') }
    # SEC-23: the create used to be `... 2>$null` with no exit check, so a refusal (a policy that forbids
    # public containers, a firewall, a wrong account) vanished and surfaced one line later as a baffling
    # upload failure. An EXISTING container is not an error here (az answers created=false, exit 0).
    $global:LASTEXITCODE = 0
    $cOut = az storage container create --account-name $StorageAccount --name $Container `
        --account-key $key @pubArgs -o none 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("Publish-PimSourceArchive: could not create/ensure container '$Container' on '$StorageAccount' (exit $LASTEXITCODE): " +
               (Hide-PimSourceUrlQuery (($cOut | Out-String).Trim())))
    }
    $global:LASTEXITCODE = 0
    az storage blob upload --account-name $StorageAccount --container-name $Container `
        --name $blob --file $archive --overwrite --account-key $key -o none
    if ($LASTEXITCODE -ne 0) { throw "Publish-PimSourceArchive: blob upload FAILED for $blob." }
    Note 'uploaded'

    # ─────────────────────────────────────────────────────────────────────────
    # 🔴 SIGN AGAINST A STORED ACCESS POLICY, NEVER AN AD-HOC SAS.
    # An ad-hoc SAS carries its expiry and permissions INSIDE the token, so the only way to change
    # either is to issue a new token -- which means reaching into every environment that holds the
    # old one. At 1000 customers that is not an operation anyone can perform, and it is exactly the
    # "touch every customer" problem §55 exists to remove. It is also unrevocable except by rotating
    # the account key, which invalidates EVERY customer's URL simultaneously and leaves none of them
    # able to fetch the replacement -- a fleet-wide outage as the only security lever.
    #
    # 🔑 A policy-backed SAS references the policy BY NAME and takes its validity from the policy at
    # READ time. So expiry is extended, or access revoked, by changing ONE object centrally --
    # every issued URL follows, and no environment is contacted.
    #
    # 🪤 THIS CANNOT BE RETROFITTED. A URL already handed out as an ad-hoc SAS stays ad-hoc forever;
    # only tokens minted against the policy gain central control. That is why this had to land
    # before the next customer was issued one.
    if ($PublicRead) {
        # No token at all. Report the plain URL and stop -- minting a SAS for an anonymous
        # container would imply a control that does not exist.
        $url = "https://$StorageAccount.blob.core.windows.net/$Container/$blob"
        try {
            $probe = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -TimeoutSec 60
            Note "verified: the public link fetches (HTTP $($probe.StatusCode))"
        } catch { Warn "the public link did NOT fetch: $($_.Exception.Message)" }
        Write-Host ''
        Write-Host '  PUBLIC source (no credential, nothing to rotate). Configure with:' -ForegroundColor DarkGray
        $pubTpl = ($url -replace [regex]::Escape("pim-src-$Version.tar.gz"), 'pim-src-{version}.tar.gz')
        Write-Host ("    PIM_UPDATE_SOURCE_URL = " + $pubTpl) -ForegroundColor White
        Write-Host "==> Source archive ready for $Version." -ForegroundColor Green
        if ($PassThru) { [pscustomobject]@{ Version = $Version; SourceUrlTemplate = $pubTpl; Credential = 'none (public read)' } }
        exit 0
    }

    Step "stored access policy '$PolicyName' on $Container (central expiry + revocation)"
    $expiry = (Get-Date).ToUniversalTime().AddDays($SasDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    # Idempotent: create, and if it is already there just move its expiry forward.
    az storage container policy create --account-name $StorageAccount -c $Container `
        -n $PolicyName --permissions r --expiry $expiry --account-key $key -o none 2>$null
    if ($LASTEXITCODE -ne 0) {
        az storage container policy update --account-name $StorageAccount -c $Container `
            -n $PolicyName --permissions r --expiry $expiry --account-key $key -o none 2>$null
    }
    $global:LASTEXITCODE = 0
    # 🔴 READ IT BACK. A policy that was not stored yields a SAS that authenticates against nothing
    # and fails at the customer, at 03:00, as "cannot fetch source".
    $polBack = "$(az storage container policy show --account-name $StorageAccount -c $Container -n $PolicyName --account-key $key --query expiry -o tsv 2>$null)".Trim()
    if (-not $polBack) { throw "Publish-PimSourceArchive: stored access policy '$PolicyName' could not be read back on '$Container'." }
    Note "policy verified, expires $polBack"

    Step 'mint a READ-ONLY link'
    # 🔴 A CONTAINER SAS (sr=c), NOT A BLOB SAS (sr=b) -- because this link is a TEMPLATE.
    # A blob SAS signs the blob NAME, so substituting {version} into it produces a URL whose
    # signature does not match, and every version except the one it was minted for fails
    # authentication. Measured on the first real publish: the link verified 200 for 2.4.308 and
    # would have 403'd for 2.4.309 -- at 03:00, in a customer tenant, as "cannot fetch source".
    # 🔒 --policy-name and NOTHING ELSE: no --permissions, no --expiry inline. Both come from the
    # stored policy, which is the entire point -- a token that carried its own would be ad-hoc
    # again, and az REFUSES to combine the two anyway. Read only; the container holds nothing but
    # published source archives, so read across it is exactly the reach an environment needs.
    $sas = "$(az storage container generate-sas --account-name $StorageAccount --name $Container `
                --policy-name $PolicyName --https-only --account-key $key `
                -o tsv 2>$null)".Trim()
    if (-not $sas) {
        # SEC-23: this is a CONTAINER SAS signed against the stored access policy -- not a
        # user-delegation SAS, which is what this line used to call it.
        Warn "could not mint the stored-policy ('$PolicyName') container SAS -- the archive is uploaded; generate a read link by hand (az storage container generate-sas --policy-name $PolicyName)."
    } else {
        $url = "https://$StorageAccount.blob.core.windows.net/$Container/$blob`?$sas"
        # 🪤 READ IT BACK. A link that does not actually fetch is discovered by a customer
        # environment at 03:00, as a build that never starts.
        try {
            $probe = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -TimeoutSec 60
            Note "verified: the link fetches (HTTP $($probe.StatusCode))"
        } catch { Warn ("the link did NOT fetch: " + (Hide-PimSourceUrlQuery "$($_.Exception.Message)")) }

        # 🔴 SEC-23 -- NEVER PRINT THE SAS. It is a read credential for every published source archive,
        # valid for $SasDays days, and this output is exactly what ends up in a transcript or a CI log.
        # Print the template with its query WITHHELD; hand the full value over as an OBJECT (-PassThru),
        # which a caller captures into a variable without it ever reaching the console. Environments that
        # already carry PIM_UPDATE_SOURCE_URL keep it across redeploys (Deploy-PimUpdateJob), so this is
        # needed once per new environment, not per release.
        $tpl = ($url -replace [regex]::Escape("pim-src-$Version.tar.gz"), 'pim-src-{version}.tar.gz')
        Write-Host ''
        Write-Host '  Configure an environment with the TEMPLATE (the version is substituted at run time):' -ForegroundColor DarkGray
        Write-Host ("    PIM_UPDATE_SOURCE_URL = " + (Hide-PimSourceUrlQuery $tpl)) -ForegroundColor White
        if ($PassThru) {
            Write-Host '    (the full value, SAS included, is in the returned object: .SourceUrlTemplate)' -ForegroundColor DarkGray
        } else {
            Write-Host '    (the SAS is withheld from this output -- re-run with -PassThru and capture the returned object to get it)' -ForegroundColor DarkGray
        }
        Write-Host ("    PIM_UPDATE_TARGET_VERSION = $Version") -ForegroundColor White
        Write-Host ''
        Write-Host '  ...and publish every version to the same container, so a ring that is behind can still fetch what it was approved for.' -ForegroundColor DarkGray
        if ($PassThru) { [pscustomobject]@{ Version = $Version; SourceUrlTemplate = $tpl; Credential = "stored access policy '$PolicyName' on $Container" } }
    }
}

Write-Host "==> Source archive ready for $Version." -ForegroundColor Green
if (-not $StorageAccount) {
    Note 'no -StorageAccount given: the archive was produced but not published.'
}
exit 0
