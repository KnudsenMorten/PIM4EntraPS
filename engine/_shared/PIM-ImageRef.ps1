<#
  PURE container-image reference helpers -- no Azure, no network, no filesystem.
  Dot-sourcing has NO side effects (same contract as PIM-DownlinkJob.ps1).

  WHY THIS EXISTS -- BUG-40. Every deploy path in this solution referenced the image by TAG
  (`<acr>.azurecr.io/pim-manager:2.4.245`). A tag is a MUTABLE pointer: rebuilding the same tag
  moves it to new content, but the container app's image FIELD does not change -- so ARM sees no
  change, creates no new revision, and the platform keeps running the image it already pulled.

  Measured live 2026-08-09: the BUG-39 fix was built into tag 2.4.245 and the tick Job updated;
  both reported success, and the next two scheduled executions still ran the OLD code. Nothing
  anywhere reported a problem. That is the dangerous shape -- a deploy that "succeeds" while
  silently continuing to run the previous build.

  Worse, the post-roll check that was supposed to catch exactly this (Update-PimContainers'
  BUG-09 verification) compared the live TAG against the requested TAG. Both were 2.4.245, so it
  passed while the running content was stale. A tag comparison cannot detect a tag that moved.

  THE FIX, in one sentence: resolve the tag to its immutable DIGEST at deploy time, deploy
  `<registry>/<repo>@sha256:<64 hex>`, and verify the running reference carries THAT digest.
  New content => new digest => a changed image field => a real revision => an actual pull.

  These functions are the decision-making half and are unit-tested offline
  (tests/Test-PimSetupHosting.ps1). The `az` half is Resolve-PimAcrImageDigest in
  tools/setup/_PimSetupShared.ps1.
#>

Set-StrictMode -Off

# A registry digest is 'sha256:' + exactly 64 LOWERCASE hex characters. Anything else is not a
# digest, and the most likely "anything else" is an az CLI call that failed and returned an
# error string or an empty line -- which must never be pasted into an image reference.
$script:PimImageDigestPattern = '^sha256:[0-9a-f]{64}$'

function Test-PimImageDigest {
    <#
      Is this a well-formed registry digest? Returns $true/$false; never throws.

      Deliberately strict about case: registries emit lowercase hex, and accepting uppercase
      would let a hand-typed value through that the registry would then reject at pull time --
      i.e. it would fail LATE, in the container platform, instead of here.
    #>
    [CmdletBinding()] param([string]$Digest)
    if (-not "$Digest".Trim()) { return $false }
    return ([regex]::IsMatch("$Digest".Trim(), $script:PimImageDigestPattern))
}

function New-PimImageReference {
    <#
      Build the image reference a container platform should be given.

        -Digest supplied => '<registry>/<repository>@sha256:...'   (IMMUTABLE -- always prefer)
        -Tag only        => '<registry>/<repository>:<tag>'        (mutable; BUG-40 lives here)

      When BOTH are supplied the DIGEST wins, because that is the whole point: the tag is kept
      only as human-readable provenance for logs, never as the thing that is deployed.

      Throws when neither is usable, rather than emitting a bare '<registry>/<repository>' --
      that reference means ':latest' to a registry, which is the single worst thing to deploy.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Registry,     # e.g. acrpimig798.azurecr.io
        [Parameter(Mandatory)][string]$Repository,   # e.g. pim-manager
        [string]$Tag,
        [string]$Digest
    )
    $reg  = "$Registry".Trim().TrimEnd('/')
    $repo = "$Repository".Trim().Trim('/')
    if (-not $reg)  { throw "New-PimImageReference: -Registry is empty." }
    if (-not $repo) { throw "New-PimImageReference: -Repository is empty." }

    if ("$Digest".Trim()) {
        if (-not (Test-PimImageDigest -Digest $Digest)) {
            throw ("New-PimImageReference: '$Digest' is not a valid digest (expected sha256: + 64 " +
                   "lowercase hex). Refusing to build an image reference from it -- an unusable " +
                   "digest here becomes an ImagePullFailure minutes later, in a different script.")
        }
        return ("{0}/{1}@{2}" -f $reg, $repo, "$Digest".Trim())
    }
    if (-not "$Tag".Trim()) {
        throw ("New-PimImageReference: neither -Tag nor -Digest supplied for $reg/$repo -- refusing " +
               "to emit a reference with no tag (a registry reads that as ':latest').")
    }
    return ("{0}/{1}:{2}" -f $reg, $repo, "$Tag".Trim())
}

function Get-PimImageReferenceParts {
    <#
      Split an image reference into its parts. Returns
      @{ registry; repository; tag; digest; pinned; ok; reason }.

      `pinned` is the fact callers actually care about: a pinned reference cannot silently
      change content underneath a running app; an unpinned one can, and did.

      Note the parse order -- '@' is looked for FIRST. A digest reference may also carry a tag
      ('repo:2.4.245@sha256:...', which registries accept), and splitting on ':' first would
      mangle it. The registry host may also carry a port (':5000'), which is why the tag is only
      ever read from the LAST path segment.
    #>
    [CmdletBinding()] param([string]$Reference)
    $r = "$Reference".Trim()
    $out = [ordered]@{ registry=''; repository=''; tag=''; digest=''; pinned=$false; ok=$false; reason='' }
    if (-not $r) { $out.reason = 'empty image reference'; return [pscustomobject]$out }

    $rest = $r
    $at = $rest.IndexOf('@')
    if ($at -ge 0) {
        $out.digest = $rest.Substring($at + 1).Trim()
        $rest = $rest.Substring(0, $at)
        $out.pinned = (Test-PimImageDigest -Digest $out.digest)
        if (-not $out.pinned) { $out.reason = "reference carries '@$($out.digest)' which is not a valid sha256 digest" }
    }
    # tag: only from the last path segment, so a registry port is never mistaken for one.
    $slash = $rest.LastIndexOf('/')
    $lastSeg = if ($slash -ge 0) { $rest.Substring($slash + 1) } else { $rest }
    $colon = $lastSeg.IndexOf(':')
    if ($colon -ge 0) {
        $out.tag = $lastSeg.Substring($colon + 1).Trim()
        $rest = $(if ($slash -ge 0) { $rest.Substring(0, $slash + 1) } else { '' }) + $lastSeg.Substring(0, $colon)
    }
    $slash = $rest.IndexOf('/')
    if ($slash -ge 0) { $out.registry = $rest.Substring(0, $slash); $out.repository = $rest.Substring($slash + 1).Trim('/') }
    else { $out.repository = $rest }

    if (-not $out.repository) { $out.reason = 'no repository in image reference'; return [pscustomobject]$out }
    if (-not $out.reason) { $out.ok = $true }
    return [pscustomobject]$out
}

function Test-PimImageDeployed {
    <#
      POST-DEPLOY VERDICT -- is the thing that is RUNNING the thing we deployed?

      Pure: takes the reference we asked for and the reference the platform reports, and returns
      @{ ok; pinned; reason }.

      The rule that matters, and the reason this function exists at all:

        * Expected is DIGEST-PINNED -> the running reference must carry the SAME digest. A
          matching tag is explicitly NOT accepted as evidence. That substitution is exactly how
          BUG-40 passed its own verification while running week-old code.
        * Expected is TAG-ONLY      -> compare tags, but return pinned=$false and say in `reason`
          that the check is WEAK. It is the best that can be done with a mutable pointer, and a
          caller printing that text is a caller who knows the difference.

      A running reference that is unreadable (empty) is NEVER ok -- "I could not tell" and
      "it is fine" are different answers, and only one of them is safe to ship.
    #>
    [CmdletBinding()]
    param([string]$Expected, [string]$Running)

    $e = Get-PimImageReferenceParts -Reference $Expected
    $r = Get-PimImageReferenceParts -Reference $Running

    if (-not $e.ok) { return [pscustomobject]@{ ok=$false; pinned=$false; reason="expected image reference is unusable: $($e.reason)" } }
    if (-not "$Running".Trim()) {
        return [pscustomobject]@{ ok=$false; pinned=$false
            reason = "could not read the running image reference -- treating that as NOT verified (an unreadable deploy is not a proven one)" }
    }

    if ($e.pinned) {
        if ($r.digest -eq $e.digest) {
            return [pscustomobject]@{ ok=$true; pinned=$true; reason="running the pinned digest $($e.digest)" }
        }
        $seen = if ($r.digest) { "digest $($r.digest)" } elseif ($r.tag) { "tag '$($r.tag)' and NO digest" } else { "'$Running'" }
        return [pscustomobject]@{ ok=$false; pinned=$true
            reason = ("expected digest $($e.digest) but the platform reports $seen -- the update reported success and did " +
                      "NOT take effect (BUG-40). Do not treat this deploy as done.") }
    }

    if ($r.tag -and $e.tag -and $r.tag -eq $e.tag) {
        return [pscustomobject]@{ ok=$true; pinned=$false
            reason = ("running tag '$($e.tag)' -- WEAK check: a tag is mutable, so this proves the field was set, NOT that " +
                      "the running content is the content just built (BUG-40). Deploy by digest to make this conclusive.") }
    }
    return [pscustomobject]@{ ok=$false; pinned=$false
        reason = "expected '$Expected' but the platform reports '$Running'" }
}
