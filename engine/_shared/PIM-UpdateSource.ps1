#Requires -Version 5.1
<#
.SYNOPSIS
    Fetch the SOURCE for an approved version, so the environment can build its own image. §55.

.DESCRIPTION
    The nightly updater needs the source of the version it has been told to move to. Where that
    comes from is the ONE thing that differs per deployment scenario -- and rather than teach the
    updater six sources, it is given ONE URL with the version substituted into it:

        S1 / S3  private   https://<store>/pim-src/pim-src-{version}.tar.gz?<read-sas>
        S2 / S4  community https://<public-host>/pim-src-{version}.tar.gz
        S6       managed   whatever its MSP master publishes for its ring
        S5       central   -- no registry of its own; nothing to fetch

    🔑 WHY A URL AND NOT A CREDENTIAL. The alternative was distributing IMAGES between registries,
    which needs a cross-tenant registry credential provisioned and rotated in every customer
    tenant. A read-scoped URL to ONE object needs none: nothing that can read the whole repository
    ever lands in a tenant we do not own, and the same mechanism serves a public host, a SAS'd
    blob and an MSP master without the updater knowing which it is.

    🪤 THE ARCHIVE MUST BE REPO-ROOT SHAPED. The Dockerfile does `COPY SOLUTIONS/PIM4EntraPS`, so
    the context root must be the repository root -- exactly what
    `git archive HEAD -- .dockerignore SOLUTIONS/PIM4EntraPS` produces, which is what the existing
    build has always uploaded. An archive with a single wrapping folder (what a GitHub tag tarball
    gives you) builds nothing and fails at COPY, minutes in. Test-PimUpdateSourceArchive checks the
    shape BEFORE a build is scheduled, so that failure arrives in seconds with a reason.

.NOTES
    PS 5.1-safe. No modules. TLS 1.2 forced -- 5.1 still defaults lower on some hosts and the
    failure reads as a connection reset rather than a protocol refusal.
#>

function Resolve-PimUpdateSourceUrl {
    <#
      Substitute the approved version into the configured URL template.
      Accepts {version} and {tag}; a template with no placeholder is used as-is, which is how a
      "always fetch latest" endpoint would be configured.
    #>
    param(
        [Parameter(Mandatory)][string]$Template,
        [Parameter(Mandatory)][string]$Version
    )
    $u = "$Template".Trim()
    if (-not $u) { return '' }
    $v = "$Version".Trim()
    $u = $u.Replace('{version}', $v).Replace('{VERSION}', $v).Replace('{tag}', $v).Replace('{TAG}', $v)
    $u
}

function Get-PimUpdateSourceArchive {
    <#
      Download the build context to a local file. Returns @{ ok; path; bytes; reason }.

      🔴 A TRUNCATED OR HTML RESPONSE IS NOT A BUILD CONTEXT. A SAS that has expired, or a private
      URL behind a sign-in page, answers 200 with HTML -- and an HTML file uploaded as a build
      context fails inside the registry, minutes later, as a tar error. The gzip magic number is
      two bytes and settles it here instead.
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$OutFile,
        [int]$TimeoutSeconds = 300
    )
    try {
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.ServicePointManager]::SecurityProtocol
    } catch { }
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    try {
        # -UseBasicParsing: 5.1 otherwise wants IE's engine, which does not exist in a container.
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec $TimeoutSeconds
    } catch {
        return @{ ok = $false; path = ''; bytes = 0; reason = "download failed: $($_.Exception.Message)" }
    }
    if (-not (Test-Path -LiteralPath $OutFile)) {
        return @{ ok = $false; path = ''; bytes = 0; reason = 'download produced no file' }
    }
    $len = (Get-Item -LiteralPath $OutFile).Length
    if ($len -lt 64) {
        return @{ ok = $false; path = $OutFile; bytes = $len; reason = "downloaded only $len byte(s) -- not an archive" }
    }
    $magic = New-Object byte[] 2
    $fs = [System.IO.File]::OpenRead($OutFile)
    try { [void]$fs.Read($magic, 0, 2) } finally { $fs.Close(); $fs.Dispose() }
    if ($magic[0] -ne 0x1f -or $magic[1] -ne 0x8b) {
        return @{ ok = $false; path = $OutFile; bytes = $len
                  reason = 'the downloaded file is not gzip -- an expired link or a sign-in page answers 200 with HTML' }
    }
    @{ ok = $true; path = $OutFile; bytes = $len; reason = '' }
}

function Get-PimUpdateSourcePlan {
    <#
      PURE. Decide what an updater run should do about building, given what it is told and what it
      last built. Returns @{ action; version; image; reason }.

        action = 'roll'   -- no source configured, or already built this version: just roll
                 'build'  -- fetch + build, then roll
                 'none'   -- nothing approved

      🔒 'roll' IS THE SAFE DEFAULT, AND DELIBERATELY SO. An environment with no source configured
      behaves EXACTLY as it does today -- it rolls to whatever image someone else put in its
      registry. That is what lets this ship without touching the three environments that already
      work every night.

      🪤 THE SHORT-CIRCUIT COMPARES WHAT WAS LAST BUILT, NOT WHAT IS DEPLOYED. A deployed container
      is usually pinned by DIGEST, so its image string never equals a tag and a "is it already
      deployed?" test would rebuild every single night -- and every rebuild produces a new digest,
      which would then roll every container in the estate nightly for no reason at all.
    #>
    param(
        [string]$TargetVersion,      # the approved version, e.g. '2.4.307'
        [string]$SourceUrlTemplate,  # empty => roll-only (today's behaviour)
        [string]$LastBuiltVersion,   # what this updater last built here
        [string]$LoginServer,        # e.g. acrx.azurecr.io
        [string]$Repository = 'pim-manager'
    )
    $v = "$TargetVersion".Trim()
    if (-not $v) { return @{ action = 'none'; version = ''; image = ''; reason = 'no approved version for this ring' } }

    $img = if ("$LoginServer".Trim()) { "$("$LoginServer".Trim())/$Repository" + ':' + $v } else { '' }

    if (-not "$SourceUrlTemplate".Trim()) {
        return @{ action = 'roll'; version = $v; image = $img
                  reason = 'no source configured -- rolling to an image the registry already holds' }
    }
    if ("$LastBuiltVersion".Trim() -eq $v) {
        return @{ action = 'roll'; version = $v; image = $img
                  reason = "already built $v here -- nothing to rebuild" }
    }
    @{ action = 'build'; version = $v; image = $img; reason = "building $v from source" }
}

# ─────────────────────────────────────────────────────────────────────────────
# §60 -- RING RELEASE, PULLED RATHER THAN PUSHED.
# The pin is the ring enforcement point and always has been: an environment moves only to the
# version it is pinned to. What did not exist was a central place saying what each ring approves --
# so "release to ring 2" meant editing the pin on every ring-2 environment, which is the same
# 1000-customer problem the source credential had.
# 🔑 Invert it: one small file next to the source archives, read by each environment with the
# credential it ALREADY holds. Approving a ring becomes editing one file, exactly as extending
# access became one policy change.
#   { "ring0": { "version": "2.4.320" },
#     "ring2": { "version": "2.4.314", "minFrom": "2.4.302" } }

function Get-PimUpdateChannelUrl {
    <#
      The channel file lives beside the archives, so its URL is the source template with the blob
      name swapped. Derived rather than configured: an operator who had to supply BOTH would
      eventually supply one that points somewhere else, and a channel from the wrong feed is worse
      than no channel at all.
      🪤 The query string is the SAS -- keep it exactly, it is what authorises the read.
    #>
    param([string]$SourceTemplate, [string]$FileName = 'channel.json')
    $t = "$SourceTemplate".Trim()
    if (-not $t) { return '' }
    $q = ''
    $qi = $t.IndexOf('?')
    if ($qi -ge 0) { $q = $t.Substring($qi); $t = $t.Substring(0, $qi) }
    $si = $t.LastIndexOf('/')
    if ($si -lt 0) { return '' }
    $t.Substring(0, $si + 1) + $FileName + $q
}

function Get-PimRingVersion {
    <#
      PURE. Which version this ring is approved for. Returns @{ version; reason }.

      🔒 AN UNKNOWN RING APPROVES NOTHING. Falling back to "newest", or to another ring's version,
      would let a ring-2 customer take a build that was only ever tested in ring 0 -- the precise
      thing rings exist to prevent. No entry means no approved version, which the updater reports
      and then does nothing.
      🪤 minFrom is a FLOOR, not a target: an environment further behind than the floor must not
      jump the gap unattended, because the schema steps between are what it would be skipping.
    #>
    param([object]$Channel, [string]$Ring, [string]$CurrentVersion)
    $r = "$Ring".Trim()
    if (-not $r) { return @{ version = ''; reason = 'no ring configured for this environment' } }
    if ($r -notmatch '^(?i)ring') { $r = "ring$r" }          # accept '2' or 'ring2'
    if (-not $Channel) { return @{ version = ''; reason = 'no channel document' } }

    $entry = $null
    foreach ($p in $Channel.PSObject.Properties) {
        if ("$($p.Name)".Trim().ToLowerInvariant() -eq $r.ToLowerInvariant()) { $entry = $p.Value; break }
    }
    if (-not $entry) { return @{ version = ''; reason = "the channel names no '$r' -- nothing approved for this ring" } }
    $v = "$($entry.version)".Trim()
    if (-not $v) { return @{ version = ''; reason = "'$r' has no version -- nothing approved" } }

    $floor = "$($entry.minFrom)".Trim()
    if ($floor -and "$CurrentVersion".Trim()) {
        $cv = $null; $fv = $null
        if ([version]::TryParse(($CurrentVersion -replace '^v',''), [ref]$cv) -and
            [version]::TryParse(($floor -replace '^v',''), [ref]$fv) -and $cv -lt $fv) {
            return @{ version = ''
                      reason  = "this environment is on $CurrentVersion, below '$r' minFrom $floor -- refusing to jump the gap unattended" }
        }
    }
    @{ version = $v; reason = "'$r' approves $v" }
}

# ---- 2026-09-17 (BUG-162) -- AN UPDATE NEVER GOES BACKWARD BY ITSELF -----------------------------
# MEASURED on the rehearsal MSP master dp998: built at 2.4.366, its own ca-pim-update ran once and
# rolled all five containers -- Manager, tick, update, dbinit and ca-pim-publish -- to 2.4.324, the
# version its (wrong, see BUG-162 part 1) ring held. 42 versions backward, while the job itself still
# recorded PIM_UPDATE_LAST_GOOD=...:2.4.366. The next ca-pim-publish then failed outright, because
# publish-job-entry.ps1 does not exist in 2.4.324 -- so the master silently STOPPED PUBLISHING and its
# managed tenants kept serving the last bundle until it expired.
#
# A ROLL FORWARD IS AN UPDATE; A ROLL BACKWARD IS A ROLLBACK, AND A ROLLBACK IS AN ATTENDED ACT.
# The updater cannot know which capability an older image lacks -- a file added in a newer version is
# simply ABSENT, which is why the failure surfaces somewhere else entirely, hours later. So it refuses
# to move backward and says exactly which two versions and which ring proposed it. A DELIBERATE
# rollback stays possible: PIM_UPDATE_ALLOW_DOWNGRADE=1 on the update job, off by default, loud when on.
#
# THE COMPARISON IS AGAINST THE HIGHEST VERSION THIS ENVIRONMENT IS KNOWN TO HAVE REACHED, not just
# the one running right now. dp998 was already half-rolled when this was found; taking only the running
# version would have called the second night's identical roll a no-op.

function ConvertTo-PimUpdateVersion {
    <#
      PURE. The comparable [version] of a version string, a tag, or a full image reference
      ('acr.azurecr.io/pim-manager:2.4.366' -> 2.4.366; 'v2.4.366' -> 2.4.366). Returns $null when the
      value is absent or is not a version number (a digest pin, 'latest', a branch name). NEVER throws:
      "I cannot read this" is an answer the caller has to handle, not an error.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Value)
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    if ($s -match '@') { $s = ($s -split '@')[0] }          # digest-pinned: the tag half, if any
    if ($s -match '[:/]') { $s = ($s -split ':')[-1] }      # <server>/<repo>:<tag> -> <tag>
    $s = $s -replace '^(?i)v', ''
    if ($s -notmatch '^\d+(\.\d+){1,3}$') { return $null }
    $v = $null
    if ([version]::TryParse($s, [ref]$v)) { return $v }
    return $null
}

function Get-PimUpdateDowngradeDecision {
    <#
      PURE. May this run move the environment to -TargetVersion? Returns
        { allowed; direction; from; fromSource; to; overridden; message; detail; errorText; note }
      direction: 'forward' | 'same' | 'backward' | 'unknown'.

      Inputs are the three things an environment knows about itself, in the order they are trusted:
        -RunningVersion    the tag the Manager app is on right now
        -LastBuiltVersion  PIM_UPDATE_LAST_BUILT
        -LastGoodImage     PIM_UPDATE_LAST_GOOD (a full image reference)
      The HIGHEST comparable of the three is what the target is measured against.

      REFUSALS (all overridable with -AllowDowngrade, which is PIM_UPDATE_ALLOW_DOWNGRADE=1):
        * the target is BEHIND that version                        -> backward
        * the target is not a version number while this environment
          has a comparable one                                     -> unknown ("cannot prove it is
          not a downgrade"). A malformed target must never pass silently -- that is how a channel
          typo becomes an unattended roll to something nobody can name.
      ALLOWED, and said so:
        * forward, or exactly the same version (the normal no-op night)
        * nothing comparable to measure against at all -- a first roll on a digest-pinned environment.
          Allowed, but the caller is told it could not be checked rather than told it was fine.
    #>
    param(
        [AllowEmptyString()][string]$TargetVersion,
        [AllowEmptyString()][string]$RunningVersion,
        [AllowEmptyString()][string]$LastBuiltVersion,
        [AllowEmptyString()][string]$LastGoodImage,
        [AllowEmptyString()][string]$Ring,
        [switch]$AllowDowngrade,
        [string]$UpdateJobName = 'ca-pim-update'
    )
    $to    = ConvertTo-PimUpdateVersion -Value $TargetVersion
    $toRaw = "$TargetVersion".Trim()
    $known = @(
        [pscustomobject]@{ source = 'the running Manager image'; raw = "$RunningVersion".Trim(); v = (ConvertTo-PimUpdateVersion -Value $RunningVersion) }
        [pscustomobject]@{ source = 'PIM_UPDATE_LAST_BUILT';     raw = "$LastBuiltVersion".Trim(); v = (ConvertTo-PimUpdateVersion -Value $LastBuiltVersion) }
        [pscustomobject]@{ source = 'PIM_UPDATE_LAST_GOOD';      raw = "$LastGoodImage".Trim();   v = (ConvertTo-PimUpdateVersion -Value $LastGoodImage) }
    )
    $seen = @($known | Where-Object { $_.v })
    $ringTxt = if ("$Ring".Trim()) { "ring $("$Ring".Trim())" } else { 'this environment' }
    $whereTxt = (@($known | Where-Object { $_.raw } | ForEach-Object { "$($_.source)=$($_.raw)" }) -join '; ')
    if (-not $whereTxt) { $whereTxt = 'nothing recorded' }
    $ok = { param($dir, $from, $src, $note)
            [pscustomobject]@{ allowed = $true; direction = $dir; from = $from; fromSource = $src; to = $toRaw
                               overridden = $false; message = ''; detail = ''; errorText = ''; note = $note } }

    if (-not $seen.Count) {
        # Nothing comparable: allow, but never call it verified.
        return (& $ok 'unknown' '' '' ("downgrade check: no comparable version for this environment ($whereTxt) -- " +
                                       "the roll to '$toRaw' could NOT be checked for direction."))
    }
    $high = @($seen | Sort-Object -Property v -Descending)[0]
    $from = $high.raw; $fromSrc = $high.source

    $refuse = { param($dir, $head, $why)
        $lead = if ($dir -eq 'backward') { 'REFUSING TO ROLL BACKWARD' } else { 'REFUSING TO ROLL' }
        $act = ("Fix the channel (channel.json) so $ringTxt approves $from or newer, or -- for a DELIBERATE rollback -- " +
                "set PIM_UPDATE_ALLOW_DOWNGRADE=1 on $UpdateJobName and run it again.")
        if ($AllowDowngrade) {
            return [pscustomobject]@{ allowed = $true; direction = $dir; from = $from; fromSource = $fromSrc; to = $toRaw
                overridden = $true
                message = "DOWNGRADE ALLOWED by PIM_UPDATE_ALLOW_DOWNGRADE=1: $head"
                detail  = "$why This is an explicit operator opt-in on $UpdateJobName; nothing else in the update path permits it."
                errorText = ''; note = '' }
        }
        [pscustomobject]@{ allowed = $false; direction = $dir; from = $from; fromSource = $fromSrc; to = $toRaw
            overridden = $false
            message = "$lead`: $head"
            detail  = "$why $act"
            errorText = "downgrade refused: $ringTxt proposed $toRaw, this environment is on $from ($fromSrc)"
            note = '' }
    }

    if (-not $to) {
        return (& $refuse 'unknown' `
            "$ringTxt proposed '$toRaw', which is not a version number, and this environment is on $from ($fromSrc)." `
            ("An unreadable target cannot be PROVEN to be a move forward, and an update that cannot prove its own " +
             "direction is exactly the one that must not run unattended. Known here: $whereTxt."))
    }
    if ($to -eq $high.v) {
        return (& $ok 'same' $from $fromSrc "already on $from -- the roll to $toRaw moves nothing.")
    }
    if ($to -gt $high.v) {
        return (& $ok 'forward' $from $fromSrc "roll FORWARD $from -> $toRaw (highest known: $fromSrc).")
    }
    & $refuse 'backward' `
        "$ringTxt approves $toRaw, but this environment is on $from ($fromSrc) -- that is BACKWARD." `
        ("A roll backward is a ROLLBACK, and a rollback is an attended operation: an older image simply does not " +
         "contain what a newer one added, so the damage surfaces somewhere else entirely (BUG-162: 2.4.324 has no " +
         "publish-job-entry.ps1, so the master stopped publishing and nothing alerted). Known here: $whereTxt.")
}

# ---- 2026-09-13 -- DOES THE UPDATER REACH THIS ENVIRONMENT'S STORE? ------------------------------
# 🔴 MEASURED ON FOUR LIVE ENVIRONMENTS: ca-pim-update carried no PIM_SqlServer / PIM_SqlDatabase
# (ca-pim-manager and ca-pim-tick do), so every nightly schema step printed
#     schema: no store connection resolved -- skipping (this environment has no local store)
# about environments whose Manager runs on Azure SQL. The sentence was false and it read as a clean
# skip -- so a release carrying a schema change would have rolled a container expecting columns
# nobody had added. "I could not look" must never be worded as "there is nothing to look at".

function Get-PimAcaStoreSettings {
    <#
      PURE. The SQL store a container app or job is configured with, read from its env across EVERY
      container (ARM GET shape, or the `az ... show -o json` shape). Returns
        { known; hasStore; server; database; via }
      known=$false when the object is $null or carries no template: an unreadable Manager is NEVER
      evidence of a store-less environment.
    #>
    param([object]$Resource)
    $out = [ordered]@{ known = $false; hasStore = $false; server = ''; database = ''; via = '' }
    if ($null -eq $Resource) { return [pscustomobject]$out }
    $tpl = $null
    if ($Resource.PSObject.Properties['properties'] -and $Resource.properties -and $Resource.properties.PSObject.Properties['template']) { $tpl = $Resource.properties.template }
    elseif ($Resource.PSObject.Properties['template']) { $tpl = $Resource.template }
    if (-not $tpl) { return [pscustomobject]$out }
    $out.known = $true
    $other = ''
    foreach ($c in @($tpl.containers | Where-Object { $_ })) {
        foreach ($e in @($c.env | Where-Object { $_ })) {
            $n = "$($e.name)"; $v = "$($e.value)".Trim()
            $ref = ''
            if ($e.PSObject.Properties['secretRef']) { $ref = "$($e.secretRef)".Trim() }
            if ($n -ceq 'PIM_SqlServer' -and $v -and -not $out.server) { $out.server = $v }
            elseif ($n -ceq 'PIM_SqlDatabase' -and $v -and -not $out.database) { $out.database = $v }
            elseif (($n -ceq 'PIM_SqlConnectionString' -or $n -ceq 'PIM_SqlConnStringVault') -and ($v -or $ref) -and -not $other) { $other = $n }
        }
    }
    if ($out.server) { $out.hasStore = $true; $out.via = 'PIM_SqlServer' }
    elseif ($other)  { $out.hasStore = $true; $out.via = $other }
    [pscustomobject]$out
}

function Get-PimUpdateSchemaStoreDecision {
    <#
      PURE. What the nightly updater's schema step may do, before any container moves.
        check      -- the updater resolved a store connection: run the additive schema step.
        storeless  -- neither the updater NOR the Manager names a store. The ONLY case that may skip
                      with "this environment has no local store".
        unverified -- the Manager has a store and the updater does not, but the roll stays on the
                      version already running, so it carries no schema change: roll, loudly.
        refuse     -- the Manager has a store (or could not be read), the updater does not, and the roll
                      MOVES to another version whose DDL cannot be verified: do NOT roll.
      🔒 Store-less must be PROVEN from the Manager's own settings. An unreadable Manager, or a version
      that cannot be read off its image (a digest-only reference), is treated as a move -- refuse.
    #>
    param(
        [AllowEmptyString()][string]$UpdaterConnection,
        [object]$ManagerStore,
        [AllowEmptyString()][string]$CurrentVersion,
        [AllowEmptyString()][string]$TargetVersion,
        [string]$UpdateJobName = 'ca-pim-update',
        [string]$ManagerApp = 'ca-pim-manager'
    )
    if ("$UpdaterConnection".Trim()) {
        return [pscustomobject]@{ mode = 'check'; message = 'store connection resolved -- checking the schema'; detail = ''; errorText = '' }
    }
    $known = ($null -ne $ManagerStore) -and [bool]$ManagerStore.known
    if ($known -and -not [bool]$ManagerStore.hasStore) {
        return [pscustomobject]@{ mode = 'storeless'
            message = "schema: no store connection resolved -- skipping (this environment has no local store: neither $UpdateJobName nor $ManagerApp names one)."
            detail = ''; errorText = '' }
    }
    $cur = ("$CurrentVersion".Trim() -replace '^(?i)v', '')
    $tgt = ("$TargetVersion".Trim() -replace '^(?i)v', '')
    # 2026-09-15 (UPD-15): "re-run Deploy-PimUpdateJob" is no longer the advice. The updater now copies
    # the Manager's PIM_SqlServer itself (Resolve-PimUpdaterStoreSettings), so the only runs that still
    # reach here are the two it genuinely cannot self-heal -- an unreadable Manager, or a Manager that
    # names its store through a secret or vault pointer -- and the detail says which.
    $head = 'updater has no PIM_SqlServer -- schema NOT checked'
    $why = if ($known) {
               if ("$($ManagerStore.server)".Trim()) {
                   "$ManagerApp uses a SQL store ($($ManagerStore.server)) but $UpdateJobName has no PIM_SqlServer"
               } else {
                   "$ManagerApp names its store through $($ManagerStore.via) (a secret or vault pointer the updater cannot copy), and $UpdateJobName has no PIM_SqlServer. Set PIM_SqlServer + PIM_SqlDatabase on $ManagerApp or on $UpdateJobName"
               }
           } else {
               "$ManagerApp could not be read, so this environment cannot be proven store-less and its store cannot be copied"
           }
    if ($cur -and $tgt -and $cur -ieq $tgt) {
        return [pscustomobject]@{ mode = 'unverified'; message = $head
            detail = "$why. The roll stays on $tgt, which is already running, so it carries no schema change -- proceeding. Fix the updater before the next release."
            errorText = '' }
    }
    $from = if ($cur) { $cur } else { 'an unreadable version' }
    $to   = if ($tgt) { $tgt } else { 'an unresolved version' }
    return [pscustomobject]@{ mode = 'refuse'; message = $head
        detail = "$why. Moving $from -> $to may need DDL that cannot be verified from here -- NOT rolling."
        errorText = "$head (roll $from -> $to refused: its schema could not be verified)" }
}

# ---- 2026-09-15 (UPD-15) -- THE UPDATER HEALS ITS OWN STORE SETTINGS ----------------------------
# MEASURED on EFIF and RIDE: both updaters failed every night from 2026-09-13 with
#     updater has no PIM_SqlServer -- schema NOT checked; re-run Deploy-PimUpdateJob ... NOT rolling
# The Manager app in the same resource group named the store the whole time. "Re-run the deploy" is an
# instruction to a human, at 03:00, for a value this job can read itself with the identity it already
# holds (it GETs the Manager to find its registry). So it copies the Manager's PIM_SqlServer /
# PIM_SqlDatabase for THIS run and records them on its own env for the next one.
# The rule that does NOT relax: only a value that CAN be copied is copied. A Manager that cannot be read,
# or names its store through a secret / vault pointer, still refuses -- guessing a store is worse than
# not rolling.

function Use-PimUpdaterStoreEnv {
    <#
      Copy the container's PIM_SqlServer / PIM_SqlDatabase ENVIRONMENT variables into the GLOBALS the
      store library reads (Get-PimSqlConnectionString reads $global:PIM_SqlServer / $global:PIM_SqlDatabase).
      Returns the names it set, so a caller can say so.

      2026-09-13: nothing in update-job-entry did this (Invoke-PimEngineCore does it with Use-Cfg), so an
      updater that DID carry PIM_SqlServer still resolved no connection -- and reported that the
      environment had no store.

      2026-09-18 (Sec.71.43): it is a FUNCTION, and it is called TWICE, on purpose. The update job needs
      the store at the TOP -- every refusal above the schema phase now records what it decided into
      pim.Settings, and those are exactly the runs an operator most needs to see -- and the schema phase
      needs it too. Idempotent by construction (an already-set global is never overwritten), so calling
      it in both places costs two environment reads and makes neither step depend on the other's order.
      One implementation, two call sites: the shape this file's own history keeps arguing for.
    #>
    $set = @()
    foreach ($sqlName in @('PIM_SqlServer', 'PIM_SqlDatabase')) {
        $ev = "$([Environment]::GetEnvironmentVariable($sqlName))".Trim()
        $gv = "$(Get-Variable -Name $sqlName -Scope Global -ValueOnly -ErrorAction SilentlyContinue)".Trim()
        if ($ev -and -not $gv) { Set-Variable -Name $sqlName -Scope Global -Value $ev; $set += $sqlName }
    }
    return ,$set
}

function Resolve-PimUpdaterStoreSettings {
    <#
      PURE. Which SQL store this updater run uses, and whether it came from the job or the Manager.
        -JobServer / -JobDatabase : the updater's own PIM_SqlServer / PIM_SqlDatabase (env or globals)
        -ManagerStore             : Get-PimAcaStoreSettings of the Manager app
      Returns { server; database; source = job|manager|none; persist (ordered writes for the job's env);
                reason }.
        job      -- the job carries PIM_SqlServer: used as-is (a missing database is taken from the
                    Manager only when the Manager names the SAME server).
        manager  -- the job carries none and the Manager names a server: copied, and persist says what
                    to write back onto the job.
        none     -- nothing copyable: the Manager is unreadable, store-less, or reaches its store
                    through a secret / vault pointer. The schema decision then refuses or skips.
    #>
    param(
        [AllowEmptyString()][string]$JobServer,
        [AllowEmptyString()][string]$JobDatabase,
        [object]$ManagerStore,
        [string]$ManagerApp = 'ca-pim-manager'
    )
    $js = "$JobServer".Trim(); $jd = "$JobDatabase".Trim()
    $persist = [ordered]@{}
    $known = ($null -ne $ManagerStore) -and [bool]$ManagerStore.known
    $ms = if ($known) { "$($ManagerStore.server)".Trim() } else { '' }
    $md = if ($known) { "$($ManagerStore.database)".Trim() } else { '' }
    if ($js) {
        $db = $jd
        $why = 'the updater carries PIM_SqlServer'
        if (-not $db -and $md -and $ms -and ($ms -ieq $js)) { $db = $md; $why = "the updater carries PIM_SqlServer; PIM_SqlDatabase taken from $ManagerApp (same server)" }
        return [pscustomobject]@{ server = $js; database = $db; source = 'job'; persist = $persist; reason = $why }
    }
    if (-not $known) {
        return [pscustomobject]@{ server = ''; database = $jd; source = 'none'; persist = $persist
            reason = "the updater carries no PIM_SqlServer and $ManagerApp could not be read -- nothing to copy" }
    }
    if (-not [bool]$ManagerStore.hasStore) {
        return [pscustomobject]@{ server = ''; database = $jd; source = 'none'; persist = $persist
            reason = "neither the updater nor $ManagerApp names a SQL store" }
    }
    if (-not $ms) {
        return [pscustomobject]@{ server = ''; database = $jd; source = 'none'; persist = $persist
            reason = "$ManagerApp reaches its store through $($ManagerStore.via), a secret or vault pointer the updater does not copy" }
    }
    $persist['PIM_SqlServer'] = $ms
    $db = if ($md) { $md } else { $jd }
    if ($md) { $persist['PIM_SqlDatabase'] = $md }
    [pscustomobject]@{ server = $ms; database = $db; source = 'manager'; persist = $persist
        reason = "the updater carries no PIM_SqlServer -- using $ManagerApp's store ($ms$(if ($db) { " / $db" })) for this run and recording it on the updater" }
}

function Save-PimUpdaterStoreSettings {
    <#
      Best-effort: write the self-healed PIM_SqlServer / PIM_SqlDatabase onto the updater job's own env,
      then READ THEM BACK. NEVER throws -- the update this run is doing must not fail because a note for
      the next run could not be written. Returns { ok; written; reason }.
      Uses Set-PimAcaJobEnvValue (ARM read-modify-write, the same call that records PIM_UPDATE_LAST_BUILT)
      and waits out the HTTP 409 an in-flight operation on the job returns.
      -Sleep is a test seam.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$JobName,
        [System.Collections.IDictionary]$Writes,
        [int[]]$RetryDelays = @(10, 20, 40),
        [scriptblock]$Sleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds }
    )
    $written = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Writes -or -not $Writes.Count) { return [pscustomobject]@{ ok = $true; written = @(); reason = 'nothing to record' } }
    try {
        foreach ($k in @($Writes.Keys)) {
            $done = $false; $last = ''
            foreach ($d in @(@(0) + @($RetryDelays))) {
                if ($d) { & $Sleep $d }
                try {
                    [void](Set-PimAcaJobEnvValue -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -JobName $JobName `
                              -VariableName "$k" -Value "$($Writes[$k])")
                    $done = $true; break
                } catch {
                    $last = "$($_.Exception.Message)"
                    if ($last -notmatch '(?i)\b409\b|OperationInProgress|active provisioning operation') { break }
                }
            }
            if (-not $done) { return [pscustomobject]@{ ok = $false; written = @($written.ToArray()); reason = "could not write $k`: $last" } }
            [void]$written.Add("$k")
        }
        $job = Invoke-PimArm -Method GET -ApiVersion $script:PimAcaApi `
                   -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName"
        $back = Get-PimAcaStoreSettings -Resource $job
        foreach ($k in @($Writes.Keys)) {
            $want = "$($Writes[$k])"
            $got = if ("$k" -ceq 'PIM_SqlServer') { "$($back.server)" } elseif ("$k" -ceq 'PIM_SqlDatabase') { "$($back.database)" } else { $want }
            if ($got -cne $want) {
                return [pscustomobject]@{ ok = $false; written = @($written.ToArray()); reason = "$k read back as '$got', not '$want'" }
            }
        }
        return [pscustomobject]@{ ok = $true; written = @($written.ToArray()); reason = 'written and read back' }
    } catch {
        return [pscustomobject]@{ ok = $false; written = @($written.ToArray()); reason = "$($_.Exception.Message)" }
    }
}

# ---- 2026-09-15 -- THE SHIPPED SCHEMA FILES REACH EVERY EXISTING STORE ---------------------------
# MEASURED on EFIF + RIDE after 2.4.360: the updater logged "schema up to date" and rolled, and
# pim.CentralAdmins.Replicate -- added by a guarded ALTER in sql/platform-schema.sql -- was MISSING on
# both stores. The updater applied the shipped files only when a LOCKED table was absent, and
# pim.CentralAdmins is not in the locked conformance schema, so every guarded addition in those files
# was silently lost on every existing environment while the step reported success.
# The files are now applied on EVERY run that resolved a store, BEFORE the conformance plan -- behind a
# store-aware destructive guard, because they are not purely additive: sql/platform-schema.sql carries
#     IF COL_LENGTH('pim.CentralAdmins','TierLevel') IS NOT NULL ALTER TABLE pim.CentralAdmins DROP COLUMN TierLevel;
# which is inert on a store without that column and a real data loss on one that has it.

function Get-PimSchemaFileApplyPlan {
    <#
      PURE (the column probe is injected). May this shipped schema file run UNATTENDED against this store?
      Returns { ok; violations; guardedDrops = @{ table; column; exists } }.
        REFUSED always : DROP TABLE / SCHEMA / DATABASE, TRUNCATE, DELETE FROM, UPDATE, MERGE, sp_rename,
                         BACKUP / RESTORE -- none belongs in a shipped schema file.
        DROP COLUMN    : allowed ONLY when guarded by `IF COL_LENGTH('<table>','<column>') IS NOT NULL`
                         AND -ColumnExists says the column is ABSENT from this store (the statement is
                         then inert). An unguarded drop, an existing column, or no way to check => refused.
        Allowed        : CREATE / ALTER ADD, DROP VIEW / CONSTRAINT / INDEX (no rows live in them), INSERT seeds.
      Comments are stripped first, so prose that says "drop" never trips it.
      -ColumnExists : scriptblock param([string]$Table, [string]$Column) -> $true / $false (throws = unknown).
    #>
    param(
        [AllowEmptyString()][string]$Sql,
        [string]$Name = 'schema file',
        [scriptblock]$ColumnExists
    )
    $code = "$Sql" -replace '(?s)/\*.*?\*/', ' ' -replace '(?m)--.*$', ' '
    $v = New-Object System.Collections.Generic.List[string]
    $bad = @(
        @{ rx = '(?i)\bDROP\s+TABLE\b';    why = 'DROP TABLE' }
        @{ rx = '(?i)\bDROP\s+SCHEMA\b';   why = 'DROP SCHEMA' }
        @{ rx = '(?i)\bDROP\s+DATABASE\b'; why = 'DROP DATABASE' }
        @{ rx = '(?i)\bTRUNCATE\b';        why = 'TRUNCATE' }
        @{ rx = '(?i)\bDELETE\s+FROM\b';   why = 'DELETE' }
        @{ rx = '(?i)\bUPDATE\s+\w';       why = 'UPDATE' }
        @{ rx = '(?i)\bMERGE\s+\w';        why = 'MERGE' }
        @{ rx = '(?i)\bsp_rename\b';       why = 'sp_rename' }
        @{ rx = '(?i)\bBACKUP\s+(DATABASE|LOG)\b|\bRESTORE\s+DATABASE\b'; why = 'BACKUP/RESTORE' }
    )
    foreach ($b in $bad) { if ($code -match $b.rx) { [void]$v.Add("$($b.why) (never allowed in a shipped schema file)") } }
    $drops = New-Object System.Collections.Generic.List[object]
    $strip = { param($s) ("$s" -replace '[\[\]]', '').Trim().ToLowerInvariant() }
    foreach ($m in [regex]::Matches($code, '(?is)ALTER\s+TABLE\s+([\w\.\[\]]+)\s+DROP\s+COLUMN\s+([\w\[\]]+)\s*(,?)')) {
        $t = & $strip $m.Groups[1].Value; $c = & $strip $m.Groups[2].Value
        if ($m.Groups[3].Value -eq ',') { [void]$v.Add("DROP COLUMN $t.$c is a multi-column drop (not allowed unattended)"); continue }
        $before = $code.Substring(0, $m.Index)
        $g = [regex]::Match($before, "(?is)IF\s+COL_LENGTH\(\s*'([^']+)'\s*,\s*'([^']+)'\s*\)\s+IS\s+NOT\s+NULL\s*$")
        if (-not $g.Success -or (& $strip $g.Groups[1].Value) -ne $t -or (& $strip $g.Groups[2].Value) -ne $c) {
            [void]$v.Add("DROP COLUMN $t.$c is not guarded by IF COL_LENGTH('$t','$c') IS NOT NULL"); continue
        }
        $exists = $null
        if ($ColumnExists) { try { $exists = [bool](& $ColumnExists $t $c) } catch { $exists = $null } }
        [void]$drops.Add([pscustomobject]@{ table = $t; column = $c; exists = $exists })
        if ($null -eq $exists) { [void]$v.Add("DROP COLUMN $t.$c could not be checked against this store") }
        elseif ($exists) { [void]$v.Add("DROP COLUMN $t.$c would REMOVE an existing column and its data -- an unattended update never destroys data") }
    }
    [pscustomobject]@{ ok = ($v.Count -eq 0); name = $Name; violations = @($v.ToArray()); guardedDrops = @($drops.ToArray()) }
}

function Get-PimJwtPrincipal {
    <#
      PURE. The principal a bearer token was issued to: { oid; appid; tid; idtyp }. Never throws; an
      unreadable token returns empty strings. Used to NAME the identity that failed to log in to SQL --
      the token is exactly what SQL saw, so it cannot name the wrong principal.
    #>
    param([AllowEmptyString()][AllowNull()][object]$Token)
    $out = [ordered]@{ oid = ''; appid = ''; tid = ''; idtyp = '' }
    try {
        $t = "$Token"
        $parts = $t.Split('.')
        if ($parts.Count -lt 2) { return [pscustomobject]$out }
        $p = $parts[1].Replace('-', '+').Replace('_', '/')
        while ($p.Length % 4) { $p += '=' }
        $c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
        foreach ($n in @('oid', 'appid', 'tid', 'idtyp')) { if ($c.PSObject.Properties[$n]) { $out[$n] = "$($c.$n)" } }
        if (-not $out.appid -and $c.PSObject.Properties['azp']) { $out.appid = "$($c.azp)" }
    } catch { }
    [pscustomobject]$out
}

function Get-PimUpdateSchemaLoginRefusal {
    <#
      PURE. When the schema step failed because the updater's identity could not LOG IN to SQL, the
      refusal must say WHO and WHAT TO DO -- not "SCHEMA STEP FAILED: Login failed for user
      '<token-identified principal>'", which names nobody and reads like a permissions puzzle.
      Returns $null when -ErrorText is not a login failure; otherwise { message; detail; errorText }.
      The fix it names is the environment's SQL admin group: every environment's store is administered by
      a group holding its managed identities and the troubleshooting identity (framework DOCS/REQUIREMENTS
      4.5), so adding the updater's identity to that group is the one step that makes it able to verify.
    #>
    param(
        [AllowEmptyString()][string]$ErrorText,
        [AllowEmptyString()][string]$PrincipalObjectId,
        [AllowEmptyString()][string]$PrincipalAppId,
        [AllowEmptyString()][string]$SqlServer,
        [string]$GroupName = 'grp-pim-sql-admins',
        [string]$UpdateJobName = 'ca-pim-update'
    )
    $e = "$ErrorText"
    if ($e -notmatch '(?i)Login failed for user|\b18456\b|token-identified principal|not currently configured to accept this token|Cannot open server .* requested by the login') { return $null }
    $g = if ("$GroupName".Trim()) { "$GroupName".Trim() } else { 'grp-pim-sql-admins' }
    $oid = "$PrincipalObjectId".Trim()
    $who = if ($oid) { "$UpdateJobName's managed identity (object id $oid$(if ("$PrincipalAppId".Trim()) { ", app id $("$PrincipalAppId".Trim())" }))" }
           else { "$UpdateJobName's managed identity (object id not readable here -- az containerapp job show -n $UpdateJobName --query identity.principalId)" }
    $srv = if ("$SqlServer".Trim()) { "$SqlServer".Trim() } else { 'the SQL server' }
    $msg = "the updater's identity cannot log in to $srv -- schema NOT checked"
    $detail = ("$who was refused by $srv. Add it to the SQL admin group '$g' (tools/setup/Initialize-PimSqlAdminGroup.ps1, " +
               "or re-run tools/setup/Deploy-PimUpdateJob.ps1, which ensures the membership when '$g' is the server's Entra admin). NOT rolling.")
    [pscustomobject]@{
        message   = $msg
        detail    = $detail
        errorText = "updater identity $(if ($oid) { $oid } else { '<unknown>' }) cannot log in to $srv -- add it to SQL admin group '$g' (roll refused: schema not verified)"
    }
}
