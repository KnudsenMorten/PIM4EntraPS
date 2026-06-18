<#
  PIM4EntraPS -- sync-automateit core (controlled container/VM auto-update).

  The PURE, fully-testable decision core behind the container/VM auto-update path
  (REQUIREMENTS.md sec.1 Hosting/Runtime + sec.2 Containers).
  No az calls, no HTTP, no PowerShell modules here -- this file only DECIDES. The thin
  STANDALONE orchestrators (tools/setup/Invoke-PimSyncAutomateIT.ps1 roll-only, and
  tools/setup/Invoke-PimUpdate.ps1 full lifecycle) feed it the facts (current deployed
  tag, latest released tag, health verdict) and ACT on the plan it returns. That split
  keeps the risky bits (only update when a NEWER pinned version exists, roll safely, roll
  back on a failed post-update health check) unit-testable offline.

  SEPARATION (operator correction 2026-06-18): the update is run by VisualCron / Task
  Scheduler / the bootstrap post-sync deploy hook -- NOT by the PIM engine or the
  in-container job scheduler. (The former scheduler 'sync-automateit' job + handler that
  shelled this orchestrator was removed; this core is now consumed only by the standalone
  update entries.)

  PS 5.1-safe: no ?./??/RSA.ImportFromPem; Set-StrictMode -Off; only built-in cmdlets.

  Public functions:
    * ConvertTo-PimSemVer            -- parse "1.2.3"/"v1.2.3"/"1.2.3-rc1" -> comparable object
    * Compare-PimSemVer              -- -1/0/1 (pre-release < release; numeric, not string, compare)
    * Test-PimSyncUpdateNeeded       -- is Latest strictly newer than Current? (with pin gate)
    * Get-PimSyncDecision            -- the whole decision: update? which tag? rollback target?
    * Test-PimSyncHealthVerdict      -- turn a smoke result into pass/fail (rollback trigger)
    * Get-PimSyncRollbackPlan        -- on a failed health check, the revision to reactivate
#>

Set-StrictMode -Off

# ---- semantic-version parse + compare (numeric, pre-release aware) ---------
function ConvertTo-PimSemVer {
    <#
      Parse a tag into { major; minor; patch; pre; raw; valid }. Accepts an optional
      leading 'v' and an optional '-pre' suffix (e.g. '2.4.218', 'v1.1.7', '2.5.0-rc1').
      Missing minor/patch default to 0 so '2'/'2.4' still compare. Anything unparseable
      returns valid=$false so callers can refuse to act on a garbage tag (NEVER update to
      a tag we can't reason about).
    #>
    param([string]$Tag)
    $raw = "$Tag".Trim()
    $invalid = [pscustomobject]@{ major=0; minor=0; patch=0; pre=''; raw=$raw; valid=$false }
    if (-not $raw) { return $invalid }
    $s = $raw
    if ($s -match '^[vV]') { $s = $s.Substring(1) }
    $pre = ''
    $dash = $s.IndexOf('-')
    if ($dash -ge 0) { $pre = $s.Substring($dash + 1); $s = $s.Substring(0, $dash) }
    # strip build metadata (+...) -- ignored for ordering
    $plus = $s.IndexOf('+'); if ($plus -ge 0) { $s = $s.Substring(0, $plus) }
    $parts = $s -split '\.'
    if ($parts.Count -lt 1 -or "$($parts[0])".Trim() -eq '') { return $invalid }
    $nums = @(0,0,0)
    for ($i = 0; $i -lt 3 -and $i -lt $parts.Count; $i++) {
        $n = 0
        if (-not [int]::TryParse("$($parts[$i])", [ref]$n)) { return $invalid }
        if ($n -lt 0) { return $invalid }
        $nums[$i] = $n
    }
    return [pscustomobject]@{ major=$nums[0]; minor=$nums[1]; patch=$nums[2]; pre=$pre; raw=$raw; valid=$true }
}

function Compare-PimSemVer {
    <#
      Returns -1 (A<B), 0 (A==B), 1 (A>B). Numeric component compare (so 2.4.218 > 2.4.99,
      which a plain string compare gets WRONG). A release outranks a pre-release of the same
      x.y.z (2.5.0 > 2.5.0-rc1). Invalid versions sort LOWEST (so we never treat an
      unparseable 'latest' as newer than a valid current).
    #>
    param([Parameter(Mandatory)][object]$A, [Parameter(Mandatory)][object]$B)
    if (-not $A.valid -and -not $B.valid) { return 0 }
    if (-not $A.valid) { return -1 }
    if (-not $B.valid) { return 1 }
    foreach ($f in 'major','minor','patch') {
        if ([int]$A.$f -lt [int]$B.$f) { return -1 }
        if ([int]$A.$f -gt [int]$B.$f) { return 1 }
    }
    # same x.y.z -- release (no pre) beats pre-release.
    $ap = "$($A.pre)"; $bp = "$($B.pre)"
    if ($ap -eq '' -and $bp -ne '') { return 1 }
    if ($ap -ne '' -and $bp -eq '') { return -1 }
    if ($ap -eq $bp) { return 0 }
    # both pre-release: ordinal compare of the pre tag (best-effort, deterministic).
    return [string]::CompareOrdinal($ap, $bp)
}

# ---- "should we update?" --------------------------------------------------
function Test-PimSyncUpdateNeeded {
    <#
      Core gate (REQUIREMENTS sec.6: "only update when a newer pinned version exists").
      Update is needed ONLY when Latest is a VALID semver STRICTLY newer than Current.
      Equal, older, or unparseable Latest => no update (safe default).
        -PinnedTag : optional hard pin. If set, we only ever move TO this exact tag, and
                     only if it is newer than Current -- a controlled, explicit roll, never
                     an open "always take whatever ACR calls latest".
    #>
    param(
        [Parameter(Mandatory)][string]$CurrentTag,
        [Parameter(Mandatory)][string]$LatestTag,
        [string]$PinnedTag
    )
    $cur = ConvertTo-PimSemVer -Tag $CurrentTag
    $target = if ("$PinnedTag".Trim()) { ConvertTo-PimSemVer -Tag $PinnedTag } else { ConvertTo-PimSemVer -Tag $LatestTag }
    if (-not $target.valid) { return $false }
    return ((Compare-PimSemVer -A $target -B $cur) -gt 0)
}

function Get-PimSyncDecision {
    <#
      The full controlled-sync decision, returned as a plan object the orchestrator acts on
      (and the tests assert). Inputs are FACTS gathered by the orchestrator (current deployed
      tag, the newest released tag in ACR, an optional pin, a gate switch). It performs NO
      side effects.

      Returns:
        action      : 'update' | 'noop' | 'blocked'
        targetTag   : the tag to roll to (when action='update')
        currentTag  : echoed
        reason      : human string for the log
        gated       : $true when -RequireGate was set but -GateOpen was not (controlled/scheduled)
    #>
    param(
        [Parameter(Mandatory)][string]$CurrentTag,
        [string]$LatestTag,
        [string]$PinnedTag,
        [switch]$RequireGate,      # controlled mode: do nothing unless the gate is explicitly open
        [switch]$GateOpen          # the gate (schedule window / -Apply flag) is open
    )
    $target = if ("$PinnedTag".Trim()) { "$PinnedTag".Trim() } else { "$LatestTag".Trim() }
    $needed = Test-PimSyncUpdateNeeded -CurrentTag $CurrentTag -LatestTag $LatestTag -PinnedTag $PinnedTag
    if (-not $needed) {
        return [pscustomobject]@{ action='noop'; targetTag=$CurrentTag; currentTag=$CurrentTag;
            reason="up to date (current=$CurrentTag, candidate=$target)"; gated=$false }
    }
    if ($RequireGate -and -not $GateOpen) {
        return [pscustomobject]@{ action='blocked'; targetTag=$target; currentTag=$CurrentTag;
            reason="newer version $target available but gate is closed (run with -Apply / inside the schedule window)"; gated=$true }
    }
    return [pscustomobject]@{ action='update'; targetTag=$target; currentTag=$CurrentTag;
        reason="newer version available: $CurrentTag -> $target"; gated=$false }
}

# ---- post-update health verdict + rollback plan ---------------------------
function Test-PimSyncHealthVerdict {
    <#
      Turn a post-update health/smoke result into a boolean pass. We reuse the hosted smoke
      (tests/live/Test-PimManagerHostedSmoke.ps1) which prints "RESULT: N pass, M fail, K skip"
      and exits non-zero on a real failure. This accepts EITHER:
        -ExitCode  : the smoke's process exit code (0 = healthy / cleanly-skipped), or
        -FailCount : the parsed fail count.
      Healthy = exit 0 AND fail count == 0.
    #>
    param([int]$ExitCode = 0, [int]$FailCount = 0)
    return (($ExitCode -eq 0) -and ($FailCount -le 0))
}

function Get-PimSyncRollbackPlan {
    <#
      On a FAILED post-update health check, decide the rollback target. We roll back to the
      revision that was live BEFORE the update (captured by the orchestrator pre-update). This
      reuses Update-PimContainers.ps1 -Rollback <revision> (instant revision reactivate).
        action : 'rollback' | 'none'
    #>
    param([Parameter(Mandatory)][bool]$Healthy, [string]$PreviousRevision)
    if ($Healthy) { return [pscustomobject]@{ action='none'; revision=''; reason='health check passed -- keep the new revision' } }
    if (-not "$PreviousRevision".Trim()) {
        return [pscustomobject]@{ action='none'; revision=''; reason='health check FAILED but no previous revision captured -- manual rollback required' }
    }
    return [pscustomobject]@{ action='rollback'; revision="$PreviousRevision".Trim(); reason="health check FAILED -- roll back to $PreviousRevision" }
}
