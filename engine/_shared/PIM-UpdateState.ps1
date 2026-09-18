#Requires -Version 5.1
<#
  Sec.71.43 -- WHICH UPDATE RING IS THIS ENVIRONMENT ON? Recorded IN the environment, in SQL.

  THE PROBLEM THIS SOLVES. The ring is an environment variable on the UPDATE JOB
  (`tools/pim-engine/update-job-entry.ps1` reads $env:PIM_UPDATE_RING; `tools/setup/Deploy-PimUpdateJob.ps1`
  writes it onto `ca-pim-update`). The MANAGER container does not carry it, so the GUI had no honest way
  to say which ring the environment is on -- an operator had to read the job's env over `az`.

  WHY NOT THE TELEMETRY RECORD. Sec.56.6 telemetry (PIM-UpdateTelemetry.ps1) already carries the ring on
  every run -- but it is written OUT of the tenant to a blob the environment CANNOT read back
  ("WRITE-ONLY FROM THE CUSTOMER'S SIDE ... It cannot list, read or delete"). It answers the VENDOR's
  fleet question, not the environment's own. So the same run also records the state HERE, in the
  environment's own store, where the Manager already reads everything else.

  WHY SQL AND NOT A FILE. PIM v2 is SQL-only: there is no settings file and no file fallback. This is one
  bounded JSON document in pim.Settings, the same shape as CutoverState / AlertFeed / FeatureGates.

  THE HONESTY RULE, and it is the whole design. An environment whose updater has never run since this
  shipped has NO record, and the answer is "not recorded yet" -- never a guessed ring, never a default.
  A ring the Manager invented would be worse than no ring at all: the operator would act on it.

  IT MUST NEVER AFFECT THE UPDATE. The writer is best-effort in exactly the way Sec.56.6's blob write is:
  it never throws, and a store that cannot be written is reported to the job log and nothing else. A
  reporting feature that could stop the fleet updating is strictly worse than no reporting.

  READ-ONLY IN THE GUI. Nothing here writes a ring. Moving an environment between rings is an operator
  act performed on the update job (Deploy-PimUpdateJob.ps1), never a click in a web page.
#>

function Get-PimUpdateStateSettingName { 'UpdateState' }

# Current record schema. Bumped only when a reader has to tell old records from new ones.
function Get-PimUpdateStateSchema { 1 }

function ConvertTo-PimUpdateStateVersion {
    <#
      PURE. The comparable [version] behind a version string, a tag or a full image reference
      ('reg.azurecr.io/pim-manager:2.4.367' -> 2.4.367; 'v2.4.367' -> 2.4.367). $null when the value is
      absent or is not a version number (a digest pin, 'latest', a branch name). NEVER throws.

      Deliberately duplicated from ConvertTo-PimUpdateVersion (PIM-UpdateSource.ps1) rather than taken
      as a dependency: this file is loaded by the MANAGER, which does not dot-source the updater's
      source-plan library, and widening a shared file so one surface can reach it is the trade this
      solution has repeatedly decided against. A dozen lines of parsing is the cheaper half.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Value)
    $s = "$Value".Trim()
    if (-not $s) { return $null }
    if ($s -match '@') { $s = ($s -split '@')[0] }
    if ($s -match '[:/]') { $s = ($s -split ':')[-1] }
    $s = $s -replace '^(?i)v', ''
    if ($s -notmatch '^\d+(\.\d+){1,3}$') { return $null }
    $v = $null
    if ([version]::TryParse($s, [ref]$v)) { return $v }
    return $null
}

function Get-PimUpdateRingLabel {
    <#
      PURE. How a ring is SPOKEN. The channel accepts '2' or 'ring2' (Get-PimRingVersion normalises
      both), so the label must too -- otherwise the same environment reads as 'ring ring2' on one
      deploy and 'ring 2' on another, and an operator comparing two environments sees a difference
      that is not there.
      An absent ring is NOT 'ring 0' and NOT 'ring -': it is 'not recorded', which is a different fact.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Ring)
    $r = "$Ring".Trim()
    if (-not $r) { return 'not recorded' }
    $r = $r -replace '^(?i)ring[\s_-]*', ''
    if (-not $r) { return 'not recorded' }
    return ('ring ' + $r)
}

function New-PimUpdateStateRecord {
    <#
      PURE. The one document an update run records in its own environment. No I/O, no clock unless
      injected -- which is what makes the shape provable offline, and the shape is the part that has to
      be right before the fleet grows.

      -Previous is the record this run is replacing, and it exists for ONE reason: lastSuccess*. A
      failing environment must still be able to say when it last succeeded, and that fact lives only in
      a record this run is about to overwrite. Carrying it forward is the difference between "this
      environment is stuck" and "this environment has never worked".
    #>
    param(
        # AllowEmptyString for the same reason Sec.56.6's builder has it: the FIRST exit path in the
        # update job fires when PIM_ResourceGroup is unset, so Environment arrives as '' -- and the
        # misconfigured environment is precisely the one whose state most needs recording.
        [Parameter(Mandatory)][AllowEmptyString()][string]$Environment,
        [AllowEmptyString()][AllowNull()][string]$Ring,
        [bool]$Hold = $false,
        [AllowEmptyString()][AllowNull()][string]$ApprovedVersion,   # what the ring approved THIS run
        [AllowEmptyString()][AllowNull()][string]$ApprovedReason,    # Get-PimRingVersion's own wording
        [AllowEmptyString()][AllowNull()][string]$RunningVersion,    # the Manager image's tag at run start
        [AllowEmptyString()][AllowNull()][string]$LastBuiltVersion,  # PIM_UPDATE_LAST_BUILT
        [AllowEmptyString()][AllowNull()][string]$TargetVersion,     # what this run tried to move to
        [ValidateSet('none','built','rolled','schema','failed')][string]$Action = 'none',
        [ValidateSet('ok','failed','skipped')][string]$Outcome = 'ok',
        [AllowEmptyString()][AllowNull()][string]$ErrorText,
        [AllowEmptyString()][AllowNull()][string]$RunId,
        [int]$DurationSeconds = 0,
        [object]$Previous,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $ts = $NowUtc.ToUniversalTime().ToString('o')
    if (-not "$RunId".Trim()) { $RunId = [guid]::NewGuid().ToString('N').Substring(0, 12) }

    # Carry the last KNOWN GOOD run forward. A run that succeeded is its own last success.
    $lastSuccessUtc = ''; $lastSuccessVersion = ''; $lastSuccessAction = ''
    if ($Previous) {
        $lastSuccessUtc     = "$(Get-PimUpdateStateField -Object $Previous -Key 'lastSuccessUtc')"
        $lastSuccessVersion = "$(Get-PimUpdateStateField -Object $Previous -Key 'lastSuccessVersion')"
        $lastSuccessAction  = "$(Get-PimUpdateStateField -Object $Previous -Key 'lastSuccessAction')"
    }
    if ($Outcome -eq 'ok') {
        $lastSuccessUtc     = $ts
        $lastSuccessVersion = "$TargetVersion".Trim()
        if (-not $lastSuccessVersion) { $lastSuccessVersion = "$RunningVersion".Trim() }
        $lastSuccessAction  = "$Action"
    }

    [ordered]@{
        schema             = (Get-PimUpdateStateSchema)
        runId              = "$RunId"
        tsUtc              = $ts
        environment        = "$Environment".Trim()
        ring               = "$Ring".Trim()
        hold               = [bool]$Hold
        approvedVersion    = "$ApprovedVersion".Trim()
        approvedReason     = "$ApprovedReason".Trim()
        runningVersion     = "$RunningVersion".Trim()
        lastBuiltVersion   = "$LastBuiltVersion".Trim()
        targetVersion      = "$TargetVersion".Trim()
        action             = "$Action"
        outcome            = "$Outcome"
        durationSec        = [int]$DurationSeconds
        # Only ever populated on a failure. An 'ok' record carrying error text is a contradiction the
        # GUI would have to guess about. Redacted through the SAME scrubber the blob record uses when
        # it is available -- error text from a failed source fetch routinely contains a SAS.
        error              = $(if ($Outcome -eq 'failed') {
                                  if (Get-Command Remove-PimTelemetrySecret -ErrorAction SilentlyContinue) {
                                      Remove-PimTelemetrySecret -Text $ErrorText
                                  } else {
                                      $t = "$ErrorText"
                                      $t = [regex]::Replace($t, '(?i)(https?://[^\s"'']+)\?[^\s"'']*', '$1?<redacted>')
                                      $t = [regex]::Replace($t, '(?i)(sig|sv|se|st|sp|skoid|sktid|password|pwd|secret|token)=[^&\s;"'']+', '$1=<redacted>')
                                      if ($t.Length -gt 900) { $t = $t.Substring(0, 900) + ' ...[truncated]' }
                                      $t
                                  }
                              } else { '' })
        lastSuccessUtc     = "$lastSuccessUtc"
        lastSuccessVersion = "$lastSuccessVersion"
        lastSuccessAction  = "$lastSuccessAction"
    }
}

function Get-PimUpdateStateField {
    <#
      One reader for both shapes. Get-PimSqlSetting hands back a PSCustomObject; an in-process caller
      may still hold the [ordered] hashtable it wrote. A reader that handles only one of them reports a
      populated record as empty, which here would read as "not recorded yet" -- the exact wrong answer.
    #>
    param([object]$Object, [Parameter(Mandatory)][string]$Key)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Key)) { return $Object[$Key] }
        foreach ($k in $Object.Keys) { if ("$k" -eq $Key) { return $Object[$k] } }
        return $null
    }
    $p = $Object.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    return $null
}

function Get-PimUpdateStateVerdict {
    <#
      PURE. Everything the GUI shows about this environment's ring, from the recorded document plus the
      version the Manager is ACTUALLY running right now.

      -RunningVersion is the Manager's OWN version (Get-PimSolutionVersion), not the record's. The
      record says what was running when the updater last ran, which can be hours or weeks stale; the
      process answering the request knows what is running NOW, with no Azure call and no guess. Using
      the stale one is how a GUI reports an environment as current after it has been rolled by hand.

      Returns a flat object the endpoint can serialise as-is:
        recorded / malformed / ring / ringLabel / hold / held / behind / failing / stale
        runningVersion / approvedVersion / lastBuiltVersion / targetVersion
        lastRunUtc / lastOutcome / lastAction / lastError / lastSuccessUtc / lastSuccessVersion
        state ('unknown'|'current'|'behind'|'held'|'failing') / headline / message / recordedAgeHours
    #>
    param(
        [object]$Record,
        [AllowEmptyString()][AllowNull()][string]$RunningVersion,
        # A nightly updater that has not reported in this long is not evidence of anything current.
        [int]$StaleAfterHours = 48,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $out = [ordered]@{
        recorded           = $false
        malformed          = $false
        ring               = ''
        ringLabel          = (Get-PimUpdateRingLabel -Ring '')
        hold               = $false
        held               = $false
        behind             = $false
        failing            = $false
        stale              = $false
        runningVersion     = "$RunningVersion".Trim()
        approvedVersion    = ''
        approvedReason     = ''
        lastBuiltVersion   = ''
        targetVersion      = ''
        lastRunUtc         = ''
        lastOutcome        = ''
        lastAction         = ''
        lastError          = ''
        lastSuccessUtc     = ''
        lastSuccessVersion = ''
        recordedAgeHours   = $null
        state              = 'unknown'
        headline           = 'ring not recorded'
        message            = ''
    }

    if ($null -eq $Record -or ("$Record".Trim() -eq '' -and -not ($Record -is [System.Collections.IDictionary]))) {
        $out.message = 'This environment has not recorded an update run yet, so its ring is not known here. ' +
                       'It is recorded by the nightly update job the first time it runs on a build that reports it.'
        return [pscustomobject]$out
    }

    # A value that is neither a dictionary nor an object with properties is a corrupt store entry.
    $isObj = ($Record -is [System.Collections.IDictionary]) -or ($Record.PSObject -and @($Record.PSObject.Properties).Count -gt 0)
    if (-not $isObj) {
        $out.malformed = $true
        $out.message   = 'The recorded update state could not be read (the stored value is not an update record). ' +
                         'The next update run overwrites it; until then the ring is not known here.'
        return [pscustomobject]$out
    }

    $ts = "$(Get-PimUpdateStateField -Object $Record -Key 'tsUtc')".Trim()
    $ring = "$(Get-PimUpdateStateField -Object $Record -Key 'ring')".Trim()
    # A record with neither a stamp nor a ring is a document that happens to be stored under this key,
    # not an update record. Saying "ring not recorded" about it is the honest answer.
    if (-not $ts -and -not $ring) {
        $out.malformed = $true
        $out.message   = 'The recorded update state is missing both its timestamp and its ring, so nothing about ' +
                         'this environment can be read from it. The next update run overwrites it.'
        return [pscustomobject]$out
    }

    $out.recorded           = $true
    $out.ring               = $ring
    $out.ringLabel          = (Get-PimUpdateRingLabel -Ring $ring)
    $out.hold               = [bool](Get-PimUpdateStateField -Object $Record -Key 'hold')
    $out.held               = $out.hold
    $out.approvedVersion    = "$(Get-PimUpdateStateField -Object $Record -Key 'approvedVersion')".Trim()
    $out.approvedReason     = "$(Get-PimUpdateStateField -Object $Record -Key 'approvedReason')".Trim()
    $out.lastBuiltVersion   = "$(Get-PimUpdateStateField -Object $Record -Key 'lastBuiltVersion')".Trim()
    $out.targetVersion      = "$(Get-PimUpdateStateField -Object $Record -Key 'targetVersion')".Trim()
    $out.lastRunUtc         = $ts
    $out.lastOutcome        = "$(Get-PimUpdateStateField -Object $Record -Key 'outcome')".Trim()
    $out.lastAction         = "$(Get-PimUpdateStateField -Object $Record -Key 'action')".Trim()
    $out.lastError          = "$(Get-PimUpdateStateField -Object $Record -Key 'error')".Trim()
    $out.lastSuccessUtc     = "$(Get-PimUpdateStateField -Object $Record -Key 'lastSuccessUtc')".Trim()
    $out.lastSuccessVersion = "$(Get-PimUpdateStateField -Object $Record -Key 'lastSuccessVersion')".Trim()
    if (-not $out.runningVersion) { $out.runningVersion = "$(Get-PimUpdateStateField -Object $Record -Key 'runningVersion')".Trim() }

    # A ring recorded as empty is a real, reportable state: the environment updates on a local pin,
    # not on a ring. It is NOT the same as "no record".
    if (-not $ring) { $out.ringLabel = 'no ring (pinned)' }

    # ---- age. Invariant-culture parse only: an ambient-culture parse turns 2026-03-04 into 3 April on
    # a de-DE host, and this value decides whether the GUI calls the record stale.
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ($ts -and [datetime]::TryParse($ts, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        $age = ($NowUtc.ToUniversalTime() - $parsed).TotalHours
        if ($age -lt 0) { $age = 0 }
        $out.recordedAgeHours = [math]::Round($age, 1)
        $out.stale = ($age -gt $StaleAfterHours)
    } else {
        # An unreadable stamp is stale by definition: we cannot say the record is recent.
        $out.stale = $true
    }

    $out.failing = ($out.lastOutcome -eq 'failed')

    # ---- behind. Only ever asserted when BOTH versions parse. "I cannot compare these" is not "behind",
    # and an environment wrongly painted amber teaches an operator to ignore the colour.
    $rv = ConvertTo-PimUpdateStateVersion -Value $out.runningVersion
    $av = ConvertTo-PimUpdateStateVersion -Value $out.approvedVersion
    if ($rv -and $av -and $rv -lt $av) { $out.behind = $true }

    # ---- one state for the colour. Precedence: failure first (something went wrong), then HOLD, then
    # behind, then current.
    # TRAP -- HOLD OUTRANKS BEHIND DELIBERATELY. A held environment is behind BECAUSE it is held; that is
    # what a hold does. Painting it amber-behind reports the consequence and hides the cause, and sends
    # an operator to investigate a state they created on purpose. `behind` stays true as its own flag,
    # so nothing is hidden; only the headline colour changes.
    if     ($out.failing) { $out.state = 'failing' }
    elseif ($out.held)    { $out.state = 'held' }
    elseif ($out.behind)  { $out.state = 'behind' }
    else                  { $out.state = 'current' }

    $out.headline = $out.ringLabel

    $bits = New-Object System.Collections.Generic.List[string]
    if ($out.held) {
        $bits.Add('This environment is HELD (PIM_UPDATE_HOLD=1): its ring is not consulted and it does not move.')
    }
    if ($out.behind) {
        $bits.Add("It runs $($out.runningVersion); $($out.ringLabel) approves $($out.approvedVersion).")
    } elseif ($out.approvedVersion -and $out.runningVersion -and $out.approvedVersion -eq $out.runningVersion) {
        $bits.Add("It runs $($out.runningVersion), which is what $($out.ringLabel) approves.")
    } elseif (-not $out.approvedVersion) {
        $bits.Add("The last update run read no approved version for $($out.ringLabel).")
    }
    if ($out.failing) {
        $bits.Add("The last update run FAILED at the '$($out.lastAction)' step.")
    }
    if ($out.stale) {
        $bits.Add('The values below are what was last RECORDED, not a live reading -- the update job has not reported recently.')
    }
    $out.message = ($bits -join ' ')

    return [pscustomobject]$out
}

function Read-PimUpdateState {
    <#
      Read the recorded document from pim.Settings. Returns $null when there is none, when there is no
      store, or when the read fails -- the CALLER decides what to say about that, and every caller here
      says "not recorded yet" rather than inventing a ring.
      NEVER throws: this sits behind a GUI panel and behind an unattended job, and neither may die
      because a settings read did.
    #>
    param([AllowEmptyString()][AllowNull()][string]$ConnectionString)
    try {
        if (-not "$ConnectionString".Trim()) { return $null }
        if (-not (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { return $null }
        $v = Get-PimSqlSetting -ConnectionString $ConnectionString -Name (Get-PimUpdateStateSettingName)
        if (-not $v) { return $null }
        if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { return $v } }   # corrupt => hand it up as-is; the verdict reports malformed
        return $v
    } catch { return $null }
}

function Save-PimUpdateState {
    <#
      Write the record. Returns @{ ok; reason }. NEVER throws, for the same reason Sec.56.6's blob write
      never throws: this runs inside the job that keeps a customer's privileged-access platform current,
      and a reporting write that could fail the run would be strictly worse than no reporting.
    #>
    param(
        [AllowEmptyString()][AllowNull()][string]$ConnectionString,
        [Parameter(Mandatory)][object]$Record,
        # Test seam: inject the writer so the fail-safe behaviour is provable offline with no SQL.
        # Signature: { param($cs, $name, $value) } -- throw to simulate a store failure.
        [scriptblock]$Writer
    )
    try {
        if (-not "$ConnectionString".Trim()) { return @{ ok = $false; reason = 'no SQL store is configured for this job' } }
        $w = $Writer
        if (-not $w) {
            if (-not (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) {
                return @{ ok = $false; reason = 'the SQL settings store is not loaded in this process' }
            }
            $w = { param($cs, $n, $v) Set-PimSqlSetting -ConnectionString $cs -Name $n -Value $v }
        }
        & $w $ConnectionString (Get-PimUpdateStateSettingName) $Record
        return @{ ok = $true; reason = 'recorded' }
    } catch {
        return @{ ok = $false; reason = "$($_.Exception.Message)" }
    }
}
