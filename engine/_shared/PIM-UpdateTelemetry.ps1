#Requires -Version 5.1
<#
  §56.6 -- UPDATE TELEMETRY. One record per update run, written OUT of the customer environment.

  🔑 IT EXISTS TO ANSWER TWO QUESTIONS, and they are different queries with different shapes:
      * "is THIS customer stuck?"          -> per-environment state + when it last SUCCEEDED.
      * "is build 2.4.310 failing everywhere?" -> the VERSION must be ON the record, and enough
                                              environments must report for a pattern to be visible.
  🔴 THE SECOND ONE CANNOT BE BACKFILLED. Telemetry added at customer 80 says nothing about the
  first 79, and the whole value of "is this build failing everywhere" is that it answers on the
  night of the release rather than a week later. That is why this ships before the fleet grows.

  🔒 WRITE-ONLY FROM THE CUSTOMER'S SIDE. The environment is given a URL that can only ADD a blob.
  It cannot list, read or delete -- so one customer's credential cannot enumerate the fleet, and a
  leaked one cannot destroy the history. Same shape as the source archive's read-only link (§55),
  inverted.

  🔴 AND IT MUST NEVER AFFECT THE UPDATE. This runs inside an unattended job that keeps a customer's
  privileged-access platform current. Telemetry that can fail, hang or throw would trade a real
  capability for a reporting one -- so every failure here is swallowed, reported to the job log, and
  returns $false. An update that succeeded must never be recorded as failed, or refused, because a
  blob write did not land.

  📌 NO SECRETS ON THE RECORD. The source URL carries a SAS, and error text from a failed fetch
  routinely contains it. Everything written here is either a version, a status, a duration, or an
  error string that has been through Remove-PimTelemetrySecret first.
#>

function Remove-PimTelemetrySecret {
    <#
      Strip anything credential-shaped from free text before it leaves the tenant.
      🪤 The realistic leak is not a password in a message -- it is a URL. A failed source fetch
      reports the URL it tried, and that URL carries `sig=`, which is the credential itself. This
      record is written to a place the vendor can read, so a SAS on it is a credential disclosed
      across a tenant boundary. Redact the QUERY STRING, keep the path: which blob 404'd is the
      useful half, and it is not secret.
    #>
    param([string]$Text)
    $t = "$Text"
    if (-not $t) { return '' }
    $t = [regex]::Replace($t, '(?i)(https?://[^\s"'']+)\?[^\s"'']*', '$1?<redacted>')
    $t = [regex]::Replace($t, '(?i)(sig|sv|se|st|sp|skoid|sktid|password|pwd|secret|token)=[^&\s;"'']+', '$1=<redacted>')
    if ($t.Length -gt 900) { $t = $t.Substring(0, 900) + ' ...[truncated]' }
    return $t
}

function New-PimUpdateTelemetryRecord {
    <#
      PURE. Build the one record an update run reports. No I/O, no clock unless injected -- which is
      what makes the shape testable, and the shape is the part that has to be right BEFORE the fleet
      grows (a field missing here is a field missing from all the history).

      -Action is what the run actually DID: none | built | rolled | schema | failed. It is passed in
      rather than inferred from the outcome, because "succeeded and had nothing to do" and
      "succeeded and rolled two containers" are the same outcome and very different facts -- and
      telling them apart is most of "is this customer stuck".
    #>
    param(
        # 🪤 AllowEmptyString, and it matters on exactly the run you most want reported: the FIRST
        # exit path fires when PIM_ResourceGroup is unset, so Environment arrives as '' -- and a
        # Mandatory [string] REJECTS '', throwing inside the telemetry helper's try/catch and
        # silently dropping the record for a misconfigured environment. That environment is
        # precisely the one nobody would otherwise notice: it never reports, and "never reported"
        # and "not configured for telemetry" look identical from the fleet view.
        # The blob-name builder already resolves a blank environment to 'unknown'.
        [Parameter(Mandatory)][AllowEmptyString()][string]$Environment,
        [string]$Ring,
        [string]$FromVersion,
        [string]$ToVersion,
        [ValidateSet('none','built','rolled','schema','failed')][string]$Action = 'none',
        [ValidateSet('ok','failed','skipped')][string]$Outcome = 'ok',
        [int]$DurationSeconds = 0,
        [string]$ErrorText,
        [string]$RunId,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    if (-not "$RunId".Trim()) { $RunId = [guid]::NewGuid().ToString('N').Substring(0, 12) }
    [ordered]@{
        schema      = 1                       # so a later reader can tell old records from new ones
        runId       = "$RunId"
        tsUtc       = $NowUtc.ToUniversalTime().ToString('o')
        environment = "$Environment".Trim()
        ring        = "$Ring".Trim()
        fromVersion = "$FromVersion".Trim()
        toVersion   = "$ToVersion".Trim()
        action      = "$Action"
        outcome     = "$Outcome"
        durationSec = [int]$DurationSeconds
        # 🔒 Only ever populated on a failure, and always redacted. An 'ok' record carrying error
        # text would be a contradiction the fleet view has to guess about.
        error       = $(if ($Outcome -eq 'failed') { Remove-PimTelemetrySecret -Text $ErrorText } else { '' })
    }
}

function Get-PimUpdateTelemetryBlobName {
    <#
      The blob NAME answers "is this customer stuck?" from a LISTING ALONE -- no downloads.
      environment first (so one customer's history is one prefix), then a sortable UTC stamp, then
      the outcome. Listing a prefix and reading the last name tells you when that environment last
      succeeded, which is the operational question, without fetching a single record.
      🪤 Lower-cased and sanitised: blob names are case-sensitive and an environment name with a
      space or a slash would silently create a different prefix -- i.e. a customer that appears to
      have stopped reporting.
    #>
    param(
        # AllowEmptyString for the same reason as the record builder: the misconfigured environment
        # is the one that most needs reporting, and it is the one whose name is blank. It is
        # resolved to 'unknown' below rather than refused.
        [Parameter(Mandatory)][AllowEmptyString()][string]$Environment,
        [Parameter(Mandatory)][object]$Record
    )
    # 🪤 NOT named $env -- that is the environment-variable drive, and shadowing it inside a function
    # that later code may extend is a trap for whoever edits this next.
    $envName = ("$Environment".Trim().ToLowerInvariant() -replace '[^a-z0-9._-]', '-').Trim('-')
    if (-not $envName) { $envName = 'unknown' }
    # 🪤 NOT [datetime]::Parse -- that reads the AMBIENT CULTURE, so on a de-DE host '2026-03-04'
    # becomes 3 April rather than 4 March. This string is the blob's SORT KEY: a stamp parsed in the
    # wrong culture silently files the record under the wrong minute, and "when did this environment
    # last succeed" is answered from exactly that ordering. Caught by Test-PimDateSafe's sweep for
    # bare ambient-culture parses in shipped source -- a gate that already existed, doing its job.
    $tsUtc = if (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue) {
                 Get-PimUtcStamp $Record.tsUtc
             } else {
                 # Same invariant-first ladder, inline, for a host that has not loaded PIM-DateSafe.
                 $d = [datetime]::MinValue
                 $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
                 if ([datetime]::TryParse("$($Record.tsUtc)", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { $d } else { $null }
             }
    if ($null -eq $tsUtc) { $tsUtc = [datetime]::UtcNow }   # an unreadable stamp must not lose the record
    $ts = $tsUtc.ToUniversalTime().ToString('yyyyMMddTHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture)
    "$envName/$ts-$($Record.outcome)-$($Record.runId).json"
}

function Get-PimUpdateTelemetryUri {
    <#
      Compose the destination from a container SAS template. Accepts either an explicit {name}
      placeholder or a plain container URL, in which case the blob name is appended before the
      query string.
      🪤 THE QUERY STRING IS THE CREDENTIAL -- it must survive composition intact. This is the same
      trap that truncated a source URL at its first '&' and left a customer a release behind (B9).
    #>
    # 🪤 AllowEmptyString: an UNSET PIM_TELEMETRY_URL arrives here as '', and a Mandatory [string]
    # REJECTS '' with a binding error. Send-PimUpdateTelemetry guards before calling, so this could
    # not bite in the shipped path -- but a helper that throws on "telemetry is switched off" is a
    # trap for the next caller, in a module whose entire contract is that it never throws.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$UrlTemplate,
          [Parameter(Mandatory)][AllowEmptyString()][string]$BlobName)
    $t = "$UrlTemplate".Trim()
    if (-not $t) { return '' }
    if ($t -match '\{name\}') { return ($t -replace '\{name\}', $BlobName) }
    $q = ''; $qi = $t.IndexOf('?')
    if ($qi -ge 0) { $q = $t.Substring($qi); $t = $t.Substring(0, $qi) }
    return ($t.TrimEnd('/') + '/' + $BlobName + $q)
}

function Send-PimUpdateTelemetry {
    <#
      Write ONE record. Best-effort by design: returns $true when it landed, $false otherwise, and
      NEVER throws.

      🔴 THE FAIL-SAFE DIRECTION IS THE WHOLE POINT. This runs inside the job that keeps a
      customer's privileged-access platform current. If telemetry could fail the run, a reporting
      feature would be able to stop updates across the fleet -- which is strictly worse than having
      no telemetry at all. So: a short timeout, one retry, everything caught, and the update
      continues regardless of what happened here.

      Off unless configured: with no PIM_TELEMETRY_URL this is a silent no-op, so an environment
      that has not been given an endpoint neither reports nor complains.
    #>
    param(
        [Parameter(Mandatory)][object]$Record,
        [string]$UrlTemplate = "$($env:PIM_TELEMETRY_URL)",
        [scriptblock]$Log,
        # Test seam: inject the transport so the retry/fail-safe behaviour is provable offline
        # without a network. Signature: { param($uri, $body) } -- throw to simulate a failure.
        [scriptblock]$Sender
    )
    $say = { param($m) if ($Log) { & $Log $m } }
    try {
        if (-not "$UrlTemplate".Trim()) { return $false }   # not configured => silently off
        $name = Get-PimUpdateTelemetryBlobName -Environment "$($Record.environment)" -Record $Record
        $uri  = Get-PimUpdateTelemetryUri -UrlTemplate $UrlTemplate -BlobName $name
        if (-not "$uri".Trim()) { return $false }
        $body = $Record | ConvertTo-Json -Depth 6 -Compress

        $send = $Sender
        if (-not $send) {
            $send = {
                param($u, $b)
                # x-ms-blob-type is what makes this a block-blob PUT; without it storage 400s.
                Invoke-WebRequest -Method PUT -Uri $u -Body $b -TimeoutSec 20 -UseBasicParsing `
                    -ContentType 'application/json' `
                    -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } | Out-Null
            }
        }
        foreach ($attempt in 1, 2) {
            try { & $send $uri $body; & $say "telemetry: reported $($Record.outcome) ($name)"; return $true }
            catch {
                if ($attempt -eq 2) {
                    # 🔑 SAY IT, but only as a note. A silent failure here means the fleet view
                    # quietly loses an environment and nobody knows the reporting stopped -- the
                    # same degrade-without-telling-anyone shape this codebase keeps removing.
                    & $say "telemetry: NOT reported (the update itself is unaffected): $(Remove-PimTelemetrySecret -Text $_.Exception.Message)"
                    return $false
                }
                Start-Sleep -Seconds 2
            }
        }
        return $false
    } catch {
        try { & $say "telemetry: skipped (the update itself is unaffected): $(Remove-PimTelemetrySecret -Text $_.Exception.Message)" } catch { }
        return $false
    }
}
