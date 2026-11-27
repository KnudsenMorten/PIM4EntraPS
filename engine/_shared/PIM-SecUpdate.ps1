#Requires -Version 5.1
<#
.SYNOPSIS
    SEC-PATCH-PIPELINE-1 pt 8 (owner 2026-11-27 via Invardia: "and dont run except when needed"; "make sure to tell them to
    make sec img solution cost efficient"): what is LEFT of the separate security image job caj-pim-secupdate.

.DESCRIPTION
    ⛔ SUPERSEDED 2026-11-27 (owner via Invardia, "and dont run except when needed"): "the separate image-only job
       caj-pim-secupdate, every 15 minutes (7,22,37,52), created by the updater at every install (3.1.72 K5: absent = ON),
       its own entry tools/pim-engine/secupdate-job-entry.ps1, the plan view tools/setup/Deploy-PimSecUpdateJob.ps1 and the
       opt-out pim.Settings 'SecUpdateJob'". The job, its entry, the plan view and their tests are DELETED.
    🔒 NOW: NO separate job. A security (image-only, <build>.N) release reaches an install through the UPDATER it already has:
       its UPDATE NOW quarter cron (every 15 minutes on every ring by default, PIM-UpdateNow.ps1 Get-PimUpdateNowQuarterCron /
       Get-PimUpdateNowDefaultRings) asks Invardia POST /head (the cheap check, one call); an image-only release of the
       running build in that answer (Test-PimUpdateNowImageOnly, IMAGE-30MIN-1) runs the update IN THAT SLOT, and the
       update takes its image-only path (Get-PimImageOnlyUpdateDecision, PIM-UpdateLifecycle.ps1): no schema step, no
       quiesce / run gate, the Single + ONE active revision last step, the post-update heartbeat. No new job, no new schedule.
    🔒 caj-pim-secupdate is NEVER created. Invoke-PimSecUpdateConverge (the updater's step 2e-secupdate) REMOVES one that
       exists (none exist in the fleet; a test install may carry one from 3.1.70-3.1.72) and reads the removal back.
    Kept here because others reuse them: the Dockerfile pin helpers (the image-patch job, internal/ops/jobs).
    PS 5.1-parse-safe, no modules, no az. Tests: tests/Test-PimSecUpdate.ps1.

      Get-PimSecUpdateJobName / Get-PimSecUpdateAcaApiVersion   literals (the job the converge removes)
      Invoke-PimSecUpdateConverge       remove an existing caj-pim-secupdate, read back; NEVER creates one
      Get-PimDockerfileBasePins         the pinned digests of one FROM image in a Dockerfile text (the image-patch job's)
      Set-PimDockerfileBasePins         move those pins to one digest (text in, text out; the image-patch job's)
#>
Set-StrictMode -Off

function Get-PimSecUpdateJobName      { return 'caj-pim-secupdate' }
function Get-PimSecUpdateAcaApiVersion { return '2024-03-01' }
function Get-PimSecUpdateBaseImage {
    <# PURE. LITERAL. The ONE base PIM pins (tools/pim-manager/Dockerfile, four FROM lines since NET10-PS76). #>
    return [ordered]@{ registry = 'mcr.microsoft.com'; repository = 'dotnet/sdk'; tag = '10.0-noble'; from = 'mcr.microsoft.com/dotnet/sdk:10.0-noble' }
}

function Get-PimSecUpdateField {
    <# PURE. A member of a parsed JSON object or a dictionary, $null when absent. #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Invoke-PimSecUpdateConverge {
    <#
      2026-11-27 (SEC-PATCH-PIPELINE-1 pt 8, owner via Invardia "and dont run except when needed"): caj-pim-secupdate is
      NEVER created. When the install has one (from 3.1.70-3.1.72), it is DELETED and the delete read back (a GET that finds
      nothing). No job = one GET, nothing else. The updater's own Contributor on the install's resource group covers the
      delete (no new right). -Arm { param($method, $path, $body) } (path WITH api-version; a GET of an absent resource
      returns $null or throws). NEVER throws. @{ lines; changed; warnings; state = absent|removed|failed; writes }.
      ⛔ SUPERSEDED 2026-11-27: "create / re-write the job when enabled (3.1.72 K5: absent = ON), NOTHING when off".
      3.1.72 review R5 (2026-11-27): the GET means "no job" ONLY when it returns $null or throws a 404 / NotFound; ANY other
      error = state 'failed' + a warn line (⛔ SUPERSEDED: "a GET that throws = absent").
      3.1.72 review R6 (2026-11-27): the DELETE is long-running (202) -- the read-back is polled, bounded (-ReadBackPolls x
      -ReadBackSeconds, default 6 x 10 s, -Sleep seam), and a job whose provisioningState is Deleting counts as removed.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][scriptblock]$Arm, [int]$ReadBackPolls = 6, [int]$ReadBackSeconds = 10, [scriptblock]$Sleep)
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($level, $text) $lines.Add([pscustomobject]@{ id = 'secupdate'; level = $level; text = $text }) }
    # @{ ok; job }: ok = $false is a read that failed for another reason than "not found"
    $get = { param($p)
        try { return @{ ok = $true; job = (& $Arm 'GET' $p $null) } }
        catch {
            $m = "$($_.Exception.Message)"; $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = 0 }
            if ($code -eq 404 -or $m -match '(?i)\b404\b|ResourceNotFound|NotFound') { return @{ ok = $true; job = $null } }
            return @{ ok = $false; job = $null; error = (($m -split "`n")[0]) }
        } }
    $state = 'failed'; $writes = 0
    $jn = Get-PimSecUpdateJobName
    try {
        $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$jn`?api-version=$(Get-PimSecUpdateAcaApiVersion)"
        $g = & $get $path
        if (-not $g.ok) { $state = 'failed'; & $add 'warn' "secupdate: $jn could not be read ($($g.error)) -- nothing removed; the next run retries" }
        elseif (-not $g.job) { $state = 'absent'; & $add 'info' "secupdate: no $jn on this install (security images come through the updater's 15-minute check)" }
        else {
            try { $writes++; [void](& $Arm 'DELETE' $path $null) }
            catch { & $add 'warn' "secupdate: $jn NOT removed: $((("$($_.Exception.Message)") -split "`n")[0]) -- the next run retries"; $state = 'failed' }
            if ($writes -and -not @($lines | Where-Object { $_.level -eq 'warn' }).Count) {
                $gone = $false; $deleting = $false; $lastErr = ''
                $n = [Math]::Max(1, $ReadBackPolls)
                for ($i = 1; $i -le $n -and -not $gone; $i++) {
                    $b = & $get $path
                    if ($b.ok -and -not $b.job) { $gone = $true; break }
                    if ($b.ok -and "$($b.job.properties.provisioningState)" -match '^(?i)Deleting$') { $gone = $true; $deleting = $true; break }
                    if (-not $b.ok) { $lastErr = "$($b.error)" }
                    if ($i -lt $n) { if ($Sleep) { & $Sleep $ReadBackSeconds } else { Start-Sleep -Seconds $ReadBackSeconds } }
                }
                if ($gone) { $state = 'removed'; & $add 'changed' "secupdate: $jn removed (read back: $(if ($deleting) { 'Deleting' } else { 'gone' })) -- security images come through the updater's 15-minute check" }
                else { $state = 'failed'; & $add 'warn' "secupdate: $jn delete sent but the job still reads back after $n read(s)$(if ($lastErr) { " (last read: $lastErr)" }) -- the next run retries" }
            }
        }
    } catch { $state = 'failed'; & $add 'warn' "secupdate: converge stopped: $((("$($_.Exception.Message)") -split "`n")[0])" }
    $arr = @($lines.ToArray())
    return [pscustomobject]@{ lines = $arr; changed = @($arr | Where-Object { $_.level -eq 'changed' }).Count; warnings = @($arr | Where-Object { $_.level -eq 'warn' }).Count
                              state = $state; writes = $writes }
}

# ---------------------------------------------------------------------------------------------------------------------
# THE DOCKERFILE PINS (used by the image-patch job, internal/ops/jobs)
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimDockerfileBasePins {
    <# PURE. The distinct sha256 pins of 'FROM <From>@sha256:...' lines (default: Microsoft's sdk:10.0-noble). #>
    param([AllowEmptyString()][string]$Text, [string]$From = (Get-PimSecUpdateBaseImage).from)
    $ms = [regex]::Matches("$Text", "(?m)^FROM\s+$([regex]::Escape($From))@(sha256:[0-9a-f]{64})")
    return @($ms | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
}

function Set-PimDockerfileBasePins {
    <#
      PURE. Every 'FROM <From>@sha256:<x>' line moved to -Digest; nothing else in the text changes (line ends kept).
      @{ ok; text; old = @(<pins before>); changed; reason }. No pinned FROM line = not ok (the pin format changed: refuse,
      never build an unpinned image).
    #>
    param([AllowEmptyString()][string]$Text, [Parameter(Mandatory)][string]$Digest, [string]$From = (Get-PimSecUpdateBaseImage).from)
    $d = "$Digest".Trim().ToLowerInvariant()
    if ($d -notmatch '^sha256:[0-9a-f]{64}$') { return @{ ok = $false; text = $Text; old = @(); changed = $false; reason = "'$Digest' is not a sha256 digest" } }
    $old = @(Get-PimDockerfileBasePins -Text $Text -From $From)
    if (-not $old.Count) { return @{ ok = $false; text = $Text; old = @(); changed = $false; reason = "no pinned 'FROM $From@sha256:' line -- refusing to build an unpinned base" } }
    $rx = "(?m)^(FROM\s+$([regex]::Escape($From))@)sha256:[0-9a-f]{64}"
    $new = [regex]::Replace("$Text", $rx, ('${1}' + $d))
    return @{ ok = $true; text = $new; old = $old; changed = ($new -cne "$Text"); reason = '' }
}

# ⛔ SUPERSEDED 2026-11-27 (SEC-PATCH-PIPELINE-1 pt 8, owner via Invardia "and dont run except when needed") and DELETED with
# their tests: Get-PimSecUpdateSettingName / -StateName / -UpdaterMinute / -Cron / -EntryPath / -RetryMinutes / -Resources /
# -TimeoutSeconds / -DockerfilePath, Test-PimSecUpdateEnabled, New-PimSecUpdateSettingValue, Get-PimSecUpdateRightsNeeds,
# Test-PimSecUpdateRightsListed, Get-PimSecUpdateSignIn, Get-PimSecUpdateJobSpec, Get-PimSecUpdateJobDrift,
# Get-PimSecUpdateDecision, Test-PimSecUpdateHeld, Test-PimSecUpdateExecutionsRunning, Get-PimSecUpdatePreSwapVerdict,
# Wait-PimSecUpdateOtherIdle, New-PimSecUpdateStateRecord, Get-PimSecUpdateCostBasis (the job they served no longer exists;
# the updater's image-only path has its own: Get-PimImageOnlyUpdateDecision, Invoke-PimRevisionModeCheck).
