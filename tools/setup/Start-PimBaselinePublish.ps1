#Requires -Version 5.1
<#
.SYNOPSIS
    71.35 -- the FIRST PUBLISH: start the master's publish job (ca-pim-publish) now and WAIT for the execution to end.

.DESCRIPTION
    A managed tenant has nothing to pull until baseline-latest.json exists. The build host CANNOT read the blob to check
    (the store's firewall denies every network except the ones it names, and this host is not one of them), so the proof
    is the EXECUTION STATUS: publish-job-entry.ps1 exits 0 only after it signed through Key Vault, verified the signature
    with the managed tenants' verifier, uploaded, read baseline-latest.json back ANONYMOUSLY from the allowed subnet and
    verified it again. Succeeded therefore means "fetchable anonymously from an allowed network, and it verifies".

    A brand-new identity's Key Vault / storage role assignments can take minutes to reach the data plane, so a Failed
    execution is retried (Get-PimBaselinePublishExecutionVerdict) before the step fails. The final execution's console log
    is printed when az can fetch it (best effort; it is diagnostics, never the verdict).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$JobName = 'ca-pim-publish',
    [ValidateRange(1, 10)][int]$MaxAttempts = 4,
    [ValidateRange(1, 60)][int]$ExecutionTimeoutMinutes = 20,
    # (71.33: no -UseSignedInAccount -- the az context the build established is used in either identity mode.)
    [ValidateRange(0, 600)][int]$RetryDelaySeconds = 180
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $PSScriptRoot '_PimAz.ps1')         # the guarded az shadow (an az WARNING on stderr must not abort)
. (Join-Path $solRoot 'engine\_shared\PIM-BaselinePublish.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$sub = @('--subscription', $SubscriptionId)

for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    Step "start $JobName (attempt $attempt of $MaxAttempts)"
    $exec = "$(az containerapp job start @sub -g $ResourceGroup -n $JobName --query name -o tsv 2>$null)".Trim()
    if (-not $exec) { throw "could not start '$JobName' in $ResourceGroup -- deploy it first (Deploy-PimBaselinePublishJob.ps1)." }
    Note "execution $exec -- waiting (timeout $ExecutionTimeoutMinutes min)"
    $status = ''
    $deadline = (Get-Date).AddMinutes($ExecutionTimeoutMinutes)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 15
        $status = "$(az containerapp job execution show @sub -g $ResourceGroup -n $JobName --job-execution-name $exec --query properties.status -o tsv 2>$null)".Trim()
        if ($status -in @('Succeeded', 'Failed', 'Degraded', 'Stopped')) { break }
    }
    $v = Get-PimBaselinePublishExecutionVerdict -Status $status -Attempt $attempt -MaxAttempts $MaxAttempts
    Note $v.reason
    $ErrorActionPreference = 'Continue'
    $logs = @(az containerapp job logs show @sub -g $ResourceGroup -n $JobName --execution $exec --container $JobName --format text 2>$null)
    $ErrorActionPreference = 'Stop'
    if ($logs.Count) { $logs | Where-Object { "$_" -match '\[publish-job\]' } | Select-Object -Last 12 | ForEach-Object { Note "  $_" } }
    else { Note "  (console log not available from here yet: az containerapp job logs show -g $ResourceGroup -n $JobName --execution $exec $($sub -join ' '))" }
    if ($v.action -eq 'done') {
        Write-Host "==> FIRST PUBLISH OK ($exec): baseline-latest.json is signed, uploaded, and was read back anonymously from the allowed subnet and verified." -ForegroundColor Green
        exit 0
    }
    if ($v.action -eq 'fail') { throw "FIRST PUBLISH FAILED ($exec): $($v.reason). Read the execution log above; fix; re-run -From publish." }
    Note "waiting ${RetryDelaySeconds}s before the next attempt"
    Start-Sleep -Seconds $RetryDelaySeconds
}
throw "FIRST PUBLISH FAILED after $MaxAttempts attempts."
