#Requires -Version 5.1
<#
.SYNOPSIS
    71.35 -- the FIRST PUBLISH: start the managing tenant's publish job (ca-pim-publish) now and WAIT for the execution to end.

.DESCRIPTION
    A managed tenant has nothing to pull until baseline-latest.json exists. The build host CANNOT read the blob to check
    (the store's firewall denies every network except the ones it names, and this host is not one of them), so the proof
    is the EXECUTION STATUS: publish-job-entry.ps1 exits 0 only after it signed through Key Vault, verified the signature
    with the managed tenants' verifier, uploaded, read baseline-latest.json back ANONYMOUSLY from the allowed subnet and
    verified it again. Succeeded therefore means "fetchable anonymously from an allowed network, and it verifies".

    A brand-new identity's Key Vault / storage role assignments can take minutes to reach the data plane, so a Failed
    execution is retried (Get-PimBaselinePublishExecutionVerdict) before the step fails. The final execution's console log
    is printed when it can be read from the environment's Log Analytics workspace (best effort; it is diagnostics, never
    the verdict).

    100.41 (framework 12.17 NO-AZ): ARM / Log Analytics REST through PIM-Rest's ONE token client
    (engine/_shared/PIM-ArmSetup.ps1). A calling build's REST session is used as it is; standalone, the Invardia Support
    app's session or the person signed in. No az.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$JobName = 'ca-pim-publish',
    [ValidateRange(1, 10)][int]$MaxAttempts = 4,
    [ValidateRange(1, 60)][int]$ExecutionTimeoutMinutes = 20,
    # (71.33: no -UseSignedInAccount -- the REST identity the build established is used in either identity mode.)
    [ValidateRange(0, 600)][int]$RetryDelaySeconds = 180
)
$ErrorActionPreference = 'Stop'
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
. (Join-Path $solRoot 'engine\msp\PIM-BaselinePublish.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$S = "$SubscriptionId".Trim()
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $S) }

for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    Step "start $JobName (attempt $attempt of $MaxAttempts)"
    # was: az containerapp job start --query name
    $exec = "$(Start-PimArmAcaJob -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $JobName)".Trim()
    if (-not $exec) { throw "could not start '$JobName' in $ResourceGroup -- deploy it first (Deploy-PimBaselinePublishJob.ps1).$(if ($global:PimSetupRestLastError) { " ($($global:PimSetupRestLastError))" })" }
    Note "execution $exec -- waiting (timeout $ExecutionTimeoutMinutes min)"
    $status = ''
    $deadline = (Get-Date).AddMinutes($ExecutionTimeoutMinutes)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 15
        # was: az containerapp job execution show --query properties.status
        $status = "$((Get-PimArmAcaJobExecution -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $JobName -Execution $exec).properties.status)".Trim()
        if ($status -in @('Succeeded', 'Failed', 'Degraded', 'Stopped')) { break }
    }
    # The execution's console lines from the environment's Log Analytics workspace (diagnostics only; @() when unreadable).
    $logs = @(Get-PimArmAcaJobLogs -SubscriptionId $S -ResourceGroup $ResourceGroup -Name $JobName -Execution $exec -Tail 200 | Where-Object { "$_".Trim() })
    if ($logs.Count) { $logs | Where-Object { "$_" -match '\[publish-job\]' } | Select-Object -Last 12 | ForEach-Object { Note "  $_" } }
    else { Note "  (console log not available from here yet: ContainerAppConsoleLogs_CL in the environment's Log Analytics workspace, execution $exec -- it arrives a few minutes after the run)" }
    # The job gates itself on the cadence set in the Manager (PIM-JobCadence.ps1): a Succeeded execution may have SKIPPED.
    # The deploy step just before this one stamps the job, so its first execution publishes; the log says which it was.
    $v = Get-PimBaselinePublishExecutionVerdict -Status $status -Attempt $attempt -MaxAttempts $MaxAttempts -LogText (@($logs) -join "`n")
    Note $v.reason
    if ($v.action -eq 'done' -and -not $logs.Count) { Note '  (without the log this host cannot tell a publish from a cadence skip -- a skip happens only after an earlier publish SUCCEEDED, or when publishing is disabled in the Manager''s Job schedule)' }
    if ($v.action -eq 'done') {
        Write-Host "==> FIRST PUBLISH OK ($exec): baseline-latest.json is signed, uploaded, and was read back anonymously from the allowed subnet and verified." -ForegroundColor Green
        exit 0
    }
    if ($v.action -eq 'fail') { throw "FIRST PUBLISH FAILED ($exec): $($v.reason). Read the execution log above; fix; re-run -From publish." }
    Note "waiting ${RetryDelaySeconds}s before the next attempt"
    Start-Sleep -Seconds $RetryDelaySeconds
}
throw "FIRST PUBLISH FAILED after $MaxAttempts attempts."
