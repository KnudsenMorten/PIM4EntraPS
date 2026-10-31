#Requires -Version 5.1

<#
.SYNOPSIS
    §80.2 / §100.63(b) PIMHYBRIDWRK -- run Install-PimHybridWorker.ps1 ON the worker through Azure run-command: an Azure VM
    (Microsoft.Compute/virtualMachines/runCommands) or an Azure Arc-enabled on-premises server
    (Microsoft.HybridCompute/machines/runCommands). Nothing inbound, no remote PowerShell, no portal box to paste into.

.DESCRIPTION
    Runs the hybrid worker installer on the worker machine (an Azure VM or an Azure Arc-enabled server) through Azure
    run-command, so nothing inbound is needed, or writes it as a self-contained script for the server's administrator.

    ONE helper for both hosts -- the managed run-command payload is the same shape on both:
      PUT <machine>/runCommands/<name>   { location, properties: { source: { script }, protectedParameters, timeoutInSeconds } }
      GET <machine>/runCommands/<name>?$expand=instanceView   -> executionState / exitCode / output / error
      DELETE <machine>/runCommands/<name>                      -> nothing of the run is left on the resource
    The script sent is a small wrapper that carries Install-PimHybridWorker.ps1 (base64) and its arguments, so switches and
    arrays bind exactly as on a console. A SECRET argument (-OdjBlob, the offline-join blob of the Azure VM worker) is never
    put in the script text: it travels as a protectedParameter (write-only on the resource) and the wrapper reads it from
    its own parameter. It runs as SYSTEM.

    FALLBACK: when run-command cannot be used (the PUT is refused -- an old Arc agent, the extension blocked by policy, an
    unsupported api-version) or -PrintOnly is given, the SAME wrapper is written to -OutScript and the output says so:
    the server's administrator runs it locally, elevated (powershell.exe -ExecutionPolicy Bypass -File <file>). The result
    object says which way it went: delivered = 'run-command' | 'local-script'.

    ARM REST through PIM-Rest's ONE token client (engine/_shared/PIM-ArmSetup.ps1): the calling run's REST session as it
    is; standalone, the Invardia Support app's session or the person signed in. No az, no module.

.EXAMPLE
    .\Invoke-PimHybridWorkerRunCommand.ps1 -SubscriptionId <sub> -TenantId <tenant> `
        -MachineResourceId /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.HybridCompute/machines/<server> `
        -Phase Configure -InstallParameters @{ HostType = 'Arc'; GmsaName = 'CORP\gMSA-PIM-L1-T0'; SqlServer = '<server>.database.windows.net'; TenantId = '<tenant>'; SourceContainerUrl = 'https://<store>.blob.core.windows.net/pim-src'; Ring = '2' }

.LINK
    https://invardia.com/docs/pim/scripts/Invoke-PimHybridWorkerRunCommand/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$MachineResourceId,
    [Parameter(Mandatory)][ValidateSet('Join', 'Configure', 'Update', 'Layout', 'Remove', 'Guests')][string]$Phase,
    [hashtable]$InstallParameters = @{},
    [string[]]$ProtectedParameterNames = @('OdjBlob'),
    [switch]$PrintOnly,
    [string]$OutScript = '',
    [int]$TimeoutMinutes = 45,
    [int]$PollSeconds = 15,
    [string]$ComputeApiVersion = '2024-03-01',
    [string]$ArcApiVersion = '2024-07-31-preview'
)
$ErrorActionPreference = 'Stop'

# 12.7 run frame: "<Script> version <x.y.z> - documentation: <page>" as the first line + a transcript in the temp folder.
. (Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Invoke-PimHybridWorkerRunCommand'
try {

function Step($m) { Write-Host "[run-command] $m" -ForegroundColor Cyan }
function Info($m) { Write-Host "              $m" -ForegroundColor Gray }

# ---------------------------------------------------------------------------------------------------------------- pure
function Get-PimRunCommandTarget {
    # PURE. What kind of machine is this resource id, and which api-version speaks to it?
    param([Parameter(Mandatory)][string]$ResourceId, [string]$ComputeApi = '2024-03-01', [string]$ArcApi = '2024-07-31-preview')
    $m = [regex]::Match($ResourceId.Trim(), '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/(Microsoft\.Compute/virtualMachines|Microsoft\.HybridCompute/machines)/([^/]+)$', 'IgnoreCase')
    if (-not $m.Success) { throw "not a VM or Arc machine resource id: '$ResourceId' (expected .../Microsoft.Compute/virtualMachines/<vm> or .../Microsoft.HybridCompute/machines/<server>)" }
    $arc = $m.Groups[3].Value -match '(?i)HybridCompute'
    return [pscustomobject]@{ kind = $(if ($arc) { 'arc' } else { 'vm' }); id = $ResourceId.Trim(); subscriptionId = $m.Groups[1].Value
                              resourceGroup = $m.Groups[2].Value; name = $m.Groups[4].Value; apiVersion = $(if ($arc) { $ArcApi } else { $ComputeApi }) }
}
function New-PimHybridWorkerRunScript {
    # PURE. The wrapper run-command executes: Install-PimHybridWorker.ps1 (base64, its #Requires line dropped -- a script
    # block may not carry one) + the non-secret arguments (base64 JSON); each protected name is a parameter of the wrapper.
    param([Parameter(Mandatory)][string]$InstallText, [hashtable]$Arguments = @{}, [string[]]$ProtectedNames = @())
    $plain = [ordered]@{}; $prot = @()
    foreach ($k in @($Arguments.Keys | Sort-Object)) {
        if ($ProtectedNames -contains $k) { if ("$($Arguments[$k])".Trim()) { $prot += [pscustomobject]@{ name = $k; value = "$($Arguments[$k])" } } }
        else { $plain[$k] = $Arguments[$k] }
    }
    foreach ($k in @($plain.Keys)) { if ($k -notmatch '^[A-Za-z][A-Za-z0-9]*$') { throw "invalid parameter name '$k'" } }
    $body = (($InstallText -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#Requires\b' }) -join "`n"
    $b64Install = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($body))
    $b64Args = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($plain | ConvertTo-Json -Depth 4 -Compress)))
    $pnames = @($prot | ForEach-Object { $_.name })
    $paramBlock = if ($pnames.Count) { 'param(' + ((@($pnames | ForEach-Object { "[string]`$$_ = ''" })) -join ', ') + ')' } else { 'param()' }
    $lines = @(
        '# PIM Manager hybrid worker -- Install-PimHybridWorker.ps1 wrapper (run-command or run locally, elevated)',
        $paramBlock,
        '$ErrorActionPreference = ''Stop''',
        ('$pimInstall = [ScriptBlock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''{0}'')))' -f $b64Install),
        ('$pimArgsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''{0}''))' -f $b64Args),
        '$a = @{}',
        'if ($pimArgsJson -and $pimArgsJson -ne ''{}'') { foreach ($p in ($pimArgsJson | ConvertFrom-Json).PSObject.Properties) { $a[$p.Name] = $(if ($p.Value -is [array]) { [string[]]$p.Value } else { $p.Value }) } }'
    )
    foreach ($n in $pnames) { $lines += ('if ("${0}".Trim()) {{ $a[''{0}''] = ${0} }}' -f $n) }
    $lines += '& $pimInstall @a'
    $lines += 'if (-not $?) { exit 1 }'
    return [pscustomobject]@{ script = ($lines -join "`r`n"); protectedParameters = $prot; argumentNames = @($plain.Keys) }
}
function New-PimRunCommandBody {
    # PURE. The managed run-command resource body -- identical for Microsoft.Compute and Microsoft.HybridCompute.
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$Script, [object[]]$ProtectedParameters = @(), [int]$TimeoutSeconds = 2700)
    $props = [ordered]@{ source = @{ script = $Script }; asyncExecution = $false; timeoutInSeconds = $TimeoutSeconds; treatFailureAsDeploymentFailure = $false }
    if (@($ProtectedParameters).Count) { $props.protectedParameters = @($ProtectedParameters | ForEach-Object { @{ name = $_.name; value = $_.value } }) }
    return @{ location = $Location; properties = $props }
}

# ---------------------------------------------------------------------------------------------------------------- run
$installPath = Join-Path $PSScriptRoot 'Install-PimHybridWorker.ps1'
$target = Get-PimRunCommandTarget -ResourceId $MachineResourceId -ComputeApi $ComputeApiVersion -ArcApi $ArcApiVersion
if ($target.subscriptionId -ne $SubscriptionId) { throw "the machine is in subscription $($target.subscriptionId), not -SubscriptionId $SubscriptionId -- refusing" }
$args2 = @{} + $InstallParameters; $args2['Phase'] = $Phase
if ($target.kind -eq 'arc' -and -not $args2.ContainsKey('HostType')) { $args2['HostType'] = 'Arc' }
if ($target.kind -eq 'arc' -and $Phase -eq 'Join') { throw 'an Arc server is the customer''s own, already domain-joined: there is no Join phase' }
# the installer dot-sources the 12.7 run-frame helper in the package; on the worker nothing is next to it -- inline it
$installText = [IO.File]::ReadAllText($installPath)
$sdLine = [regex]::Match($installText, "(?m)^\. \(Join-Path \`$PSScriptRoot '\.\.\\setup\\_PimScriptDoc\.ps1'\)[ \t]*\r?$")
if ($sdLine.Success) {
    $installText = $installText.Substring(0, $sdLine.Index) + [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1')) + $installText.Substring($sdLine.Index + $sdLine.Length)
}
$wrap = New-PimHybridWorkerRunScript -InstallText $installText -Arguments $args2 -ProtectedNames $ProtectedParameterNames
if (-not "$OutScript".Trim()) { $OutScript = Join-Path (Get-Location) ("pim-hybrid-worker-{0}-{1}.ps1" -f $Phase.ToLowerInvariant(), $target.name.ToLowerInvariant()) }

function Write-LocalScript([string]$Why) {
    if (@($wrap.protectedParameters).Count) {
        # the secret is NOT written into the file: the administrator passes it on the command line
        $hint = (@($wrap.protectedParameters | ForEach-Object { "-$($_.name) <value>" }) -join ' ')
    } else { $hint = '' }
    if ($PSCmdlet.ShouldProcess($OutScript, 'write the self-contained install script')) { [IO.File]::WriteAllText($OutScript, $wrap.script, (New-Object Text.UTF8Encoding($false))) }
    Write-Host ''
    Write-Host "[run-command] NOT delivered by run-command ($Why)." -ForegroundColor Yellow
    Write-Host "              The self-contained script is in: $OutScript" -ForegroundColor Yellow
    Write-Host "              On $($target.name), as a local administrator, elevated:  powershell.exe -ExecutionPolicy Bypass -File .\$(Split-Path $OutScript -Leaf) $hint" -ForegroundColor Yellow
    return [pscustomobject]@{ ok = $null; delivered = 'local-script'; kind = $target.kind; machine = $target.name; phase = $Phase; script = $OutScript; exitCode = $null; output = ''; error = $Why }
}

$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
if ($PrintOnly) { return (Write-LocalScript '-PrintOnly') }
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }

$m = Invoke-PimSetupArm -Path $target.id -ApiVersion $target.apiVersion -NotFoundOk
if (-not $m) { throw "$($target.kind) machine not found: $($target.id)" }
if ($target.kind -eq 'arc') {
    $st = "$($m.properties.status)"
    if ($st -and $st -ne 'Connected') { return (Write-LocalScript "the Arc machine reports status '$st', not Connected -- run-command needs a connected agent") }
    if ("$($m.properties.osType)" -and "$($m.properties.osType)" -notmatch '(?i)windows') { throw "the Arc machine is '$($m.properties.osType)', not Windows" }
}
$rcName = "pim-hybrid-worker-$($Phase.ToLowerInvariant())"
$rcId = "$($target.id)/runCommands/$rcName"
$body = New-PimRunCommandBody -Location "$($m.location)" -Script $wrap.script -ProtectedParameters $wrap.protectedParameters -TimeoutSeconds ($TimeoutMinutes * 60)
Step "$($target.kind) $($target.name): Install-PimHybridWorker.ps1 -Phase $Phase through run-command (as SYSTEM)"
if (-not $PSCmdlet.ShouldProcess($target.name, "run-command Install-PimHybridWorker.ps1 -Phase $Phase")) { return [pscustomobject]@{ ok = $null; delivered = 'whatif'; kind = $target.kind; machine = $target.name; phase = $Phase } }
$putErr = $null
try { [void](Invoke-PimSetupArm -Method PUT -Path $rcId -ApiVersion $target.apiVersion -Body $body) } catch { $putErr = "$($_.Exception.Message)" }
if ($putErr) { return (Write-LocalScript "the run-command PUT was refused: $putErr") }

$deadline = (Get-Date).AddMinutes($TimeoutMinutes + 5)
$iv = $null
while ($true) {
    $r = Invoke-PimSetupArm -Path "$rcId`?`$expand=instanceView&api-version=$($target.apiVersion)" -ApiVersion $target.apiVersion -NotFoundOk
    $iv = if ($r) { $r.properties.instanceView } else { $null }
    $state = "$($iv.executionState)"
    if ($state -and $state -notmatch '(?i)^(Pending|Running|Unknown)$') { break }
    if ((Get-Date) -ge $deadline) { $state = "TimedOut($state)"; break }
    if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
}
$out = "$($iv.output)"; $err = "$($iv.error)"
foreach ($l in @($out -split "`r?`n" | Where-Object { "$_".Trim() })) { Info $l }
if ($err.Trim()) { foreach ($l in @($err -split "`r?`n" | Where-Object { "$_".Trim() })) { Write-Host "              $l" -ForegroundColor Red } }
# nothing of the run stays on the resource (the protected parameter included)
try { [void](Invoke-PimSetupArm -Method DELETE -Path $rcId -ApiVersion $target.apiVersion -ErrorAsNull) } catch { }
$ok = ($state -eq 'Succeeded' -and @('', '0') -contains "$($iv.exitCode)".Trim())
Step ("{0}: {1} (exit {2})" -f $rcName, $state, "$($iv.exitCode)")
[pscustomobject]@{ ok = $ok; delivered = 'run-command'; kind = $target.kind; machine = $target.name; phase = $Phase; state = $state; exitCode = $iv.exitCode; output = $out; error = $err }

} finally { Stop-PimScriptRun -Script 'Invoke-PimHybridWorkerRunCommand' }
