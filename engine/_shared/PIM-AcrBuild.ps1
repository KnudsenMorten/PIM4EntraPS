#Requires -Version 5.1
<#
.SYNOPSIS
    Build a container image IN a registry, over plain ARM REST -- no `az` CLI, no Docker,
    no build host. §55.

.DESCRIPTION
    🔑 THE FACT THIS IS BUILT ON: `az acr build` NEVER BUILDS ANYTHING LOCALLY. It tars the source,
    uploads it, and asks the REGISTRY to build. Build-PimManagerImage.ps1 has always worked this
    way (`git archive` -> `az acr build`). So the CLI is a convenience over four HTTPS calls, and a
    container with a managed identity can make those four calls itself:

        1. POST   .../registries/<acr>/listBuildSourceUploadUrl   -> { uploadUrl; relativePath }
        2. PUT    <uploadUrl>                                     -> the .tar.gz build context
        3. POST   .../registries/<acr>/scheduleRun                -> a DockerBuildRequest
        4. GET    .../registries/<acr>/runs/<runId>               -> poll to a terminal status

    That is what closes DEPLOY-3: an environment with no VM can produce its own image, in its own
    registry, from source it fetched -- so nothing has to distribute IMAGES between tenants, and no
    cross-tenant registry credential has to exist at all.

    🪤 STEP 2 IS NOT AN ARM CALL. The upload URL is a blob SAS on a storage account owned by the
    ACR task service. It takes NO bearer token (the SAS is the credential) and it DOES require
    `x-ms-blob-type: BlockBlob`. Sending an ARM token to it, or omitting the blob-type header,
    fails in ways that read like an authentication problem and are not.

.NOTES
    PS 5.1-safe. Depends on Invoke-PimArm (PIM-Rest.ps1) for the three ARM calls; step 2 is a plain
    web request precisely because it must NOT carry the ARM token.
#>

# The ACR *tasks* surface is a different API version from the registry resource itself.
# listBuildSourceUploadUrl / scheduleRun / runs live under the preview tasks API and have been
# stable there for years; pinned rather than floated, for the same reason PIM-ArmContainerApps
# pins its own.
$script:PimAcrTasksApi = '2019-06-01-preview'   # kept for readers; every call uses Get-PimAcrTasksApi
# 2026-10-21 (trial install 11a17b54, HTTP 400 MissingApiVersionParameter): Install-PimManager loads this file at ITS scope,
# so the deploy's child script Build-PimManagerImage skipped loading it (the functions already existed) and $script:PimAcrTasksApi
# was EMPTY in that script's scope -- $script: is the CALLER's script scope, not this file's. A literal in a function is the
# same in every scope.
function Get-PimAcrTasksApi { return '2019-06-01-preview' }

function Get-PimAcrRegistryPath {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$RegistryName
    )
    "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.ContainerRegistry/registries/$RegistryName"
}

function Get-PimAcrBuildUploadSlot {
    <#
      Ask the registry where to put a build context. Returns @{ uploadUrl; relativePath }.
      `relativePath` -- NOT the URL -- is what the build request refers to afterwards.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$RegistryName
    )
    $p = (Get-PimAcrRegistryPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName) + '/listBuildSourceUploadUrl'
    $r = Invoke-PimArm -Method POST -Path $p -ApiVersion (Get-PimAcrTasksApi)
    if (-not $r -or -not "$($r.uploadUrl)".Trim()) {
        throw "Get-PimAcrBuildUploadSlot: registry '$RegistryName' returned no upload URL."
    }
    @{ uploadUrl = "$($r.uploadUrl)"; relativePath = "$($r.relativePath)" }
}

function Send-PimAcrBuildContext {
    <#
      PUT the .tar.gz to the SAS URL from Get-PimAcrBuildUploadSlot.

      🔴 NO BEARER TOKEN, AND `x-ms-blob-type: BlockBlob` IS MANDATORY. The SAS in the URL is the
      whole credential; attaching the ARM token makes the request ambiguous, and omitting the
      blob-type header makes blob storage reject a PUT it would otherwise accept. Both failures
      surface as 40x from a storage host, which reads like "my identity is wrong" and is not.
    #>
    param(
        [Parameter(Mandatory)][string]$UploadUrl,
        [Parameter(Mandatory)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) { throw "Send-PimAcrBuildContext: '$Path' not found." }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $null = Invoke-WebRequest -Method PUT -Uri $UploadUrl -Body $bytes -UseBasicParsing `
                -Headers @{ 'x-ms-blob-type' = 'BlockBlob' } -ContentType 'application/octet-stream'
    $bytes.Length
}

function Start-PimAcrDockerBuild {
    <#
      Schedule the build. Returns the run object (its .runId is what Wait-PimAcrRun polls).

      -ImageNames are TAGS RELATIVE TO THE REGISTRY ("pim-manager:2.4.307"), not full references:
      the registry is already the one being asked, and prefixing its login server produces an image
      called <acr>.azurecr.io/<acr>.azurecr.io/... which fails only at push time, minutes in.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$RegistryName,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string[]]$ImageNames,
        [string]$DockerFilePath = 'SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile',
        [int]$TimeoutSeconds = 3600,
        [hashtable]$Arguments = @{},
        # 🔴 A registry with public access Disabled refuses ACR's SHARED build agents ("client with IP ... is
        # not allowed access") -- only a dedicated agent pool inside the VNet can build into it. Measured on a
        # customer 2026-09-23: every nightly build failed after 11 s, so a private-registry environment could
        # never update itself. Empty = the shared agents (a public registry needs nothing).
        [string]$AgentPoolName
    )
    $args2 = @()
    foreach ($k in $Arguments.Keys) {
        $args2 += @{ name = "$k"; value = "$($Arguments[$k])"; isSecret = $false }
    }
    $body = @{
        type            = 'DockerBuildRequest'
        isPushEnabled   = $true
        # 🪤 noCache=$false is deliberate. A rebuild of the SAME version must be able to reuse
        # layers -- that is what makes a nightly run that changes nothing cheap rather than a full
        # image build every night in every tenant.
        noCache         = $false
        dockerFilePath  = $DockerFilePath
        imageNames      = @($ImageNames)
        sourceLocation  = $RelativePath
        platform        = @{ os = 'Linux'; architecture = 'amd64' }
        timeout         = $TimeoutSeconds
    }
    if ($args2.Count) { $body['arguments'] = $args2 }
    if ("$AgentPoolName".Trim()) { $body['agentPoolName'] = "$AgentPoolName".Trim() }

    $p = (Get-PimAcrRegistryPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName) + '/scheduleRun'
    $run = Invoke-PimArm -Method POST -Path $p -Body $body -ApiVersion (Get-PimAcrTasksApi)
    if (-not $run -or -not "$($run.properties.runId)$($run.runId)".Trim()) {
        throw "Start-PimAcrDockerBuild: registry '$RegistryName' accepted no run for $($ImageNames -join ', ')."
    }
    $run
}

function Get-PimAcrRunId {
    # The scheduleRun response has been seen with runId at the root and under .properties
    # depending on API version. Read both rather than depend on one shape.
    param([object]$Run)
    $id = "$($Run.runId)".Trim()
    if (-not $id) { $id = "$($Run.properties.runId)".Trim() }
    $id
}

function Wait-PimAcrRun {
    <#
      Poll a run to a terminal status. Returns @{ ok; status; runId; seconds }.

      🔴 'Queued' AND 'Started' AND 'Running' ARE ALL "STILL GOING". Treating anything that is not
      'Succeeded' as failure would call a build failed one second after scheduling it -- the same
      shape as the Container Apps health check that had to learn RunningAtMaxScale is healthy.
      Only the four terminal states end the wait.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$RegistryName,
        [Parameter(Mandatory)][string]$RunId,
        [int]$TimeoutSeconds = 1800,
        [int]$PollSeconds = 10,
        [scriptblock]$OnPoll
    )
    $base = (Get-PimAcrRegistryPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName) + "/runs/$RunId"
    $started  = Get-Date
    $deadline = $started.AddSeconds($TimeoutSeconds)
    $terminal = @('Succeeded','Failed','Canceled','Error','Timeout')
    $status   = 'Unknown'
    $runError = ''
    while ((Get-Date) -lt $deadline) {
        $r = $null
        try { $r = Invoke-PimArm -Method GET -Path $base -ApiVersion (Get-PimAcrTasksApi) } catch { }
        if ($r) {
            $s = "$($r.properties.status)".Trim()
            if (-not $s) { $s = "$($r.status)".Trim() }
            if ($s) { $status = $s }
            # UPDATER-ACR-PUSH-RETRY: the run's own error line ("failed to push ...") -- the first thing that says WHY.
            $e = "$($r.properties.runErrorMessage)".Trim()
            if (-not $e) { $e = "$($r.runErrorMessage)".Trim() }
            if ($e) { $runError = $e }
        }
        if ($OnPoll) { try { & $OnPoll $status } catch { } }
        if ($terminal -contains $status) { break }
        Start-Sleep -Seconds $PollSeconds
    }
    $secs = [int]((Get-Date) - $started).TotalSeconds
    @{ ok = ($status -eq 'Succeeded'); status = $status; runId = $RunId; seconds = $secs; error = $runError }
}

function Invoke-PimAcrRestBuild {
    <#
      The whole thing: upload a context, schedule a build, wait for it.
      Returns @{ ok; status; runId; seconds; bytes; images }.

      Idempotent from the caller's point of view -- building a tag that already exists simply
      replaces it with an identical image; the caller decides whether it is worth doing at all.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$RegistryName,
        [Parameter(Mandatory)][string]$ContextPath,          # a .tar.gz, repo-root shaped
        [Parameter(Mandatory)][string[]]$ImageNames,
        [string]$DockerFilePath = 'SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile',
        [int]$TimeoutSeconds = 1800,
        [hashtable]$Arguments = @{},
        [scriptblock]$OnPoll,
        [string]$AgentPoolName    # see Start-PimAcrDockerBuild: required for a registry with public access Disabled
    )
    $slot  = Get-PimAcrBuildUploadSlot -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName
    $bytes = Send-PimAcrBuildContext -UploadUrl $slot.uploadUrl -Path $ContextPath
    $run   = Start-PimAcrDockerBuild -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup `
                -RegistryName $RegistryName -RelativePath $slot.relativePath -ImageNames $ImageNames `
                -DockerFilePath $DockerFilePath -TimeoutSeconds $TimeoutSeconds -Arguments $Arguments -AgentPoolName $AgentPoolName
    $runId = Get-PimAcrRunId -Run $run
    if (-not $runId) { throw "Invoke-PimAcrRestBuild: no run id came back for $($ImageNames -join ', ')." }
    $w = Wait-PimAcrRun -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup `
            -RegistryName $RegistryName -RunId $runId -TimeoutSeconds $TimeoutSeconds -OnPoll $OnPoll
    @{ ok = $w.ok; status = $w.status; runId = $runId; seconds = $w.seconds; bytes = $bytes; images = @($ImageNames); error = "$($w.error)" }
}

# ---------------------------------------------------------------------------------------------------------------------
# UPDATER-ACR-PUSH-RETRY (owner 2026-10-23 "Build + ring 0/1"; measured on a customer install, SUP-2026-00290): the 2.4.670
# build SUCCEEDED, and the PUSH to the install's own registry failed 3 times with "dial tcp <ip>:443: connect: connection
# refused" -- a registry-side fault. The updater only knew "build Failed after 95s", filed it UNCLASSIFIED, and the install
# stayed behind until a person retried. Now the failed run's error line and log are read, a push that failed on the network
# or a 5xx is retried ONCE after a short wait, and a second failure goes up as its own transient code (pim-upd-0103).
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimAcrRunLogTail {
    <#
      The last -MaxChars of a run's log, or '' when it cannot be read (never throws: the log only explains a failure).
      POST .../runs/<id>/listLogSasUrl -> { logLink }; the link is a blob SAS -- a plain GET with NO bearer token, the same
      rule as the build context upload (Send-PimAcrBuildContext).
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$RegistryName,
        [Parameter(Mandatory)][string]$RunId,
        [int]$MaxChars = 4000
    )
    try {
        $p = (Get-PimAcrRegistryPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName) + "/runs/$RunId/listLogSasUrl"
        $l = Invoke-PimArm -Method POST -Path $p -ApiVersion (Get-PimAcrTasksApi)
        $link = "$($l.logLink)".Trim()
        if (-not $link) { return '' }
        $resp = Invoke-WebRequest -Method GET -Uri $link -UseBasicParsing -TimeoutSec 60
        $txt = "$($resp.Content)"
        if ($txt.Length -gt $MaxChars) { $txt = $txt.Substring($txt.Length - $MaxChars) }
        return $txt
    } catch { return '' }
}

function Test-PimAcrPushTransient {
    <#
      PURE. Did a failed run fail on PUSHING to the registry, for a reason that goes away by itself? @{ transient; reason }.
      Transient = the text is about the push AND names a network fault or a server-side 5xx / 429. NOT transient: anything
      about access (unauthorized / denied / forbidden / "is not allowed access" -- a firewall or a role, which a retry never
      fixes), and every failure that is not about the push (a Dockerfile step, a timeout of the whole run).
    #>
    param([AllowEmptyString()][string]$Text)
    $t = "$Text"
    if (-not $t.Trim()) { return @{ transient = $false; reason = '' } }
    if ($t -notmatch '(?i)\bpush(ing|ed)?\b') { return @{ transient = $false; reason = '' } }
    if ($t -match '(?i)\bunauthori[sz]ed\b|\bdenied\b|\bforbidden\b|is not allowed access|authentication required') { return @{ transient = $false; reason = '' } }
    $faults = [ordered]@{
        'connection refused'   = '(?i)connection refused'
        'connection reset'     = '(?i)connection reset'
        'timeout'              = '(?i)i/o timeout|TLS handshake timeout|context deadline exceeded|\btimed out\b'
        'unexpected EOF'       = '(?i)unexpected EOF'
        'registry unreachable' = '(?i)no such host|network is unreachable'
        'registry 5xx'         = '(?i)\b50[0234]\b|Service Unavailable|Bad Gateway|Gateway Timeout|Internal Server Error'
        'registry busy (429)'  = '(?i)\b429\b|too many requests'
    }
    foreach ($k in $faults.Keys) { if ($t -match $faults[$k]) { return @{ transient = $true; reason = $k } } }
    return @{ transient = $false; reason = '' }
}

function Invoke-PimAcrRestBuildWithRetry {
    <#
      Invoke-PimAcrRestBuild, and ONCE more after -RetryDelaySeconds when the first run failed on a transient push fault
      (Test-PimAcrPushTransient over the run's error line + log tail). The retry is a whole new build (upload + run): the
      layer cache makes it cheap, and the failed run's image never reached the registry.
      Returns Invoke-PimAcrRestBuild's result plus: attempts; pushFault ('' | the fault, e.g. 'connection refused'); firstRunId;
      detail (the error line, else the last log line that names the fault -- for the report).
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$RegistryName,
        [Parameter(Mandatory)][string]$ContextPath,
        [Parameter(Mandatory)][string[]]$ImageNames,
        [string]$DockerFilePath = 'SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile',
        [int]$TimeoutSeconds = 1800,
        [hashtable]$Arguments = @{},
        [scriptblock]$OnPoll,
        [string]$AgentPoolName,
        [int]$RetryDelaySeconds = 60,
        [scriptblock]$OnRetry
    )
    $bp = @{ SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; RegistryName = $RegistryName; ContextPath = $ContextPath
             ImageNames = $ImageNames; DockerFilePath = $DockerFilePath; TimeoutSeconds = $TimeoutSeconds; Arguments = $Arguments
             OnPoll = $OnPoll; AgentPoolName = $AgentPoolName }
    $first = $null
    $fault = ''; $detail = ''
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $b = Invoke-PimAcrRestBuild @bp
        if (-not $first) { $first = $b }
        if ($b.ok) { break }
        # Why did it fail? The error line first; the log only when the line does not say (it is a second ARM call + a download).
        $why = "$($b.error)"
        $tr = Test-PimAcrPushTransient -Text $why
        if (-not $tr.transient) {
            $log = Get-PimAcrRunLogTail -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName -RunId "$($b.runId)"
            if ($log) { $tr = Test-PimAcrPushTransient -Text ($why + "`n" + $log) }
            if ($tr.transient -and -not $why.Trim()) {
                $hit = @("$log" -split "`r?`n" | Where-Object { $_ -match '(?i)push' -and (Test-PimAcrPushTransient -Text $_).transient } | Select-Object -Last 1)
                if ($hit.Count) { $why = "$($hit[0])".Trim() }
            }
        }
        $fault = if ($tr.transient) { "$($tr.reason)" } else { '' }
        $detail = $why
        if (-not $tr.transient -or $attempt -ge 2) { break }
        if ($OnRetry) { try { & $OnRetry $b $tr.reason } catch { } }
        if ($RetryDelaySeconds -gt 0) { Start-Sleep -Seconds $RetryDelaySeconds }
    }
    $b['attempts']   = $attempt
    $b['pushFault']  = $(if ($b.ok) { '' } else { $fault })
    $b['firstRunId'] = "$($first.runId)"
    $b['detail']     = $(if ($b.ok) { '' } else { $detail })
    $b
}

function Split-PimImageReference {
    <#
      Pull a container image reference apart, so an environment can be self-configuring: the
      Manager's CURRENT image already names the registry and repository this environment uses, so
      nothing has to be told them. Same reasoning as inheriting the registry identity from the
      Manager in Deploy-PimUpdateJob.

        acrx.azurecr.io/pim-manager:2.4.307       -> registry acrx  repo pim-manager  tag 2.4.307
        acrx.azurecr.io/pim-manager@sha256:ab..   -> registry acrx  repo pim-manager  tag (none)

      🪤 The tag split is anchored past the LAST '/', because a registry may carry a port.
      Returns $null when the reference names no registry host at all (a bare docker.io image).
    #>
    param([string]$Image)
    $s = "$Image".Trim()
    if (-not $s) { return $null }
    $digest = ''
    $at = $s.IndexOf('@')
    if ($at -ge 0) { $digest = $s.Substring($at + 1); $s = $s.Substring(0, $at) }
    $tag = ''
    $slash = $s.LastIndexOf('/')
    $colon = $s.LastIndexOf(':')
    if ($colon -gt $slash) { $tag = $s.Substring($colon + 1); $s = $s.Substring(0, $colon) }
    if ($slash -lt 0) { return $null }
    $host2 = $s.Substring(0, $s.IndexOf('/'))
    $repo  = $s.Substring($s.IndexOf('/') + 1)
    if (-not $host2 -or -not $repo) { return $null }
    $regName = $host2
    if ($regName -match '^(?<n>[^.:]+)\.azurecr\.io$') { $regName = $Matches['n'] }
    @{ loginServer = $host2; registryName = $regName; repository = $repo; tag = $tag; digest = $digest }
}
