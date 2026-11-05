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

# ---------------------------------------------------------------------------------------------------------------------
# BUILDPOOL-11G (framework rule 11g, owner 2026-11-05): a private install's registry build pool is tier S2 with 0 instances
# between builds. A build on it scales the pool to 2 instances first (read back), builds, and sets it back to 0 in a finally
# -- after a failed build too -- and reads the 0 back. A build on the pool is waited for at least 90 minutes; the run's own
# task timeout is above that wait. A pool of another tier is made again at S2 (the tier cannot be changed in place), only
# while no run is queued or running on the registry. A registry with no pool (a public install) makes none of these calls.
# Every ARM call here goes through an injected -Arm { param($Method, $Path, $Body, $ApiVersion) } (default: Invoke-PimArm,
# a 404 on a GET = $null), so each rule is provable offline.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimAcrBuildPoolPolicy {
    # A literal in a function: the same in every scope (see Get-PimAcrTasksApi).
    return @{
        Tier                  = 'S2'
        IdleCount             = 0
        BuildCount            = 2
        MinWaitSeconds        = 5400      # 90 minutes: the least a build on the pool is waited for
        TaskTimeoutSeconds    = 6000      # 100 minutes: the run's own timeout, above the wait
        MaxTaskTimeoutSeconds = 28800     # ACR's largest task timeout
        ApiVersion            = '2019-06-01-preview'
        ScaleWaitSeconds      = 1200      # a count change is waited for up to 20 minutes
        # BUILDPOOL-11G-RECREATE (2026-11-05): a pool DELETE took ~14 minutes live. The delete gets its own, longer wait;
        # one that is still going at the end is not lost -- the recreate intent is in the store and the next run makes it.
        DeleteWaitSeconds     = 1800      # a delete is waited for up to 30 minutes
        CreateWaitSeconds     = 1800      # a create is waited for up to 30 minutes (as the installer does)
        # Azure REFUSES to create a pool with count 0 (400 AgentPoolInvalidCount, "bigger than or equal to 1"); a PATCH of
        # an existing pool to 0 is accepted. So a pool is CREATED with 1 instance and then set to 0 (read back).
        CreateCount           = 1
        CostNote              = 'S2 x 2 is billed for every hour it runs'
    }
}

function Get-PimAcrBuildPoolTimeouts {
    <# PURE. @{ wait; task } for a build: on a pool the wait is at least 90 minutes and the task timeout above it. #>
    param([int]$TimeoutSeconds = 1800, [bool]$OnPool = $false)
    if (-not $OnPool) { return @{ wait = $TimeoutSeconds; task = $TimeoutSeconds } }
    $pol  = Get-PimAcrBuildPoolPolicy
    $wait = [Math]::Max($TimeoutSeconds, $pol.MinWaitSeconds)
    $task = [Math]::Min($pol.MaxTaskTimeoutSeconds, [Math]::Max($pol.TaskTimeoutSeconds, $wait + 600))
    if ($wait -ge $task) { $wait = $task - 600 }
    return @{ wait = $wait; task = $task }
}

function Get-PimAcrPoolArm {
    <# The default -Arm: Invoke-PimArm, a 404 on a GET read as $null (the pool / registry is not there). #>
    return {
        param([string]$Method, [string]$Path, $Body, [string]$ApiVersion)
        try {
            if ($null -ne $Body) { Invoke-PimArm -Method $Method -Path $Path -Body $Body -ApiVersion $ApiVersion }
            else { Invoke-PimArm -Method $Method -Path $Path -ApiVersion $ApiVersion }
        } catch {
            if ($Method -eq 'GET' -and "$($_.Exception.Message)" -match '(?i)\b404\b|NotFound|ResourceNotFound') { return $null }
            throw
        }
    }
}

function Get-PimAcrAgentPoolPath {
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$RegistryName, [Parameter(Mandatory)][string]$PoolName)
    (Get-PimAcrRegistryPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName) + "/agentPools/$PoolName"
}

function ConvertTo-PimAcrPoolCount {
    # the pool's properties.count, or $null -- read as a NAMED member: PowerShell's own .Count is 1 on any object without one
    param($Pool)
    if ($null -eq $Pool -or $null -eq $Pool.properties) { return $null }
    $pr = $Pool.properties; $v = $null
    if ($pr -is [System.Collections.IDictionary]) { if ($pr.Contains('count')) { $v = $pr['count'] } }
    else { $m = $pr.PSObject.Properties['count']; if ($m) { $v = $m.Value } }
    if ($null -eq $v) { return $null }
    $n = 0; if ([int]::TryParse("$v", [ref]$n)) { return $n }
    return $null
}

function Set-PimAcrBuildPoolCount {
    <#
      PATCH the pool's instance count, wait until it reads back Succeeded with that count. NEVER throws (it runs in a
      finally, where a throw would hide the build's own result): @{ ok; count; state; tier; reason }.
    #>
    param([Parameter(Mandatory)][string]$PoolPath, [Parameter(Mandatory)][int]$Count, [int]$PollSeconds = 10,
          [int]$WaitSeconds = -1, [scriptblock]$Arm)
    if (-not $Arm) { $Arm = Get-PimAcrPoolArm }
    $pol = Get-PimAcrBuildPoolPolicy
    if ($WaitSeconds -lt 0) { $WaitSeconds = $pol.ScaleWaitSeconds }
    $p = $null
    try {
        [void](& $Arm 'PATCH' $PoolPath @{ properties = @{ count = $Count } } $pol.ApiVersion)
        $max = [Math]::Max(1, [int]($WaitSeconds / [Math]::Max(1, $PollSeconds)))
        $p = & $Arm 'GET' $PoolPath $null $pol.ApiVersion
        for ($i = 0; $i -lt $max; $i++) {
            $st = "$($p.properties.provisioningState)"
            if ($st -in 'Failed', 'Canceled') { break }
            if ($st -eq 'Succeeded' -and (ConvertTo-PimAcrPoolCount $p) -eq $Count) { break }
            if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
            $p = & $Arm 'GET' $PoolPath $null $pol.ApiVersion
        }
        $st = "$($p.properties.provisioningState)"; $c = ConvertTo-PimAcrPoolCount $p
        if (-not $p) { return @{ ok = $false; count = $null; state = ''; tier = ''; reason = 'the pool could not be read back' } }
        if ($st -eq 'Succeeded' -and $c -eq $Count) { return @{ ok = $true; count = $c; state = $st; tier = "$($p.properties.tier)"; reason = '' } }
        return @{ ok = $false; count = $c; state = $st; tier = "$($p.properties.tier)"; reason = "the pool reads back '$st' with $c instance(s), not $Count" }
    } catch {
        return @{ ok = $false; count = (ConvertTo-PimAcrPoolCount $p); state = "$($p.properties.provisioningState)"; tier = "$($p.properties.tier)"; reason = "$($_.Exception.Message)" }
    }
}

function Get-PimAcrBuildPoolDownWarning {
    <# PURE. The one WARN line when the pool could not be set back to 0: it names the pool and the cost. #>
    param([string]$PoolName, [string]$Reason)
    $pol = Get-PimAcrBuildPoolPolicy
    "WARN the build pool '$PoolName' could NOT be set back to $($pol.IdleCount) instances ($Reason) -- $($pol.CostNote); set its count to $($pol.IdleCount). The build's own result stands."
}

function Get-PimAcrActiveRuns {
    <#
      The registry's runs that are Queued, Started or Running: @{ ok; active; reason }. ok = $false when the list could
      not be read -- a caller treats that as "a build may be running" (never acts on doubt).
    #>
    param([Parameter(Mandatory)][string]$RegistryPath, [scriptblock]$Arm)
    if (-not $Arm) { $Arm = Get-PimAcrPoolArm }
    $pol = Get-PimAcrBuildPoolPolicy
    $f = [uri]::EscapeDataString("status eq 'Queued' or status eq 'Started' or status eq 'Running'")
    $r = $null
    try { $r = & $Arm 'GET' "$RegistryPath/runs?`$filter=$f&`$top=50" $null $pol.ApiVersion }
    catch { return @{ ok = $false; active = @(); reason = "$($_.Exception.Message)" } }
    if ($null -eq $r) { return @{ ok = $false; active = @(); reason = 'the registry runs could not be read' } }
    # the status is checked here too: a filter the service ignored never turns a finished run into a running one
    $act = @(@($r.value) | Where-Object { $_ -and "$($_.properties.status)" -in 'Queued', 'Started', 'Running' })
    return @{ ok = $true; active = $act; reason = '' }
}

function New-PimAcrBuildPoolState {
    <# PURE. The heartbeat's BuildPool { tier; count; building; checkedUtc } from a pool read and the run check. #>
    param($Pool, [bool]$Building, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Pool) { return $null }
    $c = ConvertTo-PimAcrPoolCount $Pool
    [ordered]@{ tier = "$($Pool.properties.tier)"; count = $(if ($null -eq $c) { 0 } else { [int]$c }); building = [bool]$Building
                checkedUtc = $NowUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") }
}

function Invoke-PimAcrBuildPoolScope {
    <#
      Runs -Build with the pool up: scale to 2 (read back), & $Build, then -- in a finally, whatever happened -- scale back
      to 0 and read it back. A pool that does not come up stops before the build (status 'PoolNotReady'; a build queued on
      a pool with no instance would only time out). A pool that does not go back down is ONE warning line; the build's
      result (or its exception) is what the caller gets. The result carries poolUp / poolDown.
    #>
    param([Parameter(Mandatory)][string]$PoolPath, [Parameter(Mandatory)][string]$PoolName, [Parameter(Mandatory)][scriptblock]$Build,
          [int]$PollSeconds = 10, [scriptblock]$Arm)
    if (-not $Arm) { $Arm = Get-PimAcrPoolArm }
    $pol = Get-PimAcrBuildPoolPolicy
    $up = $null; $down = $null; $res = $null
    try {
        $up = Set-PimAcrBuildPoolCount -PoolPath $PoolPath -Count $pol.BuildCount -PollSeconds $PollSeconds -Arm $Arm
        if (-not $up.ok) {
            $why = "the build pool '$PoolName' did not reach $($pol.BuildCount) instances: $($up.reason)"
            $res = @{ ok = $false; status = 'PoolNotReady'; runId = ''; seconds = 0; bytes = 0; images = @(); error = $why
                      attempts = 0; pushFault = ''; firstRunId = ''; detail = $why }
        } else { $res = & $Build }
    } finally {
        $down = Set-PimAcrBuildPoolCount -PoolPath $PoolPath -Count $pol.IdleCount -PollSeconds $PollSeconds -Arm $Arm
        if (-not $down.ok) { Write-Warning (Get-PimAcrBuildPoolDownWarning -PoolName $PoolName -Reason $down.reason) }
    }
    if ($res -is [System.Collections.IDictionary]) { $res['poolUp'] = $up; $res['poolDown'] = $down }
    $res
}

function New-PimAcrBuildPoolIdle {
    <#
      CREATE a build pool and leave it at its idle count. Azure refuses a create with count 0 (400 AgentPoolInvalidCount),
      so the PUT carries max(CreateCount, -Count) instances, waits for Succeeded, and -- when -Count is below that --
      PATCHes the pool down to -Count (Set-PimAcrBuildPoolCount, read back). Then tier, count and subnet are read back.
      NEVER throws: @{ ok; stage; pool; body; reason }. stage on a failure:
        'put'       the PUT (or the read after it) failed            -- no pool, or not known
        'provision' the pool did not reach Succeeded                 -- the pool is not usable
        'scale'     the pool is up with CreateCount instance(s) and the set back to -Count failed -- it is BILLED
        'readback'  the pool reads back other than asked             -- tier / count / subnet differ
    #>
    param([Parameter(Mandatory)][string]$PoolPath, [Parameter(Mandatory)][string]$Location, [string]$Tier = '', [int]$Count = -1,
          [string]$Os = 'Linux', [string]$SubnetId = '', $Tags = $null, [int]$PollSeconds = 10, [int]$WaitSeconds = -1, [scriptblock]$Arm)
    if (-not $Arm) { $Arm = Get-PimAcrPoolArm }
    $pol = Get-PimAcrBuildPoolPolicy; $api = $pol.ApiVersion
    if (-not "$Tier".Trim()) { $Tier = $pol.Tier }
    if ($Count -lt 0) { $Count = $pol.IdleCount }
    if ($WaitSeconds -lt 0) { $WaitSeconds = $pol.CreateWaitSeconds }
    if (-not "$Os".Trim()) { $Os = 'Linux' }
    $SubnetId = "$SubnetId".Trim()
    $createCount = [Math]::Max([int]$pol.CreateCount, $Count)
    $props = [ordered]@{ tier = $Tier; count = $createCount; os = $Os }
    if ($SubnetId) { $props['virtualNetworkSubnetResourceId'] = $SubnetId }
    $body = [ordered]@{ location = $Location; properties = $props }
    if ($null -ne $Tags) { $body['tags'] = $Tags }
    $made = $null
    try {
        try { [void](& $Arm 'PUT' $PoolPath $body $api) }
        catch {
            if ("$($_.Exception.Message)" -match '(?i)\b400\b|BadRequest|Invalid') { throw }   # a refusal is not retried
            [void](& $Arm 'PUT' $PoolPath $body $api)                                           # one more try on a transient fault
        }
        $max = [Math]::Max(1, [int]($WaitSeconds / [Math]::Max(1, $PollSeconds)))
        $made = & $Arm 'GET' $PoolPath $null $api
        for ($i = 0; $i -lt $max -and "$($made.properties.provisioningState)" -notin 'Succeeded', 'Failed', 'Canceled'; $i++) {
            if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
            $made = & $Arm 'GET' $PoolPath $null $api
        }
    } catch {
        return @{ ok = $false; stage = 'put'; pool = $made; body = $body; reason = "the create was refused or failed ($($_.Exception.Message))" }
    }
    if (-not $made) { return @{ ok = $false; stage = 'put'; pool = $null; body = $body; reason = 'the pool does not read back after the create' } }
    if ("$($made.properties.provisioningState)" -ne 'Succeeded') {
        return @{ ok = $false; stage = 'provision'; pool = $made; body = $body; reason = "the pool reads back '$($made.properties.provisioningState)', not Succeeded" }
    }
    if ($Count -ne $createCount) {
        $d = Set-PimAcrBuildPoolCount -PoolPath $PoolPath -Count $Count -PollSeconds $PollSeconds -Arm $Arm
        if (-not $d.ok) { return @{ ok = $false; stage = 'scale'; pool = $made; body = $body; reason = "$($d.reason)" } }
        $after = $null; try { $after = & $Arm 'GET' $PoolPath $null $api } catch { $after = $null }
        if ($after) { $made = $after }
    }
    $okBack = "$($made.properties.provisioningState)" -eq 'Succeeded' -and "$($made.properties.tier)" -eq $Tier -and
              (ConvertTo-PimAcrPoolCount $made) -eq $Count -and "$($made.properties.virtualNetworkSubnetResourceId)".Trim() -eq $SubnetId
    if (-not $okBack) {
        return @{ ok = $false; stage = 'readback'; pool = $made; body = $body
                  reason = "it reads back '$($made.properties.provisioningState)', $($made.properties.tier) x $(ConvertTo-PimAcrPoolCount $made) -- not $Tier x $Count in the same subnet" }
    }
    return @{ ok = $true; stage = ''; pool = $made; body = $body; reason = '' }
}

function Get-PimAcrBuildPoolScaleUpLine {
    <# PURE. The line when a pool was made but could not be set back to 0: it is UP, it is billed, the next run sets it to 0. #>
    param([string]$PoolName, [string]$Reason)
    $pol = Get-PimAcrBuildPoolPolicy
    "build pool '$PoolName': made at $($pol.Tier) but it is UP with $($pol.CreateCount) instance(s) -- the set back to $($pol.IdleCount) failed ($Reason); it is billed while it runs, and the next update run sets it to $($pol.IdleCount)"
}

function Invoke-PimAcrBuildPoolConverge {
    <#
      The updater's (and a re-run install's) check of an EXISTING pool. Returns @{ ok; action; line; state } where state is
      New-PimAcrBuildPoolState of the pool as last read ($null when it could not be read).
        tier not S2, nothing queued/running  -> deleted and made again at S2, count 0, same location / os / subnet / tags,
                                                read back                                         action 'recreated'
        tier not S2, a run queued/running, or the run list unreadable -> nothing changed       action 'refused-building'
        S2 with instances, nothing running   -> set back to 0, read back (a pool left up)        action 'scaled-down'
        S2 with instances while a run is on  -> left alone                                       action 'in-use'
        S2 at 0                              -> nothing                                          action 'ok'
        no pool, no recreate intent          -> nothing (the install makes it)                  action 'missing'
        no pool, a recreate intent for it    -> made from the intent (count 1, then 0), read back,
                                                the intent cleared                              action 'recreated'
        a pool that is Deleting              -> nothing written (not scaled, not deleted again)  action 'deleting'
      BUILDPOOL-11G-RECREATE (2026-11-05): a pool this converge DELETES is never left un-made. Before the DELETE the
      recreate intent (the pool path, the PUT body at S2 x 0 with the same location / os / subnet / tags, the time) is
      saved through -SaveIntent; a delete still running at the end of the wait keeps it, and the next run -- which finds
      the pool missing -- makes it from that intent. The seam is three scriptblocks (the updater: pim.Settings
      'BuildPoolRecreate'): -SaveIntent { param($intent) }, -ReadIntent { <intent or $null> }, -ClearIntent { }.
      No -SaveIntent = no intent is kept (the behaviour before); a -SaveIntent that fails = NOTHING is deleted.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$RegistryName, [Parameter(Mandatory)][string]$PoolName,
          [int]$PollSeconds = 10, [scriptblock]$Arm, [datetime]$NowUtc = [datetime]::UtcNow,
          [scriptblock]$SaveIntent, [scriptblock]$ReadIntent, [scriptblock]$ClearIntent, [int]$DeleteWaitSeconds = -1)
    if (-not $Arm) { $Arm = Get-PimAcrPoolArm }
    $pol = Get-PimAcrBuildPoolPolicy; $api = $pol.ApiVersion
    if ($DeleteWaitSeconds -lt 0) { $DeleteWaitSeconds = $pol.DeleteWaitSeconds }
    $regPath  = Get-PimAcrRegistryPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName
    $poolPath = "$regPath/agentPools/$PoolName"
    $pool = $null
    try { $pool = & $Arm 'GET' $poolPath $null $api }
    catch { return @{ ok = $false; action = 'unreadable'; state = $null; line = "build pool '$PoolName': not read ($($_.Exception.Message)) -- nothing changed" } }
    # the recreate intent for THIS pool, if the store has one (an intent for another pool path is not ours to act on)
    $intent = $null; $intentWhy = ''
    if ($ReadIntent) {
        try {
            $ri = & $ReadIntent
            if ($null -ne $ri -and "$($ri.poolPath)".Trim() -and "$($ri.poolPath)".Trim() -eq $poolPath -and $null -ne $ri.body) { $intent = $ri }
        } catch { $intentWhy = "$($_.Exception.Message)" }
    }
    if (-not $pool) {
        if (-not $intent) {
            return @{ ok = $false; action = 'missing'; state = $null
                      line = "build pool '$PoolName': not found in registry $RegistryName -- a private registry builds only on it; run the install again to make it$(if ($intentWhy) { " (the recreate record could not be read: $intentWhy)" })" }
        }
        $ib = $intent.body; $ip = $ib.properties
        $mk = New-PimAcrBuildPoolIdle -PoolPath $poolPath -Location "$($ib.location)" -Tier $pol.Tier -Count $pol.IdleCount -Os "$($ip.os)" `
                  -SubnetId "$($ip.virtualNetworkSubnetResourceId)" -Tags $ib.tags -PollSeconds $PollSeconds -Arm $Arm
        $since = "$($intent.savedUtc)"
        if (-not $mk.ok) {
            if ($mk.stage -eq 'scale') {
                # the pool IS there (up at 1): the intent is done; the next run's converge sets it to 0 (scaled-down)
                $clr = ''; if ($ClearIntent) { try { [void](& $ClearIntent) } catch { $clr = " (the recreate record could not be cleared: $($_.Exception.Message))" } }
                return @{ ok = $false; action = 'failed'; state = (New-PimAcrBuildPoolState -Pool $mk.pool -Building $false -NowUtc $NowUtc)
                          line = (Get-PimAcrBuildPoolScaleUpLine -PoolName $PoolName -Reason $mk.reason) + $clr }
            }
            return @{ ok = $false; action = 'failed'; state = $null
                      line = "build pool '$PoolName': deleted by an earlier update run (recorded $since) and NOT made again yet -- $($mk.reason); the record is kept and the next update run tries again" }
        }
        $clr = ''; if ($ClearIntent) { try { [void](& $ClearIntent) } catch { $clr = " (the recreate record could not be cleared: $($_.Exception.Message); the next run clears it)" } }
        return @{ ok = $true; action = 'recreated'; state = (New-PimAcrBuildPoolState -Pool $mk.pool -Building $false -NowUtc $NowUtc)
                  line = "build pool '$PoolName': made again at $($pol.Tier) from the record an earlier update run kept when it deleted the pool ($since), $($pol.IdleCount) instances between builds, same subnet -- read back$clr" }
    }
    $pstate = "$($pool.properties.provisioningState)"
    if ($pstate -eq 'Deleting') {
        # never scaled, never deleted again: the delete is Azure's to finish; the intent (if any) makes it on a later run
        return @{ ok = $false; action = 'deleting'; state = $null
                  line = "build pool '$PoolName': still being deleted by Azure -- nothing changed; $(if ($intent) { 'the next update run makes it again at ' + $pol.Tier + ' (the record is kept)' } else { 'no recreate record is kept for it: run the install again once it is gone' })" }
    }
    if ($intent -and $ClearIntent -and $pstate -eq 'Succeeded' -and "$($pool.properties.tier)" -eq $pol.Tier -and
        "$($pool.properties.virtualNetworkSubnetResourceId)".Trim() -eq "$($intent.body.properties.virtualNetworkSubnetResourceId)".Trim()) {
        # the pool is there again as the record asks (made by hand, or by the install): the record has nothing left to do.
        # One that differs keeps the record (it is only ever used when the pool is missing).
        try { [void](& $ClearIntent) } catch { }
    }
    $runs = Get-PimAcrActiveRuns -RegistryPath $regPath -Arm $Arm
    $building = (-not $runs.ok) -or (@($runs.active).Count -gt 0)
    $busyWhy = $(if (-not $runs.ok) { "the registry's runs could not be read ($($runs.reason))" } else { "$(@($runs.active).Count) build run(s) queued or running" })
    $tier = "$($pool.properties.tier)"; $count = ConvertTo-PimAcrPoolCount $pool
    if ($tier -ne $pol.Tier) {
        if ($building) {
            return @{ ok = $true; action = 'refused-building'; state = (New-PimAcrBuildPoolState -Pool $pool -Building $true -NowUtc $NowUtc)
                      line = "build pool '$PoolName' is $tier, not $($pol.Tier): not made again now -- $busyWhy; the next update run tries again" }
        }
        $subnet = "$($pool.properties.virtualNetworkSubnetResourceId)".Trim()
        $os = "$($pool.properties.os)".Trim(); if (-not $os) { $os = 'Linux' }
        # the pool as it must be made again (S2 x 0, same location / os / subnet / tags) -- saved BEFORE the delete
        $props = [ordered]@{ tier = $pol.Tier; count = $pol.IdleCount; os = $os }
        if ($subnet) { $props['virtualNetworkSubnetResourceId'] = $subnet }
        $body = [ordered]@{ location = "$($pool.location)"; properties = $props }
        if ($null -ne $pool.tags) { $body['tags'] = $pool.tags }
        $kept = $false
        if ($SaveIntent) {
            $rec = [ordered]@{ poolPath = $poolPath; body = $body; fromTier = $tier; savedUtc = $NowUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") }
            try { [void](& $SaveIntent $rec); $kept = $true }
            catch {
                return @{ ok = $false; action = 'failed'; state = (New-PimAcrBuildPoolState -Pool $pool -Building $false -NowUtc $NowUtc)
                          line = "build pool '$PoolName' is $tier, not $($pol.Tier): NOT deleted -- the record to make it again could not be saved ($($_.Exception.Message)); the next update run tries again" }
            }
        }
        $gone = $false
        try {
            [void](& $Arm 'DELETE' $poolPath $null $api)
            $max = [Math]::Max(1, [int]($DeleteWaitSeconds / [Math]::Max(1, $PollSeconds)))
            for ($i = 0; $i -lt $max; $i++) {
                if (-not (& $Arm 'GET' $poolPath $null $api)) { $gone = $true; break }
                if ($PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
            }
        } catch {
            return @{ ok = $false; action = 'failed'; state = $null
                      line = "build pool '$PoolName': moving it from $tier to $($pol.Tier) failed while deleting it ($($_.Exception.Message))$(if ($kept) { ' -- the record is kept: the next update run makes it again if it is gone' } else { ' -- run the install again if it is gone' })" }
        }
        if (-not $gone) {
            return @{ ok = $false; action = 'failed'; state = $null
                      line = "build pool '$PoolName': the $tier pool is still being deleted after $([int]($DeleteWaitSeconds / 60)) minutes -- $(if ($kept) { "the record is kept: the next update run makes it again at $($pol.Tier)" } else { 'the next update run tries again' })" }
        }
        $mk = New-PimAcrBuildPoolIdle -PoolPath $poolPath -Location "$($pool.location)" -Tier $pol.Tier -Count $pol.IdleCount -Os $os `
                  -SubnetId $subnet -Tags $pool.tags -PollSeconds $PollSeconds -Arm $Arm
        if (-not $mk.ok) {
            if ($mk.stage -eq 'scale') {
                if ($kept -and $ClearIntent) { try { [void](& $ClearIntent) } catch { } }
                return @{ ok = $false; action = 'failed'; state = (New-PimAcrBuildPoolState -Pool $mk.pool -Building $false -NowUtc $NowUtc)
                          line = (Get-PimAcrBuildPoolScaleUpLine -PoolName $PoolName -Reason $mk.reason) }
            }
            return @{ ok = $false; action = 'failed'; state = $(if ($mk.pool) { New-PimAcrBuildPoolState -Pool $mk.pool -Building $false -NowUtc $NowUtc } else { $null })
                      line = "build pool '$PoolName': the $tier pool is removed but the $($pol.Tier) pool was not made: $($mk.reason)$(if ($kept) { ' -- the record is kept: the next update run makes it again' } else { ' -- run the install again to make it' })" }
        }
        $clr = ''; if ($kept -and $ClearIntent) { try { [void](& $ClearIntent) } catch { $clr = " (the recreate record could not be cleared: $($_.Exception.Message); the next run clears it)" } }
        return @{ ok = $true; action = 'recreated'; state = (New-PimAcrBuildPoolState -Pool $mk.pool -Building $false -NowUtc $NowUtc)
                  line = "build pool '$PoolName': made again at $($pol.Tier) (was $tier), 0 instances between builds, same subnet -- read back$clr" }
    }
    if ($null -ne $count -and $count -ne $pol.IdleCount) {
        if ($building) {
            return @{ ok = $true; action = 'in-use'; state = (New-PimAcrBuildPoolState -Pool $pool -Building $true -NowUtc $NowUtc)
                      line = "build pool '$PoolName': $count instance(s) while a build is on ($busyWhy) -- left as it is" }
        }
        $d = Set-PimAcrBuildPoolCount -PoolPath $poolPath -Count $pol.IdleCount -PollSeconds $PollSeconds -Arm $Arm
        if (-not $d.ok) {
            return @{ ok = $false; action = 'failed'; state = (New-PimAcrBuildPoolState -Pool $pool -Building $false -NowUtc $NowUtc)
                      line = (Get-PimAcrBuildPoolDownWarning -PoolName $PoolName -Reason $d.reason) }
        }
        $after = $null; try { $after = & $Arm 'GET' $poolPath $null $api } catch { $after = $null }
        if (-not $after) { $after = $pool; $after.properties.count = $pol.IdleCount }
        return @{ ok = $true; action = 'scaled-down'; state = (New-PimAcrBuildPoolState -Pool $after -Building $false -NowUtc $NowUtc)
                  line = "build pool '$PoolName': was left at $count instance(s) with no build on -- set back to $($pol.IdleCount), read back" }
    }
    return @{ ok = $true; action = 'ok'; state = (New-PimAcrBuildPoolState -Pool $pool -Building $building -NowUtc $NowUtc)
              line = "build pool '$PoolName': $tier, $(if ($null -eq $count) { '?' } else { $count }) instances between builds" }
}

function Invoke-PimAcrRestBuild {
    <#
      The whole thing: upload a context, schedule a build, wait for it.
      Returns @{ ok; status; runId; seconds; bytes; images }.

      Idempotent from the caller's point of view -- building a tag that already exists simply
      replaces it with an identical image; the caller decides whether it is worth doing at all.

      BUILDPOOL-11G: with -AgentPoolName the pool is scaled up for this build and back to 0 after it
      (Invoke-PimAcrBuildPoolScope), the wait is at least 90 minutes and the task timeout above it.
      -PoolScaled = the caller already holds the pool up (Invoke-PimAcrRestBuildWithRetry: once for both tries).
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
        [string]$AgentPoolName,   # see Start-PimAcrDockerBuild: required for a registry with public access Disabled
        [switch]$PoolScaled,
        [int]$PoolPollSeconds = 10
    )
    $poolName = "$AgentPoolName".Trim()
    $to = Get-PimAcrBuildPoolTimeouts -TimeoutSeconds $TimeoutSeconds -OnPool ([bool]$poolName)
    # run by Invoke-PimAcrBuildPoolScope through dynamic scope: these locals are named so no callee variable shadows them
    $__rbPool = $poolName; $__rbTo = $to
    $one = {
        $slot  = Get-PimAcrBuildUploadSlot -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName
        $bytes = Send-PimAcrBuildContext -UploadUrl $slot.uploadUrl -Path $ContextPath
        $run   = Start-PimAcrDockerBuild -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup `
                    -RegistryName $RegistryName -RelativePath $slot.relativePath -ImageNames $ImageNames `
                    -DockerFilePath $DockerFilePath -TimeoutSeconds $__rbTo.task -Arguments $Arguments -AgentPoolName $__rbPool
        $runId = Get-PimAcrRunId -Run $run
        if (-not $runId) { throw "Invoke-PimAcrRestBuild: no run id came back for $($ImageNames -join ', ')." }
        $w = Wait-PimAcrRun -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup `
                -RegistryName $RegistryName -RunId $runId -TimeoutSeconds $__rbTo.wait -OnPoll $OnPoll
        @{ ok = $w.ok; status = $w.status; runId = $runId; seconds = $w.seconds; bytes = $bytes; images = @($ImageNames); error = "$($w.error)" }
    }
    if (-not $poolName -or $PoolScaled) { return (& $one) }
    Invoke-PimAcrBuildPoolScope -PoolPath (Get-PimAcrAgentPoolPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName -PoolName $poolName) `
        -PoolName $poolName -Build $one -PollSeconds $PoolPollSeconds
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
        [scriptblock]$OnRetry,
        [int]$PoolPollSeconds = 10,
        [switch]$PoolScaled
    )
    # BUILDPOOL-11G: on a pool, the pool is held up ONCE for both tries (one scale-up, one scale-down in a finally); the
    # call inside the scope carries -PoolScaled, and so does every build it makes
    $__wrPool = "$AgentPoolName".Trim()
    if ($__wrPool -and -not $PoolScaled) {
        $__wrArgs = @{}; foreach ($__k in $PSBoundParameters.Keys) { $__wrArgs[$__k] = $PSBoundParameters[$__k] }
        $__wrBody = { Invoke-PimAcrRestBuildWithRetry @__wrArgs -PoolScaled }
        return (Invoke-PimAcrBuildPoolScope -PoolPath (Get-PimAcrAgentPoolPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName -PoolName $__wrPool) `
                    -PoolName $__wrPool -Build $__wrBody -PollSeconds $PoolPollSeconds)
    }
    $bp = @{ SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; RegistryName = $RegistryName; ContextPath = $ContextPath
             ImageNames = $ImageNames; DockerFilePath = $DockerFilePath; TimeoutSeconds = $TimeoutSeconds; Arguments = $Arguments
             OnPoll = $OnPoll; AgentPoolName = $AgentPoolName; PoolScaled = [bool]$__wrPool }
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
