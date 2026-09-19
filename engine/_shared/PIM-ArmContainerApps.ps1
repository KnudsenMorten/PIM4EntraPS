<#
  PIM4EntraPS -- roll a Container App over ARM REST, with no `az` CLI.

  🔴 WHY THIS EXISTS (§53). PIM v2 is 100% cloud and has no unattended updater: every
  environment updates only when a human runs the deploy, which does not scale past a handful of
  customers. The updater has to run INSIDE the customer's cloud, on a schedule -- and the only
  scheduled compute a PIM environment has is Container Apps Jobs (the pattern `ca-pim-tick` and
  the MSP downlink job already use, per the operator's 2026-06-17 directive: "an Azure Container
  Apps scheduled JOB (cron), NOT a Windows scheduled task ... all run in cloud only compute").

  🪤 AND THAT IS WHY IT CANNOT REUSE Update-PimContainers.ps1. That roller drives everything
  through the `az` CLI, and the Manager image is mcr.microsoft.com/powershell:7.4-ubuntu-22.04
  with a pinned SQL driver and nothing else -- no az, no modules. Putting the Azure CLI into every
  customer's container to roll a container is a large dependency added to the one place this
  codebase has kept deliberately thin. ARM is a REST API and this solution already speaks it:
  `Invoke-PimArm` (PIM-Rest.ps1) carries the token, the retries and the api-version.

  🔑 READ-MODIFY-WRITE, NEVER A BLIND PATCH. A PATCH that sends only
  `properties.template.containers[0].image` replaces the container ARRAY, and every env var,
  resource limit and probe on that container goes with it. So the app is GET first, the image
  swapped inside the object that came back, and the whole template written again.

  A JOB MAY ROLL AN APP. They are separate ARM resources: rolling ca-pim-manager does not touch
  the container the job itself runs in, so the job completes normally. The one thing a container
  cannot do is roll the app it is *itself* running in -- which is why the updater is a Job and not
  a feature of the Manager.

  PS 5.1-safe. No modules, no az. Dot-source PIM-Rest.ps1 before this file.
#>

Set-StrictMode -Off

# Container Apps control plane. Pinned deliberately: a floating api-version turns a silent
# platform change into a broken updater in ~100 tenants at 03:00.
$script:PimAcaApi = '2024-03-01'

function Get-PimAcaAppId {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Name
    )
    "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$Name"
}

function Get-PimAcaApp {
    <# The whole app object. Everything else works from what this returns. #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Name
    )
    Invoke-PimArm -Method GET -Path (Get-PimAcaAppId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name) -ApiVersion $script:PimAcaApi
}

function Get-PimAcaAppImage {
    <#
      The image the app's template currently declares, for the container that matters.
      🪤 -ContainerName, not [0]. An app with a sidecar has more than one container and the order
      is not guaranteed, so "the first one" is a coin flip that reads as working until the day it
      is not. Falls back to the single container when there is exactly one.
    #>
    param([Parameter(Mandatory)][object]$App, [string]$ContainerName)
    $containers = @($App.properties.template.containers)
    if (-not $containers.Count) { return '' }
    if ("$ContainerName".Trim()) {
        $c = @($containers | Where-Object { "$($_.name)" -eq "$ContainerName".Trim() }) | Select-Object -First 1
        if ($c) { return "$($c.image)" }
        return ''
    }
    if ($containers.Count -eq 1) { return "$($containers[0].image)" }
    return ''
}

function Set-PimAcaAppImage {
    <#
      Swap the image on ONE named container and write the template back whole.
      Returns the ARM response. Does not wait -- see Wait-PimAcaProvisioned.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Image,
        [string]$ContainerName,
        [hashtable]$ExtraEnv                      # env vars to set/replace on that container
    )
    $app = Get-PimAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if (-not $app) { throw "Set-PimAcaAppImage: container app '$Name' not found in $ResourceGroup." }
    $containers = @($app.properties.template.containers)
    if (-not $containers.Count) { throw "Set-PimAcaAppImage: '$Name' declares no containers." }

    $target = if ("$ContainerName".Trim()) {
                  @($containers | Where-Object { "$($_.name)" -eq "$ContainerName".Trim() }) | Select-Object -First 1
              } elseif ($containers.Count -eq 1) { $containers[0] } else { $null }
    if (-not $target) {
        throw ("Set-PimAcaAppImage: cannot tell which of $($containers.Count) containers on '$Name' to roll. " +
               "Pass -ContainerName. Refusing to guess -- rolling the wrong container is silent.")
    }
    $target.image = $Image

    if ($ExtraEnv -and $ExtraEnv.Count) {
        # Read-modify-write here too: keep every variable the container already has.
        $env = New-Object System.Collections.Generic.List[object]
        foreach ($e in @($target.env)) { if ($e -and -not $ExtraEnv.ContainsKey("$($e.name)")) { [void]$env.Add($e) } }
        foreach ($k in $ExtraEnv.Keys) { [void]$env.Add([pscustomobject]@{ name = "$k"; value = "$($ExtraEnv[$k])" }) }
        $target | Add-Member -NotePropertyName env -NotePropertyValue @($env.ToArray()) -Force
    }

    # PATCH with the FULL template we just read back, not a fragment.
    $body = @{ properties = @{ template = $app.properties.template } }
    Invoke-PimArm -Method PATCH -Path (Get-PimAcaAppId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name) `
                  -Body $body -ApiVersion $script:PimAcaApi
}

function Wait-PimAcaProvisioned {
    <#
      Poll until the app leaves 'InProgress'. Returns the final provisioningState.
      🪤 A roll that returns before ARM has finished is how a "successful" update is followed by a
      health check against the OLD revision -- the deploy path learned this the hard way (BUG-44,
      the create that returns as soon as ARM accepts it).
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Name,
        [int]$TimeoutSeconds = 600,
        [int]$PollSeconds = 10
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $state = 'Unknown'
    while ((Get-Date) -lt $deadline) {
        $app = Get-PimAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
        $state = "$($app.properties.provisioningState)"
        if ($state -and $state -notmatch '(?i)^(InProgress|Waiting|Deleting)$') { return $state }
        Start-Sleep -Seconds $PollSeconds
    }
    return "TimedOut($state)"
}

function Get-PimAcaActiveRevision {
    <#
      The ACTIVE revision, newest first.
      🪤 Not [0]. Measured on the az path: the API returns revisions in an order that put the
      OLDEST first, so "[0]" reported a revision that was not serving -- and the auto-rollback then
      used it as its target. Filter on active, sort by creation, take the last.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Name
    )
    $path = (Get-PimAcaAppId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name) + '/revisions'
    $revs = @(Invoke-PimArm -Method GET -Path $path -ApiVersion $script:PimAcaApi -All)
    @($revs | Where-Object { $_.properties.active }) |
        Sort-Object { try { [datetimeoffset]$_.properties.createdTime } catch { [datetimeoffset]::MinValue } } |
        Select-Object -Last 1
}

function Invoke-PimAcaRoll {
    <#
      Roll one app to an image, wait, health-check, and ROLL BACK on failure.

      -HealthCheck is a scriptblock returning $true/$false. It is deliberately injected rather than
      hard-coded: the caller owns what "healthy" means, and an offline test can drive this whole
      function with no Azure at all.

      🔒 THE ROLLBACK TARGET IS CAPTURED BEFORE ANYTHING CHANGES. Reading it afterwards means
      reading the state the failed roll just created.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Image,
        [string]$ContainerName,
        [scriptblock]$HealthCheck,
        [int]$TimeoutSeconds = 600
    )
    $result = @{ app = $Name; from = ''; to = $Image; rolled = $false; healthy = $null
                 rolledBack = $false; state = ''; reason = '' }

    $app = Get-PimAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    if (-not $app) { $result.reason = "container app '$Name' not found"; return $result }
    $result.from = Get-PimAcaAppImage -App $app -ContainerName $ContainerName

    if ("$($result.from)" -eq "$Image") {
        $result.reason = 'already on this image -- nothing to roll'
        $result.healthy = $true
        return $result
    }

    [void](Set-PimAcaAppImage -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name `
                              -Image $Image -ContainerName $ContainerName)
    $result.state = Wait-PimAcaProvisioned -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name -TimeoutSeconds $TimeoutSeconds
    if ($result.state -notmatch '(?i)^Succeeded$') {
        $result.reason = "provisioning ended '$($result.state)'"
    } else {
        $result.rolled = $true
    }

    if ($result.rolled -and $HealthCheck) {
        try { $result.healthy = [bool](& $HealthCheck) }
        catch { $result.healthy = $false; $result.reason = "health check threw: $($_.Exception.Message)" }
    } elseif ($result.rolled) {
        # No health check supplied is NOT health. Say so rather than imply a pass.
        $result.healthy = $null
        $result.reason = 'rolled, but NO health check was supplied -- this update is unverified'
    }

    if ($result.rolled -and $result.healthy -eq $false -and "$($result.from)".Trim()) {
        [void](Set-PimAcaAppImage -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name `
                                  -Image $result.from -ContainerName $ContainerName)
        $back = Wait-PimAcaProvisioned -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name -TimeoutSeconds $TimeoutSeconds
        $result.rolledBack = ($back -match '(?i)^Succeeded$')
        if (-not $result.rolledBack) {
            $result.reason += " AND THE ROLLBACK FAILED ('$back') -- this environment is on $Image unverified."
        }
    }
    $result
}

function Set-PimAcaJobImage {
    <#
      The same swap for a Container Apps JOB (the tick, the downlink, and the updater itself).
      🪤 A job that stamps its OWN image takes effect on its NEXT execution -- the run in progress
      keeps the image it started with and finishes normally. That is safe, and it is why the
      updater must roll itself LAST: everything else is already on the new build by then.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Image,
        [string]$ContainerName
    )
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$Name"
    $job = Invoke-PimArm -Method GET -Path $path -ApiVersion $script:PimAcaApi
    if (-not $job) { throw "Set-PimAcaJobImage: job '$Name' not found in $ResourceGroup." }
    $containers = @($job.properties.template.containers)
    if (-not $containers.Count) { throw "Set-PimAcaJobImage: '$Name' declares no containers." }
    $target = if ("$ContainerName".Trim()) {
                  @($containers | Where-Object { "$($_.name)" -eq "$ContainerName".Trim() }) | Select-Object -First 1
              } elseif ($containers.Count -eq 1) { $containers[0] } else { $null }
    if (-not $target) { throw "Set-PimAcaJobImage: pass -ContainerName; '$Name' has $($containers.Count) containers." }
    $target.image = $Image
    Invoke-PimArm -Method PATCH -Path $path -Body @{ properties = @{ template = $job.properties.template } } -ApiVersion $script:PimAcaApi
}

function Get-PimUpdaterFollowUpDecision {
    <#
      §71.44 (operator, 2026-09-18) -- PURE. Should the updater start ONE more run of itself?

      🔴 WHY. An update run is executed by the updater image that was installed BEFORE it, so anything a
      release changes in the updater takes effect one run LATE. Measured 2026-09-18: the 2.4.367 updater
      rolled internal, EFIF and RIDE to 2.4.369, but the step that records the ring (§71.43) only exists
      in 2.4.369 -- so all three Managers showed "update ring: not recorded" until the next 03:00. A
      follow-up run on the NEW image closes that gap for this and every future updater change: it finds
      the same version already running (a no-op roll) and does the new work -- recording, reporting.

      Starts ONLY when this run moved the job onto a DIFFERENT image (stamped, and before != after).
      The follow-up runs that new image, finds its own image already equal to the target, and so can
      never start another: no loop by construction, not by a counter.
      Returns @{ start = [bool]; reason = [string] }.
    #>
    param(
        [AllowEmptyString()][AllowNull()][string]$SelfImageBefore,
        [AllowEmptyString()][AllowNull()][string]$TargetImage,
        [bool]$Stamped,
        # PIM_UPDATE_NO_FOLLOWUP=1 -- an explicit off switch for an operator who needs it.
        [AllowEmptyString()][AllowNull()][string]$Disable
    )
    if ("$Disable".Trim() -eq '1') { return @{ start = $false; reason = 'disabled (PIM_UPDATE_NO_FOLLOWUP=1)' } }
    if (-not $Stamped) { return @{ start = $false; reason = 'this job did not move to a new image this run' } }
    $b = "$SelfImageBefore".Trim(); $a = "$TargetImage".Trim()
    if (-not $a) { return @{ start = $false; reason = 'no target image known' } }
    if (-not $b) { return @{ start = $false; reason = 'the image this run started from is unknown -- not guessing' } }
    if ($b -ieq $a) { return @{ start = $false; reason = 'already on the target image (this IS the follow-up, or nothing changed)' } }
    return @{ start = $true; reason = "the updater moved $b -> $a; one follow-up run lets the NEW updater do its own work now, not at the next schedule" }
}

function Start-PimAcaJobExecution {
    <#
      §71.44 -- start ONE execution of a Container Apps job (ARM POST .../jobs/<name>/start).
      🪤 It runs right after this same job PATCHED its own image, so the job is often still provisioning
      and ARM answers 409 -- a wait, not a failure (the B8 lesson). Bounded backoff on 409 only.
      NEVER throws: returns @{ ok; execution; reason }. A follow-up that could not start costs one
      night's delay, and must never turn a successful update red.
      -Invoke / -Sleep are test seams (default: Invoke-PimArm / Start-Sleep).
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Name,
        [int[]]$Waits = @(0, 10, 20, 40, 60),
        [scriptblock]$Invoke,
        [scriptblock]$Sleep
    )
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$Name/start"
    if (-not $Invoke) { $Invoke = { param($p) Invoke-PimArm -Method POST -Path $p -ApiVersion $script:PimAcaApi -Body @{} } }
    if (-not $Sleep)  { $Sleep  = { param($s) Start-Sleep -Seconds $s } }
    $lastErr = ''
    foreach ($w in $Waits) {
        if ($w) { & $Sleep $w }
        try {
            $r = & $Invoke $path
            $exec = if ($r -and $r.PSObject.Properties['name']) { "$($r.name)" } else { '' }
            return @{ ok = $true; execution = $exec; reason = 'started' }
        } catch {
            $lastErr = "$($_.Exception.Message)"
            if ($lastErr -notmatch '(?i)OperationInProgress|active provisioning operation|\b409\b') { break }
        }
    }
    return @{ ok = $false; execution = ''; reason = $lastErr }
}

function Get-PimAcaImageRepo {
    <#
      The REPOSITORY half of a container image reference, with the tag or digest removed.

        acr.azurecr.io/pim-manager:2.4.304        -> acr.azurecr.io/pim-manager
        acr.azurecr.io/pim-manager@sha256:abc...  -> acr.azurecr.io/pim-manager
        acr.azurecr.io/pim-manager                -> acr.azurecr.io/pim-manager

      Pure, so the comparison that decides WHICH jobs an unattended updater is allowed to touch is
      provable offline. 🪤 The colon test must be anchored past the last '/': a registry may carry a
      PORT (`registry:5000/pim-manager`), and splitting on the first colon would turn that into the
      repository "registry", matching everything and nothing.
    #>
    param([string]$Image)
    $s = "$Image".Trim()
    if (-not $s) { return '' }
    $at = $s.IndexOf('@')
    if ($at -ge 0) { return $s.Substring(0, $at) }
    $slash = $s.LastIndexOf('/')
    $colon = $s.LastIndexOf(':')
    if ($colon -gt $slash) { return $s.Substring(0, $colon) }
    $s
}

function Get-PimAcaJobRollPlan {
    <#
      §53.5 -- WHICH jobs in this environment the nightly updater should roll.

      The updater used to roll a hardcoded three: the Manager, the tick job, and itself. Every other
      job in the resource group then drifted FOREVER. Measured at an MSP slave, where a green update
      execution left `ca-pim-downlink-s6` on a digest carrying NO TAG AT ALL -- a dangling manifest
      from a build whose tag had since moved, i.e. the job was running code nobody could name. MSP
      topologies are exactly where the extra jobs live, so "the three we thought of" was never the
      right set.

      🔒 THE RULE IS "SAME REPOSITORY", NOT "EVERY JOB". An unattended process with Contributor on a
      resource group must not retag a job it knows nothing about -- a customer's own job in the same
      group is not ours to move, and pointing it at the Manager image would break it outright.
      Matching on the repository the target image comes from is the narrowest test that still covers
      every job the solution deploys, present and future.

      🪤 A MULTI-CONTAINER job is SKIPPED, not guessed at. Which container carries the solution's
      image is exactly the ambiguity that made `Set-PimAcaAppImage` refuse a bare [0].

      Returns { repo; roll[]; skip[] } -- pure; no ARM, no side effects.
    #>
    param(
        [object[]]$Jobs,
        [Parameter(Mandatory)][string]$TargetImage,
        [string[]]$Exclude = @()
    )
    $repo = Get-PimAcaImageRepo -Image $TargetImage
    $ex   = @(@($Exclude) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $roll = @(); $skip = @()
    foreach ($j in @($Jobs)) {
        $name = "$($j.name)".Trim()
        if (-not $name) { continue }
        if ($ex -contains $name) {
            $skip += [pscustomobject]@{ name = $name; reason = 'rolled separately' }
            continue
        }
        $cs = @($j.properties.template.containers)
        if ($cs.Count -ne 1) {
            $skip += [pscustomobject]@{ name = $name; reason = "has $($cs.Count) containers -- roll it explicitly" }
            continue
        }
        $cur = Get-PimAcaImageRepo -Image "$($cs[0].image)"
        if (-not $cur) {
            $skip += [pscustomobject]@{ name = $name; reason = 'declares no image' }
            continue
        }
        if ($cur -ine $repo) {
            $skip += [pscustomobject]@{ name = $name; reason = "runs '$cur', not '$repo'" }
            continue
        }
        $roll += [pscustomobject]@{ name = $name; from = "$($cs[0].image)" }
    }
    [pscustomobject]@{ repo = $repo; roll = @($roll); skip = @($skip) }
}

function Get-PimAcaJobs {
    <#
      Every Container Apps Job in a resource group. 🪤 LIST, not a per-name GET: the updater does not
      know what else was deployed alongside it, which is the entire point of §53.5.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup
    )
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs"
    @(Invoke-PimArm -Method GET -Path $path -ApiVersion $script:PimAcaApi -All)
}

function Set-PimAcaJobEnvValue {
    <#
      Add or update ONE environment variable on a Container Apps Job, leaving the rest alone.

      🔴 READ-MODIFY-WRITE, NEVER A FRAGMENT PATCH. A PATCH carrying only the one variable replaces
      the whole container array and takes every other variable with it -- which on the update job
      would delete PIM_SubscriptionId / PIM_ResourceGroup / PIM_ManagerApp and leave a job that
      starts, reads nothing, and exits 2 every night. Same lesson as Set-PimAcaAppImage, and the
      same reason `az containerapp job update` gets --set-env-vars rather than --replace-env-vars.

      Used by §55 to record the version this environment last BUILT, so tomorrow night is a roll
      and not another build.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][string]$VariableName,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [string]$ContainerName
    )
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName"
    $job = Invoke-PimArm -Method GET -Path $path -ApiVersion $script:PimAcaApi
    if (-not $job) { throw "Set-PimAcaJobEnvValue: job '$JobName' not found in $ResourceGroup." }
    $containers = @($job.properties.template.containers)
    if (-not $containers.Count) { throw "Set-PimAcaJobEnvValue: '$JobName' declares no containers." }
    $target = if ("$ContainerName".Trim()) {
                  @($containers | Where-Object { "$($_.name)" -eq "$ContainerName".Trim() }) | Select-Object -First 1
              } elseif ($containers.Count -eq 1) { $containers[0] } else { $null }
    if (-not $target) { throw "Set-PimAcaJobEnvValue: pass -ContainerName; '$JobName' has $($containers.Count) containers." }

    $envList = New-Object System.Collections.Generic.List[object]
    $found = $false
    foreach ($v in @($target.env)) {
        if (-not $v) { continue }
        if ("$($v.name)" -eq $VariableName) {
            $envList.Add([pscustomobject]@{ name = $VariableName; value = $Value }) | Out-Null
            $found = $true
        } else { $envList.Add($v) | Out-Null }
    }
    if (-not $found) { $envList.Add([pscustomobject]@{ name = $VariableName; value = $Value }) | Out-Null }
    $target | Add-Member -NotePropertyName 'env' -NotePropertyValue @($envList.ToArray()) -Force

    $res = Invoke-PimArm -Method PATCH -Path $path -Body @{ properties = @{ template = $job.properties.template } } -ApiVersion $script:PimAcaApi

    # 🔴 B9 (2026-09-10) -- AN ENV VAR THAT LOOKS SET AND IS NOT IS INVISIBLE UNTIL 03:00.
    # A customer environment's PIM_UPDATE_SOURCE_URL had been TRUNCATED AT THE FIRST '&' -- stored as 88 chars
    # whose only query parameter was 'spr', with NO sig=. Every fetch went out ANONYMOUS, storage
    # answered 409 "Public access is not permitted", and the updater correctly refused to roll. The
    # environment sat a release behind and the stored value looked perfectly plausible.
    # 🪤 The cause was `az ... --set-env-vars`: az is az.cmd, cmd.exe treats '&' as a command
    # separator, and the value is cut WITHOUT ERROR. Third member of a family this repo has already
    # recorded twice (§46.1 the cost --query, §53.4c the az rest body). It fails OPEN every time.
    # 🔑 This path is ARM REST and never goes near cmd.exe, so it cannot truncate -- but "cannot"
    # was also true of the other two until it was not. A write that is not verified is a hope, so
    # READ IT BACK and compare. One GET, on a path that runs nightly at most.
    try {
        $back = Invoke-PimArm -Method GET -Path $path -ApiVersion $script:PimAcaApi
        $bc = @($back.properties.template.containers)
        $bt = if ("$ContainerName".Trim()) {
                  @($bc | Where-Object { "$($_.name)" -eq "$ContainerName".Trim() }) | Select-Object -First 1
              } elseif ($bc.Count -eq 1) { $bc[0] } else { $null }
        $stored = $null
        foreach ($v in @($bt.env)) { if ($v -and "$($v.name)" -eq $VariableName) { $stored = "$($v.value)"; break } }
        if ($null -eq $stored) { throw "wrote $VariableName but it is ABSENT on read-back." }
        if ($stored -ne $Value) {
            # 🔒 Never echo the value -- these carry SAS signatures. Lengths localise a truncation
            # precisely enough, and a truncation is exactly what this exists to catch.
            throw ("wrote $VariableName but the store returned a DIFFERENT value (wrote " +
                   "$($Value.Length) chars, read back $($stored.Length)). A value cut at the first " +
                   '& is the known shape -- never write one through az/cmd.exe.')
        }
    } catch { throw "Set-PimAcaJobEnvValue [$JobName]: $($_.Exception.Message)" }
    return $res
}

function Set-PimAcaAppEnvValue {
    <#
      Add or update ONE environment variable on a Container APP's container, leaving the rest alone, and READ IT BACK.
      The app counterpart of Set-PimAcaJobEnvValue -- same rule, same reason: a fragment PATCH replaces the container
      array and takes every other variable with it, so the app is GET, the one variable set inside what came back,
      and the whole template written again. The write creates a new revision (that is how Container Apps applies
      an env change). REQ-F: tools/setup/Set-PimEmergencyPassphrase.ps1 sets PIM_EmergencyVault on ca-pim-manager.
      Returns @{ changed; value } -- changed=$false when the variable already held the value (nothing written).
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$VariableName,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [string]$ContainerName
    )
    $path = Get-PimAcaAppId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    $pick = {
        param($appObj)
        $cs = @($appObj.properties.template.containers)
        if ("$ContainerName".Trim()) { return (@($cs | Where-Object { "$($_.name)" -eq "$ContainerName".Trim() }) | Select-Object -First 1) }
        if ($cs.Count -eq 1) { return $cs[0] }
        return $null
    }
    $app = Invoke-PimArm -Method GET -Path $path -ApiVersion $script:PimAcaApi
    if (-not $app) { throw "Set-PimAcaAppEnvValue: container app '$Name' not found in $ResourceGroup." }
    $target = & $pick $app
    if (-not $target) { throw "Set-PimAcaAppEnvValue: pass -ContainerName; '$Name' has $(@($app.properties.template.containers).Count) containers. Refusing to guess." }
    foreach ($v in @($target.env)) { if ($v -and "$($v.name)" -eq $VariableName -and "$($v.value)" -eq $Value -and -not "$($v.secretRef)".Trim()) { return [pscustomobject]@{ changed = $false; value = $Value } } }
    $envList = New-Object System.Collections.Generic.List[object]
    $found = $false
    foreach ($v in @($target.env)) {
        if (-not $v) { continue }
        if ("$($v.name)" -eq $VariableName) { $envList.Add([pscustomobject]@{ name = $VariableName; value = $Value }) | Out-Null; $found = $true }
        else { $envList.Add($v) | Out-Null }
    }
    if (-not $found) { $envList.Add([pscustomobject]@{ name = $VariableName; value = $Value }) | Out-Null }
    $target | Add-Member -NotePropertyName 'env' -NotePropertyValue @($envList.ToArray()) -Force
    [void](Invoke-PimArm -Method PATCH -Path $path -Body @{ properties = @{ template = $app.properties.template } } -ApiVersion $script:PimAcaApi)
    $back = Invoke-PimArm -Method GET -Path $path -ApiVersion $script:PimAcaApi
    $bt = & $pick $back
    $stored = $null
    foreach ($v in @($bt.env)) { if ($v -and "$($v.name)" -eq $VariableName) { $stored = "$($v.value)"; break } }
    if ($null -eq $stored) { throw "Set-PimAcaAppEnvValue [$Name]: wrote $VariableName but it is ABSENT on read-back." }
    if ($stored -ne $Value) { throw "Set-PimAcaAppEnvValue [$Name]: wrote $VariableName but read back a DIFFERENT value (wrote $($Value.Length) chars, read back $($stored.Length))." }
    return [pscustomobject]@{ changed = $true; value = $stored }
}
