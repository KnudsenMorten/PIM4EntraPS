<#
  PIM4EntraPS -- the container UPDATE RING, enforced where environments are deployed and rolled.

  Operator, 2026-09-13: "nothing releases to ring 2 without my approve", "i need 100% sure that
  updates are controlled now".

  WHAT THIS FILE GUARANTEES
    1. Every ca-pim-update job a deploy touches ends with PIM_UPDATE_RING set. The default is 2 (the
       safe customer ring); internal and test environments pass -UpdateRing 1 explicitly.
    2. A redeploy never promotes or demotes an environment: an existing ring is kept unless
       -UpdateRing is passed explicitly.
    3. A ring always has a source (PIM_UPDATE_SOURCE_URL). Without one the in-cloud updater cannot
       read channel.json and would ignore its ring, so the deploy REFUSES.
    4. Ring, source and last-built are written over ARM REST (Set-PimAcaJobEnvValue), never through
       `az --set-env-vars`: az is az.cmd and cmd.exe cuts a SAS at its first '&' without error (B9).
       Writes wait for the job to be idle (a PATCH right after a PATCH returns HTTP 409
       ContainerAppsJobOperationInProgress, measured 2026-09-13) and every value is read back.
    5. `az containerapp job update --yaml` REPLACES the container env array, so every PIM_UPDATE_*
       value set out-of-band (ring, source, last-built, last-good, HOLD) would silently vanish on a
       redeploy. The plan captures them first and puts them back.
    6. HOST-SIDE ROLLS (Update-PimContainers / Setup-PimContainers / Invoke-PimUpdate, and everything
       that calls them) read the target environment's ring. Ring 0 and ring 1 get every verified build
       by design (the mgmt1 scheduled tasks ARE the ring-1 path). Ring 2 and above: REFUSE to roll to any
       version the ring does not approve, and refuse when the channel cannot be read. The only way past
       is -OverrideRingGate -Reason '<why>', which is printed and audited.
       BUG-170 (2026-09-18): NO RING IS NOT "NO RULES". An environment that is deployed but carries no
       PIM_UPDATE_RING -- or has no updater at all -- is REFUSED, exactly like an unreadable one: it
       predates the ring, so nothing says which version it may take. The ways past are named and typed:
       give it a ring (Deploy-PimUpdateJob -UpdateRing <n>), declare the ring the SAME deploy run is
       installing (-PendingUpdateRing), or -OverrideRingGate -Reason for this one explicit version.
       Only a resource group with nothing PIM in it yet (a first install) is not a roll and passes.
    7. After a verified ring-0/1 build, Invoke-PimUpdate advances THAT ring in channel.json, forward
       only, read back. Ring 2 and above are never written by any script.
    8. The updater carries the Manager's PIM_SqlServer / PIM_SqlDatabase and its identity gets a
       contained database user (the tick's grant path), so its schema step can verify a release.

  Dot-source AFTER _PimAz.ps1 (the guarded az shadow). ASCII only: this file is read by Windows
  PowerShell 5.1 on deploy hosts.
#>

Set-StrictMode -Off

$script:PimUpdateRingHere = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:PimUpdateRingShared = Join-Path (Split-Path -Parent (Split-Path -Parent $script:PimUpdateRingHere)) 'engine\_shared'
. (Join-Path $script:PimUpdateRingShared 'PIM-UpdateSource.ps1')        # Get-PimUpdateChannelUrl / Get-PimRingVersion
. (Join-Path $script:PimUpdateRingShared 'PIM-ArmContainerApps.ps1')    # Set-PimAcaJobEnvValue (ARM read-modify-write)

$script:PimUpdateRingDefault = 2
# IMP-36: the Platform Updates Ring accepts 0..3, and EVERY reader of PIM_UPDATE_RING goes through
# ConvertTo-PimUpdateRingNumber so the range is decided in one place (it was three copies of a regex).
# The [ValidateRange(0,3)] on the -UpdateRing parameters of Deploy-PimUpdateJob / Enable-PimSelfUpdate /
# Invoke-PimDeployAll must match this number.
$script:PimUpdateRingMax = 3
# Test seam: every wait goes through this, so the offline suite can count waits instead of sleeping.
$script:PimUpdateRingSleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds }

# The names the update job's YAML owns. Anything else named PIM_UPDATE_* was set out-of-band and is
# preserved across a YAML redeploy.
$script:PimUpdateRingControlPrefix = 'PIM_UPDATE_'

function Hide-PimSasText {
    # Never let a signature reach a log, a transcript or an exception message.
    param([AllowEmptyString()][string]$Text)
    ("$Text" -replace '(?i)(sig=)[^&\s"'']+', '$1<withheld>')
}

function ConvertTo-PimUpdateRingNumber {
    <#
      PURE. A PIM_UPDATE_RING value ('2', 'ring2', ' Ring1 ') -> its ring number, or $null when it is
      not a Platform Updates Ring (empty, out of range, not a number). The ONE definition of the range
      (IMP-36): the deploy, the roll gate and the channel advance all read the ring through here.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Value)
    $v = "$Value".Trim()
    if ($v -notmatch '^(?i)(ring)?(\d{1,2})$') { return $null }
    $n = [int]$Matches[2]
    if ($n -lt 0 -or $n -gt $script:PimUpdateRingMax) { return $null }
    return $n
}

function ConvertTo-PimJobEnvMap {
    <#
      PURE. name -> value for one container of a job object (ARM GET shape or `az ... show -o json`
      shape; both carry properties.template.containers). Returns an ordered dictionary, or an empty
      one when the job or the container cannot be found.
    #>
    param([object]$Job, [string]$ContainerName)
    $map = [ordered]@{}
    if ($null -eq $Job) { return $map }
    $tpl = $null
    if ($Job.PSObject.Properties['properties'] -and $Job.properties -and $Job.properties.PSObject.Properties['template']) { $tpl = $Job.properties.template }
    elseif ($Job.PSObject.Properties['template']) { $tpl = $Job.template }
    if (-not $tpl) { return $map }
    $cs = @($tpl.containers | Where-Object { $_ })
    $c = if ("$ContainerName".Trim()) { @($cs | Where-Object { "$($_.name)" -eq "$ContainerName".Trim() }) | Select-Object -First 1 }
         elseif ($cs.Count -eq 1) { $cs[0] } else { $null }
    if (-not $c -and $cs.Count -ge 1 -and "$ContainerName".Trim()) { $c = $null }
    if (-not $c) { return $map }
    # 🪤 pwsh 7's ConvertFrom-Json turns an ISO-8601 string VALUE into [datetime], and "$dt" prints it culture-formatted
    # ("09/18/2026 20:58:28"), so a read-back of an env var holding a timestamp never matched what was written.
    # Measured on EFIF 2026-09-18 (PIM_CadenceDeployedUtc). Render a parsed date back in the invariant ISO UTC form.
    foreach ($e in @($c.env)) {
        if (-not ($e -and "$($e.name)")) { continue }
        $v = $e.value
        if ($v -is [datetime]) { $v = $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) }
        $map["$($e.name)"] = "$v"
    }
    return $map
}

function Resolve-PimUpdateRingSetting {
    <#
      PURE. Which ring a deploy leaves on the updater.
        explicit -UpdateRing   -> that ring (a change from an existing ring is stated)
        no -UpdateRing, ring   -> KEEP the existing ring (a redeploy never promotes or demotes)
        no -UpdateRing, none   -> the default ring (2, the safe customer ring)
      An existing value that is not a ring is REFUSED unless -UpdateRing is explicit: guessing a
      ring for an environment is exactly the decision this exists to take away from a script.
    #>
    param([int]$Requested = 2, [switch]$Explicit, [AllowEmptyString()][string]$Existing)
    if ($Requested -lt 0 -or $Requested -gt $script:PimUpdateRingMax) { throw "Resolve-PimUpdateRingSetting: ring $Requested is outside 0-$($script:PimUpdateRingMax)." }
    $e = "$Existing".Trim()
    $eInt = ConvertTo-PimUpdateRingNumber $e
    if ($Explicit) {
        $msg = if (-not $e) { "ring $Requested (explicit -UpdateRing)" }
               elseif ($null -ne $eInt -and $eInt -eq $Requested) { "ring $Requested (explicit -UpdateRing; unchanged)" }
               else { "ring CHANGES from '$e' to $Requested (explicit -UpdateRing)" }
        return [pscustomobject]@{ ring = $Requested; source = 'explicit'; changed = ([bool]$e -and $eInt -ne $Requested); message = $msg }
    }
    if ($null -ne $eInt) {
        return [pscustomobject]@{ ring = $eInt; source = 'kept'; changed = $false
            message = "keeping the existing ring $eInt -- -UpdateRing was not passed, and a redeploy never promotes or demotes an environment" }
    }
    if ($e) {
        throw ("Resolve-PimUpdateRingSetting: the updater carries PIM_UPDATE_RING='$e', which is not a ring (0-$($script:PimUpdateRingMax)). " +
               'REFUSING to guess one -- pass -UpdateRing explicitly.')
    }
    return [pscustomobject]@{ ring = $Requested; source = 'default'; changed = $true
        message = "no ring on this updater -- applying the default ring $Requested (the safe customer ring; internal and test environments pass -UpdateRing 1)" }
}

function Resolve-PimUpdateRingSourceTemplate {
    <#
      PURE. The source template a ring-gated updater reads channel.json through.
      Order: explicit parameter -> $env:PIM_UPDATE_SOURCE_URL -> the value the job already carries.
      None of them => REFUSE. A ring without a source is a ring the updater silently ignores.
    #>
    param([AllowEmptyString()][string]$Explicit, [AllowEmptyString()][string]$EnvValue, [AllowEmptyString()][string]$Existing)
    $url = ''; $origin = ''
    if ("$Explicit".Trim())     { $url = "$Explicit".Trim(); $origin = 'parameter' }
    elseif ("$EnvValue".Trim()) { $url = "$EnvValue".Trim(); $origin = 'env:PIM_UPDATE_SOURCE_URL' }
    elseif ("$Existing".Trim()) { $url = "$Existing".Trim(); $origin = 'kept from the existing updater' }
    if (-not $url) {
        throw ("REFUSING to deploy an updater with a ring but NO SOURCE. The in-cloud updater reads channel.json " +
               "through PIM_UPDATE_SOURCE_URL; without it the ring is skipped and nothing controls what this " +
               "environment takes. Pass -UpdateSourceUrlTemplate (Invoke-PimDeployAll) / -SourceUrlTemplate " +
               "(Deploy-PimUpdateJob, Enable-PimSelfUpdate), or set `$env:PIM_UPDATE_SOURCE_URL, to the fleet " +
               "read-only template that tools/setup/Publish-PimSourceArchive.ps1 -PassThru returns (container stored access " +
               "policy 'srcread'): https://<store>.blob.core.windows.net/pim-src/pim-src-{version}.tar.gz?<sas>")
    }
    if ($url -notmatch '^https://') { throw "Resolve-PimUpdateRingSourceTemplate: the source template must be https:// ($origin)." }
    if ($url -notmatch '\{version\}') { throw "Resolve-PimUpdateRingSourceTemplate: the source template has no {version} placeholder ($origin)." }
    $warn = if ($url -notmatch '\?') { 'the source template carries no query string -- a private container needs its read SAS' } else { '' }
    return [pscustomobject]@{ url = $url; origin = $origin; warning = $warn }
}

function Get-PimUpdateJobRingPlan {
    <#
      PURE. Everything a deploy writes to the updater out-of-band, in the order it must be written:
        1. PIM_UPDATE_SOURCE_URL -- first, so a ring is never present without a source
        2. PIM_UPDATE_RING
        3. PIM_UPDATE_LAST_BUILT -- the version this environment already runs, when the caller knows it
        4. every other PIM_UPDATE_* the job carried that the YAML does not re-specify (HOLD, LAST_GOOD,
           pins) -- because `job update --yaml` replaces the env array and would drop them
    #>
    param(
        [System.Collections.IDictionary]$ExistingEnv = @{},
        [int]$UpdateRing = 2,
        [switch]$RingExplicit,
        [AllowEmptyString()][string]$SourceUrlTemplate,
        [AllowEmptyString()][string]$EnvSourceUrl,
        [AllowEmptyString()][string]$LastBuiltVersion,
        [string[]]$YamlManagedNames = @()
    )
    if ($null -eq $ExistingEnv) { $ExistingEnv = @{} }
    $get = { param($n) if ($ExistingEnv.Contains($n)) { "$($ExistingEnv[$n])" } else { '' } }
    $ring = Resolve-PimUpdateRingSetting -Requested $UpdateRing -Explicit:$RingExplicit -Existing (& $get 'PIM_UPDATE_RING')
    $src  = Resolve-PimUpdateRingSourceTemplate -Explicit $SourceUrlTemplate -EnvValue $EnvSourceUrl -Existing (& $get 'PIM_UPDATE_SOURCE_URL')
    $writes = [ordered]@{}
    $writes['PIM_UPDATE_SOURCE_URL'] = $src.url
    $writes['PIM_UPDATE_RING'] = "$($ring.ring)"
    if ("$LastBuiltVersion".Trim()) { $writes['PIM_UPDATE_LAST_BUILT'] = "$LastBuiltVersion".Trim() }
    $preserved = New-Object System.Collections.Generic.List[string]
    $yaml = @{}; foreach ($n in @($YamlManagedNames)) { if ("$n") { $yaml["$n".ToUpperInvariant()] = $true } }
    foreach ($k in @($ExistingEnv.Keys)) {
        $name = "$k"
        if (-not $name.StartsWith($script:PimUpdateRingControlPrefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($writes.Contains($name) -or $yaml.ContainsKey($name.ToUpperInvariant())) { continue }
        $writes[$name] = "$($ExistingEnv[$k])"
        [void]$preserved.Add($name)
    }
    $msgs = New-Object System.Collections.Generic.List[string]
    [void]$msgs.Add($ring.message)
    [void]$msgs.Add("source: $($src.origin)")
    if ($src.warning) { [void]$msgs.Add($src.warning) }
    if ($preserved.Count) { [void]$msgs.Add("preserved across the YAML redeploy: $($preserved -join ', ')") }
    if ($preserved -contains 'PIM_UPDATE_HOLD') { [void]$msgs.Add('PIM_UPDATE_HOLD is KEPT -- this environment stays frozen') }
    return [pscustomobject]@{
        ring = $ring.ring; ringSource = $ring.source; ringChanged = $ring.changed
        sourceUrl = $src.url; sourceOrigin = $src.origin
        writes = $writes; preserved = @($preserved.ToArray()); messages = @($msgs.ToArray())
    }
}

function New-PimSubscriptionArmInvoker {
    <#
      A deploy host's ARM caller, bound to ONE subscription's tenant. The token is requested with
      --subscription and its tenant claim is checked against that subscription before it is used:
      on mgmt1 the default az context is frequently another company's tenant.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId)
    $raw = az account get-access-token --subscription $SubscriptionId --resource https://management.azure.com/ -o json 2>$null
    $tokObj = $null; try { $tokObj = ($raw | Out-String) | ConvertFrom-Json } catch { $tokObj = $null }
    if (-not $tokObj -or -not "$($tokObj.accessToken)") { throw "New-PimSubscriptionArmInvoker: no ARM token for subscription $SubscriptionId (az login?)." }
    $acct = $null; try { $acct = ((az account show --subscription $SubscriptionId -o json 2>$null) | Out-String) | ConvertFrom-Json } catch { $acct = $null }
    $want = "$($acct.tenantId)".Trim().ToLowerInvariant()
    $p = "$($tokObj.accessToken)".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }
    $tid = ''
    try { $tid = "$(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json).tid)".Trim().ToLowerInvariant() } catch { $tid = '' }
    if (-not $want -or $tid -ne $want) { throw "New-PimSubscriptionArmInvoker: the ARM token is for tenant '$tid', not subscription $SubscriptionId's tenant '$want' -- REFUSING." }
    $token = "$($tokObj.accessToken)"
    # Rehearsal 2026-09-17 (tests/Test-PimMspBuild.ps1 R1): GetNewClosure() binds this block to a new module that
    # cannot see functions dot-sourced into a CALLER's script scope, so every ARM error (incl. the expected 404 of a key
    # that does not exist yet) became "Hide-PimSasText is not recognized". Capture the function as a variable instead.
    $hideSas = ${function:Hide-PimSasText}
    return {
        param([string]$Method = 'GET', [string]$Path, [object]$Body, [string]$ApiVersion, [switch]$All)
        $uri = "https://management.azure.com$Path" + $(if ($Path -match '\?') { '&' } else { '?' }) + "api-version=$ApiVersion"
        $h = @{ Authorization = "Bearer $token" }
        try {
            if ($Method -eq 'GET') { return (Invoke-RestMethod -Method GET -Uri $uri -Headers $h -UseBasicParsing) }
            $json = $Body | ConvertTo-Json -Depth 40 -Compress
            return (Invoke-RestMethod -Method $Method -Uri $uri -Headers $h -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($json)) -UseBasicParsing)
        } catch {
            $code = ''; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            $detail = "$($_.ErrorDetails.Message)"; if (-not $detail) { $detail = "$($_.Exception.Message)" }
            throw ("$Method $Path -> HTTP $code : " + (& $hideSas $detail))
        }
    }.GetNewClosure()
}

function Invoke-PimUpdateJobEnvWrites {
    <#
      Write each value through Set-PimAcaJobEnvValue (ARM read-modify-write, B9-safe), one at a time,
      waiting for the job to be idle before each PATCH and retrying the in-flight 409. Values that are
      already correct are not rewritten. Finishes with a full read-back: every value must be stored
      byte-for-byte, or this throws (lengths only -- these carry a SAS).
      -ArmInvoker replaces Invoke-PimArm for this call only (dynamic scope), so a deploy host can bind
      it to one subscription and the offline suite can script ARM.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Writes,
        [string]$ContainerName,
        [scriptblock]$ArmInvoker,
        [int]$WaitTimeoutSeconds = 300,
        [int[]]$RetryDelays = @(10, 20, 40, 60)
    )
    if ($ArmInvoker) {
        # Shadows any Invoke-PimArm for everything called from here (Set-PimAcaJobEnvValue included).
        function Invoke-PimArm { param([string]$Method = 'GET', [string]$Path, [object]$Body, [string]$ApiVersion, [switch]$All, [hashtable]$Headers = @{})
            & $ArmInvoker -Method $Method -Path $Path -Body $Body -ApiVersion $ApiVersion }
    }
    if (-not (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue)) { throw 'Invoke-PimUpdateJobEnvWrites: no ARM caller (pass -ArmInvoker or load PIM-Rest.ps1).' }
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName"
    $busy = '(?i)InProgress|Updating|Provisioning|Waiting|Deleting|Creating|Scheduled'
    $waitIdle = {
        $iter = [Math]::Max(1, [int][Math]::Ceiling($WaitTimeoutSeconds / 6))
        for ($i = 0; $i -lt $iter; $i++) {
            $j = Invoke-PimArm -Method GET -Path $path -ApiVersion $script:PimAcaApi
            if (-not $j) { throw "Invoke-PimUpdateJobEnvWrites: job '$JobName' not found in $ResourceGroup." }
            $st = "$($j.properties.provisioningState)"
            if ($st -notmatch $busy) { return $j }
            $script:PimUpdateRingWaits++
            & $script:PimUpdateRingSleep 6
        }
        throw "Invoke-PimUpdateJobEnvWrites: '$JobName' stayed in an in-flight operation for $WaitTimeoutSeconds s."
    }
    $written = New-Object System.Collections.Generic.List[string]
    $skipped = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($Writes.Keys)) {
        $name = "$k"; $want = "$($Writes[$k])"
        $job = & $waitIdle
        $cur = (ConvertTo-PimJobEnvMap -Job $job -ContainerName $ContainerName)
        if ($cur.Contains($name) -and "$($cur[$name])" -ceq $want) { [void]$skipped.Add($name); continue }
        $done = $false
        foreach ($d in @(@(0) + @($RetryDelays))) {
            if ($d) { $script:PimUpdateRingWaits++; & $script:PimUpdateRingSleep $d; [void](& $waitIdle) }
            try {
                [void](Set-PimAcaJobEnvValue -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -JobName $JobName `
                        -VariableName $name -Value $want -ContainerName $ContainerName)
                $done = $true; break
            } catch {
                $m = "$($_.Exception.Message)"
                if ($m -match '(?i)\b409\b|OperationInProgress|active provisioning operation') { continue }
                throw ("Invoke-PimUpdateJobEnvWrites: writing $name FAILED: " + (Hide-PimSasText $m))
            }
        }
        if (-not $done) { throw "Invoke-PimUpdateJobEnvWrites: writing $name kept hitting an in-flight operation (HTTP 409) after $(@($RetryDelays).Count) retries." }
        [void]$written.Add($name)
    }
    $final = ConvertTo-PimJobEnvMap -Job (& $waitIdle) -ContainerName $ContainerName
    foreach ($k in @($Writes.Keys)) {
        $name = "$k"; $want = "$($Writes[$k])"
        $got = if ($final.Contains($name)) { "$($final[$name])" } else { $null }
        if ($null -eq $got) { throw "Invoke-PimUpdateJobEnvWrites: $name is ABSENT on the final read-back." }
        if ($got -cne $want) { throw "Invoke-PimUpdateJobEnvWrites: $name read back DIFFERENT from what was written (wrote $($want.Length) chars, read $($got.Length))." }
    }
    return [pscustomobject]@{ written = @($written.ToArray()); skipped = @($skipped.ToArray()) }
}

function Get-PimUpdateRingChannelReport {
    <#
      What the environment's ring approves, read through ITS OWN source template, and what that means
      for it. level = ok | warn | error. Never silent: a missing channel or an unapproved ring is an
      error-level report (the environment will not update), and a move the environment would make on
      its next run is a warn-level report naming both versions.
      backward = $true when the ring approves a version BELOW the one the environment is on (BUG-173):
      a caller that installs an updater must FAIL on that, not print it in yellow and report success.
    #>
    param([AllowEmptyString()][string]$SourceUrlTemplate, [int]$Ring, [AllowEmptyString()][string]$CurrentVersion, [scriptblock]$Fetch)
    if (-not $Fetch) { $Fetch = { param($u) (Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 60).Content } }
    $mk = { param($lvl, $appr, $msg, $back = $false) [pscustomobject]@{ ok = ($lvl -ne 'error'); level = $lvl; approved = $appr; message = $msg; backward = [bool]$back } }
    $url = Get-PimUpdateChannelUrl -SourceTemplate $SourceUrlTemplate
    if (-not $url) { return (& $mk 'error' '' "ring $Ring approves NOTHING: no channel URL can be derived (no source template) -- this environment will NOT update.") }
    $raw = $null
    try { $raw = & $Fetch $url } catch {
        return (& $mk 'error' '' ("channel.json could NOT be read (" + (Hide-PimSasText "$($_.Exception.Message)") + ") -- ring $Ring approves NOTHING until it can be; this environment will NOT update."))
    }
    # An application/octet-stream blob arrives as byte[] (see Update-PimRingChannelVersion): decode it, or every
    # report said "approves NOTHING" and the drift check, the sync and Deploy-PimUpdateJob all did nothing.
    # A byte[] returned from a scriptblock is UNROLLED by the pipeline into object[] of [byte], so test both shapes.
    if ($raw -is [array] -and -not ($raw -is [byte[]]) -and $raw.Count -gt 0 -and $raw[0] -is [byte]) { $raw = [byte[]]@($raw) }
    if ($raw -is [byte[]]) { $raw = [Text.Encoding]::UTF8.GetString($raw).TrimStart([char]0xFEFF) }
    $ch = $null
    try { $ch = ("$raw" | ConvertFrom-Json) } catch { return (& $mk 'error' '' "channel.json is not valid JSON -- ring $Ring approves NOTHING; this environment will NOT update.") }
    $rv = Get-PimRingVersion -Channel $ch -Ring "$Ring" -CurrentVersion $CurrentVersion
    $appr = "$($rv.version)".Trim()
    if (-not $appr) { return (& $mk 'error' '' "ring $Ring approves NOTHING ($($rv.reason)) -- this environment will NOT update until a version is approved for ring $Ring.") }
    $cur = ("$CurrentVersion".Trim() -replace '^v', '')
    $cv = $null; $av = $null
    $haveCur = [bool]$cur -and [version]::TryParse($cur, [ref]$cv)
    $haveAppr = [version]::TryParse(($appr -replace '^v', ''), [ref]$av)
    if (-not $cur) { return (& $mk 'ok' $appr "ring $Ring approves $appr (this environment's current version is not known here).") }
    if ($haveCur -and $haveAppr -and $av -lt $cv) {
        return (& $mk 'warn' $appr "BACKWARD: ring $Ring approves $appr but this environment is on $cur -- its next run would try to move it BACKWARD. Fix channel.json (forward-only) or pass the right -UpdateRing." $true)
    }
    if ($appr -ne $cur) {
        return (& $mk 'warn' $appr "ring $Ring approves $appr; this environment is on $cur -- its next scheduled run WILL move it to $appr.")
    }
    return (& $mk 'ok' $appr "ring $Ring approves $appr -- the version this environment is on (no move).")
}

function Test-PimRollRingGate {
    <#
      PURE (apart from the -Fetch seam). May a HOST-SIDE roll move this environment to -TargetVersion?
        nothing deployed yet        -> allowed, not gated (-Greenfield: a first install is not a roll)
        no updater / no ring        -> REFUSED (BUG-170: it predates the ring, so nothing approves ANY
                                       version for it) -- unless -PendingRing names the ring this same
                                       deploy run installs, which is then gated exactly like a real one
        updater unreadable          -> REFUSED (a roll that cannot prove it is approved does not happen)
        ring 0 or 1                 -> allowed: those rings get EVERY build by design (dev / internal +
                                       the operator's test estate). The mgmt1 Invoke-PimUpdate tasks
                                       build, roll, verify and then advance ringN in channel.json
                                       (Update-PimRingChannelVersion) so the cloud job does not roll
                                       them back the next night.
        ring >= 2, no source        -> REFUSED (the ring's channel cannot be read)
        ring >= 2, channel unreadable/no entry -> REFUSED
        ring >= 2, target != approved -> REFUSED -- ring 2 moves ONLY when the operator edits channel.json
        ring >= 2, target == approved -> allowed
    #>
    param(
        [AllowEmptyString()][string]$TargetVersion,
        [System.Collections.IDictionary]$UpdaterEnv,
        [switch]$UpdaterMissing,
        [switch]$UpdaterUnreadable,
        [AllowEmptyString()][string]$UnreadableReason,
        # Nothing PIM is deployed in the target resource group yet: a first install, not a roll.
        [switch]$Greenfield,
        # BUG-170: the ring the SAME deploy run is about to write onto the updater (Invoke-PimDeployAll
        # with an explicit -UpdateRing). Used only when the environment carries no ring of its own --
        # an existing ring always wins, because a redeploy never promotes or demotes. -1 = none.
        [int]$PendingRing = -1,
        [AllowEmptyString()][string]$PendingSourceUrl,
        # §79.11 + R25-24 (operator 2026-09-26: "community edition is free (non-PRO)"). The environment's EDITION, as a FACT
        # read from its own store (Get-PimEnvironmentEdition: no valid Pro licence = 'community'), never the caller's word.
        # The free community edition has no in-cloud updater BY DESIGN (BUG-156) and no operator channel governs it -- the
        # customer IS its release channel -- so a ring-less 'community' environment is not gated (and the caller audits it).
        # 'pro' and '' (unknown: the store could not be read) are gated exactly as before. It was a -CommunityGitPull switch
        # set from "-Source git-pull", so a PAID environment updating from git (the retired MSP-community S4) was ungated too.
        # A community environment that DOES carry a ring is gated by that ring.
        [ValidateSet('', 'community', 'pro')][string]$EnvironmentEdition = '',
        [scriptblock]$Fetch
    )
    $r = { param($allowed, $gated, $ring, $appr, $reason) [pscustomobject]@{ allowed = [bool]$allowed; gated = [bool]$gated; ring = $ring; approved = $appr; reason = $reason } }
    if ($UpdaterUnreadable) {
        return (& $r $false $true $null '' ("the environment's update job could not be read ($UnreadableReason), so its ring cannot be checked -- REFUSING to roll (a roll that cannot prove it is approved does not happen)."))
    }
    $t = ("$TargetVersion".Trim() -replace '^v', '')
    $haveEnv = (-not $UpdaterMissing) -and ($null -ne $UpdaterEnv)
    $ringRaw = if ($haveEnv -and $UpdaterEnv.Contains('PIM_UPDATE_RING')) { "$($UpdaterEnv['PIM_UPDATE_RING'])".Trim() } else { '' }
    $src     = if ($haveEnv -and $UpdaterEnv.Contains('PIM_UPDATE_SOURCE_URL')) { "$($UpdaterEnv['PIM_UPDATE_SOURCE_URL'])".Trim() } else { '' }
    $how = ''
    if (-not $ringRaw) {
        if ($Greenfield) {
            return (& $r $true $false $null '' 'nothing PIM is deployed in this resource group yet -- a first install is not a roll (the updater the deploy installs carries the ring from then on).')
        }
        if ($EnvironmentEdition -eq 'community' -and $PendingRing -lt 0) {
            $cv = & $r $true $false $null '' 'the free Community edition (no Pro licence in this environment''s store) -- no operator ring governs it (it has no in-cloud updater by design); not gated, and audited.'
            $cv | Add-Member -NotePropertyName community -NotePropertyValue $true
            return $cv
        }
        if ($PendingRing -ge 0) {
            # The ring this deploy is installing decides -- and it is gated exactly as if it were already there.
            $ringRaw = "$PendingRing"
            $how = ' (the ring this deploy run installs; the environment carries none yet)'
            if (-not $src) { $src = "$PendingSourceUrl".Trim() }
        } else {
            $what = if ($UpdaterMissing -or -not $haveEnv) { 'this environment has NO in-cloud updater' } else { "this environment's updater carries NO PIM_UPDATE_RING" }
            return (& $r $false $true $null '' ("$what, so no ring says which version it may take -- REFUSING to roll it to '$t' (an environment without a ring is not an environment without rules; it predates the ring). " +
                    "Give it a ring first (Deploy-PimUpdateJob.ps1 -UpdateRing <0-$($script:PimUpdateRingMax)>; internal and test environments are ring 1, customers ring 2), " +
                    "or roll exactly this version with -OverrideRingGate -Reason '<why>' (printed and audited)."))
        }
    }
    $ring = ConvertTo-PimUpdateRingNumber $ringRaw
    if ($null -eq $ring) { return (& $r $false $true $ringRaw '' "the updater carries PIM_UPDATE_RING='$ringRaw', which is not a ring (0-$($script:PimUpdateRingMax)) -- REFUSING to roll.") }
    if ($ring -lt 2) {
        return (& $r $true $false $ring '' "ring $ring$how gets every build by design -- a host-side roll is allowed (Invoke-PimUpdate advances ring$ring in channel.json after it verifies the roll).")
    }
    if (-not $src) { return (& $r $false $true $ring '' "ring $ring$how is configured but the updater has NO PIM_UPDATE_SOURCE_URL, so what ring $ring approves cannot be read -- REFUSING to roll.") }
    $rep = Get-PimUpdateRingChannelReport -SourceUrlTemplate $src -Ring $ring -CurrentVersion '' -Fetch $Fetch
    if (-not $rep.ok) { return (& $r $false $true $ring '' ("REFUSING to roll: " + $rep.message)) }
    if ($t -ne $rep.approved) {
        return (& $r $false $true $ring $rep.approved ("ring $ring$how approves $($rep.approved); this roll targets '$t' -- REFUSED. Nothing is released to ring $ring without the operator's approval: raise ring$ring.version in channel.json after approval, or pass -OverrideRingGate -Reason '<why>'."))
    }
    return (& $r $true $true $ring $rep.approved "ring $ring$how approves $($rep.approved) -- the roll target; allowed.")
}

function Assert-PimRollRingGate {
    <#
      The host-side gate every roller calls BEFORE it changes an environment. Reads the target
      environment's update job (az, subscription-scoped), decides with Test-PimRollRingGate, and either
      returns (allowed) or throws. -OverrideRingGate needs -Reason AND an explicit -TargetVersion (an
      override names the one version it lets through); it is printed and written to the audit trail when
      this host has one (pim.AuditEvents via -SqlConnectionString).
      -PendingUpdateRing / -PendingUpdateSourceUrl: the ring (and source) the SAME deploy run installs on
      an environment that carries none yet -- see Test-PimRollRingGate -PendingRing (BUG-170).
    #>
    param(
        [Parameter(Mandatory)][string]$ResourceGroup,
        [string[]]$SubscriptionArgs = @(),
        [AllowEmptyString()][string]$TargetVersion,
        [string]$UpdateJobName = 'ca-pim-update',
        [switch]$OverrideRingGate,
        [AllowEmptyString()][string]$Reason,
        [string]$Caller = 'roll',
        [AllowEmptyString()][string]$SqlConnectionString,
        [int]$PendingUpdateRing = -1,
        [AllowEmptyString()][string]$PendingUpdateSourceUrl,
        [scriptblock]$GetJobs,
        # R25-24: returns the environment's stored licence document (text) or throws -- tests only; production reads
        # pim.Settings['License'] through -SqlConnectionString (Get-PimEnvironmentEdition).
        [scriptblock]$ReadLicense,
        [scriptblock]$Fetch,
        [scriptblock]$Audit
    )
    if ($OverrideRingGate -and -not "$Reason".Trim()) {
        throw "$Caller`: -OverrideRingGate requires -Reason '<why this environment may take a version its ring does not approve>'."
    }
    if ($OverrideRingGate -and -not "$TargetVersion".Trim()) {
        throw "$Caller`: -OverrideRingGate needs an explicit target version -- an override lets exactly ONE named version through, never 'whatever this run builds'."
    }
    if ($PendingUpdateRing -gt $script:PimUpdateRingMax) { throw "$Caller`: -PendingUpdateRing $PendingUpdateRing is outside 0-$($script:PimUpdateRingMax)." }
    $upd = Get-PimEnvironmentUpdaterEnv -ResourceGroup $ResourceGroup -SubscriptionArgs $SubscriptionArgs -UpdateJobName $UpdateJobName -GetJobs $GetJobs
    $verdict = $null
    # R25-24: the edition is read from the ENVIRONMENT (its store's licence), never taken from the caller.
    $edition = Get-PimEnvironmentEdition -SqlConnectionString $SqlConnectionString -ReadLicense $ReadLicense
    $pend = @{ PendingRing = $PendingUpdateRing; PendingSourceUrl = "$PendingUpdateSourceUrl"; EnvironmentEdition = "$($edition.edition)" }
    if (-not $upd.ok)        { $verdict = Test-PimRollRingGate -TargetVersion $TargetVersion -UpdaterUnreadable -UnreadableReason "$($upd.reason)" -Fetch $Fetch }
    elseif (-not $upd.found) { $verdict = Test-PimRollRingGate -TargetVersion $TargetVersion -UpdaterMissing -Greenfield:(-not $upd.deployed) @pend -Fetch $Fetch }
    else                     { $verdict = Test-PimRollRingGate -TargetVersion $TargetVersion -UpdaterEnv $upd.env @pend -Fetch $Fetch }
    if ($verdict.allowed) {
        if ($verdict.gated) { Write-Host "    ring gate: $($verdict.reason)" -ForegroundColor Green }
        else { Write-Host "    ring gate: $($verdict.reason)" -ForegroundColor DarkGray }
        $cAud = $false
        $isCommunity = [bool]($verdict.PSObject.Properties['community'] -and $verdict.community)
        if ($isCommunity) {
            # R25-24: an ungated roll is ALWAYS on the record -- the same audit path an override uses.
            $who = "$($env:USERDOMAIN)\$($env:USERNAME)".Trim('\')
            $rec = [ordered]@{ event = 'ring-gate-community'; caller = $Caller; resourceGroup = $ResourceGroup; ring = $null; target = "$TargetVersion"
                               reason = "$($edition.reason)"; by = $who; utc = [datetime]::UtcNow.ToString('o') }
            try {
                if ($Audit) { & $Audit $rec; $cAud = $true }
                elseif ("$SqlConnectionString".Trim() -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
                    [void](Write-PimSqlAuditEvent -ConnectionString $SqlConnectionString -Actor $who -ActorSource 'deploy-host' `
                            -Action 'update.ring-gate.community' -Target $ResourceGroup -After $rec -Result 'ok')
                    $cAud = $true
                }
            } catch { Write-Warning "ring gate (community): the ungated roll was NOT written to the audit trail: $($_.Exception.Message)" }
            if (-not $cAud) { Write-Warning 'ring gate (community): no audit trail in this host -- the ungated roll is recorded in this deploy''s output only.' }
        }
        return [pscustomobject]@{ allowed = $true; overridden = $false; verdict = $verdict; community = $isCommunity; audited = $cAud }
    }
    if (-not $OverrideRingGate) {
        $hint = if (-not "$($edition.edition)") { " (the environment's edition could not be read: $($edition.reason) -- a free Community install is exempt only when its store says so)" } else { '' }
        throw "RING GATE ($Caller, $ResourceGroup): $($verdict.reason)$hint"
    }
    $who = "$($env:USERDOMAIN)\$($env:USERNAME)".Trim('\')
    $rec = [ordered]@{ event = 'ring-gate-override'; caller = $Caller; resourceGroup = $ResourceGroup; ring = $verdict.ring
                       approved = $verdict.approved; target = "$TargetVersion"; reason = "$Reason".Trim(); by = $who
                       utc = [datetime]::UtcNow.ToString('o'); refusal = $verdict.reason }
    Write-Host '    ============================================================================' -ForegroundColor Red
    if ($null -eq $verdict.ring) {
        Write-Host "    RING GATE OVERRIDDEN ($Caller): target '$TargetVersion' on an environment that NO ring governs (or whose updater could not be read)." -ForegroundColor Red
    } else {
        Write-Host "    RING GATE OVERRIDDEN ($Caller): target '$TargetVersion' is NOT what ring $($verdict.ring) approves ('$($verdict.approved)')." -ForegroundColor Red
    }
    Write-Host "    by: $who   reason: $("$Reason".Trim())" -ForegroundColor Red
    Write-Host '    ============================================================================' -ForegroundColor Red
    $audited = $false
    try {
        if ($Audit) { & $Audit $rec; $audited = $true }
        elseif ("$SqlConnectionString".Trim() -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
            [void](Write-PimSqlAuditEvent -ConnectionString $SqlConnectionString -Actor $who -ActorSource 'deploy-host' `
                    -Action 'update.ring-gate.override' -Target $ResourceGroup -After $rec -Result 'overridden')
            $audited = $true
        }
    } catch { Write-Warning "ring gate override was NOT written to the audit trail: $($_.Exception.Message)" }
    if (-not $audited) { Write-Warning 'ring gate override: no audit trail in this host (no -SqlConnectionString) -- it is recorded in this deploy''s output only.' }
    return [pscustomobject]@{ allowed = $true; overridden = $true; verdict = $verdict; record = $rec; audited = $audited }
}

function Get-PimEnvironmentEdition {
    <#
      R25-24 -- the environment's EDITION as a fact from its own store: pim.Settings['License'] verified with the same code
      the Manager uses (PIM-License.ps1 Get-PimLicense -LicenseText). Returns @{ edition = 'community' | 'pro' | ''; reason }.
        'pro'       -- a Valid (or Grace) Pro licence is stored;
        'community' -- none is stored, or the stored one does not verify / has expired (the free edition);
        ''          -- the store could not be read, so the edition is UNKNOWN (the gate then treats it as not exempt).
      -ReadLicense (tests): returns the document text, or throws.
    #>
    param([string]$SqlConnectionString, [scriptblock]$ReadLicense)
    $shared = Join-Path $PSScriptRoot '..\..\engine\_shared'
    $doc = $null
    try {
        if ($ReadLicense) { $doc = & $ReadLicense }
        elseif ("$SqlConnectionString".Trim()) {
            if (-not (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { . (Join-Path $shared 'PIM-SqlStore.ps1') }
            $v = Get-PimSqlSetting -ConnectionString $SqlConnectionString -Name 'License'
            $doc = if ($null -eq $v) { '' } elseif ($v -is [string]) { $v } else { ConvertTo-Json -InputObject $v -Depth 6 -Compress }
        } else { return [pscustomobject]@{ edition = ''; reason = 'no connection to the environment''s store was given' } }
    } catch {
        # A store whose schema is not there yet (a first install: the 'code' step runs before 'schema') has no
        # pim.Settings table, so no licence can be stored in it -- that IS the free edition, not an unknown one.
        # (Found on the first community install after R25-24, 2026-09-26: the read threw "Invalid object name".)
        if ("$($_.Exception.Message)" -match "(?i)Invalid object name '?pim\.Settings'?") {
            return [pscustomobject]@{ edition = 'community'; reason = 'the store has no settings table yet (first install) -- no Pro licence can be stored there' }
        }
        return [pscustomobject]@{ edition = ''; reason = "the environment's store could not be read ($($_.Exception.Message))" }
    }
    if (-not "$doc".Trim()) { return [pscustomobject]@{ edition = 'community'; reason = 'no Pro licence is stored in this environment' } }
    if (-not (Get-Command Get-PimLicense -ErrorAction SilentlyContinue)) { . (Join-Path $shared 'PIM-License.ps1') }
    $lic = $null
    try { $lic = Get-PimLicense -LicenseText "$doc" } catch { return [pscustomobject]@{ edition = ''; reason = "the stored licence could not be evaluated ($($_.Exception.Message))" } }
    if ("$($lic.Status)" -in @('Valid', 'Grace')) { return [pscustomobject]@{ edition = 'pro'; reason = "a $($lic.Status) Pro licence ($($lic.Customer)) is stored" } }
    return [pscustomobject]@{ edition = 'community'; reason = "the stored licence is $($lic.Status): $($lic.Reason)" }
}
function Get-PimEnvironmentUpdaterEnv {
    <#
      Read an environment's update job env (az, subscription-scoped). Returns
      @{ ok; found; env; reason } -- ok=$false means "could not read", which is NOT the same as
      "there is no updater" (found=$false). -GetJobs is the offline seam: it returns
      @{ ok; jobs; apps; reason } where jobs are job objects carrying properties.template.containers
      and apps are container app NAMES.
      deployed = something PIM (a job or app named ca-pim-*, or the update job) already runs in the
      group. BUG-170: only a group where NOTHING is deployed is a first install; a deployed environment
      without an updater is refused by the gate, never waved through as "no ring".
    #>
    param(
        [Parameter(Mandatory)][string]$ResourceGroup,
        [string[]]$SubscriptionArgs = @(),
        [string]$UpdateJobName = 'ca-pim-update',
        [scriptblock]$GetJobs
    )
    if (-not $GetJobs) {
        $GetJobs = {
            $global:LASTEXITCODE = 0
            $raw = az containerapp job list @SubscriptionArgs -g $ResourceGroup -o json 2>$null
            $code = $LASTEXITCODE
            $jobs = @(); $apps = @(); $ok = ($code -eq 0)
            if ($ok) { try { $jobs = @((($raw | Out-String) | ConvertFrom-Json)) } catch { $ok = $false } }
            $why = ''
            $rgMissing = $false
            if (-not $ok) {
                # A GREENFIELD install: the resource group does not exist yet, so there is no updater and
                # nothing to gate. Only a listing failure against a group that EXISTS is "unreadable".
                $global:LASTEXITCODE = 0
                $rgExists = "$(az group exists --name $ResourceGroup @SubscriptionArgs 2>$null)".Trim()
                if ($LASTEXITCODE -eq 0 -and $rgExists -eq 'false') { $ok = $true; $jobs = @(); $rgMissing = $true }
                else { $why = "az containerapp job list exit $code" }
            }
            if ($ok -and -not $rgMissing) {
                # The apps as well: an environment can run a Manager and no job at all (the always-on
                # shape), and "no jobs" must not read as "nothing deployed".
                $global:LASTEXITCODE = 0
                $appRaw = az containerapp list @SubscriptionArgs -g $ResourceGroup --query "[].name" -o tsv 2>$null
                if ($LASTEXITCODE -ne 0) { $ok = $false; $why = "az containerapp list exit $LASTEXITCODE" }
                else { $apps = @(@($appRaw) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
            }
            [pscustomobject]@{ ok = $ok; jobs = $jobs; apps = $apps; reason = $why }
        }
    }
    $res = & $GetJobs
    if (-not $res -or -not $res.ok) { return [pscustomobject]@{ ok = $false; found = $false; deployed = $true; env = [ordered]@{}; reason = "$($res.reason)" } }
    $names = @(@($res.jobs | Where-Object { $_ } | ForEach-Object { "$($_.name)" }) + @($res.apps | ForEach-Object { "$_" }))
    $deployed = @($names | Where-Object { $_ -like 'ca-pim-*' -or $_ -eq $UpdateJobName }).Count -gt 0
    $job = @($res.jobs | Where-Object { $_ -and "$($_.name)" -eq $UpdateJobName }) | Select-Object -First 1
    if (-not $job) { return [pscustomobject]@{ ok = $true; found = $false; deployed = $deployed; env = [ordered]@{}; reason = "no '$UpdateJobName' in $ResourceGroup" } }
    $envMap = ConvertTo-PimJobEnvMap -Job $job -ContainerName $UpdateJobName
    if (-not $envMap.Count) { $envMap = ConvertTo-PimJobEnvMap -Job $job }
    return [pscustomobject]@{ ok = $true; found = $true; deployed = $true; env = $envMap; reason = '' }
}

function Get-PimRingChannelAdvancePlan {
    <#
      PURE. The channel.json an automatic advance of ring 0 / ring 1 would write. Forward-only: an
      entry already at or above the verified version is left alone. Every other ring is carried over
      unchanged.
      RING 2 AND ABOVE ARE NEVER ADVANCED AUTOMATICALLY (operator, 2026-09-13: "nothing releases to
      ring 2 without my approve"). Asking for it THROWS -- not a skip, because a caller that asks has a
      bug that must not be quiet.
    #>
    param(
        [AllowEmptyString()][string]$ChannelJson,
        [Parameter(Mandatory)][int]$Ring,
        [Parameter(Mandatory)][string]$VerifiedVersion,
        [string]$By = 'Invoke-PimUpdate (verified build + roll)',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    if ($Ring -ge 2) { throw "Get-PimRingChannelAdvancePlan: ring $Ring is NEVER advanced automatically -- only the operator moves ring 2 and above, by editing channel.json after approval." }
    if ($Ring -lt 0) { throw "Get-PimRingChannelAdvancePlan: ring $Ring is not a ring." }
    $v = "$VerifiedVersion".Trim() -replace '^v', ''
    $vv = $null
    if (-not [version]::TryParse($v, [ref]$vv)) { throw "Get-PimRingChannelAdvancePlan: '$VerifiedVersion' is not a version -- a channel entry must name one." }
    $doc = $null
    if ("$ChannelJson".Trim()) {
        try { $doc = ("$ChannelJson" | ConvertFrom-Json) } catch { throw 'Get-PimRingChannelAdvancePlan: the current channel.json is not valid JSON -- refusing to overwrite it.' }
    }
    if ($null -eq $doc) { $doc = New-Object psobject }
    $key = "ring$Ring"
    $prop = @($doc.PSObject.Properties | Where-Object { "$($_.Name)".ToLowerInvariant() -eq $key }) | Select-Object -First 1
    $cur = if ($prop -and $prop.Value) { "$($prop.Value.version)".Trim() } else { '' }
    $cv = $null
    if ($cur -and [version]::TryParse(($cur -replace '^v', ''), [ref]$cv) -and $cv -ge $vv) {
        return [pscustomobject]@{ action = 'skip'; key = $key; from = $cur; to = $cur; json = ''
                                  reason = "$key already approves $cur (>= $v) -- forward-only, not lowered" }
    }
    $entry = if ($prop -and $prop.Value) { $prop.Value } else { New-Object psobject }
    $entry | Add-Member -NotePropertyName version -NotePropertyValue $v -Force
    $entry | Add-Member -NotePropertyName approvedBy -NotePropertyValue $By -Force
    $entry | Add-Member -NotePropertyName approvedUtc -NotePropertyValue ($NowUtc.ToUniversalTime().ToString('o')) -Force
    $keyName = if ($prop) { "$($prop.Name)" } else { $key }
    $doc | Add-Member -NotePropertyName $keyName -NotePropertyValue $entry -Force
    $why = if ($cur) { "$key $cur -> $v" } else { "$key created at $v" }
    return [pscustomobject]@{ action = 'write'; key = $keyName; from = $cur; to = $v; json = ($doc | ConvertTo-Json -Depth 10); reason = $why }
}

function Get-PimChannelRingVersions {
    # PURE. ringN -> version for every ring entry in a channel document (for the before/after check).
    param([AllowEmptyString()][string]$ChannelJson)
    $map = @{}
    if (-not "$ChannelJson".Trim()) { return $map }
    $doc = $null; try { $doc = ("$ChannelJson" | ConvertFrom-Json) } catch { return $map }
    foreach ($p in @($doc.PSObject.Properties)) {
        if ("$($p.Name)" -match '^(?i)ring(\d+)$') { $map["ring$($Matches[1])"] = "$($p.Value.version)".Trim() }
    }
    return $map
}

function Update-PimRingChannelVersion {
    <#
      Advance ring 0 / ring 1 in channel.json to a version that was just BUILT, ROLLED and VERIFIED, so
      the in-cloud updater (whose ring wins over its pin) does not roll the environment back the next
      night. Forward-only, read back, never fatal: returns @{ ok; action; reason } and the caller warns
      on ok=$false.
      Write = Entra ID (--auth-mode login, IMP-36; the pattern New-PimBaselineStorage uses), scoped to
      -SubscriptionId, optionally in an isolated az profile (-AzureConfigDir): the host running an estate
      update is often signed in to the ENVIRONMENT's tenant, not to the one that owns the source store.
      No account key is read: the writing identity needs 'Storage Blob Data Contributor' on the source
      container, and without it the advance is SKIPPED with that reason (never fatal, never a key).
      Ring 2 and above: refused, always. After the write every ring >= 2 entry is compared with what
      was there before; any difference is reported loudly.
    #>
    param(
        [Parameter(Mandatory)][string]$SourceUrlTemplate,
        [Parameter(Mandatory)][int]$Ring,
        [Parameter(Mandatory)][string]$VerifiedVersion,
        [string]$SubscriptionId,
        [string]$AzureConfigDir,
        [scriptblock]$Fetch,
        [scriptblock]$Upload
    )
    $res = { param($ok, $action, $reason) [pscustomobject]@{ ok = [bool]$ok; action = $action; reason = $reason } }
    if ($Ring -ge 2) { return (& $res $false 'refused' "ring $Ring is never advanced automatically -- only the operator moves it.") }
    $url = Get-PimUpdateChannelUrl -SourceTemplate $SourceUrlTemplate
    if ($url -notmatch '^https://(?<acct>[a-z0-9]+)\.blob\.core\.windows\.net/(?<ctr>[^/?]+)/channel\.json') {
        return (& $res $false 'skipped' 'the source template does not name a blob container -- channel.json location unknown.')
    }
    $acct = $Matches['acct']; $ctr = $Matches['ctr']
    if (-not $Fetch) {
        $Fetch = { param($u)
            # 🪤 A blob served as application/octet-stream (how channel.json was uploaded before this tool set a
            # content type) comes back from Invoke-WebRequest as byte[], not text, and the planner then refused
            # it as "not valid JSON" -- so the ring advance was skipped on every run (measured 2026-09-18).
            try {
                $c = (Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 60).Content
                if ($c -is [byte[]]) { $c = [Text.Encoding]::UTF8.GetString($c).TrimStart([char]0xFEFF) }
                [pscustomobject]@{ found = $true; content = "$c" }
            }
            catch {
                $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
                if ($code -eq 404) { [pscustomobject]@{ found = $false; content = '' } } else { throw }
            }
        }
    }
    if (-not $Upload) {
        $Upload = { param($account, $container, $file)
            $saved = $env:AZURE_CONFIG_DIR
            try {
                if ("$AzureConfigDir".Trim()) { $env:AZURE_CONFIG_DIR = "$AzureConfigDir".Trim() }
                # IMP-36: Entra ID, not the storage ACCOUNT KEY. A key is the whole account's master
                # credential; the ring advance needs one blob in one container.
                $global:LASTEXITCODE = 0
                $out = az storage blob upload --subscription $SubscriptionId --account-name $account --container-name $container --name channel.json --file $file --overwrite --content-type application/json --auth-mode login -o none 2>&1
                if ($LASTEXITCODE -ne 0) {
                    $txt = (Hide-PimSasText (($out | Out-String).Trim()))
                    if ($txt.Length -gt 300) { $txt = $txt.Substring(0, 300) + '...' }
                    return ("az storage blob upload (--auth-mode login) exit $LASTEXITCODE -- the identity in this az profile needs 'Storage Blob Data Contributor' on $account/$container. $txt").Trim()
                }
                return ''
            } finally { $env:AZURE_CONFIG_DIR = $saved }
        }
    }
    $before = $null
    try { $before = & $Fetch $url } catch { return (& $res $false 'skipped' ('channel.json could not be read: ' + (Hide-PimSasText "$($_.Exception.Message)"))) }
    $beforeJson = if ($before -and $before.found) { "$($before.content)" } else { '' }
    $plan = $null
    try { $plan = Get-PimRingChannelAdvancePlan -ChannelJson $beforeJson -Ring $Ring -VerifiedVersion $VerifiedVersion } catch { return (& $res $false 'skipped' "$($_.Exception.Message)") }
    if ($plan.action -eq 'skip') { return (& $res $true 'skip' $plan.reason) }
    if (-not "$SubscriptionId".Trim()) { return (& $res $false 'skipped' "no -ChannelSubscriptionId: cannot write channel.json ($($plan.reason) NOT applied)") }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("pim-channel-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    try {
        [IO.File]::WriteAllText($tmp, $plan.json, (New-Object System.Text.UTF8Encoding($false)))
        $err = & $Upload $acct $ctr $tmp
        if ("$err".Trim()) { return (& $res $false 'skipped' ("write failed: $err ($($plan.reason) NOT applied)")) }
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    $after = $null
    try { $after = & $Fetch $url } catch { return (& $res $false 'written-unverified' ('written but could not be read back: ' + (Hide-PimSasText "$($_.Exception.Message)"))) }
    $was = Get-PimChannelRingVersions -ChannelJson $beforeJson
    $now = Get-PimChannelRingVersions -ChannelJson "$($after.content)"
    $k0 = "$($plan.key)".ToLowerInvariant()
    if ("$($now[$k0])" -ne $plan.to) {
        return (& $res $false 'written-unverified' "read back $($plan.key)='$($now[$k0])', expected '$($plan.to)'")
    }
    foreach ($k in @($was.Keys)) {
        if ($k -eq $k0) { continue }
        if ($k -match '^ring(\d+)$' -and [int]$Matches[1] -ge 2 -and "$($now[$k])" -ne "$($was[$k])") {
            return (& $res $false 'written-unverified' "$k CHANGED ('$($was[$k])' -> '$($now[$k])') during an automatic ring advance -- it must never move without the operator. Check channel.json NOW.")
        }
    }
    return (& $res $true 'written' "$($plan.reason) (read back)")
}

# ---- the updater's STORE (2026-09-13) -----------------------------------------------------------
# ca-pim-update carried no PIM_SqlServer / PIM_SqlDatabase on four live environments, so its schema step
# reported "no local store" about environments whose Manager runs on Azure SQL. The Manager is the
# authority on which store an environment uses; the updater copies it, and its managed identity gets a
# contained database user through the SAME grant path as the tick (Grant-PimMiSql, or the in-cloud
# bootstrap job when SQL is private).

function Get-PimUpdateJobStorePlan {
    <#
      PURE. Which SQL settings the updater must carry, copied from the Manager.
        -ManagerStore : Get-PimAcaStoreSettings of the Manager app ($null / known=$false = unreadable)
        -ExistingEnv  : the updater's current env (name -> value)
      Returns { writes (ordered PIM_SqlServer, PIM_SqlDatabase); hasStore; storeless; level ok|warn|error;
                messages }. Never removes a value: an unreadable Manager keeps what the updater has.
    #>
    param(
        [object]$ManagerStore,
        [System.Collections.IDictionary]$ExistingEnv = @{},
        [string]$UpdateJobName = 'ca-pim-update',
        [string]$ManagerApp = 'ca-pim-manager'
    )
    if ($null -eq $ExistingEnv) { $ExistingEnv = @{} }
    $get = { param($n) if ($ExistingEnv.Contains($n)) { "$($ExistingEnv[$n])".Trim() } else { '' } }
    $writes = [ordered]@{}
    $msgs = New-Object System.Collections.Generic.List[string]
    $known = ($null -ne $ManagerStore) -and [bool]$ManagerStore.known
    if (-not $known) {
        foreach ($n in @('PIM_SqlServer', 'PIM_SqlDatabase')) { $v = & $get $n; if ($v) { $writes[$n] = $v } }
        $kept = if ($writes.Count) { " -- keeping the updater's own $(@($writes.Keys) -join ' / ')" } else { '' }
        [void]$msgs.Add("could NOT read $ManagerApp's SQL settings$kept. If this environment has a store and $UpdateJobName cannot reach it, every release that moves the version is REFUSED by the updater.")
        return [pscustomobject]@{ writes = $writes; hasStore = [bool]$writes.Contains('PIM_SqlServer'); storeless = $false; level = 'error'; messages = @($msgs.ToArray()) }
    }
    if (-not [bool]$ManagerStore.hasStore) {
        [void]$msgs.Add("$ManagerApp names no SQL store -- this environment is store-less; the updater's schema step will say so and skip.")
        return [pscustomobject]@{ writes = $writes; hasStore = $false; storeless = $true; level = 'ok'; messages = @($msgs.ToArray()) }
    }
    $srv = "$($ManagerStore.server)".Trim()
    if (-not $srv) {
        [void]$msgs.Add("$ManagerApp reaches its store through $($ManagerStore.via), which is not copied (a secret or a vault pointer). $UpdateJobName has NO PIM_SqlServer, so it cannot verify schema and REFUSES every release that moves the version. Set PIM_SqlServer on $ManagerApp, or grant the updater that pointer by hand.")
        return [pscustomobject]@{ writes = $writes; hasStore = $true; storeless = $false; level = 'error'; messages = @($msgs.ToArray()) }
    }
    $writes['PIM_SqlServer'] = $srv
    $db = "$($ManagerStore.database)".Trim()
    if ($db) { $writes['PIM_SqlDatabase'] = $db }
    foreach ($n in @($writes.Keys)) {
        $had = & $get $n
        if (-not $had) { [void]$msgs.Add("$n copied from $ManagerApp ($($writes[$n]))") }
        elseif ($had -cne "$($writes[$n])") { [void]$msgs.Add("$n CHANGES from '$had' to '$($writes[$n])' (copied from $ManagerApp, the authority on this environment's store)") }
        else { [void]$msgs.Add("$n already matches $ManagerApp ($had)") }
    }
    if (-not $db) { [void]$msgs.Add("$ManagerApp carries no PIM_SqlDatabase -- the updater resolves the same default database the Manager does") }
    return [pscustomobject]@{ writes = $writes; hasStore = $true; storeless = $false; level = 'ok'; messages = @($msgs.ToArray()) }
}

function Get-PimUpdaterSqlGrantPlan {
    <#
      PURE. How the updater's managed identity gets its contained database user -- the tick's path, not
      a new one.
        none    -- no store to grant on
        direct  -- public SQL + an SQL-admin credential: Grant-PimMiSql from this host
        dbinit  -- private SQL + the in-cloud bootstrap job exists: add the updater to its principals and run it
        infra   -- private SQL, no bootstrap job yet: the INFRA step (Setup-PimContainers) queues it
        manual  -- public SQL, no credential given: cannot grant from here
    #>
    param([bool]$HasStore, [bool]$SqlPrivate, [bool]$HaveAdminCredential, [bool]$DbInitJobExists,
          [string]$UpdateJobName = 'ca-pim-update', [string]$DbInitJobName = 'ca-pim-dbinit')
    if (-not $HasStore) { return [pscustomobject]@{ action = 'none'; message = 'no SQL store -- no database user to grant' } }
    if ($SqlPrivate) {
        if ($DbInitJobExists) {
            return [pscustomobject]@{ action = 'dbinit'; message = "SQL is private: adding '$UpdateJobName' to $DbInitJobName's principals and running it inside the environment" }
        }
        return [pscustomobject]@{ action = 'infra'
            message = "SQL is private and '$DbInitJobName' does not exist yet: the database user for '$UpdateJobName' is created by the INFRA step (Setup-PimContainers queues it). Until then the updater cannot reach the store and REFUSES every release that moves the version." }
    }
    if ($HaveAdminCredential) {
        return [pscustomobject]@{ action = 'direct'; message = "granting '$UpdateJobName' a contained database user (SID from its managed identity's appId) from this host" }
    }
    return [pscustomobject]@{ action = 'manual'
        message = "no SQL-admin credential (-SqlAdminClientId + -SqlAdminCertThumbprint) -- the database user for '$UpdateJobName' was NOT granted. Re-run with it, or run the INFRA step. Until then the updater REFUSES every release that moves the version." }
}

function Merge-PimDbInitPrincipals {
    <#
      PURE. Add one principal to the bootstrap job's PIM_DBINIT_PRINCIPALS JSON array without dropping any
      that are there. Same name + same appId = unchanged; same name + a different appId = replaced (the
      identity was rebuilt). Always returns an ARRAY shape (a one-element array collapses to an object in
      ConvertTo-Json, and the job then reads it as a set of properties).
    #>
    param([AllowEmptyString()][string]$Json, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$AppId)
    $list = New-Object System.Collections.Generic.List[object]
    if ("$Json".Trim()) {
        $parsed = $null
        try { $parsed = ("$Json" | ConvertFrom-Json) } catch { throw "Merge-PimDbInitPrincipals: PIM_DBINIT_PRINCIPALS is not valid JSON -- refusing to overwrite it: $($_.Exception.Message)" }
        foreach ($p in @($parsed)) { if ($p -and "$($p.name)".Trim()) { [void]$list.Add([ordered]@{ name = "$($p.name)"; appId = "$($p.appId)" }) } }
    }
    $changed = $true
    $hit = @($list | Where-Object { "$($_.name)" -ieq $Name })
    if ($hit.Count -and "$($hit[0].appId)" -ieq $AppId) { $changed = $false }
    elseif ($hit.Count) { $hit[0].appId = $AppId }
    else { [void]$list.Add([ordered]@{ name = $Name; appId = $AppId }) }
    $out = ConvertTo-Json -Compress -Depth 5 -InputObject @($list.ToArray())
    if ($out -notmatch '^\s*\[') { $out = "[$out]" }
    return [pscustomobject]@{ json = $out; changed = $changed }
}
