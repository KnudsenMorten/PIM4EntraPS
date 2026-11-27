#Requires -Version 5.1
<#
.SYNOPSIS
    SEC-PATCH-PIPELINE-1 (1)-(3), the INSTALL side (framework SEC-PATCH-PIPELINE-1, owner 2026-11-26: "all installs upd
    separately to normal updater" / "it should built it without vm req in azure job"): the separate image-only job
    caj-pim-secupdate. Every 15 minutes it checks ONE thing: does THIS install's ring serve an IMAGE-ONLY release of the
    running version (<release>.N, Get-PimImageOnlyUpdateDecision)? Then that release is pulled (the signed Invardia archive,
    the updater's own pull code), built in the install's OWN registry (ACR Tasks over REST, PIM-AcrBuild.ps1) with the bases
    THE RELEASE names, to the release's own tag, and swapped in.
    FIX 2026-11-26 (Invardia, 3.1.70 review scope): the former second trigger -- a rebuild of the running version on a new
    Microsoft digest ('new-base') -- is REMOVED: no rebuild here without the ring and its testGate (rings 0/1 proof).
    NO SCHEMA-QUIESCE, NO RUN GATE (G3): images only -- no schema, data or settings step, no wait for engine runs; a running
    execution keeps its image, the next one uses the new; the web app gets a new revision and ends Single with ONE active
    revision (framework item 6). A code release on the ring is never touched here: the normal updater takes it in its window.

.DESCRIPTION
    🔒 OFF BY DEFAULT, THREE TIMES (owner/Invardia: "an install gets it only when we switch it on"):
      1. setup creates the job only with -SecUpdateJob (Invoke-PimDeployAll) / -Enable (Deploy-PimSecUpdateJob.ps1);
      2. the in-cloud updater converges it only when pim.Settings 'SecUpdateJob' says enabled (Test-PimSecUpdateEnabled);
      3. the job's own entry (tools/pim-engine/secupdate-job-entry.ps1) reads the same setting first and exits 0 when it is
         not on -- a job that exists with the setting off does nothing.
    🔒 RIGHTS: the job signs in as the UPDATER's user-assigned identity (id-pim-updater) and needs nothing that identity does
       not already hold on the approved list (RIGHTS-1, engine/_shared/PIM-RightsList.ps1): Contributor on the install's
       resource group (ACR Tasks listBuildSourceUploadUrl / scheduleRun / runs, the app / job PATCH) and AcrPull
       on the install's registry (the running-image read-back). Get-PimSecUpdateRightsNeeds is that list; Test-PimSecUpdate-
       RightsListed proves it against the approved list and NOTHING here grants a right.
    Shape: every decision PURE (state -> plan) with an injected -Arm seam for the ARM writes, offline-tested in
    tests/Test-PimSecUpdate.ps1. PS 5.1-parse-safe (the job runs on pwsh 7.6), no modules, no az.

      Get-PimSecUpdateJobName / -SettingName / -StateName / -Cron / -EntryPath / -Resources   literals
      Test-PimSecUpdateEnabled          the setting -> enabled (default OFF)
      Get-PimSecUpdateRightsNeeds       the rights the job needs (ids of the approved list)
      Test-PimSecUpdateRightsListed     those against Get-PimApprovedRightsList -> @{ ok; missing }
      Get-PimSecUpdateJobSpec           the job's ARM body, derived from the updater job
      Get-PimSecUpdateJobDrift          what differs between the job and the spec
      Invoke-PimSecUpdateConverge       create / re-write the job when enabled, NOTHING when off; read back
      Get-PimDockerfileBasePins         the pinned digests of one FROM image in a Dockerfile text (the image-patch job's)
      Set-PimDockerfileBasePins         move those pins to one digest (text in, text out; the image-patch job's)
      Get-PimSecUpdateDecision          none | hold | wait | leave-to-updater | build (kind ring-image-only only)
      Test-PimSecUpdateHeld             PIM_UPDATE_HOLD=1 on the updater job -> held (F3)
      Test-PimSecUpdateExecutionsRunning  the other roller's executions -> running (fail closed, F2)
      Get-PimSecUpdatePreSwapVerdict    the last look before the swap: updater not running, Manager image unchanged (F2)
      Wait-PimSecUpdateOtherIdle        the updater's bounded wait while caj-pim-secupdate runs (F2; never stops it)
      (Single + ONE active revision: engine/_shared/PIM-RevisionMode.ps1 Invoke-PimRevisionModeCheck, the updater's own check)
      New-PimSecUpdateStateRecord       pim.Settings 'SecUpdateState' (what was built on which base, the last attempt)
#>
Set-StrictMode -Off

function Get-PimSecUpdateJobName      { return 'caj-pim-secupdate' }
function Get-PimSecUpdateSettingName  { return 'SecUpdateJob' }
function Get-PimSecUpdateStateName    { return 'SecUpdateState' }
function Get-PimSecUpdateUpdaterMinute {
    <#
      PURE. FIXED 2026-11-26 (3.1.71 review K2): the updater's minute (0-14, mod 15) from ITS job's cron -- the daily 'M H * * *'
      (minute M) or the UPDATE NOW quarter cron 'a,b,c,d * * * *' (PIM-UpdateNow.ps1 Get-PimUpdateNowQuarterCron: every minute
      = the nightly minute mod 15) or '*/15' (minute 0). -1 = unknown (any other shape, or nothing read).
    #>
    param([AllowNull()][AllowEmptyString()][string]$UpdaterCron)
    $c = ("$UpdaterCron".Trim() -replace '\s+', ' ')
    if ($c -match '^(\d{1,2}) (\d{1,2}) \* \* \*$') { $m = [int]$Matches[1]; if ($m -le 59 -and [int]$Matches[2] -le 23) { return ($m % 15) } ; return -1 }
    if ($c -match '^(\d{1,2}),(\d{1,2}),(\d{1,2}),(\d{1,2}) \* \* \* \*$') {
        $mm = $Matches; $ms = @(1..4 | ForEach-Object { [int]$mm[$_] })
        if (@($ms | Where-Object { $_ -gt 59 }).Count) { return -1 }
        $o = $ms[0] % 15
        if (@($ms | Where-Object { ($_ % 15) -ne $o }).Count) { return -1 }
        return $o
    }
    if ($c -match '^(\*|0)/15 \* \* \* \*$') { return 0 }
    return -1
}

function Get-PimSecUpdateCron {
    <#
      PURE. 3.1.71 I2: every 15 minutes, never on the updater's minutes. FIXED 2026-11-26 (3.1.71 review K2): the fixed
      7,22,37,52 still equalled the updater's quarter cron when the updater's nightly minute mod 15 = 7 (e.g. 03:07 or 02:52).
      The minutes are now DERIVED from the updater's own cron (-UpdaterCron): (updater minute + 7) mod 15, then +15/+30/+45 --
      a 7-minute offset mod 15 is never 0, so the two never share a minute. Updater minute unknown -> 7,22,37,52 (as before).
    #>
    param([AllowNull()][AllowEmptyString()][string]$UpdaterCron = '')
    $um = Get-PimSecUpdateUpdaterMinute -UpdaterCron $UpdaterCron
    $o = if ($um -lt 0) { 7 } else { ($um + 7) % 15 }
    return ('{0},{1},{2},{3} * * * *' -f $o, ($o + 15), ($o + 30), ($o + 45))
}
function Get-PimSecUpdateEntryPath    { return '/app/PIM4EntraPS/tools/pim-engine/secupdate-job-entry.ps1' }
function Get-PimSecUpdateAcaApiVersion { return '2024-03-01' }
function Get-PimSecUpdateRetryMinutes { <# a failed build of the SAME target on the SAME base is not tried again sooner #> return 60 }
function Get-PimSecUpdateResources    { return [ordered]@{ cpu = 0.5; memory = '1Gi' } }
function Get-PimSecUpdateTimeoutSeconds { <# one execution: build (<= 90 min on a private pool) + roll #> return 7200 }
function Get-PimSecUpdateDockerfilePath { return 'SOLUTIONS/PIM4EntraPS/tools/pim-manager/Dockerfile' }
function Get-PimSecUpdateBaseImage {
    <# PURE. LITERAL. The ONE base PIM pins (tools/pim-manager/Dockerfile, four FROM lines since NET10-PS76). #>
    return [ordered]@{ registry = 'mcr.microsoft.com'; repository = 'dotnet/sdk'; tag = '10.0-noble'; from = 'mcr.microsoft.com/dotnet/sdk:10.0-noble' }
}
# FIX 2026-11-26 (Invardia, 3.1.70 review scope): the NEW-BASE path is REMOVED -- no rebuild on a new Microsoft digest here (no
# ring, no testGate would prove it). Gone with it: Get-PimSecUpdateStampName (PIM_IMAGE_BASE_DIGEST), Read-PimMcrDigest and
# Update-PimSecUpdateContextBase. The fast path is the image-patch job -> <build>.N -> rings 0/1 proof -> rings 2/3 -> this job
# picks the ring's <build>.N up within 15 min and builds it with the bases THE RELEASE names.

function Get-PimSecUpdateField {
    <# PURE. A member of a parsed JSON object or a dictionary, $null when absent. #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Test-PimSecUpdateEnabled {
    <#
      PURE. pim.Settings 'SecUpdateJob' -> @{ enabled; reason }. DEFAULT OFF: no setting, an unreadable one, anything that is
      not an explicit yes = off. Yes = { "enabled": true } (the shape setup writes), or the plain values true / 1 / on / yes.
    #>
    param([AllowNull()]$Value)
    $v = $Value
    if ($v -is [string]) {
        $s = "$v".Trim()
        if (-not $s) { return @{ enabled = $false; reason = "pim.Settings '$(Get-PimSecUpdateSettingName)' is empty -- the security image job is OFF (the default)" } }
        if ($s.StartsWith('{')) { try { $v = $s | ConvertFrom-Json } catch { return @{ enabled = $false; reason = "pim.Settings '$(Get-PimSecUpdateSettingName)' is not readable JSON -- OFF" } } }
        elseif ($s -match '^(?i)(true|1|on|yes)$') { return @{ enabled = $true; reason = "pim.Settings '$(Get-PimSecUpdateSettingName)' = $s -- ON" } }
        else { return @{ enabled = $false; reason = "pim.Settings '$(Get-PimSecUpdateSettingName)' = $s -- OFF" } }
    }
    if ($null -eq $v) { return @{ enabled = $false; reason = "no pim.Settings '$(Get-PimSecUpdateSettingName)' -- the security image job is OFF (the default)" } }
    if ($v -is [bool]) { return @{ enabled = [bool]$v; reason = "pim.Settings '$(Get-PimSecUpdateSettingName)' = $v" } }
    $e = Get-PimSecUpdateField $v 'enabled'
    if ($e -is [bool] -and $e) { return @{ enabled = $true; reason = "pim.Settings '$(Get-PimSecUpdateSettingName)'.enabled = true -- ON" } }
    if ("$e" -match '^(?i)(true|1)$') { return @{ enabled = $true; reason = "pim.Settings '$(Get-PimSecUpdateSettingName)'.enabled = $e -- ON" } }
    return @{ enabled = $false; reason = "pim.Settings '$(Get-PimSecUpdateSettingName)'.enabled is not true -- OFF" }
}

function New-PimSecUpdateSettingValue {
    <# PURE. The value setup writes to switch it ON (or OFF with -Off). #>
    param([switch]$Off, [string]$By = 'setup', [datetime]$NowUtc = [datetime]::UtcNow)
    return [pscustomobject][ordered]@{ enabled = (-not $Off); by = "$By"; changedUtc = $NowUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") }
}

# ---------------------------------------------------------------------------------------------------------------------
# RIGHTS -- the job needs only rights already on the approved list (RIGHTS-1); nothing in this file grants one
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimSecUpdateRightsNeeds {
    <# PURE. LITERAL. Every Azure right the job uses, as the approved list's right id, with the call that needs it. #>
    return @(
        [ordered]@{ identity = 'updater'; id = 'updater.azure.contributor@install-rg'; role = 'Contributor'
                    why = 'ACR Tasks build in the install registry (listBuildSourceUploadUrl, scheduleRun, runs), the app / job PATCH of the swap and of its rollback, revision deactivate' }
        [ordered]@{ identity = 'updater'; id = 'updater.azure.acrpull@registry'; role = 'AcrPull'
                    why = 'pulls its own image; reads the running digests back from the install registry (Update.runningImages)' }
    )
}

function Test-PimSecUpdateRightsListed {
    <#
      PURE. -List = Get-PimApprovedRightsList (or its parsed JSON); -Needs = Get-PimSecUpdateRightsNeeds (or a test's own).
      @{ ok; missing = @(<id>); found = @(<id>); reason }. A need whose identity or right id is not on the list = missing --
      the job is then NOT to be deployed (the caller refuses), and the right is reported, never added.
    #>
    param([Parameter(Mandatory)]$List, [object[]]$Needs = (Get-PimSecUpdateRightsNeeds))
    $missing = New-Object System.Collections.Generic.List[string]; $found = New-Object System.Collections.Generic.List[string]
    $ids = @(Get-PimSecUpdateField $List 'identities')
    foreach ($n in @($Needs)) {
        $who = "$(Get-PimSecUpdateField $n 'identity')"; $rid = "$(Get-PimSecUpdateField $n 'id')"
        $idn = @($ids | Where-Object { $_ -and "$(Get-PimSecUpdateField $_ 'role')" -eq $who })[0]
        $hit = $false
        if ($idn) { $hit = [bool](@(@(Get-PimSecUpdateField $idn 'rights') | Where-Object { $_ -and "$(Get-PimSecUpdateField $_ 'id')" -eq $rid }).Count) }
        if ($hit) { $found.Add($rid) } else { $missing.Add($rid) }
    }
    $ok = ($missing.Count -eq 0)
    return @{ ok = $ok; missing = @($missing.ToArray()); found = @($found.ToArray())
              reason = $(if ($ok) { "every right the job uses is on the approved list ($(@($found.ToArray()) -join ', '))" } else { "NOT on the approved list: $(@($missing.ToArray()) -join ', ') -- the job is not deployed; the right is reported, never added" }) }
}

# ---------------------------------------------------------------------------------------------------------------------
# THE JOB -- derived from the updater job (same image, environment, identity, store settings, registry pull)
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimSecUpdateSignIn {
    <# PURE. The identity a job signs in as: PIM_ManagedIdentityClientId -> that attached user-assigned identity, else system. #>
    param($Resource)
    $o = [ordered]@{ principalId = ''; clientId = ''; kind = ''; resourceId = ''; reason = '' }
    if ($null -eq $Resource) { $o.reason = 'not found'; return [pscustomobject]$o }
    $cid = ''
    foreach ($c in @(Get-PimSecUpdateField (Get-PimSecUpdateField (Get-PimSecUpdateField $Resource 'properties') 'template') 'containers')) {
        foreach ($e in @(Get-PimSecUpdateField $c 'env')) { if ($e -and "$(Get-PimSecUpdateField $e 'name')" -eq 'PIM_ManagedIdentityClientId' -and "$(Get-PimSecUpdateField $e 'value')".Trim()) { $cid = "$(Get-PimSecUpdateField $e 'value')".Trim() } }
        if ($cid) { break }
    }
    $idn = Get-PimSecUpdateField $Resource 'identity'
    if ($cid) {
        $ua = Get-PimSecUpdateField $idn 'userAssignedIdentities'
        $pairs = if ($ua -is [System.Collections.IDictionary]) { @($ua.Keys | ForEach-Object { @{ k = "$_"; v = $ua[$_] } }) } elseif ($ua) { @($ua.PSObject.Properties | ForEach-Object { @{ k = $_.Name; v = $_.Value } }) } else { @() }
        foreach ($p in $pairs) {
            if ("$(Get-PimSecUpdateField $p.v 'clientId')".Trim() -ieq $cid -and "$(Get-PimSecUpdateField $p.v 'principalId')".Trim()) {
                $o.principalId = "$(Get-PimSecUpdateField $p.v 'principalId')".Trim(); $o.clientId = $cid; $o.kind = 'user'; $o.resourceId = "$($p.k)"
                return [pscustomobject]$o
            }
        }
        $o.reason = "it signs in with client id $cid, but no attached user-assigned identity has that client id"; return [pscustomobject]$o
    }
    $sp = "$(Get-PimSecUpdateField $idn 'principalId')".Trim()
    if ($sp) { $o.principalId = $sp; $o.kind = 'system'; return [pscustomobject]$o }
    $o.reason = 'it has no managed identity'; return [pscustomobject]$o
}

function Get-PimSecUpdateJobSpec {
    <#
      PURE. The job's ARM body, DERIVED FROM THE UPDATER JOB (-UpdaterJob = its ARM GET): the same environment, workload
      profile, image (or -Image), store settings, registry pull and USER-ASSIGNED identity; a Schedule trigger 7,22,37,52 (3.1.71 I2), ONE
      execution at a time, no retry, its own size (0.5 CPU / 1 GiB: it only asks the registry to build) and the secupdate
      entry. PIM_SECUPDATE_UPDATER_JOB names the updater (its live env holds the ring watermark). REFUSED (ok = false): an
      updater on its system identity (a second job cannot share it -- the identity move first), a plain secret (only Key
      Vault references are copied, never a value), a registry pulled with a password.
      Returns @{ ok; reason; resource; identity; image }.
    #>
    param([Parameter(Mandatory)]$UpdaterJob, [string]$UpdaterJobName = '', [string]$JobName = (Get-PimSecUpdateJobName),
          [string]$Image = '', [string]$EntryPath = (Get-PimSecUpdateEntryPath), [string]$Cron = '')
    $no = { param($why) return @{ ok = $false; reason = $why; resource = $null; identity = $null; image = '' } }
    # 3.1.71 review K2: no -Cron = derived from the UPDATER's own cron (never its minute); the converge re-writes a job that
    # drifted from it (Get-PimSecUpdateJobDrift compares the cron).
    if (-not "$Cron".Trim()) { $Cron = Get-PimSecUpdateCron -UpdaterCron "$(Get-PimSecUpdateField (Get-PimSecUpdateField (Get-PimSecUpdateField (Get-PimSecUpdateField $UpdaterJob 'properties') 'configuration') 'scheduleTriggerConfig') 'cronExpression')" }
    $si = Get-PimSecUpdateSignIn -Resource $UpdaterJob
    if ($si.kind -ne 'user' -or "$($si.resourceId)" -notmatch '(?i)/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/[^/]+$') {
        return (& $no "the updater job signs in as $(if ($si.kind -eq 'system') { 'its system-assigned identity' } else { "no readable identity ($($si.reason))" }) -- the security image job runs as the updater's USER-ASSIGNED identity, available after the identity move")
    }
    $props = Get-PimSecUpdateField $UpdaterJob 'properties'
    $cfg = Get-PimSecUpdateField $props 'configuration'
    $tpl = Get-PimSecUpdateField $props 'template'
    $c0 = @(Get-PimSecUpdateField $tpl 'containers')[0]
    if (-not $c0) { return (& $no 'the updater job declares no container') }
    $img = if ("$Image".Trim()) { "$Image".Trim() } else { "$(Get-PimSecUpdateField $c0 'image')".Trim() }
    if (-not $img) { return (& $no 'the updater job has no image') }
    $envId = "$(Get-PimSecUpdateField $props 'environmentId')".Trim(); if (-not $envId) { $envId = "$(Get-PimSecUpdateField $props 'managedEnvironmentId')".Trim() }
    if (-not $envId) { return (& $no 'the updater job names no Container Apps environment') }
    $updName = "$UpdaterJobName".Trim(); if (-not $updName) { $updName = "$(Get-PimSecUpdateField $UpdaterJob 'name')".Trim() }
    $engSecrets = @{}
    foreach ($s in @(Get-PimSecUpdateField $cfg 'secrets')) { if ($s -and "$(Get-PimSecUpdateField $s 'name')") { $engSecrets["$(Get-PimSecUpdateField $s 'name')"] = $s } }
    $secrets = New-Object System.Collections.Generic.List[object]
    $envList = New-Object System.Collections.Generic.List[object]
    # the updater's own run switches are NOT copied: this job never runs the normal update
    $skipEnv = '^(PIM_SECUPDATE_.*|PIM_UpdateJobName|PIM_UPDATE_HOLD|PIM_UPDATE_ALLOW_DOWNGRADE|PIM_UPDATE_ALLOW_MAJOR|PIM_UPDATE_NOW.*)$'
    foreach ($e in @(Get-PimSecUpdateField $c0 'env')) {
        $en = "$(Get-PimSecUpdateField $e 'name')"
        if (-not $en -or $en -match $skipEnv) { continue }
        $sr = "$(Get-PimSecUpdateField $e 'secretRef')".Trim()
        if ($sr) {
            $sd = $engSecrets[$sr]
            $kv = "$(Get-PimSecUpdateField $sd 'keyVaultUrl')".Trim()
            if (-not $kv) { return (& $no "the updater job carries '$en' as a plain secret -- the security image job copies only Key Vault references (move the secrets to Key Vault first)") }
            if (-not @($secrets | Where-Object { $_.name -eq $sr }).Count) { $secrets.Add([ordered]@{ name = $sr; keyVaultUrl = $kv; identity = "$(Get-PimSecUpdateField $sd 'identity')".Trim() }) }
            $envList.Add([ordered]@{ name = $en; secretRef = $sr })
        } else {
            $ev = "$(Get-PimSecUpdateField $e 'value')"
            if ($ev -match '(?i)([?&]sig=|AccountKey=|SharedAccessKey=|-----BEGIN)') { return (& $no "the updater job's '$en' looks like a credential -- the security image job carries none") }
            $envList.Add([ordered]@{ name = $en; value = $ev })
        }
    }
    $envList.Add([ordered]@{ name = 'PIM_SECUPDATE'; value = '1' })
    $envList.Add([ordered]@{ name = 'PIM_SECUPDATE_UPDATER_JOB'; value = $updName })
    $regs = New-Object System.Collections.Generic.List[object]
    $uaIds = [ordered]@{}; $uaIds["$($si.resourceId)"] = @{}
    foreach ($rg0 in @(Get-PimSecUpdateField $cfg 'registries')) {
        if (-not $rg0) { continue }
        if ("$(Get-PimSecUpdateField $rg0 'passwordSecretRef')".Trim()) { return (& $no 'the updater job pulls its image with a registry password -- the security image job pulls with a managed identity only') }
        $ri = "$(Get-PimSecUpdateField $rg0 'identity')".Trim()
        if (-not $ri -or $ri -ieq 'system') { $ri = "$($si.resourceId)" }
        elseif ($ri -match '(?i)/userAssignedIdentities/') { $uaIds[$ri] = @{} }
        $regs.Add([ordered]@{ server = "$(Get-PimSecUpdateField $rg0 'server')"; identity = $ri })
    }
    $config = [ordered]@{
        triggerType            = 'Schedule'
        replicaTimeout         = (Get-PimSecUpdateTimeoutSeconds)
        replicaRetryLimit      = 0
        scheduleTriggerConfig  = [ordered]@{ cronExpression = "$Cron"; parallelism = 1; replicaCompletionCount = 1 }
        registries             = @($regs.ToArray())
    }
    if ($secrets.Count) { $config['secrets'] = @($secrets.ToArray()) }
    $p2 = [ordered]@{ environmentId = $envId; configuration = $config
        template = [ordered]@{ containers = @([ordered]@{ name = $JobName; image = $img; command = @('pwsh'); args = @('-NoProfile', '-File', "$EntryPath"); env = @($envList.ToArray()); resources = (Get-PimSecUpdateResources) }) } }
    $wp = "$(Get-PimSecUpdateField $props 'workloadProfileName')".Trim(); if ($wp) { $p2['workloadProfileName'] = $wp }
    $resource = [ordered]@{ location = "$(Get-PimSecUpdateField $UpdaterJob 'location')"; tags = @{ 'pim-component' = 'secupdate' }
                            identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $uaIds }; properties = $p2 }
    return @{ ok = $true; reason = ''; resource = $resource; image = $img; identity = @{ principalId = "$($si.principalId)"; clientId = "$($si.clientId)"; resourceId = "$($si.resourceId)" } }
}

function Get-PimSecUpdateJobDrift {
    <# PURE. What differs between the job as it is (-Job, ARM GET) and the spec -- @() = current. The image is NOT drift: the
       job rolls itself (a newer image the job runs is kept; the updater's job roll moves it with everything else). #>
    param($Job, [Parameter(Mandatory)][hashtable]$Spec)
    $why = New-Object System.Collections.Generic.List[string]
    $cfg = Get-PimSecUpdateField (Get-PimSecUpdateField $Job 'properties') 'configuration'
    $c0 = @(Get-PimSecUpdateField (Get-PimSecUpdateField (Get-PimSecUpdateField $Job 'properties') 'template') 'containers')[0]
    $want = $Spec.resource.properties.template.containers[0]
    if ("$(Get-PimSecUpdateField $cfg 'triggerType')" -ne 'Schedule') { $why.Add("trigger $(Get-PimSecUpdateField $cfg 'triggerType') -> Schedule") }
    $cron = "$(Get-PimSecUpdateField (Get-PimSecUpdateField $cfg 'scheduleTriggerConfig') 'cronExpression')"
    if ($cron -ne "$($Spec.resource.properties.configuration.scheduleTriggerConfig.cronExpression)") { $why.Add("cron '$cron' -> '$($Spec.resource.properties.configuration.scheduleTriggerConfig.cronExpression)'") }
    if ((@(Get-PimSecUpdateField $c0 'args') -join ' ') -ne (@($want.args) -join ' ')) { $why.Add('entry -> the secupdate entry') }
    $have = @{}; foreach ($e in @(Get-PimSecUpdateField $c0 'env')) { if ($e) { $have["$(Get-PimSecUpdateField $e 'name')"] = "$(Get-PimSecUpdateField $e 'value')$(Get-PimSecUpdateField $e 'secretRef')" } }
    $envBad = @(foreach ($e in @($want.env)) { $k = "$($e.name)"; $v = "$($e.value)$($e.secretRef)"; if (-not $have.ContainsKey($k) -or $have[$k] -cne $v) { $k } })
    $wantNames = @($want.env | ForEach-Object { "$($_.name)" })
    $envBad += @($have.Keys | Where-Object { $wantNames -notcontains $_ })
    if ($envBad.Count) { $why.Add("env ($(@($envBad | Select-Object -First 5) -join ', '))") }
    return @($why.ToArray())
}

function Invoke-PimSecUpdateConverge {
    <#
      The job on an install, idempotent, read back. Run by setup (Deploy-PimSecUpdateJob.ps1) and by the in-cloud updater
      (step 2e-secupdate). -Enabled is the setting's answer (Test-PimSecUpdateEnabled): $false = NOTHING is written (an
      existing job is left as it is -- its own entry exits at once while the setting is off; removal is a decision, not a
      converge). -RightsList: the approved list; a needed right that is not on it = nothing written, reported; NO list ($null:
      it could not be built) = state 'refused', nothing written (3.1.70 review F5 -- the check is never skipped).
      -Arm { param($method, $path, $body) } (path WITH api-version; a GET of an absent resource may throw or return $null).
      NEVER throws. @{ lines; changed; warnings; state = off|ok|missing|refused; jobImage; writes }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$UpdaterJob, [Parameter(Mandatory)][bool]$Enabled, [string]$EnabledReason = '',
          [Parameter(Mandatory)][scriptblock]$Arm, $RightsList = $null, [string]$Image = '')
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($level, $text) $lines.Add([pscustomobject]@{ id = 'secupdate'; level = $level; text = $text }) }
    $get = { param($p) try { & $Arm 'GET' $p $null } catch { $null } }
    $state = 'unknown'; $jobImage = ''; $writes = 0; $cronOut = ''
    $jn = Get-PimSecUpdateJobName
    $finish = {
        $arr = @($lines.ToArray())
        return [pscustomobject]@{ lines = $arr; changed = @($arr | Where-Object { $_.level -eq 'changed' }).Count; warnings = @($arr | Where-Object { $_.level -eq 'warn' }).Count
                                  state = $state; jobImage = $jobImage; writes = $writes; cron = $cronOut }
    }
    try {
        if (-not $Enabled) {
            $state = 'off'
            & $add 'info' "secupdate: OFF -- $(if ($EnabledReason) { $EnabledReason } else { "pim.Settings '$(Get-PimSecUpdateSettingName)' is not on" }); job $jn not created or changed"
            return (& $finish)
        }
        # FIX 2026-11-26 (3.1.70 review F5): NO list = NO check = REFUSED. An approved list that could not be built is never
        # read as "nothing to check"; the job is not created or changed until the list is readable again.
        if ($null -eq $RightsList) { $state = 'refused'; & $add 'warn' "secupdate: the approved rights list could not be built -- the rights check cannot run, so job $jn is not created or changed (the next run tries again)"; return (& $finish) }
        $rl = Test-PimSecUpdateRightsListed -List $RightsList
        if (-not $rl.ok) { $state = 'refused'; & $add 'warn' "secupdate: $($rl.reason)"; return (& $finish) }
        $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $aca = "api-version=$(Get-PimSecUpdateAcaApiVersion)"
        $upd = & $get "$rg/providers/Microsoft.App/jobs/$UpdaterJob`?$aca"
        if (-not $upd) { $state = 'missing'; & $add 'warn' "secupdate: the updater job '$UpdaterJob' could not be read -- job $jn not converged"; return (& $finish) }
        $spec = Get-PimSecUpdateJobSpec -UpdaterJob $upd -UpdaterJobName $UpdaterJob -Image $Image
        if (-not $spec.ok) { $state = 'missing'; & $add 'warn' "secupdate: job $jn not converged -- $($spec.reason)"; return (& $finish) }
        $path = "$rg/providers/Microsoft.App/jobs/$jn`?$aca"
        $job = & $get $path
        $why = if ($job) { @(Get-PimSecUpdateJobDrift -Job $job -Spec $spec) } else { @() }
        if (-not $job -or $why.Count) {
            if ($job) {
                # the job's own image stays (it may already run a newer security build); only the definition is converged
                $cur = "$(@(Get-PimSecUpdateField (Get-PimSecUpdateField (Get-PimSecUpdateField $job 'properties') 'template') 'containers')[0].image)".Trim()
                if ($cur) { $spec.resource.properties.template.containers[0].image = $cur; $spec.image = $cur }
            }
            try { $writes++; [void](& $Arm 'PUT' $path $spec.resource) }
            catch { $state = 'missing'; & $add 'warn' "secupdate: job $jn not $(if ($job) { 'updated' } else { 'created' }): $((("$($_.Exception.Message)") -split "`n")[0]) -- the next run retries"; return (& $finish) }
            $back = & $get $path
            $left = if ($back) { @(Get-PimSecUpdateJobDrift -Job $back -Spec $spec) } else { @('not readable') }
            if ($left.Count) { $state = 'missing'; & $add 'warn' "secupdate: job $jn written but does not read back as planned ($($left -join '; ')) -- the next run retries"; return (& $finish) }
            & $add 'changed' "secupdate: job $jn $(if ($job) { "updated ($($why -join '; '))" } else { 'created' }) -- cron $($spec.resource.properties.configuration.scheduleTriggerConfig.cronExpression), image-only, as the updater identity; read back"
        } else { & $add 'info' "secupdate: job $jn current" }
        $jobImage = "$($spec.image)"; $state = 'ok'; $cronOut = "$($spec.resource.properties.configuration.scheduleTriggerConfig.cronExpression)"
    } catch { & $add 'warn' "secupdate: converge stopped: $((("$($_.Exception.Message)") -split "`n")[0])" }
    return (& $finish)
}

# ---------------------------------------------------------------------------------------------------------------------
# THE DOCKERFILE PINS (used by the image-patch job, internal/ops/jobs; this job builds a release as it pins itself)
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

# ---------------------------------------------------------------------------------------------------------------------
# THE DECISION
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimSecUpdateDecision {
    <#
      PURE. What this execution does. Inputs: the running version (the web app's image tag), the version THIS install's ring
      serves ('' = nothing / unreadable), the state of earlier runs (SecUpdateState), whether the NORMAL updater is running
      now (fail closed: the caller passes $true when its executions could not be read), the customer freeze PIM_UPDATE_HOLD=1
      of the updater job (-Hold), and the updater's image-only rule (Get-PimImageOnlyUpdateDecision when loaded; a copy of its
      <release>.N test otherwise). Returns @{ action; kind; version; digest; reason }:
        hold               the install is frozen (PIM_UPDATE_HOLD=1 on the updater job) -- nothing built, nothing rolled
        wait               the normal updater runs now (two rollers never race on one app) / a failed identical try < 60 min
        leave-to-updater   the ring serves a CODE release: the normal updater takes it in its window, never this job
        build              kind 'ring-image-only' ONLY: the ring's <release>.N of the running version, built with the bases
                           THE RELEASE names (its signed source as it is); version = what to build; digest = '' (kept in
                           the shape for SecUpdateState)
        none               nothing to do (said why)
      FIX 2026-11-26 (Invardia, 3.1.70 review scope): there is NO 'new-base' build any more. A new Microsoft digest with no
      <build>.N on the ring is NEVER built here (it would skip the rings 0/1 proof); the image-patch job makes the <build>.N.
    #>
    param([AllowEmptyString()][string]$RunningVersion = '', [AllowEmptyString()][string]$RingVersion = '',
          $State = $null, [bool]$UpdaterRunning = $false, [bool]$Hold = $false,
          [datetime]$NowUtc = [datetime]::UtcNow, [int]$RetryMinutes = (Get-PimSecUpdateRetryMinutes))
    $r = "$RunningVersion".Trim(); $t = "$RingVersion".Trim()
    $out = { param($a, $k, $v, $why) return @{ action = $a; kind = $k; version = $v; digest = ''; reason = $why; needPins = $false } }
    if (-not $r) { return (& $out 'none' '' '' "the running version could not be read from the web app's image -- nothing built") }
    if ($Hold) { return (& $out 'hold' '' '' 'PIM_UPDATE_HOLD=1 on the updater job -- this install is frozen: the security image job builds and rolls nothing') }
    if ($UpdaterRunning) { return (& $out 'wait' '' '' 'the normal updater is running now (or its executions could not be read) -- the next round (15 min) checks again') }
    $isImgOnly = $false
    if ($t) {
        if (Get-Command Get-PimImageOnlyUpdateDecision -ErrorAction SilentlyContinue) { $isImgOnly = [bool](Get-PimImageOnlyUpdateDecision -RunningVersion $r -TargetVersion $t).imageOnly }
        else {
            $tm = [regex]::Match($t, '^(\d+\.\d+\.\d+)\.(\d+)$'); $rm = [regex]::Match($r, '^(\d+\.\d+\.\d+)(?:\.(\d+))?$')
            if ($tm.Success -and $rm.Success -and $tm.Groups[1].Value -eq $rm.Groups[1].Value) { $isImgOnly = ([int]$tm.Groups[2].Value -gt $(if ($rm.Groups[2].Success) { [int]$rm.Groups[2].Value } else { 0 })) }
        }
    }
    $last = Get-PimSecUpdateField $State 'lastAttempt'
    $recent = {
        param($ver)
        if (-not $last -or [bool](Get-PimSecUpdateField $last 'ok')) { return $false }
        if ("$(Get-PimSecUpdateField $last 'version')" -ne $ver) { return $false }
        $at = [datetime]::MinValue
        if (-not [datetime]::TryParse("$(Get-PimSecUpdateField $last 'utc')", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$at)) { return $false }
        return (($NowUtc - $at).TotalMinutes -lt $RetryMinutes)
    }
    if ($isImgOnly) {
        if (& $recent $t) { return (& $out 'wait' 'ring-image-only' $t "the build of $t failed less than $RetryMinutes min ago -- tried again after that") }
        return (& $out 'build' 'ring-image-only' $t "the ring serves the image-only release $t of the running $r -- built here with the bases the release names, to its own tag, and swapped in; no schema step, no run gate")
    }
    if ($t -and $t -ne $r) { return (& $out 'leave-to-updater' '' $t "the ring serves $t (running $r) -- not an image-only release of it: the normal updater takes it in its window") }
    return (& $out 'none' '' '' "the ring serves $(if ($t) { "the running $r" } else { 'nothing readable' }) -- no image-only release to build (a new Microsoft base is never built here without the rings' proof)")
}

function Test-PimSecUpdateHeld {
    <#
      PURE. FIX 2026-11-26 (3.1.70 review F3): the customer freeze. PIM_UPDATE_HOLD is stripped from this job's own spec
      (Get-PimSecUpdateJobSpec), so it is read from the UPDATER job's live environment (-JobEnv: name -> value). '1' = held.
    #>
    param([AllowNull()][hashtable]$JobEnv)
    $v = ''; if ($JobEnv -and $JobEnv.ContainsKey('PIM_UPDATE_HOLD')) { $v = "$($JobEnv['PIM_UPDATE_HOLD'])".Trim() }
    if ($v -eq '1') { return @{ held = $true; reason = 'PIM_UPDATE_HOLD=1 on the updater job -- this install is frozen; the security image job builds and rolls nothing' } }
    return @{ held = $false; reason = '' }
}

function Test-PimSecUpdateExecutionsRunning {
    <#
      PURE. FIX 2026-11-26 (3.1.70 review F2): is the OTHER roller (the updater, read by caj-pim-secupdate; or caj-pim-secupdate,
      read by the updater) running? -Executions = the ARM list of that job's executions; -Readable $false (or $null executions)
      = the list could not be read. FAIL CLOSED:
        unreadable list                                    -> running
        a Running / Processing execution with NO or an
        UNPARSABLE startTime                               -> running
        a Running / Processing execution started less than
        -MaxHours ago (default 6: longer than either job's replicaTimeout, so an older one is a stale record) -> running
      -ExcludeName: an execution name never counted (the caller's own execution, when both read the same job).
      Returns @{ running; reason; names }.
    #>
    param([AllowNull()][object[]]$Executions, [bool]$Readable = $true, [string]$ExcludeName = '',
          [datetime]$NowUtc = [datetime]::UtcNow, [double]$MaxHours = 6)
    if (-not $Readable -or $null -eq $Executions) { return @{ running = $true; reason = 'its executions could not be read -- treated as RUNNING (fail closed)'; names = @() } }
    $names = New-Object System.Collections.Generic.List[string]; $why = ''
    foreach ($x in @($Executions | Where-Object { $null -ne $_ })) {
        $p = Get-PimSecUpdateField $x 'properties'
        $st = "$(Get-PimSecUpdateField $p 'status')".Trim()
        if ($st -notmatch '^(?i)(Running|Processing)$') { continue }
        $nm = "$(Get-PimSecUpdateField $x 'name')".Trim()
        if ($ExcludeName -and $nm -ieq "$ExcludeName".Trim()) { continue }
        $sv = Get-PimSecUpdateField $p 'startTime'
        $at = [datetime]::MinValue; $ok = $false
        if ($sv -is [datetime]) { $at = ([datetime]$sv).ToUniversalTime(); $ok = $true }
        elseif ("$sv".Trim()) { $ok = [datetime]::TryParse("$sv", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$at) }
        if (-not $ok) { $names.Add($nm); if (-not $why) { $why = "execution '$nm' is $st with no readable start time -- treated as RUNNING (fail closed)" }; continue }
        if (($NowUtc.ToUniversalTime() - $at).TotalHours -lt $MaxHours) { $names.Add($nm); if (-not $why) { $why = "execution '$nm' is $st (started $($at.ToString('yyyy-MM-dd HH:mm'))Z)" } }
    }
    if ($names.Count) { return @{ running = $true; reason = $why; names = @($names.ToArray()) } }
    return @{ running = $false; reason = 'no execution is running'; names = @() }
}

function Get-PimSecUpdatePreSwapVerdict {
    <#
      PURE. FIX 2026-11-26 (3.1.70 review F2): the LAST look before anything moves (the build took minutes). go only when
        - the updater is NOT running (Test-PimSecUpdateExecutionsRunning of a FRESH read, fail closed), and
        - the Manager still runs exactly the image it ran when this execution started (-StartImage vs -CurrentImage; an
          unreadable current image = changed).
      Otherwise abort: nothing is swapped (a swap now could put an older <build>.N over what the updater just rolled).
      -TargetVersion vs -RunningVersion: the build goes to the release's OWN tag and never overwrites the running tag (F4).
      Returns @{ go; reason }.
    #>
    param([AllowEmptyString()][string]$StartImage = '', [AllowEmptyString()][string]$CurrentImage = '', [Parameter(Mandatory)][hashtable]$Updater,
          [AllowEmptyString()][string]$TargetVersion = '', [AllowEmptyString()][string]$RunningVersion = '')
    if ($Updater.running) { return @{ go = $false; reason = "the normal updater started while this build ran ($($Updater.reason)) -- nothing swapped" } }
    $s = "$StartImage".Trim(); $c = "$CurrentImage".Trim()
    if (-not $c) { return @{ go = $false; reason = "the web app's image could not be read again before the swap -- nothing swapped" } }
    if ($s -ine $c) { return @{ go = $false; reason = "the web app's image changed while this build ran ($s -> $c) -- nothing swapped" } }
    $tv = "$TargetVersion".Trim(); $rv = "$RunningVersion".Trim()
    if (-not $tv -or $tv -ieq $rv) { return @{ go = $false; reason = "the target tag '$tv' is the running tag -- the running tag is never overwritten" } }
    return @{ go = $true; reason = 'the updater is not running and the web app still runs the image this execution started from' }
}

function Wait-PimSecUpdateOtherIdle {
    <#
      FIX 2026-11-26 (3.1.70 review F2): the UPDATER's side. While caj-pim-secupdate runs, the updater does not roll: it waits
      (bounded, -MaxWaitSeconds) and then SKIPS this run (go = $false; the caller ends 'waiting' and the next run retries). It
      NEVER stops the other job. Seams: -ListJobs { } -> the names of the jobs in the resource group (throws = unreadable);
      -ReadExecutions { param($Job) } -> that job's executions (throws = unreadable); -Sleep { param($Seconds) }.
      No caj-pim-secupdate job in the list = go at once (it is off on most installs). An unreadable job list or execution list
      = running (fail closed). Returns @{ go; waited; reason }.
    #>
    param([Parameter(Mandatory)][scriptblock]$ListJobs, [Parameter(Mandatory)][scriptblock]$ReadExecutions, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [string]$JobName = (Get-PimSecUpdateJobName), [int]$MaxWaitSeconds = 600, [int]$PollSeconds = 30, [scriptblock]$Now = { [datetime]::UtcNow })
    $waited = 0
    while ($true) {
        $names = $null; try { $names = @(& $ListJobs | ForEach-Object { "$_" }) } catch { $names = $null }
        if ($null -ne $names -and -not @($names | Where-Object { $_ -ieq $JobName }).Count) { return @{ go = $true; waited = $waited; reason = "no $JobName job on this install" } }
        $v = $null
        if ($null -eq $names) { $v = @{ running = $true; reason = 'the job list could not be read -- treated as RUNNING (fail closed)' } }
        else {
            $ex = $null; $rd = $true; try { $ex = @(& $ReadExecutions $JobName) } catch { $rd = $false }
            $v = Test-PimSecUpdateExecutionsRunning -Executions $ex -Readable $rd -NowUtc (& $Now)
        }
        if (-not $v.running) { return @{ go = $true; waited = $waited; reason = "$JobName is not running" } }
        if ($waited -ge $MaxWaitSeconds) { return @{ go = $false; waited = $waited; reason = "$JobName is running ($($v.reason)) after $waited s -- this run does not roll; the next run tries again (the other job is never stopped)" } }
        $step = [Math]::Max(1, [Math]::Min($PollSeconds, $MaxWaitSeconds - $waited))
        & $Sleep $step; $waited += $step
    }
}

function New-PimSecUpdateStateRecord {
    <# PURE. pim.Settings 'SecUpdateState': what runs (version + the base it was built on) and the last attempt. #>
    param($Previous = $null, [string]$Version = '', [string]$BaseDigest = '', [string]$Image = '', [string]$Kind = '',
          [bool]$Ok = $true, [string]$Reason = '', [string]$AttemptVersion = '', [string]$AttemptDigest = '', $Revisions = $null,
          [datetime]$NowUtc = [datetime]::UtcNow, [switch]$AttemptOnly)
    $now = $NowUtc.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    $rec = [ordered]@{
        version    = $(if ($AttemptOnly) { "$(Get-PimSecUpdateField $Previous 'version')" } else { "$Version" })
        baseDigest = $(if ($AttemptOnly) { "$(Get-PimSecUpdateField $Previous 'baseDigest')" } else { "$BaseDigest".ToLowerInvariant() })
        image      = $(if ($AttemptOnly) { "$(Get-PimSecUpdateField $Previous 'image')" } else { "$Image" })
        builtUtc   = $(if ($AttemptOnly) { "$(Get-PimSecUpdateField $Previous 'builtUtc')" } else { $now })
        lastAttempt = [ordered]@{ version = $(if ("$AttemptVersion".Trim()) { "$AttemptVersion" } else { "$Version" }); digest = $(if ("$AttemptDigest".Trim()) { "$AttemptDigest".ToLowerInvariant() } else { "$BaseDigest".ToLowerInvariant() })
                                  kind = "$Kind"; ok = [bool]$Ok; reason = "$Reason"; utc = $now }
    }
    if ($null -ne $Revisions) { $rec['revisions'] = $Revisions } elseif ($AttemptOnly -and (Get-PimSecUpdateField $Previous 'revisions')) { $rec['revisions'] = Get-PimSecUpdateField $Previous 'revisions' }
    return [pscustomobject]$rec
}

# After the swap nothing old stays reachable (framework SEC-PATCH-PIPELINE-1 item 6): the job runs the SAME check as the
# updater, engine/_shared/PIM-RevisionMode.ps1 Invoke-PimRevisionModeCheck (one implementation; Update.revisions shape).

function Get-PimSecUpdateCostBasis {
    <#
      PURE. LITERAL ASSUMPTIONS for the cost line setup prints (an ESTIMATE; Azure list prices change -- read the Azure pricing
      page before relying on it): consumption-plan active rates, one execution every 15 min, the run length when nothing
      moves, the ACR Tasks build second rate, a PIM image build length and how often Microsoft moves the base.
    #>
    param([double]$RunSeconds = 90, [int]$BuildsPerMonth = 4, [int]$BuildSeconds = 600)
    $res = Get-PimSecUpdateResources
    $runs = 4 * 24 * 30
    $vcpuS = $runs * $RunSeconds * [double]$res.cpu
    $gibS = $runs * $RunSeconds * [double](("$($res.memory)" -replace '(?i)gi$', ''))
    $vcpuRate = 0.000024; $gibRate = 0.000003; $acrRate = 0.0001
    $job = ($vcpuS * $vcpuRate) + ($gibS * $gibRate)
    $acr = $BuildsPerMonth * $BuildSeconds * $acrRate
    return [ordered]@{ runsPerMonth = $runs; runSeconds = $RunSeconds; cpu = $res.cpu; memory = "$($res.memory)"; vcpuSeconds = $vcpuS; gibSeconds = $gibS
                       jobUsdPerMonth = [Math]::Round($job, 2); acrBuildsPerMonth = $BuildsPerMonth; acrBuildSeconds = $BuildSeconds; acrUsdPerMonth = [Math]::Round($acr, 2)
                       totalUsdPerMonth = [Math]::Round($job + $acr, 2)
                       note = 'consumption active rates (vCPU 0.000024 USD/s, memory 0.000003 USD/GiB-s) before the monthly free grant; ACR Tasks 0.0001 USD per build second on the shared agents; a private install building on its S2 pool also pays the pool hours while it is scaled up (BUILDPOOL-11G)' }
}
