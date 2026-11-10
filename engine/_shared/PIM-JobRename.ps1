#Requires -Version 5.1
<#
.SYNOPSIS
    JOB-RENAME (PIM 3.0.68; framework NAMING-PROGRAMME-1 / RIGHTS-1, owner 2026-11-09): every PIM Container Apps JOB of an
    existing install moves to its standard name caj-pim-<purpose>, running as the same user-assigned identity id-pim-<role>.

.DESCRIPTION
    Azure cannot rename a job. The step CREATES the new job with the old one's spec, proves it, then switches; the old job
    is DISABLED (its trigger set to Manual = no schedule). By default it is KEPT with its identity and its rights.
    -DeleteOld (owner 2026-11-09, confirmed directly in the PIM session: "Yes - delete once new is proven"; default OFF so plan / apply can be tried first): after the
    proof AND the switch read back, the OLD job is DELETED as a separate final step (its system identity goes with it) --
    the rollback record (the old job's full spec without secret values + its job-scoped role assignments) is written FIRST,
    then the DELETE, then read back = 404. Old user-assigned id-pim-* identities that NOTHING attaches any more (and that are
    not a standard id-pim-<role>) are listed by Get-PimJobRenameOrphanIdentities and deleted by
    Remove-PimJobRenameOrphanIdentities under the same rules (re-checked unattached at delete time; record first; 404).
    NEVER: a role assignment deleted (of any identity), anything deleted before the proof, an attached identity deleted.
    Rights are only ADDED (the job-scoped ones are copied to the new job). A RUNNING execution of the old job is never
    interrupted: the step waits, and reports 'waiting' when it is still running.
    WEB APPS ARE NEVER RENAMED (ca-pim-manager, ca-pim-rfa stay).

      ca-pim-tick (or ca-pim-engine) -> caj-pim-engine       ca-pim-update   -> caj-pim-updater
      ca-pim-dbinit                  -> caj-pim-dbinit       ca-pim-publish  -> caj-pim-publish   (MSP managing installs)
      ca-pim-downlink[-s<N>]         -> caj-pim-downlink     caj-pim-asbuilt -> caj-pim-docs      ("Installation documentation";
                                                                                                  keeps id-pim-asbuilt)
    REST only, through caller-supplied seams (no modules, no az CLI):
      -Arm { param($Method, $Path, $Body) }   Path is ARM-relative WITH api-version (or a full nextLink URL)
      -Sql { param($Action, $Name, $Value) }  pim.Settings: 'get' -> the stored value (parsed), 'set' -> write it
    A GET of an absent object may throw (404) or return $null -- both read as "absent".

      Get-PimJobRenameMap            PURE. the old -> new mapping per role
      Get-PimJobRenamePlan           READ ONLY. per PIM job: the spec to copy, the identity, the job-scoped rights, the
                                     settings that name it, the running state, blocked reasons; plus 'notCovered'
      Invoke-PimJobRename            APPLY one role: create (Manual) -> copy rights -> prove one run -> switch -> disable old
      ConvertTo-PimJobRenameReport   the plain per-install plan text for Invardia's approval

    Container Apps job API shapes assumed (api-version 2024-03-01, the version the rest of PIM uses):
      properties.configuration.triggerType  'Schedule' | 'Manual' | 'Event'
      properties.configuration.scheduleTriggerConfig  { cronExpression; parallelism; replicaCompletionCount }
      properties.configuration.manualTriggerConfig    { parallelism; replicaCompletionCount }
      the job's start action, empty body -> { name = <execution> }   (Start-PimAcaJobExecution, override-free)
      GET  {jobId}/executions -> value[].properties.status  Running | Processing | Succeeded | Failed | Stopped | Degraded
      POST {jobId}/listSecrets -> value[] { name; value | keyVaultUrl + identity }
      A configuration PATCH WITHOUT 'secrets' keeps the job's secrets (the proven PIM-UpdateNow / PIM-JobSelfId pattern).
    ASCII only; PS 5.1 + 7.
#>

if (-not (Get-Command Get-PimIdentityMoveField -ErrorAction SilentlyContinue)) {
    $__pimJrMove = Join-Path $PSScriptRoot 'PIM-IdentityMove.ps1'
    if (Test-Path -LiteralPath $__pimJrMove) { . $__pimJrMove }
}
if (-not (Get-Command New-PimInstallNamesRecord -ErrorAction SilentlyContinue)) {
    $__pimJrNames = Join-Path $PSScriptRoot 'PIM-InstallNames.ps1'
    if (Test-Path -LiteralPath $__pimJrNames) { . $__pimJrNames }
}

function Get-PimJobRenameApi { <# PURE. The ARM api-versions (a literal: child-scope safe). #> return @{ aca = '2024-03-01'; auth = '2022-04-01'; rg = '2021-04-01' } }

function Get-PimJobRenameMap {
    <#
      PURE. The rename per role, in the agreed order (one role at a time): role (the -Role value), namesRole (the install
      record's key, Get-PimInstallName), pattern (the OLD job names, regex), new (the standard name), identity (the identity the
      job runs as -- unchanged by this step), note. Reads nothing.
    #>
    return @(
        [pscustomobject]@{ role = 'engine';   namesRole = 'engine';   pattern = '^(?i)(ca-pim-tick|ca-pim-engine)$'; new = 'caj-pim-engine';   identity = 'id-pim-engine';   note = '' }
        [pscustomobject]@{ role = 'updater';  namesRole = 'updater';  pattern = '^(?i)ca-pim-update$';               new = 'caj-pim-updater';  identity = 'id-pim-updater';  note = '' }
        [pscustomobject]@{ role = 'dbinit';   namesRole = 'dbinit';   pattern = '^(?i)ca-pim-dbinit$';               new = 'caj-pim-dbinit';   identity = 'id-pim-dbinit';   note = '' }
        [pscustomobject]@{ role = 'publish';  namesRole = 'publish';  pattern = '^(?i)ca-pim-publish$';              new = 'caj-pim-publish';  identity = 'id-pim-publish';  note = 'MSP managing installs only' }
        [pscustomobject]@{ role = 'downlink'; namesRole = 'downlink'; pattern = '^(?i)ca-pim-downlink(-s\d+)?$';     new = 'caj-pim-downlink'; identity = 'id-pim-downlink'; note = 'MSP managed installs only' }
        [pscustomobject]@{ role = 'docs';     namesRole = 'asbuilt';  pattern = '^(?i)caj-pim-asbuilt$';             new = 'caj-pim-docs';     identity = 'id-pim-asbuilt';  note = 'Installation documentation; the identity id-pim-asbuilt -> id-pim-docs is a later, separate step' }
    )
}

function Get-PimJobRenameRoles { <# PURE. The -Role values. #> return @(Get-PimJobRenameMap | ForEach-Object { $_.role }) }

function Get-PimJobRenameEntry {
    <# PURE. The map entry for an OLD job name ($null = not a job this step renames: a web app, a standard name, a foreign job). #>
    param([AllowEmptyString()][string]$Name)
    $n = "$Name".Trim()
    foreach ($e in @(Get-PimJobRenameMap)) { if ($n -match $e.pattern) { return $e } }
    return $null
}

function Get-PimJobRenameNotCovered {
    <# PURE. What stores a job name / id and is NOT switched by this step (listed in every plan, for the approval). #>
    return @(
        'setup scripts re-run by hand take their job names as parameters with today''s defaults (Setup-PimContainers -TickJobName, Deploy-PimUpdateJob -UpdateJobName / -TickJobName, New-PimHostingPrerequisites -UpdateJobName, Initialize-PimHostingAccess, Grant-PimSupportAccess, ...): after the rename pass the new names (Invoke-PimDeployAll reads them from the resource group)'
        'engine/msp/PIM-MspBuild.ps1 config defaults for a NEW managed / managing build (tickJobName ca-pim-tick, publishJobName ca-pim-publish, downlinkJobName ca-pim-downlink-s6): creation naming of a new build, not read at runtime'
        'the docs job''s identity id-pim-asbuilt -> id-pim-docs: a separate, later identity step (this step keeps id-pim-asbuilt)'
        'anything outside the install''s resource group that names a job: the hybrid worker (PIMHYBRIDWRK) configuration, Invardia back-office checks, customer alerts / Log Analytics queries on the job name (the old job''s run history stays under the old name)'
        'env values that only CONTAIN a job name inside a larger value (JSON such as PIM_DBINIT_SQL_ACCESS updaterUserName -- a database USER name, deliberately not switched)'
        'the OLD job itself (without -DeleteOld): never changed except its trigger (Manual); its env still names itself -- it is not run any more'
        'role assignments held by a deleted old identity / on a deleted old job are never deleted by this step (they are left for the owner-decided clean-up)'
    )
}

function Get-PimJobRenameStandardIdentityNames {
    <# PURE. The standard per-role identities (never an orphan, never deleted by this step). #>
    # id-pim-asbuilt is NOT standard (owner 2026-11-09: the docs identity is id-pim-docs) -- once nothing attaches it, it is an
    # orphan like any old identity (record first, re-checked unattached at delete time)
    return @('web', 'engine', 'updater', 'downlink', 'publish', 'requests', 'mcp', 'dbinit', 'docs') | ForEach-Object { "id-pim-$_" }
}

function Get-PimJobRenameOrphanIdentities {
    <#
      READ-ONLY. The OLD user-assigned identities of the resource group that nothing uses any more: named id-pim-* (PIM's own --
      a customer's identity is never listed), NOT a standard id-pim-<role>, and attached to NO container app, job, SQL server
      or storage account of the group. An identity any of them still attaches is never listed (the engine-exception installs
      keep the engine on its old identity). Each with its Azure role assignments (for the rollback record).
      Returns @(@{ name; id; clientId; principalId; location; tags; roleAssignments }).
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $api = Get-PimIdentityMoveApi
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $ids = @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=$($api.msi)")
    $users = @(@(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.App/containerApps?api-version=$($api.aca)") +
               @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.App/jobs?api-version=$($api.aca)") +
               @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.Sql/servers?api-version=$($api.sql)") +
               @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.Storage/storageAccounts?api-version=$($api.st)"))
    $attached = @{}
    foreach ($u in @($users | Where-Object { $_ })) { foreach ($pair in @(Get-PimIdentityMoveMapPairs (Get-PimJobRenameField (Get-PimJobRenameField $u 'identity') 'userAssignedIdentities'))) { $attached["$($pair.key)".ToLowerInvariant()] = $true } }
    $std = @(Get-PimJobRenameStandardIdentityNames)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($i in @($ids | Where-Object { $_ })) {
        $n = "$(Get-PimJobRenameField $i 'name')"; $id = "$(Get-PimJobRenameField $i 'id')"
        if (-not (Test-PimIdentityMovePimIdentityName -Name $n) -or ($std -contains $n.ToLowerInvariant()) -or $attached.ContainsKey($id.ToLowerInvariant())) { continue }
        $p = Get-PimJobRenameField $i 'properties'; $pid0 = "$(Get-PimJobRenameField $p 'principalId')"
        $ras = @()
        if ($pid0) { $ras = @(Get-PimIdentityMoveList -Seam $Arm -Path "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('$pid0')&api-version=$((Get-PimJobRenameApi).auth)" | Where-Object { "$(Get-PimJobRenameField (Get-PimJobRenameField $_ 'properties') 'principalId')" -ieq $pid0 } | ForEach-Object { $pp = Get-PimJobRenameField $_ 'properties'; [pscustomobject]@{ id = "$(Get-PimJobRenameField $_ 'id')"; roleDefinitionId = "$(Get-PimJobRenameField $pp 'roleDefinitionId')"; scope = "$(Get-PimJobRenameField $pp 'scope')" } }) }
        $out.Add([pscustomobject]@{ name = $n; id = $id; clientId = "$(Get-PimJobRenameField $p 'clientId')"; principalId = $pid0; location = "$(Get-PimJobRenameField $i 'location')"; tags = (Get-PimJobRenameField $i 'tags'); roleAssignments = $ras })
    }
    return @($out.ToArray())
}

function Write-PimJobRenameDeleteRecord {
    <# The rollback record of ONE delete, written BEFORE it and read back (no record = no delete). Returns the file path. #>
    param([Parameter(Mandatory)][string]$LogDir, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][object]$Content)
    if (-not "$LogDir".Trim()) { throw "no -LogDir: the rollback record of $Name cannot be written -- nothing deleted" }
    if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $f = Join-Path $LogDir ("job-rename-delete-$Kind-$Name-" + [datetime]::UtcNow.ToString('yyyyMMdd-HHmmssfff') + '.json')
    Set-Content -LiteralPath $f -Value ($Content | ConvertTo-Json -Depth 40) -Encoding UTF8
    if (-not (Test-Path -LiteralPath $f) -or -not "$([IO.File]::ReadAllText($f))".Trim()) { throw "the rollback record $f did not read back -- nothing deleted" }
    return $f
}

function Wait-PimJobRenameGone {
    <# READ BACK of a DELETE: GET until absent (404 / $null). Returns $true when gone. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Tries = 18, [int]$WaitSeconds = 10)
    for ($i = 1; $i -le [Math]::Max(1, $Tries); $i++) {
        if ($i -gt 1) { & $Sleep $WaitSeconds }
        if (-not (Invoke-PimIdentityMoveGet -Seam $Arm -Path $Path)) { return $true }
    }
    return $false
}

function Remove-PimJobRenameOrphanIdentities {
    <#
      DELETES the orphaned OLD identities (Get-PimJobRenameOrphanIdentities), each only when it is STILL unattached at delete
      time (re-read), its rollback record (name, id, clientId, principalId, location, tags, role assignments) written first,
      then DELETE, then read back = 404. Its role assignments are never deleted. -DryRun writes nothing.
      Returns @(@{ name; state (deleted|kept|failed|dry-run); detail; record }).
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$LogDir = '', [switch]$DryRun, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $msi = (Get-PimIdentityMoveApi).msi
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($o in @(Get-PimJobRenameOrphanIdentities -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup)) {
        if ($DryRun) { $out.Add([pscustomobject]@{ name = $o.name; state = 'dry-run'; detail = "would delete the unattached old identity $($o.name) (record first, then 404 read back)"; record = '' }); continue }
        try {
            # re-checked at delete time: an identity something attaches now is KEPT
            $still = @(Get-PimJobRenameOrphanIdentities -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup | Where-Object { $_.id -ieq $o.id })
            if (-not $still.Count) { $out.Add([pscustomobject]@{ name = $o.name; state = 'kept'; detail = 'attached again (or gone) at delete time -- kept'; record = '' }); continue }
            $f = Write-PimJobRenameDeleteRecord -LogDir $LogDir -Kind 'identity' -Name $o.name -Content ([pscustomobject]@{ kind = 'user-assigned identity'; name = $o.name; id = $o.id; clientId = $o.clientId; principalId = $o.principalId; location = $o.location; tags = $o.tags; roleAssignments = @($o.roleAssignments)
                note = 'a re-created identity gets a NEW principal / client id: its role assignments must be granted to the new principal'; recreate = "Invoke-PimArm -Method PUT -Path '$($o.id)?api-version=$msi' -Body @{ location = '$($o.location)' }"; deletedUtc = [datetime]::UtcNow.ToString('o') })
            [void](& $Arm 'DELETE' "$($o.id)?api-version=$msi" $null)
            if (-not (Wait-PimJobRenameGone -Arm $Arm -Path "$($o.id)?api-version=$msi" -Sleep $Sleep)) { throw "$($o.name) still reads back after the DELETE" }
            $out.Add([pscustomobject]@{ name = $o.name; state = 'deleted'; detail = 'deleted; read back 404'; record = $f })
        } catch { $out.Add([pscustomobject]@{ name = $o.name; state = 'failed'; detail = "$($_.Exception.Message)"; record = '' }) }
    }
    return @($out.ToArray())
}

# ---------------------------------------------------------------------------------------------------------- pure helpers
function Get-PimJobRenameField { param([AllowNull()][object]$Object, [string]$Name) return (Get-PimIdentityMoveField $Object $Name) }

function Copy-PimJobRenameObject {
    <# PURE. A deep copy as plain objects (ConvertTo-Json round trip); $null stays $null. #>
    param([AllowNull()][object]$Object)
    if ($null -eq $Object) { return $null }
    # A LIST stays a list, also with ONE item: ConvertFrom-Json (PS 7) unrolls an array in the pipeline and a function's
    # return unrolls it again -- a job with ONE registry went out as an object (internal 2026-11-09: PUT caj-pim-docs ->
    # 400 "could not be converted to ContainerAppRegistryCredentialsCollection")
    $isList = ($Object -is [System.Collections.IList] -or ($Object -is [System.Collections.IEnumerable] -and $Object -isnot [string] -and $Object -isnot [System.Collections.IDictionary] -and $Object -isnot [pscustomobject]))
    $json = ConvertTo-Json -InputObject $Object -Depth 40 -Compress
    $copy = if ($PSVersionTable.PSVersion.Major -ge 7) { ConvertFrom-Json -InputObject $json -NoEnumerate } else { ConvertFrom-Json -InputObject $json }
    if ($isList) { return , @($copy) }
    return $copy
}

function Get-PimJobRenameTrigger {
    <# PURE. The trigger of a job: @{ type; cron; parallelism; replicaCompletionCount }. #>
    param([AllowNull()][object]$Job)
    $cfg = Get-PimJobRenameField (Get-PimJobRenameField $Job 'properties') 'configuration'
    $t = "$(Get-PimJobRenameField $cfg 'triggerType')"
    $src = if ($t -eq 'Schedule') { Get-PimJobRenameField $cfg 'scheduleTriggerConfig' } elseif ($t -eq 'Manual') { Get-PimJobRenameField $cfg 'manualTriggerConfig' } else { Get-PimJobRenameField $cfg 'eventTriggerConfig' }
    $par = Get-PimJobRenameField $src 'parallelism'; $rcc = Get-PimJobRenameField $src 'replicaCompletionCount'
    return @{ type = $t; cron = "$(Get-PimJobRenameField (Get-PimJobRenameField $cfg 'scheduleTriggerConfig') 'cronExpression')"
              parallelism = $(if ($null -ne $par) { [int]$par } else { 1 }); replicaCompletionCount = $(if ($null -ne $rcc) { [int]$rcc } else { 1 }) }
}

function Get-PimJobRenameSignIn {
    <#
      PURE. Which identity a job signs in as: PIM_ManagedIdentityClientId (any non-signin-front container) -> the ATTACHED
      user-assigned identity with that client id. @{ kind (user|system|unknown); clientId; identityId; identityName; hasSystem }.
      'system' = no client id named (the job runs as its SYSTEM identity); 'unknown' = a client id no attached identity has.
    #>
    param([Parameter(Mandatory)][object]$Job)
    $ident = Get-PimJobRenameField $Job 'identity'
    $hasSys = "$(Get-PimJobRenameField $ident 'type')" -match '(?i)SystemAssigned'
    $cid = ''
    foreach ($c in @(Get-PimJobRenameField (Get-PimJobRenameField (Get-PimJobRenameField $Job 'properties') 'template') 'containers')) {
        if (-not $c -or "$(Get-PimJobRenameField $c 'name')" -eq 'signin-front') { continue }
        foreach ($e in @(Get-PimJobRenameField $c 'env')) { if ($e -and "$(Get-PimJobRenameField $e 'name')" -eq 'PIM_ManagedIdentityClientId' -and "$(Get-PimJobRenameField $e 'value')".Trim()) { $cid = "$(Get-PimJobRenameField $e 'value')".Trim() } }
    }
    if (-not $cid) { return @{ kind = 'system'; clientId = ''; identityId = ''; identityName = ''; hasSystem = $hasSys } }
    foreach ($pair in @(Get-PimIdentityMoveMapPairs (Get-PimJobRenameField $ident 'userAssignedIdentities'))) {
        if ("$(Get-PimJobRenameField $pair.value 'clientId')" -ieq $cid) { return @{ kind = 'user'; clientId = $cid; identityId = "$($pair.key)"; identityName = @("$($pair.key)" -split '/' | Where-Object { $_ })[-1]; hasSystem = $hasSys } }
    }
    return @{ kind = 'unknown'; clientId = $cid; identityId = ''; identityName = ''; hasSystem = $hasSys }
}

function Get-PimJobRenameSecretRefs {
    <# PURE. The job's secrets as REFERENCES (never values): @{ name; kind (keyvault|value); keyVaultUrl; identity }. #>
    param([Parameter(Mandatory)][object]$Job)
    $cfg = Get-PimJobRenameField (Get-PimJobRenameField $Job 'properties') 'configuration'
    return @(@(Get-PimJobRenameField $cfg 'secrets') | Where-Object { $_ } | ForEach-Object {
        $kvu = "$(Get-PimJobRenameField $_ 'keyVaultUrl')".Trim()
        [pscustomobject]@{ name = "$(Get-PimJobRenameField $_ 'name')"; kind = $(if ($kvu) { 'keyvault' } else { 'value' }); keyVaultUrl = $kvu; identity = "$(Get-PimJobRenameField $_ 'identity')" } })
}

function Test-PimJobRenameJobNameVar { <# PURE. An env variable that holds a JOB name / id (PIM_TickJobName, PIM_ENGINE_JOB_NAME, PIM_JobId, ...). #> param([string]$Name) return ("$Name" -match '(?i)job') }

function Get-PimJobRenameSettingChanges {
    <#
      PURE. Every container env value in -Resources (apps + jobs; the OLD job itself left out) that names the old job: a value
      equal to its resource id (any variable), a value ending in /jobs/<old name> (another casing of the id), or a value equal
      to its NAME in a job-name variable (Test-PimJobRenameJobNameVar). Secret references are never touched.
      Returns @(@{ resourceId; resource; kind; container; name; from; to }).
    #>
    param([AllowEmptyCollection()][object[]]$Resources = @(), [Parameter(Mandatory)][string]$OldName, [Parameter(Mandatory)][string]$OldId,
          [Parameter(Mandatory)][string]$NewName, [Parameter(Mandatory)][string]$NewId)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Resources | Where-Object { $_ })) {
        $rid = "$(Get-PimJobRenameField $r 'id')"
        if ($rid -ieq $OldId) { continue }
        $kind = if ($rid -match '(?i)/Microsoft\.App/jobs/') { 'job' } else { 'app' }
        foreach ($c in @(Get-PimJobRenameField (Get-PimJobRenameField (Get-PimJobRenameField $r 'properties') 'template') 'containers')) {
            if (-not $c) { continue }
            foreach ($e in @(Get-PimJobRenameField $c 'env')) {
                if (-not $e -or "$(Get-PimJobRenameField $e 'secretRef')".Trim()) { continue }
                $en = "$(Get-PimJobRenameField $e 'name')"; $v = "$(Get-PimJobRenameField $e 'value')".Trim()
                if (-not $v) { continue }
                $to = ''
                if ($v -ieq $OldId) { $to = $NewId }
                elseif ($v -match ('(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.App/jobs/' + [regex]::Escape($OldName) + '$')) { $to = $NewId }
                elseif ($v -ieq $OldName -and (Test-PimJobRenameJobNameVar $en)) { $to = $NewName }
                if ($to -and $to -cne $v) {
                    $out.Add([pscustomobject]@{ resourceId = $rid; resource = "$(Get-PimJobRenameField $r 'name')"; kind = $kind; container = "$(Get-PimJobRenameField $c 'name')"; name = $en; from = $v; to = $to })
                }
            }
        }
    }
    return @($out.ToArray())
}

function New-PimJobRenameSpec {
    <#
      PURE. The body that CREATES the new job: the old job's spec (location, tags, identity block = the same user-assigned
      identities and SystemAssigned only if the old had it, environmentId, workloadProfileName, configuration -- replicaTimeout,
      replicaRetryLimit, registries, every other setting -- and the template: containers with image / command / args / env /
      resources / probes / volume mounts, init containers, volumes) with the trigger MANUAL (it must not fire before the
      switch) and the old trigger remembered in tags (pim-rename-trigger / pim-rename-cron, so a re-run can finish the
      switch after the old one is already Manual). The new job's PIM_JobId names the new job ITSELF. Secrets: the
      REFERENCES only (-SecretValues, read at apply with listSecrets, fills a plain-value secret; never in a plan or record).
    #>
    param([Parameter(Mandatory)][object]$Job, [Parameter(Mandatory)][string]$NewName, [Parameter(Mandatory)][string]$NewId,
          [hashtable]$SecretValues = @{})
    $oldName = "$(Get-PimJobRenameField $Job 'name')"; $oldId = "$(Get-PimJobRenameField $Job 'id')"
    $pr = Get-PimJobRenameField $Job 'properties'; $cfg = Get-PimJobRenameField $pr 'configuration'
    $trg = Get-PimJobRenameTrigger -Job $Job
    # identity
    $ident = Get-PimJobRenameField $Job 'identity'
    $hasSys = "$(Get-PimJobRenameField $ident 'type')" -match '(?i)SystemAssigned'
    $uai = [ordered]@{}; foreach ($pair in @(Get-PimIdentityMoveMapPairs (Get-PimJobRenameField $ident 'userAssignedIdentities'))) { $uai["$($pair.key)"] = @{} }
    $type = if ($hasSys -and $uai.Count) { 'SystemAssigned,UserAssigned' } elseif ($uai.Count) { 'UserAssigned' } elseif ($hasSys) { 'SystemAssigned' } else { 'None' }
    $identBody = [ordered]@{ type = $type }; if ($uai.Count) { $identBody['userAssignedIdentities'] = $uai }
    # tags
    $tags = [ordered]@{}
    foreach ($pair in @(Get-PimIdentityMoveMapPairs (Get-PimJobRenameField $Job 'tags'))) { $tags["$($pair.key)"] = "$($pair.value)" }
    $tags['pim-renamed-from'] = $oldName
    if (-not $tags.Contains('pim-rename-trigger')) { $tags['pim-rename-trigger'] = $trg.type; if ($trg.type -eq 'Schedule') { $tags['pim-rename-cron'] = $trg.cron } }
    # configuration: everything but the trigger + secrets, then a Manual trigger
    $cfgOut = [ordered]@{}
    if ($cfg) { foreach ($p in @(Get-PimIdentityMoveMapPairs $cfg)) { if ($p.key -notin @('triggerType', 'scheduleTriggerConfig', 'manualTriggerConfig', 'eventTriggerConfig', 'secrets')) { $cfgOut[$p.key] = (Copy-PimJobRenameObject $p.value) } } }
    $cfgOut['triggerType'] = 'Manual'
    $cfgOut['manualTriggerConfig'] = [ordered]@{ parallelism = $trg.parallelism; replicaCompletionCount = $trg.replicaCompletionCount }
    $secs = @(Get-PimJobRenameSecretRefs -Job $Job | ForEach-Object {
        if ($_.kind -eq 'keyvault') { [ordered]@{ name = $_.name; keyVaultUrl = $_.keyVaultUrl; identity = $_.identity } }
        else { [ordered]@{ name = $_.name; value = $(if ($SecretValues.ContainsKey($_.name)) { "$($SecretValues[$_.name])" } else { '' }) } } })
    if ($secs.Count) { $cfgOut['secrets'] = $secs }
    # template: as is, PIM_JobId = the new job itself
    $tpl = Copy-PimJobRenameObject (Get-PimJobRenameField $pr 'template')
    foreach ($c in @(Get-PimJobRenameField $tpl 'containers')) {
        if (-not $c) { continue }
        foreach ($e in @(Get-PimJobRenameField $c 'env')) { if ($e -and "$(Get-PimJobRenameField $e 'name')" -eq 'PIM_JobId' -and "$(Get-PimJobRenameField $e 'value')" -ieq $oldId) { $e.value = $NewId } }
    }
    $props = [ordered]@{}
    $envId = "$(Get-PimJobRenameField $pr 'environmentId')".Trim(); if (-not $envId) { $envId = "$(Get-PimJobRenameField $pr 'managedEnvironmentId')".Trim() }
    if ($envId) { $props['environmentId'] = $envId }
    $wp = "$(Get-PimJobRenameField $pr 'workloadProfileName')".Trim(); if ($wp) { $props['workloadProfileName'] = $wp }
    $props['configuration'] = $cfgOut
    $props['template'] = $tpl
    return [ordered]@{ location = "$(Get-PimJobRenameField $Job 'location')"; tags = $tags; identity = $identBody; properties = $props }
}

function Get-PimJobRenameRunning {
    <# PURE. The executions of a job that are still running (Running / Processing): names. #>
    param([AllowEmptyCollection()][object[]]$Executions = @())
    return @(@($Executions | Where-Object { $_ -and "$(Get-PimJobRenameField (Get-PimJobRenameField $_ 'properties') 'status')" -in @('Running', 'Processing') }) | ForEach-Object { "$(Get-PimJobRenameField $_ 'name')" })
}

function Get-PimJobRenameJobAssignments {
    <# PURE. The role assignments made AT a scope (not inherited from above): @(@{ id; principalId; principalType; roleDefinitionId }). #>
    param([AllowEmptyCollection()][object[]]$Assignments = @(), [Parameter(Mandatory)][string]$Scope)
    return @(@($Assignments | Where-Object { $_ }) | Where-Object { "$(Get-PimJobRenameField (Get-PimJobRenameField $_ 'properties') 'scope')".TrimEnd('/') -ieq $Scope.TrimEnd('/') } | ForEach-Object {
        $p = Get-PimJobRenameField $_ 'properties'
        [pscustomobject]@{ id = "$(Get-PimJobRenameField $_ 'id')"; principalId = "$(Get-PimJobRenameField $p 'principalId')"; principalType = "$(Get-PimJobRenameField $p 'principalType')"; roleDefinitionId = "$(Get-PimJobRenameField $p 'roleDefinitionId')" } })
}

function Get-PimJobRenameAssignmentsToCopy {
    <# PURE. The old job's own assignments the new job's scope does not hold yet (same principal + role). #>
    param([AllowEmptyCollection()][object[]]$Old = @(), [AllowEmptyCollection()][object[]]$New = @())
    $k = { param($a) "$($a.principalId)".ToLowerInvariant() + '|' + (@("$($a.roleDefinitionId)" -split '/')[-1]).ToLowerInvariant() }
    $have = @{}; foreach ($a in @($New | Where-Object { $_ })) { $have[(& $k $a)] = $true }
    $seen = @{}
    return @(foreach ($a in @($Old | Where-Object { $_ })) { $kk = & $k $a; if (-not $have.ContainsKey($kk) -and -not $seen.ContainsKey($kk)) { $seen[$kk] = $true; $a } })
}

function Get-PimJobRenameSqlPlan {
    <#
      PURE. The pim.Settings writes one role's switch makes: SchedulerTickJobId (the engine; only when it names the old job --
      another value is kept) and InstallNames (the record, New-PimInstallNamesRecord: only this role's name changes).
      -Current: @{ SchedulerTickJobId = <value or $null>; InstallNames = <record or $null> }; -Read: whether they were read.
      Returns @(@{ name; from; to; statement }) -- the statement is the T-SQL the caller's -Sql seam runs (text for the plan).
    #>
    param([Parameter(Mandatory)][object]$Entry, [Parameter(Mandatory)][string]$OldName, [Parameter(Mandatory)][string]$OldId,
          [Parameter(Mandatory)][string]$NewName, [Parameter(Mandatory)][string]$NewId, [hashtable]$Current = @{}, [bool]$Read = $true)
    $out = New-Object System.Collections.Generic.List[object]
    $st = { param($n, $v) $j = (ConvertTo-Json -InputObject $v -Compress -Depth 8) -replace "'", "''"; "MERGE pim.Settings AS t USING (SELECT N'$n' AS Name) AS s ON t.Name = s.Name WHEN MATCHED THEN UPDATE SET ValueJson = N'$j', UpdatedUtc = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, ValueJson, UpdatedUtc) VALUES (N'$n', N'$j', SYSUTCDATETIME());" }
    if ($Entry.role -eq 'engine') {
        $cur = if ($Current.ContainsKey('SchedulerTickJobId')) { "$($Current['SchedulerTickJobId'])".Trim().Trim('"') } else { '' }
        if (-not $Read -or $cur -ieq $OldId) { $out.Add([pscustomobject]@{ name = 'SchedulerTickJobId'; from = $(if ($Read) { $cur } else { '(not read)' }); to = $NewId; value = $NewId; statement = (& $st 'SchedulerTickJobId' $NewId) }) }
    }
    $recCur = if ($Current.ContainsKey('InstallNames')) { $Current['InstallNames'] } else { $null }
    if (Get-Command New-PimInstallNamesRecord -ErrorAction SilentlyContinue) {
        $nmKey = "$($Entry.namesRole)"; $nmMap = @{}; $nmMap[$nmKey] = $NewName
        $r = New-PimInstallNamesRecord -Names $nmMap -Current $recCur
        $was = ''; if ($null -ne $recCur) { $was = "$(Get-PimJobRenameField $recCur $Entry.namesRole)".Trim() }
        if (-not $Read -or $was -ne $NewName) {
            $out.Add([pscustomobject]@{ name = 'InstallNames'; from = $(if ($Read) { $(if ($was) { "$($Entry.namesRole)=$was" } else { "$($Entry.namesRole) not recorded" }) } else { '(not read)' }); to = "$($Entry.namesRole)=$NewName"; value = ([pscustomobject]$r.record); statement = (& $st 'InstallNames' ([pscustomobject]$r.record)) })
        }
    }
    return @($out.ToArray())
}

# ---------------------------------------------------------------------------------------------------------- reads
function Read-PimJobRenameInstall {
    <# READ. The install's container apps and jobs (resource group); an absent group throws (a wrong subscription / name). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $api = Get-PimJobRenameApi
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $rgObj = Invoke-PimIdentityMoveGet -Seam $Arm -Path "$rg`?api-version=$($api.rg)"
    if (-not $rgObj) { throw "resource group $ResourceGroup was not found in subscription $SubscriptionId (wrong subscription or name?) -- nothing planned" }
    return @{ rgId = $rg; location = "$(Get-PimJobRenameField $rgObj 'location')"
              apps = @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.App/containerApps?api-version=$($api.aca)")
              jobs = @(Get-PimIdentityMoveList -Seam $Arm -Path "$rg/providers/Microsoft.App/jobs?api-version=$($api.aca)") }
}

function Read-PimJobRenameScopeAssignments {
    <# READ. The role assignments AT one scope (atScope() also returns inherited ones: filtered). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Scope)
    $api = Get-PimJobRenameApi
    $all = @(Get-PimIdentityMoveList -Seam $Arm -Path "$Scope/providers/Microsoft.Authorization/roleAssignments?`$filter=atScope()&api-version=$($api.auth)")
    return @(Get-PimJobRenameJobAssignments -Assignments $all -Scope $Scope)
}

function Read-PimJobRenameExecutions {
    <# READ. A job's executions (absent -> none). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$JobId)
    return @(Get-PimIdentityMoveList -Seam $Arm -Path "$JobId/executions?api-version=$((Get-PimJobRenameApi).aca)")
}

function Read-PimJobRenameSql {
    <# READ. pim.Settings SchedulerTickJobId + InstallNames through -Sql ('get'); no seam / a failed read -> @{ read = $false }. #>
    param([scriptblock]$Sql)
    if (-not $Sql) { return @{ read = $false; reason = 'no SQL seam (-Sql): the pim.Settings writes are listed as statements, the switch waits for them'; values = @{} } }
    try {
        $v = @{ SchedulerTickJobId = (& $Sql 'get' 'SchedulerTickJobId' $null); InstallNames = (& $Sql 'get' 'InstallNames' $null) }
        if ($v.InstallNames -is [string] -and "$($v.InstallNames)".Trim()) { try { $v.InstallNames = ($v.InstallNames | ConvertFrom-Json) } catch { } }
        return @{ read = $true; reason = ''; values = $v }
    } catch { return @{ read = $false; reason = "pim.Settings could not be read: $((("$($_.Exception.Message)") -split "`n")[0])"; values = @{} } }
}

# ---------------------------------------------------------------------------------------------------------- the plan
function Get-PimJobRenamePlan {
    <#
      READ-ONLY. One row per PIM job this step renames (Get-PimJobRenameMap): old name / id, new name / id, whether the new job
      exists (and is ours: tag pim-renamed-from), the old job's trigger, the identity it signs in as, the secrets (references
      only), the job-scoped role assignments to copy, the settings that name it (other apps' / jobs' env, pim.Settings), its
      running executions, and a state:
        rename   ready (create -> copy -> prove -> switch -> disable)
        waiting  an old execution is running (never interrupted; the step waits)
        blocked  never renamed (reasons): signs in as its SYSTEM identity (its rights would not carry to the new job's new
                 system identity), a registry / Key Vault secret read as 'system', an event trigger, a second job for the
                 same new name, a job of that name that this step did not create
        done     the new job exists (ours), the old one is Manual and nothing names the old one any more
      -Sql: pim.Settings read ('get'); without it the writes are listed and the switch waits for them.
      Returns @{ subscriptionId; resourceGroup; location; jobs; sqlRead; sqlReason; notCovered }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [scriptblock]$Sql, [AllowNull()][object]$Install = $null, [switch]$DeleteOld)
    $inst = if ($Install) { $Install } else { Read-PimJobRenameInstall -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup }
    $sq = Read-PimJobRenameSql -Sql $Sql
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $resources = @(@($inst.apps) + @($inst.jobs) | Where-Object { $_ })
    $jobByName = @{}; foreach ($j in @($inst.jobs | Where-Object { $_ })) { $jobByName["$(Get-PimJobRenameField $j 'name')".ToLowerInvariant()] = $j }
    $rows = New-Object System.Collections.Generic.List[object]
    $taken = @{}
    foreach ($j in @($inst.jobs | Where-Object { $_ } | Sort-Object { "$(Get-PimJobRenameField $_ 'name')" })) {
        $name = "$(Get-PimJobRenameField $j 'name')"; $e = Get-PimJobRenameEntry -Name $name
        if (-not $e) { continue }
        $oldId = "$(Get-PimJobRenameField $j 'id')"; if (-not $oldId) { $oldId = "$rg/providers/Microsoft.App/jobs/$name" }
        $newId = "$rg/providers/Microsoft.App/jobs/$($e.new)"
        $newJob = $jobByName[$e.new.ToLowerInvariant()]
        $blocked = New-Object System.Collections.Generic.List[string]
        $trg = Get-PimJobRenameTrigger -Job $j
        $si = Get-PimJobRenameSignIn -Job $j
        if ($si.kind -eq 'system') { $blocked.Add("$name signs in as its SYSTEM identity (no PIM_ManagedIdentityClientId): its rights would not carry over to a new job's new system identity -- move it to id-pim-$($e.namesRole) first (Move-PimIdentities.ps1)") }
        if ($si.kind -eq 'unknown') { $blocked.Add("$name names client id $($si.clientId) in PIM_ManagedIdentityClientId but no attached identity has it -- fix its identity first") }
        $cfg = Get-PimJobRenameField (Get-PimJobRenameField $j 'properties') 'configuration'
        foreach ($rr in @(Get-PimJobRenameField $cfg 'registries')) { if ($rr -and "$(Get-PimJobRenameField $rr 'identity')" -ieq 'system') { $blocked.Add("$name pulls its image from $(Get-PimJobRenameField $rr 'server') as its SYSTEM identity: a new job's system identity would hold no AcrPull") } }
        $secs = @(Get-PimJobRenameSecretRefs -Job $j)
        foreach ($s in @($secs | Where-Object { $_.kind -eq 'keyvault' -and $_.identity -ieq 'system' })) { $blocked.Add("$name reads the Key Vault secret $($s.name) as its SYSTEM identity: a new job's system identity would hold no Key Vault right") }
        if ($trg.type -notin @('Schedule', 'Manual')) { $blocked.Add("$name has a '$($trg.type)' trigger: this step renames Schedule and Manual jobs only") }
        if ($taken.ContainsKey($e.new)) { $blocked.Add("$name and $($taken[$e.new]) would both become $($e.new): only one can -- the owner decides which") } else { $taken[$e.new] = $name }
        $ours = $false
        if ($newJob) {
            $tagFrom = "$(Get-PimJobRenameField (Get-PimJobRenameField $newJob 'tags') 'pim-renamed-from')"
            $ours = ($tagFrom -ieq $name)
            if (-not $ours) { $blocked.Add("a job named $($e.new) already exists and was not created by this step from $name (tag pim-renamed-from = '$tagFrom') -- never overwritten") }
        }
        $raOld = @(); $raNew = @(); $raReadErr = ''
        try { $raOld = @(Read-PimJobRenameScopeAssignments -Arm $Arm -Scope $oldId); if ($newJob) { $raNew = @(Read-PimJobRenameScopeAssignments -Arm $Arm -Scope $newId) } } catch { $raReadErr = "$((("$($_.Exception.Message)") -split "`n")[0])" }
        if ($raReadErr) { $blocked.Add("the role assignments on $name could not be read ($raReadErr): they would not be copied -- the Support app needs Microsoft.Authorization/roleAssignments/read there") }
        $toCopy = @(Get-PimJobRenameAssignmentsToCopy -Old $raOld -New $raNew)
        $running = @(Get-PimJobRenameRunning -Executions (Read-PimJobRenameExecutions -Arm $Arm -JobId $oldId))
        $settings = @(Get-PimJobRenameSettingChanges -Resources $resources -OldName $name -OldId $oldId -NewName $e.new -NewId $newId)
        $sqlW = @(Get-PimJobRenameSqlPlan -Entry $e -OldName $name -OldId $oldId -NewName $e.new -NewId $newId -Current $sq.values -Read $sq.read)
        $origTrigger = $trg
        if ($newJob -and $ours -and $trg.type -eq 'Manual') {
            # the old one may already be disabled by this step: its original trigger is on the new job's tags
            $tt = "$(Get-PimJobRenameField (Get-PimJobRenameField $newJob 'tags') 'pim-rename-trigger')"
            if ($tt -eq 'Schedule') { $origTrigger = @{ type = 'Schedule'; cron = "$(Get-PimJobRenameField (Get-PimJobRenameField $newJob 'tags') 'pim-rename-cron')"; parallelism = $trg.parallelism; replicaCompletionCount = $trg.replicaCompletionCount } }
        }
        $newTrg = if ($newJob) { Get-PimJobRenameTrigger -Job $newJob } else { $null }
        $isDone = [bool]($newJob -and $ours -and $trg.type -eq 'Manual' -and -not $settings.Count -and -not $sqlW.Count -and $sq.read -and
                         ($origTrigger.type -ne 'Schedule' -or ($newTrg -and $newTrg.type -eq 'Schedule' -and $newTrg.cron -eq $origTrigger.cron)))
        $state = if ($blocked.Count) { 'blocked' } elseif ($isDone) { 'done' } elseif ($running.Count) { 'waiting' } else { 'rename' }
        $rows.Add([pscustomobject]@{
            role = $e.role; namesRole = $e.namesRole; old = $name; oldId = $oldId; new = $e.new; newId = $newId; newExists = [bool]$newJob; newIsOurs = $ours
            state = $state; blocked = @($blocked.ToArray()); running = $running; note = $e.note
            trigger = $origTrigger; currentTrigger = $trg; newTrigger = $newTrg
            signIn = $si; identities = @(@(Get-PimIdentityMoveMapPairs (Get-PimJobRenameField (Get-PimJobRenameField $j 'identity') 'userAssignedIdentities')) | ForEach-Object { @("$($_.key)" -split '/')[-1] })
            hasSystem = $si.hasSystem; secrets = $secs; valueSecrets = @($secs | Where-Object { $_.kind -eq 'value' } | ForEach-Object { $_.name })
            location = "$(Get-PimJobRenameField $j 'location')"; environmentId = "$(Get-PimJobRenameField (Get-PimJobRenameField $j 'properties') 'environmentId')"
            workloadProfileName = "$(Get-PimJobRenameField (Get-PimJobRenameField $j 'properties') 'workloadProfileName')"
            replicaTimeout = (Get-PimJobRenameField $cfg 'replicaTimeout'); replicaRetryLimit = (Get-PimJobRenameField $cfg 'replicaRetryLimit')
            containers = @(@(Get-PimJobRenameField (Get-PimJobRenameField (Get-PimJobRenameField $j 'properties') 'template') 'containers') | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ name = "$(Get-PimJobRenameField $_ 'name')"; image = "$(Get-PimJobRenameField $_ 'image')"; env = @(@(Get-PimJobRenameField $_ 'env') | Where-Object { $_ } | ForEach-Object { "$(Get-PimJobRenameField $_ 'name')" }) } })
            roleAssignments = @($raOld); toCopy = $toCopy; settings = $settings; sql = $sqlW
        })
    }
    $nc = New-Object System.Collections.Generic.List[string]
    foreach ($x in @(Get-PimJobRenameNotCovered)) { $nc.Add($x) }
    if (-not $sq.read) { $nc.Add("pim.Settings (SchedulerTickJobId, InstallNames) NOT READ: $($sq.reason)") }
    $orph = @(); $orphErr = ''
    try { $orph = @(Get-PimJobRenameOrphanIdentities -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup) } catch { $orphErr = "$((("$($_.Exception.Message)") -split "`n")[0])" }
    if ($orphErr) { $nc.Add("the old identities could not be read ($orphErr): none is listed for deletion") }
    return @{ subscriptionId = $SubscriptionId; resourceGroup = $ResourceGroup; rgId = $rg; location = $inst.location; jobs = @($rows.ToArray())
              deleteOld = [bool]$DeleteOld; orphanIdentities = $orph
              sqlRead = [bool]$sq.read; sqlReason = "$($sq.reason)"; notCovered = @($nc.ToArray()); plannedUtc = [datetime]::UtcNow.ToString('o') }
}

# ---------------------------------------------------------------------------------------------------------- writes
function Set-PimJobRenameTrigger {
    <#
      ONE job's trigger: -Type Schedule (-Cron) or Manual. READ-MODIFY-WRITE of the configuration WITHOUT secrets (a GET
      returns none with values; sending them back would blank them -- omitted they are kept), READ BACK. -DryRun writes
      nothing. Returns @{ changed; detail }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$JobId, [Parameter(Mandatory)][ValidateSet('Schedule', 'Manual')][string]$Type,
          [string]$Cron = '', [int]$Parallelism = 1, [int]$ReplicaCompletionCount = 1, [switch]$DryRun,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$ReadBackTries = 12, [int]$ReadBackWaitSeconds = 10)
    $path = "$JobId`?api-version=$((Get-PimJobRenameApi).aca)"
    $j = Invoke-PimIdentityMoveGet -Seam $Arm -Path $path
    if (-not $j) { throw "$JobId not found" }
    $cur = Get-PimJobRenameTrigger -Job $j
    if ($cur.type -eq $Type -and ($Type -eq 'Manual' -or $cur.cron -eq $Cron)) { return @{ changed = $false; detail = "already $Type$(if ($Type -eq 'Schedule') { " ($Cron)" })" } }
    if ($Type -eq 'Schedule' -and -not "$Cron".Trim()) { throw "no schedule to set on $JobId" }
    $what = "$(@($JobId -split '/')[-1]) trigger $($cur.type)$(if ($cur.type -eq 'Schedule') { " ($($cur.cron))" }) -> $Type$(if ($Type -eq 'Schedule') { " ($Cron)" })"
    if ($DryRun) { return @{ changed = $true; dryRun = $true; detail = $what } }
    $cfg = Get-PimJobRenameField (Get-PimJobRenameField $j 'properties') 'configuration'
    $out = [ordered]@{}
    foreach ($p in @(Get-PimIdentityMoveMapPairs $cfg)) { if ($p.key -notin @('secrets', 'triggerType', 'scheduleTriggerConfig', 'manualTriggerConfig', 'eventTriggerConfig')) { $out[$p.key] = $p.value } }
    $out['triggerType'] = $Type
    if ($Type -eq 'Schedule') { $out['scheduleTriggerConfig'] = [ordered]@{ cronExpression = $Cron; parallelism = $Parallelism; replicaCompletionCount = $ReplicaCompletionCount } }
    else { $out['manualTriggerConfig'] = [ordered]@{ parallelism = $Parallelism; replicaCompletionCount = $ReplicaCompletionCount } }
    [void](Invoke-PimJobRenamePatch -Arm $Arm -Path $path -Body @{ properties = @{ configuration = $out } } -Sleep $Sleep)
    $b = $null
    for ($i = 1; $i -le [Math]::Max(1, $ReadBackTries); $i++) {
        if ($i -gt 1) { & $Sleep $ReadBackWaitSeconds }
        $b = Invoke-PimIdentityMoveGet -Seam $Arm -Path $path
        $bt = Get-PimJobRenameTrigger -Job $b
        if ($bt.type -eq $Type -and ($Type -eq 'Manual' -or $bt.cron -eq $Cron)) { return @{ changed = $true; detail = $what } }
    }
    throw "read-back of $(@($JobId -split '/')[-1]): the trigger is not $Type$(if ($Type -eq 'Schedule') { " ($Cron)" }) after $ReadBackTries read(s)"
}

function Invoke-PimJobRenamePatch {
    <#
      A PATCH that waits out "operation in progress": a job ARM is still finishing a change on (a create, a trigger switch, a
      run starting) answers 409 ContainerAppsJobOperationInProgress (internal + a test install 2026-11-09, the updater's
      switch). Retries every -WaitSeconds up to -Tries times; any other error is thrown at once.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][object]$Body,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Tries = 18, [int]$WaitSeconds = 10)
    for ($i = 1; ; $i++) {
        try { return (& $Arm 'PATCH' $Path $Body) }
        catch {
            if ($i -ge $Tries -or "$($_.Exception.Message)" -notmatch '(?i)OperationInProgress') { throw }
            & $Sleep $WaitSeconds
        }
    }
}

function Set-PimJobRenameEnv {
    <#
      ONE app / job: env values switched (-Changes @(@{ container; name; from; to }) -- only where the value is still 'from').
      READ-MODIFY-WRITE of the template only, READ BACK. Returns @{ changed; detail }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceId, [Parameter(Mandatory)][object[]]$Changes, [switch]$DryRun,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$ReadBackTries = 12, [int]$ReadBackWaitSeconds = 10)
    $path = "$ResourceId`?api-version=$((Get-PimJobRenameApi).aca)"
    $o = Invoke-PimIdentityMoveGet -Seam $Arm -Path $path
    if (-not $o) { throw "$ResourceId not found" }
    $tpl = Copy-PimJobRenameObject (Get-PimJobRenameField (Get-PimJobRenameField $o 'properties') 'template')
    $done = New-Object System.Collections.Generic.List[string]
    foreach ($c in @(Get-PimJobRenameField $tpl 'containers')) {
        if (-not $c) { continue }
        foreach ($e in @(Get-PimJobRenameField $c 'env')) {
            if (-not $e) { continue }
            foreach ($ch in @($Changes | Where-Object { "$($_.container)" -eq "$(Get-PimJobRenameField $c 'name')" -and "$($_.name)" -eq "$(Get-PimJobRenameField $e 'name')" })) {
                if ("$(Get-PimJobRenameField $e 'value')".Trim() -ieq "$($ch.from)" -and "$(Get-PimJobRenameField $e 'value')" -cne "$($ch.to)") { $e.value = "$($ch.to)"; $done.Add("$($ch.container)/$($ch.name) = $($ch.to)") }
            }
        }
    }
    if (-not $done.Count) { return @{ changed = $false; detail = 'already as asked' } }
    if ($DryRun) { return @{ changed = $true; dryRun = $true; detail = ($done -join '; ') } }
    [void](Invoke-PimJobRenamePatch -Arm $Arm -Path $path -Body @{ properties = @{ template = $tpl } } -Sleep $Sleep)
    for ($i = 1; $i -le [Math]::Max(1, $ReadBackTries); $i++) {
        if ($i -gt 1) { & $Sleep $ReadBackWaitSeconds }
        $b = Invoke-PimIdentityMoveGet -Seam $Arm -Path $path
        $bad = 0
        foreach ($ch in $Changes) {
            $v = @(@(Get-PimJobRenameField (Get-PimJobRenameField (Get-PimJobRenameField $b 'properties') 'template') 'containers') | Where-Object { $_ -and "$(Get-PimJobRenameField $_ 'name')" -eq "$($ch.container)" } | ForEach-Object { @(Get-PimJobRenameField $_ 'env') } | Where-Object { $_ -and "$(Get-PimJobRenameField $_ 'name')" -eq "$($ch.name)" } | ForEach-Object { "$(Get-PimJobRenameField $_ 'value')" })
            if (-not ($v -contains "$($ch.to)")) { $bad++ }
        }
        if (-not $bad) { return @{ changed = $true; detail = ($done -join '; ') } }
    }
    throw "read-back of $(@($ResourceId -split '/')[-1]): $($done -join '; ') not confirmed"
}

# ---------------------------------------------------------------------------------------------------------- apply one role
function Invoke-PimJobRename {
    <#
      APPLY ONE role of a plan (Get-PimJobRenamePlan), in order, each step read back:
        1 create   the new job = the old one's spec with a MANUAL trigger (plain-value secrets copied with listSecrets, never
                   recorded); read back until provisioned
        2 rights   each job-scoped role assignment of the old job copied to the new job (deterministic name), read back
        3 prove    ONE manual execution of the new job: Succeeded (+ -Prove { param($row, $execution) -> @{ ok; detail } }).
                   A FAILED proof STOPS: nothing switched, the old job untouched, state 'failed', undo = delete the NEW job
        4 switch   the new job gets the old schedule (same cron); every setting that names the old job (apps' / jobs' env,
                   pim.Settings SchedulerTickJobId + InstallNames through -Sql) names the new one
        5 disable  the OLD job's trigger -> Manual (kept, with its identity and rights)
      An old execution still running before 3 / 4 = waited for (-WaitTries x -WaitSeconds), then state 'waiting' (never
      stopped). Never a DELETE: not of the old job, not of a role assignment. -DryRun writes nothing.
      Returns the record @{ role; old; new; state (done|nothing-to-do|waiting|blocked|failed|dry-run); steps (step, what,
      readBack, undo); rollback (newest first); proof; error; failedStep }; with -LogDir it is also written there as JSON.
    #>
    param([Parameter(Mandatory)][object]$Plan, [Parameter(Mandatory)][string]$Role, [Parameter(Mandatory)][scriptblock]$Arm,
          [scriptblock]$Sql, [scriptblock]$Prove, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [int]$WaitTries = 20, [int]$WaitSeconds = 30, [int]$ProvisionTries = 30, [int]$MaxPolls = 60, [switch]$DryRun, [string]$LogDir = '',
          # owner 2026-11-09 (confirmed directly): step 6 -- DELETE the old job after the proof + the switch read back; default OFF
          [switch]$DeleteOld)
    $api = Get-PimJobRenameApi
    $rows = @($Plan.jobs | Where-Object { $_.role -eq $Role })
    $row = $rows | Select-Object -First 1
    $rec = [ordered]@{ role = $Role; old = "$($row.old)"; new = "$($row.new)"; state = ''; steps = New-Object System.Collections.Generic.List[object]
                       proof = New-Object System.Collections.Generic.List[string]; error = ''; failedStep = ''; rollback = @(); startedUtc = [datetime]::UtcNow.ToString('o') }
    $step = { param($name, $what, $readBack, $undo) $rec.steps.Add([pscustomobject]@{ step = $name; what = $what; readBack = $readBack; undo = $undo; atUtc = [datetime]::UtcNow.ToString('o') }) }
    $setRollback = { $rb = @(@($rec.steps.ToArray()) | Where-Object { "$($_.undo)".Trim() }); $rev = New-Object System.Collections.Generic.List[object]; for ($i = $rb.Count - 1; $i -ge 0; $i--) { $rev.Add($rb[$i]) }; $rec.rollback = @($rev.ToArray()) }
    $finish = {
        & $setRollback
        $rec.endedUtc = [datetime]::UtcNow.ToString('o')
        if ("$LogDir".Trim()) {
            try { if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
                  Set-Content -LiteralPath (Join-Path $LogDir ("job-rename-$Role-" + [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '.json')) -Value ([pscustomobject]$rec | ConvertTo-Json -Depth 10) -Encoding UTF8 } catch { }
        }
        return $rec
    }
    if (-not $row) { $rec.state = 'nothing-to-do'; $rec.error = "no job of role '$Role' to rename at this install"; return (& $finish) }
    if ($rows.Count -gt 1) { $rec.state = 'blocked'; $rec.error = "$($rows.Count) jobs of role '$Role' ($(@($rows | ForEach-Object { $_.old }) -join ', ')): only one can become $($row.new) -- the owner decides"; return (& $finish) }
    if ($row.state -eq 'blocked') { $rec.state = 'blocked'; $rec.error = (@($row.blocked) -join '; '); return (& $finish) }
    $onlyDelete = ($row.state -eq 'done')
    if ($onlyDelete -and -not $DeleteOld) { $rec.state = 'nothing-to-do'; $rec.proof.Add("$($row.new) already runs the role; $($row.old) is disabled (Manual) and kept"); return (& $finish) }
    if ($DeleteOld -and -not $DryRun -and -not "$LogDir".Trim()) { $rec.state = 'blocked'; $rec.failedStep = 'delete'; $rec.error = '-DeleteOld needs -LogDir: the rollback record of the old job is written there BEFORE it is deleted -- nothing written'; return (& $finish) }
    if ($row.new -notmatch '^caj-pim-[a-z]+$') { throw "refusing a new name that is not caj-pim-<purpose>: $($row.new)" }
    if (-not $Sql -and -not $DryRun) { $rec.state = 'blocked'; $rec.failedStep = 'sql'; $rec.error = 'no SQL seam (-Sql): pim.Settings (SchedulerTickJobId / InstallNames) could not be switched with the rest -- nothing written. The statements are in the plan.'; return (& $finish) }
    $oldId = "$($row.oldId)"; $newId = "$($row.newId)"; $oldPath = "$oldId`?api-version=$($api.aca)"; $newPath = "$newId`?api-version=$($api.aca)"
    $waitOld = {
        param($when)
        for ($i = 1; $i -le [Math]::Max(1, $WaitTries); $i++) {
            $run = @(Get-PimJobRenameRunning -Executions (Read-PimJobRenameExecutions -Arm $Arm -JobId $oldId))
            if (-not $run.Count) { return $true }
            if ($i -lt $WaitTries) { & $Sleep $WaitSeconds }
        }
        $rec.state = 'waiting'; $rec.error = "$($row.old) is running ($(@($run) -join ', ')) $when -- never interrupted; run the same command again after it ends"
        return $false
    }
    $cur = ''
    try {
        # ------------------------------------------------------------------ 1 create (Manual)
        $cur = 'create'
        $old = Invoke-PimIdentityMoveGet -Seam $Arm -Path $oldPath
        if (-not $old) { throw "$($row.old) is not there any more" }
        $new = Invoke-PimIdentityMoveGet -Seam $Arm -Path $newPath
        if ($onlyDelete) { & $step 'create' "$($row.new) runs the role already (renamed earlier; switched, $($row.old) Manual)" 'read back' '' }
        if (-not $onlyDelete) {
        if ($new) {
            if ("$(Get-PimJobRenameField (Get-PimJobRenameField $new 'tags') 'pim-renamed-from')" -ine $row.old) { $rec.state = 'blocked'; $rec.error = "$($row.new) exists and was not created by this step from $($row.old) -- never overwritten"; return (& $finish) }
            & $step 'create' "$($row.new) exists (created by this step earlier)" 'read back' ''
        } elseif ($DryRun) {
            & $step 'create' "would create $($row.new) from $($row.old): same spec, the same identity ($(@($row.identities) -join ', ')), trigger Manual until the switch" '' ''
        } else {
            $vals = @{}
            if (@($row.valueSecrets).Count) {
                $ls = $null; try { $ls = & $Arm 'POST' "$oldId/listSecrets?api-version=$($api.aca)" @{} } catch { $ls = $null }
                foreach ($s in @(Get-PimJobRenameField $ls 'value')) { if ($s -and -not "$(Get-PimJobRenameField $s 'keyVaultUrl')".Trim()) { $vals["$(Get-PimJobRenameField $s 'name')"] = "$(Get-PimJobRenameField $s 'value')" } }
                $miss = @($row.valueSecrets | Where-Object { -not $vals.ContainsKey("$_") })
                if ($miss.Count) { $rec.state = 'blocked'; $rec.failedStep = 'create'; $rec.error = "the value of the secret(s) $($miss -join ', ') of $($row.old) could not be read (listSecrets) -- an ops step: give the Support app Microsoft.App/jobs/listSecrets/action on the job, or move the secret to Key Vault. Nothing created."; return (& $finish) }
            }
            $body = New-PimJobRenameSpec -Job $old -NewName $row.new -NewId $newId -SecretValues $vals
            [void](& $Arm 'PUT' $newPath $body)
            $vals = $null; $body = $null
            $ok = $false; $ps = ''
            for ($i = 1; $i -le [Math]::Max(1, $ProvisionTries); $i++) {
                if ($i -gt 1) { & $Sleep 10 }
                $new = Invoke-PimIdentityMoveGet -Seam $Arm -Path $newPath
                $ps = "$(Get-PimJobRenameField (Get-PimJobRenameField $new 'properties') 'provisioningState')"
                if ($new -and ($ps -eq 'Succeeded' -or -not $ps)) { $ok = $true; break }
                if ($ps -eq 'Failed') { break }
            }
            & $step 'create' "created $($row.new) from $($row.old) (trigger Manual; identity $(@($row.identities) -join ', '))" $(if ($ok) { 'read back: provisioned' } else { "NOT provisioned ($ps)" }) "Invoke-PimArm -Method DELETE -Path '$newPath'   # the NEW job only"
            if (-not $ok) { throw "$($row.new) did not provision (state '$ps')" }
            if ((Get-PimJobRenameTrigger -Job $new).type -ne 'Manual') { throw "$($row.new) does not read back with a Manual trigger" }
            $si = Get-PimJobRenameSignIn -Job $new
            if ($si.kind -ne 'user' -or $si.identityId -ine $row.signIn.identityId) { throw "$($row.new) does not read back signing in as $($row.signIn.identityName)" }
        }
        # ------------------------------------------------------------------ 2 rights (job-scoped role assignments, copied -- never removed)
        $cur = 'rights'
        $haveNew = @(); if ($new) { $haveNew = @(Read-PimJobRenameScopeAssignments -Arm $Arm -Scope $newId) }
        foreach ($a in @(Get-PimJobRenameAssignmentsToCopy -Old @(Read-PimJobRenameScopeAssignments -Arm $Arm -Scope $oldId) -New $haveNew)) {
            $rd = @("$($a.roleDefinitionId)" -split '/')[-1]
            if ($DryRun) { & $step 'rights' "would give $($a.principalId) the role $rd on $($row.new) (as on $($row.old))" '' ''; continue }
            $aName = New-PimIdentityMoveGuid -Seed "$newId|$($a.principalId)|$($a.roleDefinitionId)"
            $aPath = "$newId/providers/Microsoft.Authorization/roleAssignments/$aName`?api-version=$($api.auth)"
            $body = @{ properties = @{ roleDefinitionId = $a.roleDefinitionId; principalId = $a.principalId } }
            if ("$($a.principalType)".Trim()) { $body.properties.principalType = "$($a.principalType)" }
            try { [void](& $Arm 'PUT' $aPath $body) } catch { if ("$($_.Exception.Message)" -notmatch '(?i)RoleAssignmentExists|\b409\b') { throw } }
            $back = @(Get-PimJobRenameAssignmentsToCopy -Old @($a) -New @(Read-PimJobRenameScopeAssignments -Arm $Arm -Scope $newId))
            if ($back.Count) { throw "the role $rd for $($a.principalId) does not read back on $($row.new)" }
            & $step 'rights' "gave $($a.principalId) the role $rd on $($row.new) (copied from $($row.old); the old one is kept)" 'read back (kept on undo: no role assignment is ever deleted by this step)' ''
        }
        # ------------------------------------------------------------------ 3 prove (one run of the new job)
        $cur = 'prove'
        if ($DryRun) { & $step 'prove' "would start ONE execution of $($row.new) and prove it (Succeeded$(if ($Prove) { ' + the caller''s check' }))" '' '' }
        else {
            $newTrgNow = Get-PimJobRenameTrigger -Job $new
            $alreadySwitched = ($newTrgNow.type -eq 'Schedule')
            $earlier = @(@(Read-PimJobRenameExecutions -Arm $Arm -JobId $newId) | Where-Object { "$(Get-PimJobRenameField (Get-PimJobRenameField $_ 'properties') 'status')" -eq 'Succeeded' })
            if ($alreadySwitched -or $earlier.Count) {
                $rec.proof.Add("$($row.new): proven earlier ($(if ($earlier.Count) { "execution $(Get-PimJobRenameField $earlier[0] 'name') Succeeded" } else { 'already switched' }))")
                & $step 'prove' "$($row.new) proven earlier -- no second proof run" 'proof' ''
            } else {
                if (-not (& $waitOld 'before the proof run')) { return (& $finish) }
                $st = Start-PimIdentityMoveJob -Arm $Arm -JobId $newId -Sleep $Sleep
                $exe = "$($st.execution)"
                if (-not $st.ok -or -not $exe) { throw "$($row.new) did not start$(if ($st.reason -and $st.reason -ne 'started') { ': ' + $st.reason })" }
                $w = Wait-PimIdentityMoveJobExecution -Arm $Arm -JobId $newId -Execution $exe -Sleep $Sleep -MaxPolls $MaxPolls
                if (-not $w.ok) { throw "the proof run $exe of $($row.new) ended '$($w.status)' -- nothing switched; $($row.old) is untouched and still runs the role" }
                $detail = "execution $exe Succeeded"
                if ($Prove) {
                    $pv = & $Prove $row $exe
                    if (-not $pv -or -not $pv.ok) { throw "the proof of $($row.new) failed: $(if ($pv) { $pv.detail }) -- nothing switched; $($row.old) is untouched" }
                    $detail += "; $($pv.detail)"
                }
                $rec.proof.Add("$($row.new): $detail")
                & $step 'prove' "$($row.new) proven: $detail" 'proof' ''
            }
        }
        # ------------------------------------------------------------------ 4 switch
        $cur = 'switch'
        if (-not $DryRun -and -not (& $waitOld 'before the switch')) { return (& $finish) }
        $trg = $row.trigger
        if ($trg.type -eq 'Schedule' -and $DryRun -and -not $new) { & $step 'switch' "would set $($row.new) to the schedule of $($row.old) ($($trg.cron))" '' '' }
        elseif ($trg.type -eq 'Schedule') {
            $r = Set-PimJobRenameTrigger -Arm $Arm -JobId $newId -Type Schedule -Cron $trg.cron -Parallelism $trg.parallelism -ReplicaCompletionCount $trg.replicaCompletionCount -DryRun:$DryRun -Sleep $Sleep
            & $step 'switch' "$(if ($DryRun) { 'would set' } else { 'set' }) $($row.new) to the schedule of $($row.old): $($r.detail)" $(if ($DryRun -or -not $r.changed) { '' } else { 'read back' }) $(if ($DryRun -or -not $r.changed) { '' } else { "Set-PimJobRenameTrigger -Arm `$arm -JobId '$newId' -Type Manual" })
        }
        # the settings that name the old job: read FRESH (an earlier role's switch may have changed them)
        $inst = Read-PimJobRenameInstall -Arm $Arm -SubscriptionId $Plan.subscriptionId -ResourceGroup $Plan.resourceGroup
        $chg = @(Get-PimJobRenameSettingChanges -Resources @(@($inst.apps) + @($inst.jobs)) -OldName $row.old -OldId $oldId -NewName $row.new -NewId $newId)
        foreach ($g in @($chg | Group-Object resourceId)) {
            $items = @($g.Group); $nm = "$($items[0].resource)"
            $r = Set-PimJobRenameEnv -Arm $Arm -ResourceId $g.Name -Changes $items -DryRun:$DryRun -Sleep $Sleep
            $undoCh = '@(' + (@($items | ForEach-Object { "@{ container = '$($_.container)'; name = '$($_.name)'; from = '$($_.to)'; to = '$($_.from)' }" }) -join ', ') + ')'
            & $step 'switch' "$(if ($DryRun) { 'would switch' } else { 'switched' }) $nm`: $($r.detail)" $(if ($DryRun -or -not $r.changed) { '' } else { 'read back' }) $(if ($DryRun -or -not $r.changed) { '' } else { "Set-PimJobRenameEnv -Arm `$arm -ResourceId '$($g.Name)' -Changes $undoCh" })
        }
        $sqv = Read-PimJobRenameSql -Sql $Sql
        if (-not $DryRun -and -not $sqv.read) { throw "pim.Settings could not be read for the switch: $($sqv.reason)" }
        foreach ($w in @(Get-PimJobRenameSqlPlan -Entry (Get-PimJobRenameEntry -Name $row.old) -OldName $row.old -OldId $oldId -NewName $row.new -NewId $newId -Current $sqv.values -Read ([bool]$sqv.read -or -not $DryRun))) {
            if ($DryRun) { & $step 'switch' "would set pim.Settings '$($w.name)': $($w.from) -> $($w.to)" '' ''; continue }
            $before = $sqv.values[$w.name]
            [void](& $Sql 'set' $w.name $w.value)
            $back = & $Sql 'get' $w.name $null
            if ($back -is [string] -and $w.name -eq 'InstallNames') { try { $back = $back | ConvertFrom-Json } catch { } }
            $okB = if ($w.name -eq 'SchedulerTickJobId') { "$back".Trim().Trim('"') -ieq $newId } else { "$(Get-PimJobRenameField $back $row.namesRole)" -eq $row.new }
            if (-not $okB) { throw "pim.Settings '$($w.name)' does not read back as $($w.to)" }
            $beforeJson = if ($null -eq $before) { '$null' } else { "'" + ((ConvertTo-Json -InputObject $before -Compress -Depth 8) -replace "'", "''") + "'" }
            & $step 'switch' "pim.Settings '$($w.name)': $($w.from) -> $($w.to)" 'read back' "& `$sql 'set' '$($w.name)' $(if ($null -eq $before) { '$null' } else { "(ConvertFrom-Json $beforeJson)" })"
        }
        # ------------------------------------------------------------------ 5 disable the OLD job (Manual; kept)
        $cur = 'disable'
        if ((Get-PimJobRenameTrigger -Job $old).type -eq 'Schedule') {
            $ot = Get-PimJobRenameTrigger -Job $old
            $r = Set-PimJobRenameTrigger -Arm $Arm -JobId $oldId -Type Manual -Parallelism $ot.parallelism -ReplicaCompletionCount $ot.replicaCompletionCount -DryRun:$DryRun -Sleep $Sleep
            & $step 'disable' "$(if ($DryRun) { 'would set' } else { 'set' }) $($row.old) to Manual (schedule off; the job, its identity and its rights are KEPT): $($r.detail)" $(if ($DryRun -or -not $r.changed) { '' } else { 'read back' }) $(if ($DryRun -or -not $r.changed) { '' } else { "Set-PimJobRenameTrigger -Arm `$arm -JobId '$oldId' -Type Schedule -Cron '$($ot.cron)'" })
        } else { & $step 'disable' "$($row.old) is Manual already: nothing to switch off$(if (-not $DeleteOld) { ' (kept as it is)' })" '' '' }
        }   # -not $onlyDelete
        # ------------------------------------------------------------------ 6 delete the OLD job (-DeleteOld only; after the proof + the switch read back)
        if ($DeleteOld) {
            $cur = 'delete'
            if ($DryRun) { & $step 'delete' "would delete the old job $($row.old) (after the proof and the switch read back): its rollback record (full spec + job-scoped role assignments) written first, then 404 read back" '' '' }
            else {
                # the proof on record: this run's, or a Succeeded run of the new job
                $proven = (@($rec.proof).Count -gt 0) -or [bool]@(@(Read-PimJobRenameExecutions -Arm $Arm -JobId $newId) | Where-Object { "$(Get-PimJobRenameField (Get-PimJobRenameField $_ 'properties') 'status')" -eq 'Succeeded' }).Count
                if (-not $proven) { throw "no proven run of $($row.new) -- nothing deleted" }
                # the switch, READ BACK fresh: nothing names the old job, pim.Settings switched, the new job on the old schedule
                $inst2 = Read-PimJobRenameInstall -Arm $Arm -SubscriptionId $Plan.subscriptionId -ResourceGroup $Plan.resourceGroup
                $left = @(Get-PimJobRenameSettingChanges -Resources @(@($inst2.apps) + @($inst2.jobs)) -OldName $row.old -OldId $oldId -NewName $row.new -NewId $newId)
                $sq2 = Read-PimJobRenameSql -Sql $Sql
                $sqlLeft = @(if ($sq2.read) { Get-PimJobRenameSqlPlan -Entry (Get-PimJobRenameEntry -Name $row.old) -OldName $row.old -OldId $oldId -NewName $row.new -NewId $newId -Current $sq2.values -Read $true })
                $newNow = Invoke-PimIdentityMoveGet -Seam $Arm -Path $newPath
                $nt = Get-PimJobRenameTrigger -Job $newNow
                $trgOk = $newNow -and ($row.trigger.type -ne 'Schedule' -or ($nt.type -eq 'Schedule' -and $nt.cron -eq $row.trigger.cron))
                if ($left.Count -or -not $sq2.read -or $sqlLeft.Count -or -not $trgOk) {
                    throw "the switch to $($row.new) does not read back ($(@($(if ($left.Count) { "$($left.Count) setting(s) still name $($row.old)" }), $(if (-not $sq2.read) { 'pim.Settings not readable' }), $(if ($sqlLeft.Count) { 'pim.Settings not switched' }), $(if (-not $trgOk) { "$($row.new) is not on the old schedule" })) | Where-Object { $_ }) -join '; ')) -- nothing deleted"
                }
                if (-not (& $waitOld 'before the delete')) { return (& $finish) }
                $oldNow = Invoke-PimIdentityMoveGet -Seam $Arm -Path $oldPath
                if (-not $oldNow) { & $step 'delete' "$($row.old) is gone already" 'read back: 404' '' }
                else {
                    $ras = @(Read-PimJobRenameScopeAssignments -Arm $Arm -Scope $oldId)
                    $f = Write-PimJobRenameDeleteRecord -LogDir $LogDir -Kind 'job' -Name $row.old -Content ([pscustomobject]@{
                        kind = 'container apps job'; name = $row.old; id = $oldId; job = (Copy-PimJobRenameObject $oldNow); originalTrigger = $row.trigger; roleAssignments = $ras
                        valueSecretsNotRecorded = @($row.valueSecrets); note = 'the job''s system-assigned identity was deleted with it: a re-created job gets a new one; secret VALUES are not in this record (re-enter them)'
                        recreate = "Invoke-PimArm -Method PUT -Path '$oldPath' -Body <the 'job' of this record without id, systemData and provisioningState, its trigger = originalTrigger>; then each roleAssignment PUT on '$oldId'"; deletedUtc = [datetime]::UtcNow.ToString('o') })
                    & $step 'delete' "rollback record of $($row.old) written before the delete: $f" 'read back' ''
                    [void](& $Arm 'DELETE' $oldPath $null)
                    if (-not (Wait-PimJobRenameGone -Arm $Arm -Path $oldPath -Sleep $Sleep)) { throw "$($row.old) still reads back after the DELETE" }
                    & $step 'delete' "deleted the old job $($row.old) (proven + switched first; its system identity goes with it)" 'read back: 404' "re-create $($row.old) from the record $f (Invoke-PimArm -Method PUT -Path '$oldPath' ...)"
                }
            }
        }
        $rec.state = if ($DryRun) { 'dry-run' } else { 'done' }
    } catch {
        $rec.state = 'failed'; $rec.failedStep = $cur; $rec.error = "$($_.Exception.Message)"
    }
    return (& $finish)
}

# ---------------------------------------------------------------------------------------------------------- the report
function ConvertTo-PimJobRenameReport {
    <# PURE. The plain per-install plan text for Invardia's approval: what is created / copied / switched / disabled, blocked items. #>
    param([Parameter(Mandatory)][object]$Plan)
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add("PIM Manager job rename (JOB-RENAME 3.0.68) -- plan for resource group $($Plan.resourceGroup) (subscription $($Plan.subscriptionId))")
    if ($Plan.deleteOld) { $L.Add('-DeleteOld: each old job is DISABLED, then DELETED only after its new job is proven and the switch reads back (rollback record first, 404 read back). No role assignment is ever deleted; rights are only added.') }
    else { $L.Add('Nothing is removed or deleted: each old job is DISABLED (trigger Manual) and kept with its identity and rights; rights are only added.') }
    $L.Add('')
    if (-not @($Plan.jobs).Count) { $L.Add('No PIM job to rename at this install.') }
    foreach ($j in @($Plan.jobs)) {
        $L.Add("[$($j.state)] $($j.role): $($j.old) -> $($j.new)$(if ($j.note) { "  ($($j.note))" })")
        if ($j.state -eq 'blocked') { foreach ($b in @($j.blocked)) { $L.Add("    BLOCKED: $b") }; continue }
        if ($j.state -eq 'done') { $L.Add("    already done: $($j.new) runs the role; $($j.old) is Manual$(if ($Plan.deleteOld) { " -- delete old job $($j.old) (after proof)" } else { ' and kept' })"); continue }
        if ($j.state -eq 'waiting') { $L.Add("    WAITING: $($j.old) is running ($(@($j.running) -join ', ')) -- never interrupted; the step waits for it to end") }
        $L.Add("    create : $($j.new)$(if ($j.newExists) { ' (exists, created by this step)' }) -- same spec, runs as $($j.signIn.identityName), trigger Manual until the switch")
        $L.Add("    secrets: $(if (@($j.secrets).Count) { (@($j.secrets | ForEach-Object { "$($_.name) ($(if ($_.kind -eq 'keyvault') { 'Key Vault reference' } else { 'value, copied at apply with listSecrets -- never written down' }))" }) -join ', ') } else { 'none' })")
        foreach ($a in @($j.toCopy)) { $L.Add("    copy   : role $(@("$($a.roleDefinitionId)" -split '/')[-1]) for $($a.principalId) on $($j.new) (as on $($j.old))") }
        $L.Add("    prove  : one run of $($j.new) must succeed; a failed proof switches nothing (undo: delete the new job only)")
        $L.Add("    switch : $($j.new) gets $(if ($j.trigger.type -eq 'Schedule') { "the schedule '$($j.trigger.cron)'" } else { 'no schedule (a Manual-trigger job)' })")
        foreach ($s in @($j.settings)) { $L.Add("    switch : $($s.resource) $($s.container)/$($s.name): $($s.from) -> $($s.to)") }
        foreach ($s in @($j.sql)) { $L.Add("    switch : pim.Settings '$($s.name)': $($s.from) -> $($s.to)") }
        $L.Add("    disable: $($j.old) $(if ($j.currentTrigger.type -eq 'Schedule') { '-> trigger Manual (schedule off)' } else { 'is Manual already' })$(if (-not $Plan.deleteOld) { ', kept' })")
        if ($Plan.deleteOld) { $L.Add("    delete : delete old job $($j.old) (after proof) -- its full spec + job-scoped role assignments recorded first; its system identity goes with it") }
    }
    $L.Add('')
    $orph = @($Plan.orphanIdentities)
    $L.Add("Old user-assigned identities nothing attaches any more: $(if ($orph.Count) { '' } else { 'none' })")
    foreach ($o in $orph) { $L.Add("  - $($o.name) ($(@($o.roleAssignments).Count) Azure role assignment(s), kept)$(if ($Plan.deleteOld) { ' -- delete (re-checked unattached at delete time, record first)' } else { ' -- listed only (deleted with -DeleteOld)' })") }
    $L.Add('')
    $L.Add('Not covered by this step (listed for the approval):')
    foreach ($n in @($Plan.notCovered)) { $L.Add("  - $n") }
    return ($L -join "`n")
}
