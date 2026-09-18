#Requires -Version 5.1
<#
.SYNOPSIS
    §53 -- deploy the NIGHTLY UPDATER as an Azure Container Apps scheduled Job (`ca-pim-update`).
    ONE command. Idempotent. Cloud-only: no Windows host, no scheduled task, no VisualCron.

.DESCRIPTION
    PIM v2 is 100% cloud, and until this existed nothing in a customer environment updated it:
    every environment moved only when a human ran the deploy. That does not scale past a handful
    of customers, and it is why a live environment sat several versions behind while newer builds
    were released.

    This creates a Container Apps Job on a cron trigger, running the SAME pim-manager image with
    the entry `tools/pim-engine/update-job-entry.ps1`, which rolls the environment over ARM REST.
    It is the same shape the MSP downlink job already uses, and the same operator directive:
    "an Azure Container Apps scheduled JOB (cron), NOT a Windows scheduled task ... all run in
    cloud only compute" (2026-06-17).

    🔑 IT ROLLS, IT DOES NOT BUILD. The job needs no ACR push rights, no source tree and no git:
    it can only move the environment between images that already exist in the registry. Which
    image it may move to is `-TargetImage` -- an operator/ring decision, not the job's.

    🪤 A JOB CAN ROLL AN APP; A CONTAINER CANNOT ROLL ITSELF. That is exactly why the updater is a
    separate Job rather than a feature of the Manager. The job stamps its own image LAST, which
    takes effect on its NEXT run -- the run in progress finishes on the image it started with.

.PARAMETER TargetImage
    The image to roll to, e.g. myacr.azurecr.io/pim-manager:2.4.295. Leave empty to install the
    job "armed but idle": it runs nightly and reports that no target is approved, which is the
    correct steady state until you publish one.

.EXAMPLE
    .\Deploy-PimUpdateJob.ps1 -SubscriptionId <sub> -ResourceGroup rg-automateit-pim01 `
        -EnvName cae-pim -AcrName acrpimpim01 -ImageTag 2.4.295
    Installs the nightly updater at 03:00 UTC and points it at 2.4.295.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$EnvName,
    [Parameter(Mandatory)][string]$AcrName,
    # 🔴 THE NIGHTLY BUILD NEEDS THE AGENT POOL, AND NOBODY IS WATCHING WHEN IT DOES NOT HAVE IT.
    # `az acr build` runs on ACR's build fleet regardless of where the command is issued, so on a
    # registry with public access off the shared agent is refused by the registry's own firewall
    # ("denied: client with IP ... is not allowed"). Being inside the VNet does not help the JOB,
    # because the JOB is not what connects. Every internal-only customer's 03:00 self-update would
    # fail this way, unattended, with the fleet silently staying behind.
    [string]$AcrAgentPoolName,
    [string]$ImageRepo   = 'pim-manager',
    [string]$ImageTag,                                  # the image the JOB ITSELF runs
    [string]$TargetImage,                               # what it rolls the environment TO
    [string]$JobName     = 'ca-pim-update',
    [string]$ManagerApp  = 'ca-pim-manager',
    [string]$TickJobName = 'ca-pim-tick',
    # 03:00 UTC daily. Stagger across an estate so 100 environments do not all roll at once.
    [string]$Cron        = '0 3 * * *',
    [string]$RegistryIdentityResourceId,                # user-assigned identity holding AcrPull
    # §55 -- WHAT LETS AN ENVIRONMENT WITH NO BUILD HOST UPDATE ITSELF.
    # Given a source URL, the job fetches the approved version's source and asks its OWN registry
    # to build it before rolling. Given none, it behaves exactly as before: roll to an image the
    # registry already holds. That default is deliberate -- it is what makes this safe to ship to
    # environments that already update themselves nightly.
    [string]$SourceUrlTemplate,                         # e.g. https://<store>/pim-src/pim-src-{version}.tar.gz?<read-sas>
    [string]$TargetVersion,                             # the approved version, e.g. 2.4.307 (preferred over -TargetImage)
    # 2026-09-13 -- THE UPDATE RING (operator: "nothing releases to ring 2 without my approve").
    # Every updater this installs ends with PIM_UPDATE_RING set. DEFAULT 2 = the safe customer ring;
    # internal and test environments pass 1 explicitly. NOT passing it on a redeploy KEEPS the ring the
    # job already has -- a redeploy never promotes or demotes an environment (_PimUpdateRing.ps1).
    [ValidateRange(0,3)][int]$UpdateRing = 2,
    # The version this environment already runs, so its first nightly run ROLLS instead of rebuilding
    # it. Omitted => the job's existing PIM_UPDATE_LAST_BUILT is kept.
    [string]$LastBuiltVersion,
    # 2026-09-13 -- THE UPDATER'S DATABASE USER. The schema step runs as this job's managed identity, so
    # it needs a contained user exactly like the tick. Public SQL: granted from here with the SQL-admin
    # SPN (certificate). Private SQL (-SqlPrivate): added to the in-cloud bootstrap job and run inside.
    [string]$TenantId,
    [string]$SqlAdminClientId,
    [string]$SqlAdminCertThumbprint,
    [string]$SqlAdminClientSecret,
    # 71.33: grant the updater's database user as the SIGNED-IN az user (a member of the SQL admin group).
    [switch]$UseSignedInAccount,
    [switch]$SqlPrivate,
    [string]$DbInitJobName = 'ca-pim-dbinit',
    [switch]$SkipRoleAssignment,
    # 2026-09-15 -- THE SQL ADMIN GROUP. When this group is the SQL server's Entra admin, the updater's
    # identity is made a member of it on every run, so its schema step can log in without a contained user.
    # Never creates the group and never moves the admin -- that is Initialize-PimSqlAdminGroup.ps1.
    [string]$SqlAdminGroupName = 'grp-pim-sql-admins',
    [switch]$SkipSqlAdminGroup
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
. (Join-Path $here '_PimAz.ps1')                        # the guarded az shadow
. (Join-Path $here '_PimUpdateRing.ps1')                # ring + source enforcement, ARM-safe env writes
. (Join-Path $here '_PimSqlAdminGroup.ps1')             # the SQL admin group: membership for the updater identity

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

$sub   = @('--subscription', $SubscriptionId)
$image = "$AcrName.azurecr.io/$ImageRepo" + ':' + $(if ("$ImageTag".Trim()) { "$ImageTag".Trim() } else { 'latest' })

Write-Host "`n=== PIM nightly updater ($JobName) ===" -ForegroundColor Cyan
Note "environment $EnvName / $ResourceGroup"
Note "job image    $image"
Note "rolls to     $(if ("$TargetImage".Trim()) { $TargetImage } else { '(nothing yet -- armed but idle)' })"
Note "cron         $Cron (UTC)"

# ---- 0. the image the job will run MUST EXIST --------------------------------------------------
# 🔴 A TAG THAT WAS NEVER BUILT PRODUCES A JOB THAT REPORTS "Unknown" FOREVER, AND SAYS WHY NOWHERE.
# The job is created happily -- ARM does not check that the image resolves -- then every execution
# fails to pull before any container starts, so there is no console log, no system log, and the
# execution status is "Unknown". That is indistinguishable from a missing AcrPull, which is how the
# first live install burned two rounds of diagnosis on the wrong cause: the tag passed to -ImageTag
# had simply never been built (the registry's newest was ten versions older).
# The deploy path already refuses to roll an image it cannot see; this installer did not inherit
# that check, because it was written as a separate script. Ask the registry BEFORE creating a job
# that cannot possibly run.
function Test-PimAcrTag {
    param([string]$Registry, [string]$Repository, [string]$Tag)
    try {
        # show-tags + match in PowerShell, never `show --image repo:tag`: absent is a legitimate
        # answer here and that form prints an ERROR for it (same reasoning as the deploy path).
        $global:LASTEXITCODE = 0
        $raw  = @(az acr repository show-tags @sub -n $Registry --repository $Repository -o tsv 2>$null)
        $code = $LASTEXITCODE
        $tags = @($raw | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        # 🔴 "I COULD NOT READ THE REGISTRY" MUST NOT LOOK LIKE "THE TAG IS ABSENT" -- and an empty
        # result is not the only way that happens. `az acr repository show-tags` is a DATA-PLANE
        # call, so against a registry with public access off it fails from a deploy host outside
        # the VNet and prints its own text:
        #     WARNING: Unable to get AAD authorization tokens ... CONNECTIVITY_REFRESH_TOKEN_ERROR
        #     Username:                                   <- an interactive prompt, on stdout
        # That text arrived here AS A TAG LIST, so `$tags` was non-empty, the match failed, and this
        # returned $false -- "the image does NOT exist" -- about an image built 90 seconds earlier.
        # The empty-result guard below was already right; it simply could not see this shape.
        # Measured at a customer 2026-09-12, the FOURTH place this private-registry assumption has
        # surfaced (after the roller's pre-roll guard, its digest pin, and the agent pool).
        if ($code -ne 0) { return $null }
        $noise = @($tags | Where-Object { $_ -match '(?i)^(Username|Password|WARNING|ERROR|Traceback):' })
        if ($noise.Count) { return $null }
        if (-not $tags.Count) { return $null }   # cannot see the registry at all -- NOT the same as absent
        return ([bool](@($tags) -contains "$Tag".Trim()))
    } catch { return $null }
}

$jobTag   = if ("$ImageTag".Trim()) { "$ImageTag".Trim() } else { 'latest' }
$jobTagOk = Test-PimAcrTag -Registry $AcrName -Repository $ImageRepo -Tag $jobTag
if ($jobTagOk -eq $false) {
    throw ("Deploy-PimUpdateJob: the job image '$image' does NOT exist in registry '$AcrName'. " +
           "Build that tag first (or pass an -ImageTag that is present). Installing the job against " +
           "a missing image gives you executions that report 'Unknown' and log nothing at all.")
}
elseif ($null -eq $jobTagOk) {
    # 🪤 Say WHY it could not be verified, and that this is expected on a private registry -- an
    # unexplained "NOT verified" on an otherwise clean deploy reads as something being wrong.
    Warn "could not list tags in '$AcrName' -- job image NOT verified (normal when the registry has"
    Warn "  no public endpoint: this host has no data-plane route to it). The image was pushed by the"
    Warn "  build step in this same run; the job will pull it from inside the environment."
}
else { Note "job image verified present in $AcrName" }

# 🔴 AND THE TAG MUST BE NEW ENOUGH TO CONTAIN THE UPDATER AT ALL.
# "the tag exists" is NOT "the tag can run this job". `update-job-entry.ps1` first shipped in
# 2.4.296, and 2.4.296-2.4.301 resolve the engine folder one directory too high (fixed in 2.4.302).
# So an image older than 2.4.302 produces an execution that fails instantly -- either because pwsh
# is handed a -File that does not exist in the image, or because the script cannot find the engine.
# 🪤 MEASURED THREE TIMES AT THE SAME CUSTOMER, on 2.4.290: two `Failed` executions diagnosed as a
# missing AcrPull, then a third after the tag-existence check above was added -- which passed it,
# because 2.4.290 exists. A check that asks the registry "is this there?" cannot answer "is this
# the right one?", and the failure looks identical from outside either way.
$script:PimUpdateJobMinImage = '2.4.302'
$parsedTag = $null
if ([version]::TryParse(($jobTag -replace '^v', ''), [ref]$parsedTag)) {
    if ($parsedTag -lt [version]$script:PimUpdateJobMinImage) {
        throw ("Deploy-PimUpdateJob: image tag '$jobTag' is too old to run this job. The updater " +
               "entry script first shipped in 2.4.296, and versions before $script:PimUpdateJobMinImage " +
               "cannot locate the engine inside the image -- every execution would fail immediately, " +
               "which is indistinguishable from a registry-permission problem. Build and pass " +
               "$script:PimUpdateJobMinImage or newer.")
    }
} else {
    Warn "image tag '$jobTag' is not a version number -- cannot check it is new enough to run this job"
    Warn "  (the updater entry script requires $script:PimUpdateJobMinImage or newer)."
}

# The same trap applies to what it ROLLS TO: an updater armed with an image nobody built will run
# nightly, fail the roll, and roll back -- quietly succeeding at doing nothing.
# 🔑 §55 EXCEPTION: with a source URL the environment BUILDS its own target, so the target is not
# expected to exist yet -- that is the entire point. Demanding it here would refuse the one
# configuration that lets a site with no build host update itself.
if ("$TargetImage".Trim() -and -not "$SourceUrlTemplate".Trim()) {
    $t = "$TargetImage".Trim()
    if ($t -match '^(?<srv>[^/]+)/(?<repo>.+):(?<tag>[^:]+)$' -and $Matches['srv'] -eq "$AcrName.azurecr.io") {
        $tgtOk = Test-PimAcrTag -Registry $AcrName -Repository $Matches['repo'] -Tag $Matches['tag']
        if ($tgtOk -eq $false) {
            throw ("Deploy-PimUpdateJob: the target image '$t' does NOT exist in registry '$AcrName'. " +
                   "The updater would roll the environment to an image that cannot be pulled.")
        }
        elseif ($tgtOk) { Note "target image verified present in $AcrName" }
    }
}

# ---- 1. create or update the Job ---------------------------------------------------------------
# 🪤 LIST, NOT SHOW. `job show` on a job that does not exist ERRORS -- and "it does not exist yet"
# is the NORMAL answer the first time this runs, so the very first line a customer saw was
# "az exit 1: ERROR: (ResourceNotFound)" during a completely healthy install. Same defect, same
# fix, as the image-tag probe in Invoke-PimDeployAll: ask "what is there", not "show me this one".
$exists = @(az containerapp job list @sub -g $ResourceGroup --query "[].name" -o tsv 2>$null) |
          Where-Object { "$_".Trim() -eq $JobName }

$envVars = @(
    "PIM_SubscriptionId=$SubscriptionId"
    "PIM_ResourceGroup=$ResourceGroup"
    "PIM_ManagerApp=$ManagerApp"
    "PIM_TickJobName=$TickJobName"
    "PIM_UpdateJobName=$JobName"
    "PIM_HOSTED=1"
)
if ("$AcrAgentPoolName".Trim()) { $envVars += "PIM_ACR_AGENT_POOL=$("$AcrAgentPoolName".Trim())" }
# The updater names this group when its identity is refused by SQL; only written when it is not the default.
if ("$SqlAdminGroupName".Trim() -and "$SqlAdminGroupName".Trim() -ne 'grp-pim-sql-admins') { $envVars += "PIM_SqlAdminGroupName=$("$SqlAdminGroupName".Trim())" }
if ("$TargetImage".Trim()) { $envVars += "PIM_UPDATE_TARGET_IMAGE=$("$TargetImage".Trim())" }
# §55. A bare version is the modern pin: ONE value, identical in every environment, instead of a
# registry-qualified reference that has to be rewritten per site. -TargetImage still works and
# still means what it meant.
if ("$TargetVersion".Trim())     { $envVars += "PIM_UPDATE_TARGET_VERSION=$("$TargetVersion".Trim())" }
# 🔴 PIM_UPDATE_SOURCE_URL IS NOT IN THE YAML ANY MORE, and neither are the ring or last-built. They are
# written over ARM REST after the job exists (Invoke-PimUpdateJobEnvWrites): the source carries a SAS,
# and every az/cmd.exe path has cut a SAS at its first '&' at least once (B9). And because
# `job update --yaml` REPLACES the env array, the plan below also puts back every PIM_UPDATE_* the job
# already carried (HOLD, LAST_GOOD, ...) -- a redeploy must never silently unfreeze or re-pin anything.

# ---- 0c. the RING and its SOURCE, decided BEFORE anything is changed ---------------------------
$armInvoker = New-PimSubscriptionArmInvoker -SubscriptionId $SubscriptionId
$jobArmPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName"
$existingEnv = [ordered]@{}
if ($exists) {
    $existingJob = & $armInvoker -Method GET -Path $jobArmPath -ApiVersion $script:PimAcaApi
    $existingEnv = ConvertTo-PimJobEnvMap -Job $existingJob -ContainerName $JobName
    if (-not $existingEnv.Count) { $existingEnv = ConvertTo-PimJobEnvMap -Job $existingJob }
}

# ---- 0d. the STORE the updater's schema step must reach -- copied from the Manager ---------------
# 🔴 MEASURED 2026-09-13 on four live environments: this job carried no PIM_SqlServer, so its schema
# step logged "no local store" about environments running on Azure SQL -- a false sentence that read as
# a clean skip. The Manager is the authority on which store the environment uses: read it, copy it.
$mgrObj = $null
try {
    $mgrObj = & $armInvoker -Method GET -ApiVersion $script:PimAcaApi `
                  -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$ManagerApp"
} catch { Warn ("could not read $ManagerApp over ARM: " + (Hide-PimSasText "$($_.Exception.Message)")) }
$storePlan = Get-PimUpdateJobStorePlan -ManagerStore (Get-PimAcaStoreSettings -Resource $mgrObj) -ExistingEnv $existingEnv `
                 -UpdateJobName $JobName -ManagerApp $ManagerApp
Step 'store the updater checks the schema against'
foreach ($m in @($storePlan.messages)) {
    if ($storePlan.level -eq 'error') { Write-Host "    $m" -ForegroundColor Red } elseif ($m -match 'CHANGES') { Warn $m } else { Note $m }
}
# In the YAML as well as over ARM below: `job update --yaml` REPLACES the env array, so a value that
# lived only out-of-band would vanish on every redeploy until the ARM write put it back. The ARM write
# then reads every value back byte-for-byte.
foreach ($k in @($storePlan.writes.Keys)) { $envVars += "$k=$($storePlan.writes[$k])" }

$yamlNames = @($envVars | ForEach-Object { ("$_" -split '=', 2)[0] })
# Throws -- before any create/update -- when no source can be resolved, or when the job carries a ring
# value that is not a ring and -UpdateRing was not passed.
$ringPlan = Get-PimUpdateJobRingPlan -ExistingEnv $existingEnv -UpdateRing $UpdateRing `
                -RingExplicit:($PSBoundParameters.ContainsKey('UpdateRing')) `
                -SourceUrlTemplate $SourceUrlTemplate -EnvSourceUrl "$($env:PIM_UPDATE_SOURCE_URL)" `
                -LastBuiltVersion $LastBuiltVersion -YamlManagedNames $yamlNames
Step "update ring $($ringPlan.ring)"
foreach ($m in @($ringPlan.messages)) { if ($m -match '(?i)CHANGES|default ring|KEPT|no query') { Warn $m } else { Note $m } }

$entry = '/app/PIM4EntraPS/tools/pim-engine/update-job-entry.ps1'

# 🔴 --yaml, NEVER A MULTI-TOKEN --command. `az containerapp job create --command pwsh -NoProfile
# -File <x>` fails with "unrecognized arguments: -NoProfile -ExecutionPolicy Bypass -File ..."
# because az takes only the FIRST token as the command and then tries to parse the rest as its own
# arguments. Measured on the first live install, 2026-09-09 -- and this repo already knew: the
# worker containers use --yaml for exactly this reason, and a standing assertion in
# Test-PimSetupHosting says so ("uses --ingress external + worker --yaml (NOT multi-token
# --command)"). A rule that lives in a test for one script does not protect the next one.
$envId = "$(az containerapp env show @sub -g $ResourceGroup -n $EnvName --query id -o tsv 2>$null)".Trim()
if (-not $envId) { throw "Deploy-PimUpdateJob: Container Apps environment '$EnvName' not found in $ResourceGroup." }
$location = "$(az containerapp env show @sub -g $ResourceGroup -n $EnvName --query location -o tsv 2>$null)".Trim()

# 🔴 WHICH IDENTITY PULLS THE IMAGE -- and getting this wrong produces a job that runs, says
# NOTHING, and reports status "Unknown" forever.
# A SYSTEM-assigned identity does not exist until the job that owns it exists, so it cannot hold
# AcrPull at the moment of the first pull -- the job is created, immediately tries to pull, and
# fails before any container writes a line. Nothing appears in the console logs (no container) and
# nothing in the system logs either. Measured on the first two executions here, and the downlink
# job already carries this lesson in Build-PimDownlinkJobArgs.
# 🔑 SO REUSE THE IDENTITY THAT ALREADY PULLS THIS IMAGE. The Manager app is running the very
# image this job needs, from the very same registry, with a user-assigned identity that already
# holds AcrPull. Asking it which identity it uses is both correct and self-configuring -- no new
# parameter for the operator to know about, and no new role assignment to wait for.
if (-not "$RegistryIdentityResourceId".Trim()) {
    $mgrRegId = "$(az containerapp show @sub -g $ResourceGroup -n $ManagerApp --query "configuration.registries[0].identity" -o tsv 2>$null)".Trim()
    if (-not $mgrRegId) {
        $mgrRegId = "$(az containerapp show @sub -g $ResourceGroup -n $ManagerApp --query "properties.configuration.registries[0].identity" -o tsv 2>$null)".Trim()
    }
    if ($mgrRegId -and $mgrRegId -ne 'system') {
        $RegistryIdentityResourceId = $mgrRegId
        Note "registry identity inherited from $ManagerApp (it already pulls this image)"
    }
}

$identityYaml = 'identity: { type: SystemAssigned }'
$registryYaml = "    registries: [ { server: `"$AcrName.azurecr.io`", identity: `"system`" } ]"
if ("$RegistryIdentityResourceId".Trim()) {
    # SystemAssigned as well: the system identity is what gets Contributor to ROLL, while the
    # user-assigned one PULLS. Two identities, two jobs, neither able to do the other's.
    $identityYaml = "identity: { type: `"SystemAssigned, UserAssigned`", userAssignedIdentities: { `"$("$RegistryIdentityResourceId".Trim())`": {} } }"
    $registryYaml = "    registries: [ { server: `"$AcrName.azurecr.io`", identity: `"$("$RegistryIdentityResourceId".Trim())`" } ]"
} else {
    Warn 'no registry identity found: the job will pull as its SYSTEM identity, which cannot hold AcrPull'
    Warn '  until after the job exists -- so the FIRST execution will fail to pull. AcrPull is granted'
    Warn '  below and the next execution will succeed; pass -RegistryIdentityResourceId to avoid the gap.'
}
$envYaml = "        env: [ " + (($envVars | ForEach-Object {
                $kv = "$_" -split '=', 2; "{ name: $($kv[0]), value: `"$($kv[1])`" }" }) -join ', ') + " ]"

# 🔴 THE IDENTITY BLOCK BELONGS TO `create` ONLY.
# `az containerapp job update --yaml <doc with identity:>` fails with
#     (FailedIdentityOperation) ... "The request format was unexpected : Request requires
#     identities to be assigned."
# because the update path does not accept an identity assignment inside the document -- identity is
# established at CREATE and changed afterwards with `az containerapp job identity assign`. Measured
# on the third live install. The same YAML therefore cannot serve both verbs, which is the sort of
# thing that only shows up on the RE-RUN of an installer, never on the first one.
$y = New-Object System.Collections.Generic.List[string]
[void]$y.Add("location: $location")
if (-not $exists) { [void]$y.Add($identityYaml) }
[void]$y.Add('properties:')
[void]$y.Add("  environmentId: $envId")
[void]$y.Add('  configuration:')
[void]$y.Add('    triggerType: Schedule')
[void]$y.Add('    replicaTimeout: 1800')
[void]$y.Add('    replicaRetryLimit: 0')
[void]$y.Add('    scheduleTriggerConfig:')
[void]$y.Add("      cronExpression: `"$Cron`"")
[void]$y.Add('      parallelism: 1')
[void]$y.Add('      replicaCompletionCount: 1')
[void]$y.Add($registryYaml)
[void]$y.Add('  template:')
[void]$y.Add('    containers:')
[void]$y.Add("      - name: $JobName")
[void]$y.Add("        image: $image")
[void]$y.Add('        command: [pwsh]')
[void]$y.Add("        args: [`"-NoProfile`", `"-ExecutionPolicy`", `"Bypass`", `"-File`", `"$entry`"]")
[void]$y.Add($envYaml)
[void]$y.Add('        resources: { cpu: 0.5, memory: 1.0Gi }')
$yamlPath = Join-Path ([IO.Path]::GetTempPath()) ("pim-update-job-{0}.yaml" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
Set-Content -LiteralPath $yamlPath -Value (($y.ToArray()) -join "`n") -Encoding ascii

# 🔴 AN ARM OPERATION ALREADY IN FLIGHT IS NOT A FAILURE -- IT IS A WAIT.
# Measured on the second live install: the first attempt created the job and then errored on a
# later step, and the re-run died with
#     (ContainerAppsJobOperationInProgress) Cannot modify a container apps job ... because there
#     is an active provisioning operation in progress.
# Re-running a deploy immediately after one that stopped part-way is the NORMAL recovery, and it
# is precisely when this happens. An idempotent installer that cannot be run twice in a row is not
# idempotent. Wait for the job to go idle first, then retry the call itself on the same error --
# the same bounded-backoff shape this repo already uses for Graph replication (BUG-44).
function Wait-PimJobIdle {
    param([string]$Name, [int]$TimeoutSeconds = 300)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $st = "$(az containerapp job show @sub -g $ResourceGroup -n $Name --query properties.provisioningState -o tsv 2>$null)".Trim()
        if (-not $st) { return 'Absent' }                       # not created yet -- nothing to wait for
        if ($st -notmatch '(?i)InProgress|Deleting|Waiting') { return $st }
        Note "  an operation is still in progress ($st) -- waiting"
        Start-Sleep -Seconds 10
    }
    return 'TimedOut'
}

try {
    $action = if ($exists) { 'update' } else { 'create' }
    if ($exists) {
        [void](Wait-PimJobIdle -Name $JobName)
        # An EXISTING job keeps whatever identity it has; if the registry identity we resolved is
        # not attached yet, attach it the only way the update path allows.
        if ("$RegistryIdentityResourceId".Trim()) {
            $attached = @(az containerapp job show @sub -g $ResourceGroup -n $JobName `
                            --query "identity.userAssignedIdentities" -o json 2>$null) -join ''
            if ("$attached" -notmatch [regex]::Escape("$RegistryIdentityResourceId".Trim())) {
                Step 'attach the registry identity to the existing job'
                az containerapp job identity assign @sub -g $ResourceGroup -n $JobName `
                    --user-assigned "$("$RegistryIdentityResourceId".Trim())" -o none 2>$null
                $global:LASTEXITCODE = 0
                [void](Wait-PimJobIdle -Name $JobName)
            }
        }
    }
    if ($PSCmdlet.ShouldProcess($JobName, "$action the nightly update job")) {
        Step "$action $JobName$(if ($exists) { ' (already exists)' })"
        $ok = $false
        foreach ($wait in @(0, 15, 30, 60)) {
            if ($wait) { Note "  retrying in ${wait}s"; Start-Sleep -Seconds $wait }
            $global:LASTEXITCODE = 0
            az containerapp job $action @sub -g $ResourceGroup -n $JobName --yaml $yamlPath -o none
            if ($LASTEXITCODE -eq 0) { $ok = $true; break }
            # Only the in-flight-operation case is worth retrying; anything else is a real failure
            # and retrying it just delays the report.
            $st = "$(az containerapp job show @sub -g $ResourceGroup -n $JobName --query properties.provisioningState -o tsv 2>$null)".Trim()
            if ($st -notmatch '(?i)InProgress|Waiting') { break }
        }
        if (-not $ok) { throw "Deploy-PimUpdateJob: 'az containerapp job $action' FAILED for $JobName (see the error above)." }
    }
} finally { Remove-Item -LiteralPath $yamlPath -Force -ErrorAction SilentlyContinue }

# ---- 1b. ring, source, last-built (+ everything the YAML would have dropped) -- over ARM ---------
if (-not $WhatIfPreference) {
    Step "write the update ring ($($ringPlan.ring)), its source and the store over ARM REST (never through az/cmd.exe: B9)"
    $allWrites = [ordered]@{}
    foreach ($k in @($ringPlan.writes.Keys))  { $allWrites["$k"] = $ringPlan.writes[$k] }
    foreach ($k in @($storePlan.writes.Keys)) { $allWrites["$k"] = $storePlan.writes[$k] }
    $wr = Invoke-PimUpdateJobEnvWrites -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -JobName $JobName `
              -Writes $allWrites -ContainerName $JobName -ArmInvoker $armInvoker
    Note ("written + read back: " + $(if ($wr.written.Count) { $wr.written -join ', ' } else { '(nothing -- already correct)' }))
    if ($wr.skipped.Count) { Note ("already correct: " + ($wr.skipped -join ', ')) }
} else {
    Note ("-WhatIf: would write over ARM: " + ((@($ringPlan.writes.Keys) + @($storePlan.writes.Keys)) -join ', '))
}

# ---- 2. the identity must be allowed to ROLL ---------------------------------------------------
# 🔴 WITHOUT THIS THE JOB RUNS NIGHTLY AND CHANGES NOTHING, reporting an ARM 403 into a log nobody
# reads. Contributor on the RESOURCE GROUP is the smallest role that can PATCH a container app and
# a job; it is scoped to this environment's own resource group and nothing wider.
if (-not $SkipRoleAssignment -and -not $WhatIfPreference) {
    $mi = "$(az containerapp job show @sub -g $ResourceGroup -n $JobName --query identity.principalId -o tsv 2>$null)".Trim()
    if (-not $mi) {
        Warn 'could not read the job managed identity -- grant Contributor on this resource group by hand, or the nightly roll will 403.'
    } else {
        $scope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $has = @(az role assignment list @sub --assignee $mi --scope $scope --query "[].roleDefinitionName" -o tsv 2>$null) |
               Where-Object { "$_".Trim() -in @('Contributor','Owner') }
        if ($has) { Note "identity already holds $($has -join ', ') on the resource group" }
        else {
            Step 'grant the job identity Contributor on this resource group'
            az role assignment create @sub --assignee-object-id $mi --assignee-principal-type ServicePrincipal `
                --role Contributor --scope $scope -o none 2>$null
            # 🪤 Read it back. A role assignment that silently failed is indistinguishable from one
            # that worked until the first nightly run 403s at 03:00 -- see the deploy path's own
            # history of creates that were trusted rather than verified.
            $after = @(az role assignment list @sub --assignee $mi --scope $scope --query "[].roleDefinitionName" -o tsv 2>$null) |
                     Where-Object { "$_".Trim() -in @('Contributor','Owner') }
            if ($after) { Note 'granted + verified' }
            else { Warn 'the role assignment did NOT take. The nightly roll will fail with 403 until it is granted.' }
        }

        # 🔴 AND AcrPull ON THE REGISTRY -- what the job needs to START, as opposed to what it
        # needs to DO. Contributor on the resource group lets it roll apps; it does not let it pull
        # its own image. Granting only the first produced a job that ran twice, wrote nothing to any
        # log table, and reported "Unknown": there was no container to write anything.
        # This is belt-and-braces when the registry identity was inherited above (that one already
        # holds AcrPull), and it is the ONLY thing that makes the system-identity fallback work at
        # all -- from its second execution onward.
        # 🔴 §55 -- BUILDING NEEDS MORE THAN PULLING. Scheduling a build in the registry is a
        # CONTROL-PLANE write on the registry resource, so AcrPull is not enough: the identity
        # needs Contributor there. It already gets Contributor on the RESOURCE GROUP above, which
        # covers a registry living in that group -- but an environment whose registry sits in a
        # different resource group would pass every check here and then fail its first build with
        # a 403, at 03:00, in a customer tenant.
        if ("$($ringPlan.sourceUrl)".Trim()) {
            $acrGroup ="$(az acr show @sub -n $AcrName --query resourceGroup -o tsv 2>$null)".Trim()
            if ($acrGroup -and $acrGroup -ne $ResourceGroup) {
                # 🔴 §55.3 -- GRANT IT, DO NOT WARN ABOUT IT.
                # This used to print three yellow lines and carry on reporting success. A warning
                # at install time is read once, by someone who is watching; the 403 it predicts
                # arrives at 03:00 in a customer tenant, unattended, and the install that caused it
                # said OK. An installer that can see the exact missing grant and does not make it is
                # handing the operator a bug with a receipt.
                Step "grant the job identity Contributor on registry '$AcrName' (it lives in '$acrGroup', not '$ResourceGroup')"
                $acrScope = "$(az acr show @sub -n $AcrName --query id -o tsv 2>$null)".Trim()
                if (-not $acrScope) {
                    Warn "registry '$AcrName' could not be resolved -- cannot grant build rights; the first nightly build will 403."
                } else {
                    $hasBuild = @(az role assignment list @sub --assignee $mi --scope $acrScope --query "[].roleDefinitionName" -o tsv 2>$null) |
                                Where-Object { "$_".Trim() -in @('Contributor','Owner') }
                    if ($hasBuild) { Note "identity already holds $($hasBuild -join ', ') on the registry" }
                    else {
                        az role assignment create @sub --assignee-object-id $mi --assignee-principal-type ServicePrincipal `
                            --role Contributor --scope $acrScope -o none 2>$null
                        $global:LASTEXITCODE = 0
                        # 🔑 VERIFY. A role assignment that did not take looks exactly like one that
                        # did from here, and the difference only surfaces on the first build.
                        $buildAfter = @(az role assignment list @sub --assignee $mi --scope $acrScope --query "[].roleDefinitionName" -o tsv 2>$null) |
                                      Where-Object { "$_".Trim() -in @('Contributor','Owner') }
                        if ($buildAfter) { Note 'build rights granted + verified on the registry' }
                        else {
                            Warn "could NOT grant Contributor on '$AcrName' (in '$acrGroup')."
                            Warn '  This job builds its own image, which is a control-plane write on the registry.'
                            Warn '  Grant it there, or the first nightly build will 403 after this install reports success.'
                        }
                    }
                }
            } else {
                Note 'build rights: Contributor on this resource group covers the registry in it'
            }
        }

        $acrId = "$(az acr show @sub -n $AcrName --query id -o tsv 2>$null)".Trim()
        if (-not $acrId) {
            Warn "registry '$AcrName' not found in this subscription -- cannot grant AcrPull; the job may be unable to pull its image."
        } else {
            $hasPull = @(az role assignment list @sub --assignee $mi --scope $acrId --query "[].roleDefinitionName" -o tsv 2>$null) |
                       Where-Object { "$_".Trim() -in @('AcrPull','Contributor','Owner') }
            if ($hasPull) { Note "identity already holds $($hasPull -join ', ') on the registry" }
            else {
                Step 'grant the job identity AcrPull on the registry'
                az role assignment create @sub --assignee-object-id $mi --assignee-principal-type ServicePrincipal `
                    --role AcrPull --scope $acrId -o none 2>$null
                $pullAfter = @(az role assignment list @sub --assignee $mi --scope $acrId --query "[].roleDefinitionName" -o tsv 2>$null) |
                             Where-Object { "$_".Trim() -in @('AcrPull','Contributor','Owner') }
                if ($pullAfter) { Note 'AcrPull granted + verified' }
                else { Warn 'AcrPull did NOT take -- the job will not be able to pull its image and will report status Unknown.' }
            }
        }
    }
}

# ---- 2c. the updater's DATABASE USER -- the tick's grant path, not a new one ---------------------
# 🔴 Copying PIM_SqlServer is half of it: the schema step connects as THIS job's managed identity, and an
# identity with no contained user gets "Login failed for user <token-identified principal>" -- which the
# updater correctly turns into "NOT ROLLING", every night. Same helpers as the tick (Setup-PimContainers):
# Resolve-PimMiAppId, then Grant-PimMiSql on public SQL, or the in-cloud bootstrap job on private SQL.
$sqlGrantProblem = ''
# ---- 2b. 2026-09-15 -- THE SQL ADMIN GROUP: the updater identity joins it -------------------------
# 🔑 Where the server's Entra admin is the SQL admin group, membership IS the database access -- no
# contained user, no SQL connection from this host, and it works the same on public and private SQL.
# Measured live 2026-09-15 on two tenants: a managed identity that is a member of the admin group logs in
# and runs the schema DDL. MEMBERS ONLY: this never creates the group or moves the admin, so running it
# against an environment still on a single-principal admin changes nothing (it says so).
$groupMember = $false
if (-not $WhatIfPreference -and -not $SkipSqlAdminGroup -and $storePlan.hasStore -and $storePlan.writes.Contains('PIM_SqlServer')) {
    Step "SQL admin group '$SqlAdminGroupName' -- the updater identity"
    try {
        $inv = New-PimSqlAdminGroupInvokers -SubscriptionId $SubscriptionId
        $srvRes = Resolve-PimSqlServerFromFqdn -Arm $inv.Arm -SubscriptionId $SubscriptionId -Server "$($storePlan.writes['PIM_SqlServer'])"
        if (-not $srvRes) { throw "SQL server '$($storePlan.writes['PIM_SqlServer'])' is not in subscription $SubscriptionId." }
        $gr = Invoke-PimSqlAdminGroupStep -Graph $inv.Graph -Arm $inv.Arm -TenantId $inv.TenantId -SubscriptionId $SubscriptionId `
                  -ResourceGroup $ResourceGroup -SqlResourceGroup $srvRes.resourceGroup -SqlServerName $srvRes.name `
                  -GroupName $SqlAdminGroupName -UpdateJobName $JobName -Mode membersOnly -NoDiscovery
        Write-PimSqlAdminGroupReport -Result $gr
        if ($gr.ok -and -not $gr.blocked) {
            $groupMember = $true
            Note "the updater identity is a member of '$SqlAdminGroupName', the Entra admin of $($srvRes.name) -- its schema step can log in"
        } elseif ($gr.ok) {
            Note 'not on the group model -- the updater reaches SQL through its contained database user (next step)'
        } else {
            Warn "could not make the updater identity a member of '$SqlAdminGroupName' -- the contained-user step below still runs"
        }
    } catch {
        Warn "SQL admin group step skipped: $($_.Exception.Message) -- the contained-user step below still runs"
    }
}
if (-not $WhatIfPreference -and $storePlan.hasStore) {
    $haveCred = [bool]("$SqlAdminClientId".Trim() -and "$TenantId".Trim() -and ("$SqlAdminCertThumbprint".Trim() -or "$SqlAdminClientSecret".Trim()))
    if ($UseSignedInAccount -and "$TenantId".Trim()) { $haveCred = $true }   # 71.33
    $dbInitExists = $false
    if ($SqlPrivate) {
        $dbInitExists = [bool](@(az containerapp job list @sub -g $ResourceGroup --query "[].name" -o tsv 2>$null) |
                               Where-Object { "$_".Trim() -eq $DbInitJobName })
    }
    $grantPlan = Get-PimUpdaterSqlGrantPlan -HasStore $true -SqlPrivate ([bool]$SqlPrivate) -HaveAdminCredential $haveCred `
                    -DbInitJobExists $dbInitExists -UpdateJobName $JobName -DbInitJobName $DbInitJobName
    Step "database user for $JobName ($($grantPlan.action))"
    if ($grantPlan.action -in @('infra', 'manual') -and $groupMember) {
        # Group membership already gives the updater its database access; a contained user is not needed.
        Note "no contained user granted from here ($($grantPlan.action)) -- not needed: the updater is a member of '$SqlAdminGroupName'"
    } elseif ($grantPlan.action -in @('infra', 'manual')) {
        $sqlGrantProblem = $grantPlan.message
        Write-Host "    $($grantPlan.message)" -ForegroundColor Red
    } elseif (-not $storePlan.writes.Contains('PIM_SqlServer')) {
        $sqlGrantProblem = "$JobName has no PIM_SqlServer to grant against (see the store step above)."
        Write-Host "    $sqlGrantProblem" -ForegroundColor Red
    } else {
        Note $grantPlan.message
        try {
            $updOid = "$(az containerapp job show @sub -g $ResourceGroup -n $JobName --query identity.principalId -o tsv 2>$null)".Trim()
            if (-not $updOid) { throw "$JobName has no system-assigned identity -- nothing to grant." }
            . (Join-Path $here '_PimSetupShared.ps1')                  # Resolve-PimMiAppId / Grant-PimMiSql
            $updAppId = Resolve-PimMiAppId -ObjectId $updOid -What $JobName
            if ($grantPlan.action -eq 'direct') {
                if (-not $storePlan.writes.Contains('PIM_SqlDatabase')) {
                    throw "$ManagerApp carries no PIM_SqlDatabase -- refusing to guess which database to create the user in."
                }
                $solRootG = Split-Path -Parent (Split-Path -Parent $here)
                . (Join-Path $solRootG 'engine\_shared\PIM-Rest.ps1')      # Get-PimRestToken
                . (Join-Path $solRootG 'engine\_shared\PIM-SqlStore.ps1')  # New-PimSqlConnection
                if ($UseSignedInAccount) {
                    Grant-PimMiSql -DbUserName $JobName -MiAppId $updAppId -SqlServerFqdn "$($storePlan.writes['PIM_SqlServer'])" `
                        -SqlDatabase "$($storePlan.writes['PIM_SqlDatabase'])" -TenantId $TenantId -UseSignedInAccount
                } else {
                $cred = if ("$SqlAdminCertThumbprint".Trim()) { @{ SqlAdminCertThumbprint = $SqlAdminCertThumbprint } }
                        else { @{ SqlAdminClientSecret = $SqlAdminClientSecret } }
                Grant-PimMiSql -DbUserName $JobName -MiAppId $updAppId -SqlServerFqdn "$($storePlan.writes['PIM_SqlServer'])" `
                    -SqlDatabase "$($storePlan.writes['PIM_SqlDatabase'])" -TenantId $TenantId -SqlAdminClientId $SqlAdminClientId @cred
                }
                Note "database user [$JobName] granted (MI appId $updAppId)"
            } else {
                $dbPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$DbInitJobName"
                $dbEnv  = ConvertTo-PimJobEnvMap -Job (& $armInvoker -Method GET -Path $dbPath -ApiVersion $script:PimAcaApi) -ContainerName $DbInitJobName
                $merged = Merge-PimDbInitPrincipals -Json $(if ($dbEnv.Contains('PIM_DBINIT_PRINCIPALS')) { "$($dbEnv['PIM_DBINIT_PRINCIPALS'])" } else { '' }) `
                              -Name $JobName -AppId $updAppId
                if (-not $merged.changed) {
                    Note "[$JobName] is already one of $DbInitJobName's principals -- created by its last run"
                } else {
                    # ARM, never az: the value is a JSON array, and cmd.exe strips its quotes (measured twice).
                    [void](Invoke-PimUpdateJobEnvWrites -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -JobName $DbInitJobName `
                               -Writes ([ordered]@{ PIM_DBINIT_PRINCIPALS = $merged.json }) -ContainerName $DbInitJobName -ArmInvoker $armInvoker)
                    $exec = "$(az containerapp job start @sub -g $ResourceGroup -n $DbInitJobName --query name -o tsv 2>$null)".Trim()
                    if (-not $exec) { throw "could not start '$DbInitJobName'." }
                    Note "execution $exec -- waiting"
                    $status = ''
                    for ($i = 0; $i -lt 60; $i++) {
                        Start-Sleep -Seconds 10
                        $status = "$(az containerapp job execution show @sub -g $ResourceGroup -n $DbInitJobName --job-execution-name $exec --query properties.status -o tsv 2>$null)".Trim()
                        if ($status -in @('Succeeded', 'Failed', 'Degraded')) { break }
                    }
                    if ($status -ne 'Succeeded') { throw "the database bootstrap '$exec' ended '$status' (az containerapp job logs show -g $ResourceGroup -n $DbInitJobName --execution $exec --subscription $SubscriptionId)." }
                    Note "database user [$JobName] created in-cloud ($exec)"
                }
            }
        } catch {
            $sqlGrantProblem = "the database user for $JobName was NOT granted: $($_.Exception.Message)"
            Write-Host "    $sqlGrantProblem" -ForegroundColor Red
        }
    }
}

# ---- 3. read the job back ----------------------------------------------------------------------
if (-not $WhatIfPreference) {
    $back = az containerapp job show @sub -g $ResourceGroup -n $JobName `
                --query "{name:name,trigger:properties.configuration.triggerType,cron:properties.configuration.scheduleTriggerConfig.cronExpression,image:properties.template.containers[0].image}" -o json 2>$null
    if (-not $back) { throw "Deploy-PimUpdateJob: '$JobName' cannot be read back after deployment -- do not treat this as installed." }
    Note "verified: $back"

    # BUG-162 -- THE RING THE JOB ACTUALLY CARRIES, READ OFF THE DEPLOYED JOB.
    # A silently different ring is a silently different VERSION: dp998 was built at 2.4.366 with
    # `"updater": { "ring": 1 }` in its config and came up carrying PIM_UPDATE_RING=2, whose channel
    # held 2.4.324 -- and its first nightly run rolled the whole environment 42 versions backward.
    # The env writes above are already read back value-by-value, so this cannot fail for a value this
    # script wrote; it catches the case the writes cannot see -- something else (a later YAML apply, a
    # concurrent deploy, a hand edit) leaving a ring that is not the one this run decided. Cheap, and
    # the alternative is finding out at 03:00.
    $ringBack = ''
    try {
        $jobBack  = & $armInvoker -Method GET -Path $jobArmPath -ApiVersion $script:PimAcaApi
        $envBack  = ConvertTo-PimJobEnvMap -Job $jobBack -ContainerName $JobName
        if (-not $envBack.Count) { $envBack = ConvertTo-PimJobEnvMap -Job $jobBack }
        if ($envBack.Contains('PIM_UPDATE_RING')) { $ringBack = "$($envBack['PIM_UPDATE_RING'])".Trim() }
    } catch { Warn ("could not read the ring back over ARM: " + (Hide-PimSasText "$($_.Exception.Message)")) }
    if (-not $ringBack) {
        throw ("Deploy-PimUpdateJob: '$JobName' carries NO PIM_UPDATE_RING after this deploy. An updater with " +
               'no ring is an updater nothing controls -- do not treat this as installed.')
    }
    if ($ringBack -ne "$($ringPlan.ring)") {
        throw ("Deploy-PimUpdateJob: the DEPLOYED ring is not the ring this deploy decided -- '$JobName' carries " +
               "PIM_UPDATE_RING=$ringBack, expected $($ringPlan.ring). A different ring approves a different " +
               'VERSION, so this environment would move somewhere nobody asked for (BUG-162: a ring-2 job on an ' +
               'environment built for ring 1 rolled it 42 versions BACKWARD overnight). Re-run this script with ' +
               "-UpdateRing $($ringPlan.ring) and check nothing else is writing this job.")
    }
    Note "ring verified on the deployed job: PIM_UPDATE_RING=$ringBack"
}

# ---- 4. what does this ring APPROVE, read the way the job itself will read it -----------------
# A deploy that reports "installed" while its ring approves nothing -- or approves a version this
# environment is not on -- is a success message about an environment that will not do what the
# operator thinks. Say it here, loudly, while someone is watching.
$curVer = if ("$LastBuiltVersion".Trim()) { "$LastBuiltVersion".Trim() }
          elseif ("$TargetVersion".Trim()) { "$TargetVersion".Trim() }
          elseif ($ringPlan.writes.Contains('PIM_UPDATE_LAST_BUILT')) { "$($ringPlan.writes['PIM_UPDATE_LAST_BUILT'])" }
          elseif ("$TargetImage" -match ':(?<t>[^:/]+)$') { $Matches['t'] } else { '' }
$chRep = Get-PimUpdateRingChannelReport -SourceUrlTemplate $ringPlan.sourceUrl -Ring $ringPlan.ring -CurrentVersion $curVer
switch ($chRep.level) {
    'ok'    { Write-Host "==> ring $($ringPlan.ring): $($chRep.message)" -ForegroundColor Green }
    'warn'  { Write-Host "==> ring $($ringPlan.ring): $($chRep.message)" -ForegroundColor Yellow }
    default { Write-Host "==> ring $($ringPlan.ring): $($chRep.message)" -ForegroundColor Red }
}

if ($sqlGrantProblem -or $storePlan.level -eq 'error') {
    Write-Host '==> STORE: this updater cannot verify schema yet, so it REFUSES every release that moves the version.' -ForegroundColor Red
    if ($sqlGrantProblem) { Write-Host "    $sqlGrantProblem" -ForegroundColor Red }
}
Write-Host "==> Nightly updater installed on ring $($ringPlan.ring). It runs $Cron (UTC)." -ForegroundColor Green
Write-Host "    Trigger it now with:" -ForegroundColor DarkGray
Write-Host "      az containerapp job start -g $ResourceGroup -n $JobName --subscription $SubscriptionId" -ForegroundColor White
Write-Host "    Watch it with:" -ForegroundColor DarkGray
Write-Host "      az containerapp job execution list -g $ResourceGroup -n $JobName --subscription $SubscriptionId -o table" -ForegroundColor White
exit 0
