# =============================================================================
# PIM-DownlinkJob.ps1 -- the PURE, offline-testable plan brain for the §31.3
# CLOUD-NATIVE master->managed (slave) downlink as an Azure Container Apps JOB
# with a CRON schedule (operator directive 2026-06-17: "all run in cloud only
# compute, in one test"; "run it through the containers in the slave").
#
# WHAT this delivers
#   The downlink (PIM-Downlink.ps1 / setup/Invoke-PimDownlinkSync.ps1) was a
#   wrapper run by-hand or by a Windows scheduled task. THIS turns it into a
#   first-class CLOUD scheduled JOB: an `az containerapp job` of trigger-type
#   Schedule that, on its cron cadence, runs the SAME pim-manager image with a
#   command/entrypoint that pulls -> verifies -> stages -> applies the ring-gated
#   downlink for ONE scenario+tenant+ring. Two placements:
#     * S5 -> the Job runs in the CENTRAL ACA env (cae-pim, MSP tenant) using the
#             MULTI-TENANT SPN (acts into the slave).
#     * S6 -> the Job runs in the SLAVE tenant's OWN ACA env using a LOCAL SPN.
#
# DESIGN TENETS (mirror the rest of PIM4EntraPS)
#   * PURE core here: NO az / Graph / SQL / HTTP / file I/O / global mutation. The
#     functions take FACTS and RETURN the `az containerapp job` argument arrays +
#     decisions. The thin live wrapper (tools/setup/Deploy-PimDownlinkJob.ps1)
#     gathers facts and INVOKES az with these arrays. That keeps every risky
#     decision -- which placement, which env, which identity, private-only, no
#     inline secret, idempotent create-vs-update -- unit-testable in real PS 5.1
#     with NO az and NO live tenant.
#   * private transport (REQUIREMENTS §31.3 hard constraint): the Job runs on the
#     INTERNAL ACA env (already private-only via Setup-PimContainers). A scheduled
#     Job has NO ingress at all (it is not an app) -- there is nothing public to
#     expose. The signed-baseline pull + sync-file staging traverse private
#     cross-tenant VNet only. The plan NEVER emits a public endpoint.
#   * no inline secret: identity is a Managed Identity (system/user-assigned) or an
#     SPN cert resolved at runtime from the store -- the plan emits identity refs /
#     secret-refs (Key Vault) ONLY, never a secret VALUE on the command line.
#   * idempotent: a re-deploy emits an `az containerapp job update` for an existing
#     Job (same name) instead of `create`; -Unregister emits `delete`.
#
# PS 5.1 COMPATIBLE: no ?. / ??, no ternary, Set-StrictMode -Off, null-guarded
#   property access, IDictionary-vs-PSCustomObject dual reads.
#
# REUSE (does not reinvent): the env/MI/registry/private pattern proven in
#   tools/setup/Setup-PimContainers.ps1 (the worker matrix); the image built by
#   tools/setup/Build-PimManagerImage.ps1; the downlink invoked by
#   setup/Invoke-PimDownlinkSync.ps1 + setup/Invoke-PimScenarioRun.ps1; scenario
#   resolution in engine/_shared/PIM-ScenarioProfile.ps1.
# =============================================================================

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Small null-safe property reader (IDictionary OR PSCustomObject). Mirrors
# Get-PimDownlinkValue so this file is self-contained.
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobValue {
    param([object]$Object, [Parameter(Mandatory)][string]$Key)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Key)) { return $Object[$Key] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    return $null
}

# ---------------------------------------------------------------------------
# PLACEMENT RESOLUTION (pure). Where does the cron Job live + which identity does
# it act with, for a given scenario? Mirrors the scenario descriptor (S5 central /
# S6 local) WITHOUT importing the whole resolver (so this core is standalone +
# testable). The caller may pass the resolved scenario context to override.
#   S5 -> placement=central, spnModel=multi-tenant-spn, syncFileLocation=central-msp
#   S6 -> placement=local,   spnModel=local-spn,        syncFileLocation=local-slave
# Returns @{ ok; reason; scenarioId; placement; spnModel; syncFileLocation;
#            hostingLocation; envScope }. envScope = 'central-msp' | 'local-slave'.
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobPlacement {
    param(
        [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario
    )
    $id = "$Scenario".Trim().ToUpperInvariant()
    if ($id -eq 'S5') {
        return @{
            ok = $true; reason = 'S5: cron Job runs in the CENTRAL ACA env (MSP tenant), multi-tenant SPN acts into the slave'
            scenarioId = 'S5'; placement = 'central'; spnModel = 'multi-tenant-spn'
            syncFileLocation = 'central-msp'; hostingLocation = 'central-msp'; envScope = 'central-msp'
        }
    }
    return @{
        ok = $true; reason = "S6: cron Job runs in the SLAVE tenant's OWN ACA env, local SPN"
        scenarioId = 'S6'; placement = 'local'; spnModel = 'local-spn'
        syncFileLocation = 'local-slave'; hostingLocation = 'local-slave'; envScope = 'local-slave'
    }
}

# ---------------------------------------------------------------------------
# CRON VALIDATION (pure). A standard 5-field cron expression (min hour dom mon dow).
# ACA Jobs use 5-field cron (UTC). Returns @{ ok; reason }. Fail-safe: blank/wrong
# field count is rejected so the deploy never silently schedules nothing.
# ---------------------------------------------------------------------------
function Test-PimDownlinkJobCron {
    param([Parameter(Mandatory)][string]$Cron)
    $c = "$Cron".Trim()
    if (-not $c) { return @{ ok = $false; reason = 'cron expression is blank' } }
    $fields = @($c -split '\s+' | Where-Object { "$_".Trim() })
    if ($fields.Count -ne 5) {
        return @{ ok = $false; reason = "cron must have 5 fields (min hour day-of-month month day-of-week); got $($fields.Count): '$c'" }
    }
    return @{ ok = $true; reason = "valid 5-field cron '$c' (UTC)" }
}

# ---------------------------------------------------------------------------
# THE CONTAINER COMMAND (pure). The command/args array the Job container runs --
# pwsh invoking the in-container downlink-job entrypoint with the scenario/tenant/
# ring + the baseline source. This is what makes a run actually pull+sync+apply.
# Returns a string[] (command + args) suitable for `--command` / YAML.
#   -EntryPath      : container path to the entrypoint (default the engine path).
#   -Scenario/-TenantId/-SlaveRing : forwarded to the entrypoint.
#   -BaselineUrl    : private-endpoint blob URL of the signed baseline (S5/S6).
#   -BaselineDocPath: mounted/local path to a pulled bundle (alt to -BaselineUrl).
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobCommand {
    param(
        [string]$EntryPath = '/app/PIM4EntraPS/tools/pim-engine/downlink-job-entry.ps1',
        [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario,
        [Parameter(Mandatory)][string]$TenantId,
        [ValidateRange(0,2)][int]$SlaveRing = 2,
        [string]$BaselineUrl,
        [string]$BaselineDocPath
    )
    $cmd = New-Object System.Collections.Generic.List[string]
    $cmd.Add('pwsh') | Out-Null
    $cmd.Add('-NoProfile') | Out-Null
    $cmd.Add('-ExecutionPolicy') | Out-Null
    $cmd.Add('Bypass') | Out-Null
    $cmd.Add('-File') | Out-Null
    $cmd.Add("$EntryPath") | Out-Null
    $cmd.Add('-Scenario') | Out-Null;  $cmd.Add("$Scenario") | Out-Null
    $cmd.Add('-TenantId') | Out-Null;  $cmd.Add("$TenantId") | Out-Null
    $cmd.Add('-SlaveRing') | Out-Null; $cmd.Add("$SlaveRing") | Out-Null
    if ("$BaselineUrl".Trim())     { $cmd.Add('-BaselineUrl') | Out-Null;     $cmd.Add("$BaselineUrl") | Out-Null }
    if ("$BaselineDocPath".Trim()) { $cmd.Add('-BaselineDocPath') | Out-Null; $cmd.Add("$BaselineDocPath") | Out-Null }
    return @($cmd.ToArray())
}

# ---------------------------------------------------------------------------
# ENV-VAR SET (pure). The non-secret env the Job container needs: scenario knobs,
# SQL coordinates (MI-auth, NO password), sync-file roots, REST-only flag. NEVER a
# secret value -- secrets are injected as secret-refs by Build-...JobArgs, not here.
# Returns string[] of NAME=VALUE.
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobEnv {
    param(
        [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$SqlServerFqdn,
        [string]$SqlDatabase = 'PimPlatform',
        [string]$SyncRootCentral = '/sync/central',
        [string]$SyncRootLocal   = '/sync/local',
        # BUG-72: the engine's app-only identity. ClientId is NOT secret and goes in as a plain
        # value; the secret is referenced, never valued (see -EngineSecretRef).
        [string]$EngineClientId,
        [string]$EngineSecretRef,
        # BUG-73: the baseline URL when it carries a SAS -- a credential, so it is referenced too.
        [string]$BaselineUrlSecretRef,
        # BUG-76: the USER-ASSIGNED MI's client id. Container Apps attaches a user-assigned
        # identity with no system identity alongside it, and the IDENTITY_ENDPOINT token call
        # cannot pick an identity on its own -- so without this the container gets NO token and
        # presents no credential to SQL.
        [string]$ManagedIdentityClientId,
        # BUG-84: fallback TAP delivery address for synced admins. Not a secret -- an address --
        # so it travels as a plain env value. Absent => the AdminTap guard still refuses, which is
        # the correct behaviour and not a silent downgrade.
        [string]$DefaultManagerEmail
    )
    $placement = Get-PimDownlinkJobPlacement -Scenario $Scenario
    $ev = New-Object System.Collections.Generic.List[string]
    $ev.Add('PIM_HOSTED=1') | Out-Null
    $ev.Add('PIM_UseGraphSdk=false') | Out-Null
    $ev.Add("PIM_ActiveScenario=$Scenario") | Out-Null
    $ev.Add("PIM_TenantId=$TenantId") | Out-Null
    $ev.Add('PIM_StorageBackend=sql') | Out-Null
    if ("$SqlServerFqdn".Trim()) { $ev.Add("PIM_SqlServer=$SqlServerFqdn") | Out-Null }
    $ev.Add("PIM_SqlDatabase=$SqlDatabase") | Out-Null
    # Sync-file staging root the scenario uses (central for S5, local for S6).
    if ("$($placement.envScope)" -eq 'central-msp') { $ev.Add("PIM_SyncRootCentral=$SyncRootCentral") | Out-Null }
    else { $ev.Add("PIM_SyncRootLocal=$SyncRootLocal") | Out-Null }

    # 🔴 BUG-72 -- THIS FUNCTION USED TO EMIT NO ENGINE CREDENTIAL AT ALL, so every scheduled
    # downlink ran as the container's Managed Identity. Measured on the first real execution:
    #   [downlink-job] [INFO] identity model: Managed Identity (local-spn)
    # while the deploy script's own header claimed it passed "an SPN cert whose thumbprint/clientId
    # are read from the store". It did not. MI is fine for SQL (the tick job proves it), but the
    # engine's Graph work needs the engine SPN.
    # 🪤 AND THE OBVIOUS FIX IS WRONG: do NOT copy the tick job's PIM_ClientId + PIM_CertThumbprint.
    # Resolve-PimCertificate (PIM-Rest.ps1) only searches Cert:\CurrentUser\My and
    # Cert:\LocalMachine\My, which are EMPTY in a Linux container -- and setting PIM_ClientId also
    # DISABLES the MI branch (Get-PimRestToken takes 'mi' only when IDENTITY_ENDPOINT is set AND
    # there is no client id). So a cert thumbprint in here would break the working SQL path and
    # authenticate nothing: measured on the live tick job, which reports Succeeded every 5 minutes
    # while logging ~15x "SPN token failed: could not acquire a token for database.windows.net".
    # The container path is CLIENT ID + SECRET (IMP-08, the same shape Setup-PimContainers uses,
    # whose own comment says "a container has no cert store, so the estate uses the secret path").
    if ("$EngineClientId".Trim()) {
        $ev.Add("PIM_ClientId=$EngineClientId") | Out-Null
        if ("$EngineSecretRef".Trim()) { $ev.Add("AZURE_CLIENT_SECRET=secretref:$EngineSecretRef") | Out-Null }
    }
    # BUG-73: a SAS-bearing baseline URL arrives as a secret reference and is read from the env by
    # downlink-job-entry.ps1 ($BaselineUrl = $env:PIM_BaselineUrl). It is deliberately NOT put on
    # the command line, where it would be readable in the job definition forever.
    if ("$BaselineUrlSecretRef".Trim()) { $ev.Add("PIM_BaselineUrl=secretref:$BaselineUrlSecretRef") | Out-Null }
    # BUG-76: name the identity the IDENTITY_ENDPOINT call must ask for. Not a secret -- a client id.
    if ("$ManagedIdentityClientId".Trim()) { $ev.Add("PIM_ManagedIdentityClientId=$ManagedIdentityClientId") | Out-Null }
    # BUG-84: Invoke-PimScenarioRun defaults -DefaultManagerEmail from this env var.
    if ("$DefaultManagerEmail".Trim()) { $ev.Add("PIM_DefaultManagerEmail=$DefaultManagerEmail") | Out-Null }
    return @($ev.ToArray())
}

# ---------------------------------------------------------------------------
# THE az containerapp job ARG SET (pure). Build the exact argument array for a
# create / update / delete / start of the scheduled downlink Job. This is the
# single decision the deploy wrapper executes via `& az @args`. Mirrors the proven
# Setup-PimContainers pattern (env id, workload profile, MI, registry-by-MI) but
# for a JOB (trigger-type Schedule + cron) instead of an App.
#
#   -Action          : create | update | delete | start  (idempotent: the wrapper
#                      picks create-vs-update from an existence probe; this fn just
#                      emits the requested action's args).
#   -JobName/-ResourceGroup/-EnvName : the ACA job + its env (private, internal-only).
#   -Image           : <acr>.azurecr.io/<repo>:<tag> (the pim-manager image).
#   -AcrServer       : <acr>.azurecr.io (registry pulled via MI -- no creds).
#   -Cron            : 5-field cron (UTC). Required for create/update.
#   -Command         : string[] from Get-PimDownlinkJobCommand.
#   -EnvVars         : string[] from Get-PimDownlinkJobEnv (NAME=VALUE, non-secret).
#   -IdentityResourceId : a USER-assigned MI resource id to attach (S5/S6). When
#                      blank, -SystemAssigned attaches the system MI instead.
#   -SystemAssigned  : attach a system-assigned MI (default when no user MI).
#   -RegistryIdentity: 'system' | <user-MI-resource-id> -- how the Job pulls from
#                      ACR (AcrPull on that identity). Default 'system'.
#   -Cpu/-Memory     : container resources (defaults 0.5 / 1Gi).
#   -ReplicaTimeout  : per-execution timeout seconds (default 1800).
#   -ReplicaRetryLimit : retries on failure (default 1).
#
# Returns @{ ok; reason; action; args=string[]; private=$true; hasInlineSecret=$bool }.
# hasInlineSecret is ALWAYS $false by construction -- the test asserts it; if a
# caller ever tried to pass a raw secret this fn would still not emit one (it has no
# secret parameter). private=$true documents the no-ingress invariant (a Job is not
# an app; it exposes no endpoint), reinforced by the internal-only env it targets.
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobYaml {
    <#
      PURE. Render the `az containerapp job --yaml` document for the scheduled downlink Job.

      🪤 BUG-38 -- WHY THIS EXISTS INSTEAD OF `--command`.
      `az containerapp job create --command pwsh -NoProfile -File <x> -Scenario S5` FAILS with
      "unrecognized arguments: -NoProfile -File ... -Scenario". The CLI's parser treats ANY
      '-'-prefixed token as a new OPTION rather than a value, so a command whose arguments carry
      leading dashes cannot be expressed through --command AT ALL. Every downlink command this
      module builds is exactly that shape, so the shipped MSP deploy path could never have worked.
      The worker apps and the ESTATE-06 tick Job already deploy via YAML for this reason; this
      brings the downlink Job onto the same proven shape -- `command: [pwsh]` + a separate `args`
      array, where a leading dash is just a string.

      Takes FACTS (location, environmentId) rather than looking them up: the wrapper probes Azure,
      this stays pure and unit-testable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$EnvironmentId,
        [Parameter(Mandatory)][string]$Image,
        [Parameter(Mandatory)][string]$Cron,
        [string[]]$Command = @(),
        [string[]]$EnvVars = @(),
        [string]$AcrServer,
        [string]$IdentityResourceId,
        [switch]$SystemAssigned,
        [string]$RegistryIdentity = '',   # '' = AUTO: the user-assigned MI if attached, else system (BUG-42)
        [double]$Cpu = 0.5,
        [string]$Memory = '1Gi',
        [int]$ReplicaTimeout = 1800,
        [int]$ReplicaRetryLimit = 1,
        # BUG-72/73: ACA secrets as `name=value`; referenced from env as `secretref:<name>`.
        [string[]]$Secrets = @()
    )
    # identity. 🪤 `type` MUST be a QUOTED string: in a YAML flow mapping
    # `{ type: SystemAssigned, UserAssigned }` parses as `type: SystemAssigned` PLUS a separate
    # null key `UserAssigned`, so the type silently degrades and ARM rejects the identity ids with
    # "(InvalidResourceIdentityType)". The comma is part of the VALUE. Learned in Setup-PimContainers.
    if ("$IdentityResourceId".Trim()) {
        $idType = 'UserAssigned'
        if ($SystemAssigned) { $idType = 'SystemAssigned, UserAssigned' }
        $identityYaml = "identity: { type: `"$idType`", userAssignedIdentities: { `"$IdentityResourceId`": {} } }"
    } else {
        $identityYaml = 'identity: { type: SystemAssigned }'
    }
    # registry via MANAGED IDENTITY only -- never an inline credential.
    #
    # 🪤 BUG-42 -- WHICH identity pulls. `-RegistryIdentity` is '' by default, meaning AUTO:
    # when a user-assigned MI is attached it does the pull, otherwise the system identity does.
    # It used to default to the literal 'system' even when a UAMI was supplied, which contradicts
    # the only reason the UAMI is attached (stated in Build-PimDownlinkJobArgs): a system identity
    # CANNOT pull the first image, because it does not exist until the job it belongs to does. So
    # a create with a UAMI told ACA to pull with the one identity that could not -- and nothing
    # granted AcrPull to the system identity in that branch either.
    # An EXPLICIT -RegistryIdentity (including 'system') is still honoured verbatim.
    $registryYaml = ''
    if ("$AcrServer".Trim()) {
        $regId = "$RegistryIdentity".Trim()
        if (-not $regId) {
            if ("$IdentityResourceId".Trim()) { $regId = "$IdentityResourceId".Trim() } else { $regId = 'system' }
        }
        $registryYaml = "    registries: [ { server: $AcrServer, identity: `"$regId`" } ]"
    }
    # command[0] is the executable; everything after it is args, where a leading dash is
    # just a string and not an option. That split IS the fix.
    $cmdList = @($Command)
    $exe = 'pwsh'
    if ($cmdList.Count -gt 0) { $exe = "$($cmdList[0])" }
    $rest = @()
    if ($cmdList.Count -gt 1) { $rest = @($cmdList[1..($cmdList.Count - 1)]) }
    $argsYaml = ''
    if ($rest.Count -gt 0) {
        $quoted = foreach ($r in $rest) { '"' + ("$r" -replace '"', '\"') + '"' }
        $argsYaml = "        args: [" + ($quoted -join ',') + "]"
    }
    # env. A value of the form `secretref:<name>` renders as a secretRef, NEVER as a value --
    # that is the whole mechanism by which the engine secret and a SAS-bearing baseline URL reach
    # the container without ever appearing as readable text in the job definition. Same convention
    # as Setup-PimContainers (`AZURE_CLIENT_SECRET=secretref:pim-engine-client-secret`).
    $envLines = ''
    if (@($EnvVars).Count -gt 0) {
        $envLines = "        env:`n" + ((@($EnvVars) | ForEach-Object {
            $kv = "$_" -split '=', 2
            $v = ''
            if ($kv.Count -gt 1) { $v = $kv[1] }
            if ("$v" -match '^(?i)secretref:(.+)$') {
                "          - { name: $($kv[0]), secretRef: $($Matches[1]) }"
            } else {
                "          - { name: $($kv[0]), value: `"$v`" }"
            }
        }) -join "`n")
    }
    # secrets block. Items arrive as `name=value`; the VALUE is written into the YAML, so the
    # caller must treat the rendered document as sensitive and delete it after the deploy.
    $secretsYaml = ''
    if (@($Secrets).Count -gt 0) {
        $items = foreach ($s in @($Secrets)) {
            $kv = "$s" -split '=', 2
            $sv = ''
            if ($kv.Count -gt 1) { $sv = $kv[1] }
            "{ name: $($kv[0]), value: `"$sv`" }"
        }
        $secretsYaml = "    secrets: [ $($items -join ', ') ]"
    }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("location: $Location")                        | Out-Null
    $lines.Add($identityYaml)                                | Out-Null
    $lines.Add('properties:')                                | Out-Null
    $lines.Add("  environmentId: $EnvironmentId")            | Out-Null
    $lines.Add('  workloadProfileName: Consumption')         | Out-Null
    $lines.Add('  configuration:')                           | Out-Null
    $lines.Add('    triggerType: Schedule')                  | Out-Null
    $lines.Add("    replicaTimeout: $ReplicaTimeout")        | Out-Null
    $lines.Add("    replicaRetryLimit: $ReplicaRetryLimit")  | Out-Null
    $lines.Add('    scheduleTriggerConfig:')                 | Out-Null
    $lines.Add("      cronExpression: `"$Cron`"")            | Out-Null
    $lines.Add('      parallelism: 1')                       | Out-Null
    $lines.Add('      replicaCompletionCount: 1')            | Out-Null
    if ($secretsYaml)  { $lines.Add($secretsYaml)            | Out-Null }
    if ($registryYaml) { $lines.Add($registryYaml)           | Out-Null }
    $lines.Add('  template:')                                | Out-Null
    $lines.Add('    containers:')                            | Out-Null
    $lines.Add("      - name: $JobName")                     | Out-Null
    $lines.Add("        image: $Image")                      | Out-Null
    $lines.Add("        command: [$exe]")                    | Out-Null
    if ($argsYaml) { $lines.Add($argsYaml)                   | Out-Null }
    if ($envLines) { $lines.Add($envLines)                   | Out-Null }
    $lines.Add("        resources: { cpu: $Cpu, memory: $Memory }") | Out-Null
    return (($lines.ToArray()) -join "`n")
}

function Build-PimDownlinkJobArgs {
    param(
        [Parameter(Mandatory)][ValidateSet('create','update','delete','start')][string]$Action,
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [string]$EnvName,
        [string]$Image,
        [string]$AcrServer,
        [string]$Cron,
        [string[]]$Command = @(),
        [string[]]$EnvVars = @(),
        [string]$IdentityResourceId,
        [switch]$SystemAssigned,
        [string]$RegistryIdentity = '',   # '' = AUTO: the user-assigned MI if attached, else system (BUG-42)
        [double]$Cpu = 0.5,
        [string]$Memory = '1Gi',
        [int]$ReplicaTimeout = 1800,
        [int]$ReplicaRetryLimit = 1,
        # BUG-38: create/update now go through --yaml, because --command cannot express a command
        # with dashed arguments. The caller supplies the path the wrapper will write the returned
        # `yaml` text to, plus the two facts only a live probe can know.
        [string]$YamlPath,
        [string]$Location,
        [string]$EnvironmentId,
        [string[]]$Secrets = @()
    )
    $a = New-Object System.Collections.Generic.List[string]
    $a.Add('containerapp') | Out-Null
    $a.Add('job') | Out-Null

    # ---- delete (unregister) -------------------------------------------------
    if ($Action -eq 'delete') {
        $a.Add('delete') | Out-Null
        $a.Add('-g') | Out-Null; $a.Add("$ResourceGroup") | Out-Null
        $a.Add('-n') | Out-Null; $a.Add("$JobName") | Out-Null
        $a.Add('--yes') | Out-Null
        return @{ ok = $true; reason = "delete (unregister) job $JobName"; action = $Action; args = @($a.ToArray()); private = $true; hasInlineSecret = $false; yaml = '' }
    }

    # ---- start (on-demand manual execution, for verification) ----------------
    if ($Action -eq 'start') {
        $a.Add('start') | Out-Null
        $a.Add('-g') | Out-Null; $a.Add("$ResourceGroup") | Out-Null
        $a.Add('-n') | Out-Null; $a.Add("$JobName") | Out-Null
        return @{ ok = $true; reason = "start one on-demand execution of job $JobName"; action = $Action; args = @($a.ToArray()); private = $true; hasInlineSecret = $false; yaml = '' }
    }

    # ---- create / update -----------------------------------------------------
    if (-not "$EnvName".Trim() -and $Action -eq 'create') { return @{ ok = $false; reason = '-EnvName required for create'; action = $Action; args = @(); private = $true; hasInlineSecret = $false; yaml = '' } }
    if (-not "$Image".Trim())   { return @{ ok = $false; reason = '-Image required'; action = $Action; args = @(); private = $true; hasInlineSecret = $false; yaml = '' } }
    $cronCheck = Test-PimDownlinkJobCron -Cron $Cron
    if (-not $cronCheck.ok) { return @{ ok = $false; reason = "bad cron: $($cronCheck.reason)"; action = $Action; args = @(); private = $true; hasInlineSecret = $false; yaml = '' } }

    # BUG-38: create/update deploy via YAML, NOT --command. See Get-PimDownlinkJobYaml for the
    # mechanism; in short, `--command pwsh -NoProfile -File x` is rejected outright by the CLI
    # parser, so the arg set this function used to return could never have been executed. It was
    # never caught because the 34 tests asserted the ARGUMENT ARRAY and never that az accepts it.
    if (-not "$YamlPath".Trim())      { return @{ ok = $false; reason = '-YamlPath required (create/update deploy via --yaml; --command cannot express dashed arguments -- BUG-38)'; action = $Action; args = @(); private = $true; hasInlineSecret = $false; yaml = '' } }
    if (-not "$Location".Trim())      { return @{ ok = $false; reason = '-Location required for the job YAML'; action = $Action; args = @(); private = $true; hasInlineSecret = $false; yaml = '' } }
    if (-not "$EnvironmentId".Trim()) { return @{ ok = $false; reason = '-EnvironmentId required for the job YAML (probe it with: az containerapp env show --query id)'; action = $Action; args = @(); private = $true; hasInlineSecret = $false; yaml = '' } }

    # identity: user-assigned MI if supplied, else system-assigned. NO secret.
    # -SystemAssigned adds the system identity ALONGSIDE a user-assigned one. That combination is
    # what the scheduler tick Job needs (ESTATE-06): the user-assigned MI holds AcrPull so the
    # FIRST image pull works -- a system identity cannot, because it does not exist until the job
    # does -- while the system identity is what gets the SQL contained-DB user and the Graph
    # app-roles, exactly as the worker apps do. Without it the two would share one broad identity.
    $yaml = Get-PimDownlinkJobYaml -JobName $JobName -Location $Location -EnvironmentId $EnvironmentId `
        -Image $Image -Cron $Cron -Command $Command -EnvVars $EnvVars -AcrServer $AcrServer `
        -IdentityResourceId $IdentityResourceId -SystemAssigned:$SystemAssigned -RegistryIdentity $RegistryIdentity `
        -Cpu $Cpu -Memory $Memory -ReplicaTimeout $ReplicaTimeout -ReplicaRetryLimit $ReplicaRetryLimit -Secrets $Secrets

    $a.Add("$Action") | Out-Null
    $a.Add('-g') | Out-Null; $a.Add("$ResourceGroup") | Out-Null
    $a.Add('-n') | Out-Null; $a.Add("$JobName") | Out-Null
    $a.Add('--yaml') | Out-Null; $a.Add("$YamlPath") | Out-Null
    $a.Add('-o') | Out-Null; $a.Add('none') | Out-Null

    # By construction no element is a raw secret value (identity = MI ref/secret-ref,
    # registry = MI). Assert it for the test: no env entry that looks like an inline
    # secret value (PIM_*_SECRET / *PASSWORD / connection-string with Password=).
    # 🪤 BUG-73 -- A SAS IS A CREDENTIAL AND THIS GUARD DID NOT KNOW IT. The patterns below used to
    # stop at `client_secret=` / `accountkey=` / `sharedaccesskey=`. A blob SAS carries neither: it
    # is `?sv=...&sig=<base64>`, so a SAS-bearing baseline URL could have been pasted straight onto
    # the command line and this function would have reported hasInlineSecret=$false -- a read
    # credential for the MASTER's bundle store, readable in the job definition by anyone with
    # Reader on the slave's resource group, forever, and rotated by nobody.
    $secretish = '(?i)(password=|pwd=|client[_-]?secret=|accountkey=|sharedaccesskey=|[?&]sig=)'
    $inline = $false
    foreach ($e in @($EnvVars)) {
        # `secretref:<name>` is the SANCTIONED form -- it names a secret, it does not carry one.
        if ("$e" -match '(?i)=secretref:') { continue }
        if ("$e" -match $secretish) { $inline = $true }
    }
    foreach ($x in @($a.ToArray())) {
        if ("$x" -match $secretish) { $inline = $true }
    }
    # The env now travels in the YAML, not on the command line, so the guard MUST read the YAML
    # too -- otherwise moving to --yaml would have quietly disarmed the very check that stops a
    # secret being deployed, and the arg scan above would keep reporting "clean" forever.
    # 🔒 The `secrets:` block is the ONE place a value is allowed to appear -- that is what an ACA
    # secret IS -- so it is excluded from this scan and nothing else is. Excluding the whole YAML
    # would disarm the check; not excluding this line would make the sanctioned mechanism
    # unusable and push callers back to plain env values, which is the outcome the guard exists
    # to prevent.
    $yamlToScan = (($yaml -split "`n") | Where-Object { "$_" -notmatch '^\s*secrets:\s*\[' }) -join "`n"
    if ("$yamlToScan" -match $secretish) { $inline = $true }
    return @{ ok = $true; reason = "$Action scheduled downlink job $JobName (cron '$Cron')"; action = $Action; args = @($a.ToArray()); private = $true; hasInlineSecret = $inline; yaml = "$yaml" }
}

# ---------------------------------------------------------------------------
# WHOLE DEPLOY PLAN (pure). Compose placement + command + env + the create/update
# arg set into ONE plan object the wrapper executes. -Exists decides create vs
# update (idempotent). PURE: no probe here -- the wrapper supplies -Exists from its
# `az containerapp job show` probe.
# Returns @{ ok; reason; placement; command; envVars; jobArgs=<Build-...> ; exists }.
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobDeployPlan {
    param(
        [Parameter(Mandatory)][ValidateSet('S5','S6')][string]$Scenario,
        [Parameter(Mandatory)][string]$TenantId,
        [ValidateRange(0,2)][int]$SlaveRing = 2,
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$EnvName,
        [Parameter(Mandatory)][string]$Image,
        [string]$AcrServer,
        [Parameter(Mandatory)][string]$Cron,
        [string]$EntryPath = '/app/PIM4EntraPS/tools/pim-engine/downlink-job-entry.ps1',
        [string]$BaselineUrl,
        [string]$BaselineDocPath,
        [string]$SqlServerFqdn,
        [string]$SqlDatabase = 'PimPlatform',
        [string]$SyncRootCentral = '/sync/central',
        [string]$SyncRootLocal   = '/sync/local',
        [string]$IdentityResourceId,
        [string]$RegistryIdentity = '',   # '' = AUTO: the user-assigned MI if attached, else system (BUG-42)
        [bool]$Exists = $false,
        # BUG-38: the three facts the YAML deploy needs. Location/EnvironmentId come from the
        # wrapper's `az containerapp env show` probe -- supplied as facts so this stays pure.
        [string]$YamlPath,
        [string]$Location,
        [string]$EnvironmentId,
        # BUG-72: the engine's app-only identity for the container (client id + SECRET -- a
        # container has no cert store, see Get-PimDownlinkJobEnv).
        [string]$EngineClientId,
        [string]$EngineClientSecret,
        # BUG-73: a SAS-bearing baseline URL. Delivered as an ACA secret, never on the command line.
        [string]$BaselineSasUrl,
        # BUG-76: client id of the user-assigned MI the container runs as.
        [string]$ManagedIdentityClientId,
        # BUG-84: fallback TAP delivery address for synced admins (plain value, not a secret).
        [string]$DefaultManagerEmail
    )
    $placement = Get-PimDownlinkJobPlacement -Scenario $Scenario
    # 🔒 BUG-73: when the baseline URL carries a SAS it must NOT reach the command line -- the job
    # definition is readable by anyone with Reader on the RG, and a SAS there is a standing
    # credential to the master's bundle store. It travels as an ACA secret and the entrypoint picks
    # it up from $env:PIM_BaselineUrl, which it already falls back to.
    $secrets = New-Object System.Collections.Generic.List[string]
    $engineSecretRef = ''
    $baselineUrlRef  = ''
    $cmdBaselineUrl  = $BaselineUrl
    if ("$BaselineSasUrl".Trim()) {
        $baselineUrlRef = 'pim-baseline-url'
        $secrets.Add("$baselineUrlRef=$BaselineSasUrl") | Out-Null
        $cmdBaselineUrl = ''    # the env carries it instead
    }
    if ("$EngineClientId".Trim() -and "$EngineClientSecret".Trim()) {
        $engineSecretRef = 'pim-engine-client-secret'
        $secrets.Add("$engineSecretRef=$EngineClientSecret") | Out-Null
    }
    $command = Get-PimDownlinkJobCommand -EntryPath $EntryPath -Scenario $Scenario -TenantId $TenantId -SlaveRing $SlaveRing -BaselineUrl $cmdBaselineUrl -BaselineDocPath $BaselineDocPath
    $envVars = Get-PimDownlinkJobEnv -Scenario $Scenario -TenantId $TenantId -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -SyncRootCentral $SyncRootCentral -SyncRootLocal $SyncRootLocal `
        -EngineClientId $EngineClientId -EngineSecretRef $engineSecretRef -BaselineUrlSecretRef $baselineUrlRef `
        -ManagedIdentityClientId $ManagedIdentityClientId -DefaultManagerEmail $DefaultManagerEmail
    $action = if ($Exists) { 'update' } else { 'create' }
    $jobArgs = Build-PimDownlinkJobArgs -Action $action -JobName $JobName -ResourceGroup $ResourceGroup `
        -EnvName $EnvName -Image $Image -AcrServer $AcrServer -Cron $Cron `
        -Command $command -EnvVars $envVars -IdentityResourceId $IdentityResourceId -RegistryIdentity $RegistryIdentity `
        -YamlPath $YamlPath -Location $Location -EnvironmentId $EnvironmentId -Secrets @($secrets.ToArray())
    return @{
        ok        = [bool]$jobArgs.ok
        reason    = "$($placement.reason); $($jobArgs.reason)"
        scenarioId = "$($placement.scenarioId)"
        placement = $placement
        command   = @($command)
        envVars   = @($envVars)
        jobArgs   = $jobArgs
        exists    = [bool]$Exists
        action    = $action
    }
}

# ---------------------------------------------------------------------------
# EXECUTION VERDICT (pure). The verification helper's decision core: given a Job's
# last-execution status (from `az containerapp job execution list`) + the execution
# LOG text (from the log stream), decide whether a REAL successful execution ran
# AND actually pulled+synced+applied -- distinguishing "the job exists" from "a run
# really did the downlink". Returns @{ ran; succeeded; pulled; synced; applied;
# verified; reason }. verified = ran AND succeeded AND (pulled & synced & applied
# evidence in the log).
#   -Status     : the execution status string ('Succeeded'|'Failed'|'Running'|'').
#   -LogText    : the captured execution log (stdout) of the run.
# Evidence markers are the entrypoint's own log lines (see downlink-job-entry.ps1):
#   pulled  : 'baseline: loaded' / 'baseline: pulled' / 'DOWNLINK PLANNED|APPLIED'
#   synced  : 'staged files:' / 'sync files:'
#   applied : 'engine-apply' / 'DOWNLINK APPLIED' / 'SCENARIO RUN'
# ---------------------------------------------------------------------------
function Get-PimDownlinkJobExecutionVerdict {
    param(
        [string]$Status,
        [string]$LogText
    )
    $st = "$Status".Trim()
    $log = "$LogText"
    $ran = [bool]$st   # any execution status means an execution exists/ran
    $succeeded = ($st -eq 'Succeeded')
    $pulled  = ($log -match '(?i)baseline:\s*(loaded|pulled)' -or $log -match '(?i)DOWNLINK\s+(PLANNED|APPLIED)')
    $synced  = ($log -match '(?i)(staged files:|sync files:)')
    $applied = ($log -match '(?i)(engine-apply|DOWNLINK APPLIED|SCENARIO RUN)')
    $verified = ($ran -and $succeeded -and $pulled -and $synced -and $applied)
    $reason =
        if (-not $ran) { 'NO execution found -- the job exists but has never run (deploy != run)' }
        elseif (-not $succeeded) { "last execution status='$st' (not Succeeded)" }
        elseif (-not ($pulled -and $synced -and $applied)) { "execution Succeeded but log lacks downlink evidence (pulled=$pulled synced=$synced applied=$applied)" }
        else { "VERIFIED: a real execution pulled + synced + applied the downlink (status=$st)" }
    return @{
        ran = $ran; succeeded = $succeeded; pulled = [bool]$pulled; synced = [bool]$synced; applied = [bool]$applied
        verified = [bool]$verified; reason = $reason
    }
}
