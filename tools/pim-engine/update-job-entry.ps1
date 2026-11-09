#Requires -Version 7.0
<#
.SYNOPSIS
    §53 -- the in-container entry point of the nightly PIM update job (`ca-pim-update`).

.DESCRIPTION
    Runs INSIDE the pim-manager image, on the Container Apps Job's cron cadence, and rolls the
    environment to a ring-approved image over ARM REST. No `az` CLI, no PowerShell modules -- the
    image has neither, and adding the Azure CLI to every customer's container to roll a container
    is a dependency this codebase has deliberately avoided everywhere else.

    🔑 IT ROLLS, IT DOES NOT BUILD. The target image is BUILT ELSEWHERE and named here. That is
    the whole safety property: this job needs no ACR push rights, no source tree and no git, so
    the worst it can do is move an environment between two images that already exist. Which image
    it is allowed to move to is the operator's decision (the ring), not this job's.

    ORDER MATTERS, and it is the reverse of what feels natural:
      1. the Manager app   -- the thing users see
      2. the tick job      -- so the engine matches the Manager
      3. ITSELF, last      -- a job that stamps its own image takes effect on the NEXT run, so
                              doing it first would leave the current run rolling everything else
                              with a definition it had already replaced.

    🪤 A ROLL WITHOUT A HEALTH CHECK IS NOT AN UPDATE, IT IS A CHANGE. The Manager roll is gated
    on the app reaching a healthy running revision, and rolls back on its own if it does not.

.NOTES
    Every input arrives as an environment variable, because that is what a Container Apps Job can
    be given. Nothing is read from a command line.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'

# 🔴 TWO LEVELS UP, NOT ONE. This file lives in <solution>\tools\pim-engine\, so the solution root
# is '..\..' -- exactly what both sibling job entries already do (Invoke-PimEngineCore line 66,
# downlink-job-entry line 78). One Split-Path lands on <solution>\tools, and the first thing the
# job did in its first live execution was:
#     The term '/app/PIM4EntraPS/tools/engine/_shared/PIM-Rest.ps1' is not recognized ...
# 🪤 There is no offline test that can catch this by reading the file -- the path is only wrong
# once something resolves it -- so the guard below turns "wrong path" into a message that names
# what it looked for, instead of a dot-source failure that reads like a missing cmdlet.
$here    = Split-Path -Parent $PSCommandPath
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
$shared  = Join-Path $solRoot 'engine\_shared'
if (-not (Test-Path -LiteralPath (Join-Path $shared 'PIM-Rest.ps1'))) {
    throw ("update-job-entry: the engine shared folder was not found at '$shared' " +
           "(resolved from '$PSCommandPath'). The image layout is not what this job expects.")
}
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-InstallNames.ps1')   # CR5 step 1 (PIM 100.149): every resource name from one resolver
. (Join-Path $solRoot 'engine\_shared\PIM-DisplayNameRename.ps1')   # CR5 item 5: the display names people read (switch, OFF)
. (Join-Path $solRoot 'engine\_shared\PIM-ArmContainerApps.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-SyncAutomateIT.ps1')   # the decision core (semver + pin gate)
. (Join-Path $solRoot 'engine\_shared\PIM-AcrBuild.ps1')         # §55 build in the registry, over ARM
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateSource.ps1')     # §55 where this ring's source comes from
. (Join-Path $solRoot 'engine\_shared\PIM-SigninFrontImage.ps1') # CR7 (framework 12.11g, PIM 100.168) the sign-in front image -- opt-in only
# 🔴 BUG-231 -- LOAD-BEARING, AND ITS ABSENCE IS SILENT. The desired-state gate below calls
# Get-PimPolicyBaselineFromArchive / Compare-PimPolicyBaseline behind a `Get-Command ... -ErrorAction
# SilentlyContinue` guard. Without this line that guard is FALSE FOREVER: the gate reports
# "SKIPPED -- the target version's policy templates could not be read" on every run and waves every
# roll through, looking correct while protecting nothing. Caught by Test-PimCodeAudit's
# INERT-CAPABILITY class, which exists because this exact shape shipped before.
. (Join-Path $solRoot 'engine\_shared\PIM-PolicyBaseline.ps1')   # BUG-231 the desired-state gate's fingerprint + verdict
# §56.4 -- the SCHEMA phase. Loaded HERE with the rest, not lazily next to the step that uses it:
# a shared file this entry point never dot-sources makes every `Get-Command` guard around it false
# forever, which is the audit's INERT-CAPABILITY class and reports "skipped" as though it were fine.
. (Join-Path $solRoot 'engine\_shared\PIM-ChangeQueue.ps1')      # Initialize-PimSqlStore CALLS Get-PimChangeQueueDdl
. (Join-Path $solRoot 'engine\_shared\PIM-SqlStore.ps1')         # connection + query/DDL, over the container's MI
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateTelemetry.ps1')  # §56.6 one record per run, write-only
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateState.ps1')      # §71.43 the SAME run, recorded IN the environment
. (Join-Path $solRoot 'engine\_shared\PIM-FailureCatalog.ps1')   # 100.31 the OOM code the sizing self-correct reads
. (Join-Path $solRoot 'engine\_shared\PIM-TenantSizing.ps1')     # 100.31 the tick's size for this tenant + the SQL tier / max size (100.37)
. (Join-Path $solRoot 'engine\_shared\PIM-JobSelfId.ps1')        # 100.166 (a) pull / publish learn their own id + Reader on themselves
. (Join-Path $solRoot 'engine\_shared\PIM-KeyVaultPrivate.ps1')  # rule 11: a private install's Key Vault is private (step 2g-bis)
. (Join-Path $solRoot 'engine\_shared\PIM-ReturnRoute.ps1')      # rule 11d: a private install's return route -- REPORTED only (step 2g-ter)
. (Join-Path $solRoot 'engine\_shared\PIM-ConvergeDefaults.ps1') # 100.40 / framework 12.16 the install defaults an EXISTING install converges to
. (Join-Path $solRoot 'engine\_shared\PIM-UpdaterPermissionCheck.ps1') # 95.2i the engine's rights vs. what this version needs (report only, never a grant)
. (Join-Path $solRoot 'engine\_shared\PIM-EngineAzureAccess.ps1') # 95.2k the engine's Azure rights vs the DEFINED scopes -- REPORT only here
. (Join-Path $solRoot 'engine\_shared\PIM-SqlAccess.ps1')        # framework 12.23 / PIM 100.156 least-privilege roles via the signed procedure
. (Join-Path $solRoot 'engine\_shared\PIM-SqlAccessCutover.ps1')  # framework 12.23 P8 exception: a private-SQL install starts its own in-network cut-over
. (Join-Path $solRoot 'engine\_shared\PIM-AsBuilt.ps1')          # 100.61 the as-built job + store + view an EXISTING install converges to
. (Join-Path $solRoot 'engine\_shared\PIM-DbInitJob.ps1')        # OPEN-06 the in-network database job on every install (created, NEVER started)
. (Join-Path $solRoot 'engine\_shared\PIM-DbInitMembership.ps1') # framework 4.5 point 5: the database job identity in the SQL admin group, (a)-(d) + renewal
. (Join-Path $solRoot 'engine\_shared\PIM-DownlinkSqlUser.ps1')  # G3A-COPY-LEFTOVER: the pull job's OWN database user (100.156 B); its admin group membership READ only
. (Join-Path $solRoot 'engine\_shared\PIM-UpdaterGraphRoles.ps1') # owner 2026-11-05: the updater's Graph permissions, ONE list; checked (never self-granted)
. (Join-Path $solRoot 'engine\_shared\PIM-AppRegOwner.ps1')      # APP-REG-OWNER (SECAUDIT-1a item 2): the updater owns PIM's app registrations -- READ + one proof PATCH (step 2f-bis)
. (Join-Path $solRoot 'engine\_shared\PIM-SqlAudit.ps1')         # SECPACK-SQL-AUDIT the SQL server's audit -> the install's workspace
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateNow.ps1')        # framework 8.18 UPDATE-NOW: the 15-minute signal check + the run kind + own cron
. (Join-Path $solRoot 'engine\_shared\PIM-SetupSteps.ps1')        # FLEET-SETUPSTEPS the one-time install steps' facts (read only) for the heartbeat
. (Join-Path $solRoot 'engine\_shared\PIM-IdentitySplit.ps1')     # NAM-03 the identity standard id-pim-<role>: the setup fact identityNames (read only, step 2g)
. (Join-Path $solRoot 'engine\_shared\PIM-GuardLimits.ps1')      # framework 8.18: an update-now waits while guard Strict mode is on
. (Join-Path $solRoot 'engine\_shared\PIM-SchemaQuiesce.ps1')    # SCHEMA-QUIESCE-818 (framework 8.18): no database change under a running PIM job
. (Join-Path $solRoot 'engine\_shared\PIM-UpdateTrack.ps1')      # OPEN-13 / framework 8.8 UPDATE-TRACK: the run's stages to Invardia (best effort)

function Say($m, $c = 'Gray') { Write-Host ("[update] " + $m) -ForegroundColor $c }
# 100.61: the image the as-built converge (2e) left caj-pim-asbuilt on THIS run ('' = it did not converge the job) -- the job
# roll (2b) skips that job when this equals the target image, instead of PATCHing it a second time (409 OperationInProgress).
$script:PimAsBuiltJobImageThisRun = ''
# OPEN-06: the database job converge of THIS run (step 2e-ter); after the job roll (2b) its image is READ BACK into it.
$script:PimDbInitResult = $null

# ---- 100.40 / framework 12.16 CONVERGE-DEFAULTS -- one step, two call sites -----------------------------------------
# 🔴 A changed install default reaches only NEW installs unless the updater brings the existing ones there (owner
# 2026-10-09, "important finding"). This is that step: 2a the tick's size + the database tier / max size (100.31 /
# 100.37), 2d the other install defaults the updater's identity can reach (engine/_shared/PIM-ConvergeDefaults.ps1).
# Called after the tick roll (step 2a below) AND on the 'ahead' exit -- an environment running ahead of its ring is
# healthy and must still converge; it used to exit before any of this ran. Never throws, never fails the update.
function Invoke-PimUpdaterConvergeStep {
    param([string]$When = 'update')
    # FLEET-SETUPSTEPS: the results the setup-step facts (2g) are read from; $null = that step did not run this time.
    $cv = $null; $si = $null; $ab = $null; $sa = $null; $db = $null; $dlu = $null
    $script:PimSqlTierResult = $null     # OPEN-27: this run's database tier result ($null = not read -> setupSteps 'sql-tier' unknown)
    $csSize = $null; try { $csSize = Get-PimSqlConnectionString } catch { $csSize = $null }
    if (-not "$csSize".Trim()) {
        # the test-tenant shape (no PIM_SqlServer on this job): the Manager names the store -- same self-heal as the schema step.
        try {
            $heal = Resolve-PimUpdaterStoreSettings -JobServer "$($global:PIM_SqlServer)" -JobDatabase "$($global:PIM_SqlDatabase)" `
                        -ManagerStore (Get-PimAcaStoreSettings -Resource $app) -ManagerApp $managerApp
            if ($heal.source -eq 'manager' -and "$($heal.server)".Trim()) {
                Set-Variable -Name 'PIM_SqlServer' -Scope Global -Value "$($heal.server)"
                if ("$($heal.database)".Trim()) { Set-Variable -Name 'PIM_SqlDatabase' -Scope Global -Value "$($heal.database)" }
                try { $csSize = Get-PimSqlConnectionString } catch { $csSize = $null }
            }
        } catch { }
    }
    $armSeam = { param($m, $p, $b) if ($null -ne $b) { Invoke-PimArm -Method $m -Path $p -Body $b } else { Invoke-PimArm -Method $m -Path $p } }
    $cvChanged = 0; $cvWarnings = 0; $abChanged = 0; $abWarnings = 0
    # FLEET-ASBUILT-REPORT: the as-built state of this run, for the heartbeat setupSteps (Get-PimAsBuiltSetupState's shape)
    $script:PimAsBuiltSetupState = [ordered]@{ storage = 'unknown'; rights = 'unknown'; detail = 'as-built: not converged this run' }
    # ---- 2a. 100.31 / framework 12.15 -- THE TICK'S SIZE FOR THIS TENANT, ON EVERY UPDATE -------------------------------
    # Same rule as the install (engine/_shared/PIM-TenantSizing.ps1): users + groups + service principals by Graph $count,
    # else the counts recorded on the job; raise only; PIM_Bootstrap_*_Tick on this job wins. SELF-CORRECT: a run that ran
    # out of memory or hit the time limit since the job was last sized raises it one band and one timeout step (max 6 h).
    # The pim.Settings database: Basic -> S0 (raise only; owner 2026-10-09: S0 for every install, Pro too; never on a database
    # tagged pim-sql-tier-pin) and EVERY Standard database gets its 250 GB max size (100.37: a tier raise does not grow it;
    # an existing DB at 2 GB is fixed HERE, on its next update).
    # 100.114 (owner 2026-10-12): the database default is S3 now -- below S3 -> S3, raise only -- and the Manager web app is
    # 4 CPU / 8 GiB; both defaults are defined once, in engine/_shared/PIM-TenantSizing.ps1.
    try {
        $runs = @()
        if ($csSize) {
            try { $rawRuns = Get-PimSqlSettingRaw -ConnectionString $csSize -Name 'JobRunHistory'; if ("$rawRuns".Trim()) { $tmpRuns = "$rawRuns" | ConvertFrom-Json; if ($tmpRuns -is [string]) { $tmpRuns = $tmpRuns | ConvertFrom-Json }; $runs = @($tmpRuns) } }
            catch { Say "  sizing: the run history could not be read ($($_.Exception.Message)) -- no self-correct this run" 'Yellow' }
        }
        $graphSeam = { param($p) Invoke-PimGraph -Path $p -Headers @{ ConsistencyLevel = 'eventual' } }
        $envMap = @{}; foreach ($ev in [Environment]::GetEnvironmentVariables().GetEnumerator()) { $envMap["$($ev.Key)"] = "$($ev.Value)" }
        $stored = $null   # 2.4.544: the counts the tick recorded -- the fallback when this identity's Graph count is refused (403)
        if ($csSize) { try { $rawC = Get-PimSqlSettingRaw -ConnectionString $csSize -Name 'TenantObjectCounts'; if ("$rawC".Trim()) { $stored = "$rawC" | ConvertFrom-Json; if ($stored -is [string]) { $stored = $stored | ConvertFrom-Json } } } catch { $stored = $null } }
        $sz = Invoke-PimJobSizingUpdate -SubscriptionId $sub -ResourceGroup $rg -JobName $tickJob -Arm $armSeam -Graph $graphSeam -Runs $runs -Environment $envMap -StoredCounts $stored
        foreach ($l in @($sz.log)) { Say "  sizing: $l" 'DarkGray' }
        Say ("sizing: $($sz.detail)") $(if (-not $sz.ok) { 'Yellow' } elseif ($sz.changed) { 'Cyan' } else { 'DarkGray' })
        # framework 12.24 JOB-RUN-LIMIT (owner 2026-10-15): every PIM job in this resource group -> the 7-day maximum run limit.
        # Raise only; never fails the update.
        try {
            $rl = Invoke-PimJobRunLimitUpdate -SubscriptionId $sub -ResourceGroup $rg -Arm $armSeam
            foreach ($l in @($rl.log)) { Say "  run limit: $l" 'DarkGray' }
            Say ("run limit: $($rl.detail)") $(if (-not $rl.ok) { 'Yellow' } elseif (@($rl.changed).Count) { 'Cyan' } else { 'DarkGray' })
        } catch { Say "  run limit: not checked: $($_.Exception.Message)" 'Yellow' }
        # PIM 100.166 (a): the pull / publish jobs learn their own id (PIM_JobId) and get 'Reader' on themselves where this
        # identity may grant it (else a plain note). Never fails the update.
        try {
            $si = Invoke-PimJobSelfIdUpdate -SubscriptionId $sub -ResourceGroup $rg -Arm $armSeam
            foreach ($l in @($si.log) + @($si.notes)) { Say "  own run status: $l" 'DarkGray' }
            Say ("own run status: $($si.detail)") $(if (-not $si.ok) { 'Yellow' } elseif (@($si.envSet).Count) { 'Cyan' } else { 'DarkGray' })
        } catch { Say "  own run status: not checked: $($_.Exception.Message)" 'Yellow' }
        # PIM 100.114 (owner 2026-10-12: "4 CPU / 8 GB at all ring 1+2 installs") -- THE MANAGER WEB APP'S SIZE, ON EVERY UPDATE.
        # Raise only; PIM_Bootstrap_Cpu_Manager / PIM_Bootstrap_Memory_Manager on this job wins. A run that rolled the Manager
        # carried the size in the roll's own write (step 1), so this finds nothing to change and reads the result back; a run
        # that rolled nothing (ahead of its ring, already on the image) does the one write here. Never fails the update.
        try {
            $mgrSz = Invoke-PimManagerAppSizeUpdate -SubscriptionId $sub -ResourceGroup $rg -AppName $managerApp -ContainerName $container -Arm $armSeam -Environment $envMap
            foreach ($l in @($mgrSz.log)) { Say "  sizing: $l" 'DarkGray' }
            Say ("sizing: $($mgrSz.detail)") $(if (-not $mgrSz.ok) { 'Yellow' } elseif ($mgrSz.changed) { 'Cyan' } else { 'DarkGray' })
        } catch { Say "  sizing: the Manager web app's size was not checked: $($_.Exception.Message)" 'Yellow' }
        $sqlSrv =$(if ("$($env:PIM_SqlServer)".Trim()) { "$($env:PIM_SqlServer)".Trim() } else { "$($global:PIM_SqlServer)".Trim() })
        $sqlDb = $(if ("$($env:PIM_SqlDatabase)".Trim()) { "$($env:PIM_SqlDatabase)".Trim() } elseif ("$($global:PIM_SqlDatabase)".Trim()) { "$($global:PIM_SqlDatabase)".Trim() } else { 'PimPlatform' })
        $sqlSz = Invoke-PimSqlTierUpdate -SubscriptionId $sub -Server $sqlSrv -Database $sqlDb -Arm $armSeam
        $script:PimSqlTierResult = $sqlSz     # OPEN-27: read by step 2g (setupSteps 'sql-tier')
        # A database pinned below the product tier is NOT changed (the pin tag cannot say who pinned it) -- it is said in
        # yellow, every update, so support can act: "database is pinned at <tier>, the new default is S3 - not changed".
        # OPEN-27 (3.0.50): the raise above is unchanged (owner 2026-10-12) and behind PimSqlTierUpdaterRaiseEnabled (on); where
        # support switched it off, a database below S3 is said in yellow too ("... below the product tier S3 -- not raised by the updater").
        Say ("sizing: $($sqlSz.detail)") $(if (-not $sqlSz.ok -or $sqlSz.pinnedBelowDefault -or $sqlSz.belowDefault) { 'Yellow' } elseif ($sqlSz.changed) { 'Cyan' } else { 'DarkGray' })
    } catch { Say "  sizing skipped: $($_.Exception.Message)" 'Yellow' }
    # ---- 2d. 100.40 -- THE OTHER INSTALL DEFAULTS (alert recipients, immediate engine start, the install's role checks) ----
    try {
        $storeSeam = $null
        if ("$csSize".Trim()) {
            $cvCs = "$csSize"
            $storeSeam = {
                param($op, $name, $value)
                switch ($op) {
                    'get'   { return (Get-PimSqlSetting -ConnectionString $cvCs -Name $name) }
                    'set'   { Set-PimSqlSetting -ConnectionString $cvCs -Name $name -Value $value; return $null }
                    'audit' {
                        $act = if ($value -is [System.Collections.IDictionary] -and $value.Contains('action')) { "$($value['action'])" } elseif ($name -eq 'Alerting') { 'settings.alerting.save' } else { "settings.$name".ToLowerInvariant() }
                        Write-PimSqlAuditEvent -ConnectionString $cvCs -Actor $selfJob -ActorSource 'update' -Action $act -Target $name -Before $value.before -After $value.after
                        return $null
                    }
                }
            }
        }
        $graphGet = { param($p) Invoke-PimGraph -Path ('/' + "$p".TrimStart('/')) }
        # PIM 95.2k: the Azure scopes the store defines -> the engine's Azure rights are REPORTED (never granted here: the
        # updater may not grant roles; Confirm-PimInstall's repair, run by a person, grants them).
        $eaRows = @{ error = 'no store connection' }
        if ("$csSize".Trim()) {
            try { $eaRows = @{ assignments = @(Get-PimSqlRows -ConnectionString $csSize -Entity 'PIM-Assignments-Azure-Resources'); definitions = @(Get-PimSqlRows -ConnectionString $csSize -Entity 'PIM-Definitions-Resources') } }
            catch { $eaRows = @{ error = ((("$($_.Exception.Message)") -split "`n")[0]).Trim() } }
        }
        $cv = Invoke-PimUpdateConvergeDefaults -SubscriptionId $sub -ResourceGroup $rg -ManagerApp $managerApp -TickJob $tickJob `
                  -Arm $armSeam -Store $storeSeam -Graph $graphGet -SqlServer "$($global:PIM_SqlServer)" -TenantId "$($env:PIM_TenantId)" `
                  -AlertRecipientsScript (Join-Path $solRoot 'tools/setup/Set-PimAlertRecipients.ps1') -EngineAzureRows $eaRows
        foreach ($l in @($cv.lines)) { Say ("converge: " + $l.text) $(switch ($l.level) { 'changed' { 'Cyan' } 'warn' { 'Yellow' } default { 'DarkGray' } }) }
        # FLEET-ASBUILT-REPORT: the "to fix by hand" summary is said after step 2e, so the as-built warnings are counted too.
        $cvChanged = [int]$cv.changed; $cvWarnings = [int]$cv.warnings
    } catch { Say "  converge skipped: $($_.Exception.Message)" 'Yellow' }
    # ---- 2d-perm. REQUIREMENTS 95.2i -- THE ENGINE'S RIGHTS vs. WHAT THIS VERSION NEEDS (report only) ---------------------
    # A newer version can need a Graph permission (or an Azure right) the engine identity was never given: the roll went
    # through and nothing said so (2.4.419 -> 2.4.519). Read the engine's Graph app roles (live, else the Manager's last real
    # check) and its Azure rights at the tenant root; judge them with the SAME functions the Manager's banner uses; say what
    # is missing with the exact Grant-PimEnginePermissions command, and record it in this run's record (Send-PimUpdateOutcome
    # -> UpdateState.enginePermissions), which the Manager's update panel and permission banner read.
    # RULE: the updater may not grant roles -- this step only READS (GET over ARM and Graph, a get from pim.Settings). A read that
    # fails is a yellow line, never a stop; the step never fails the update. The list it judges against is the one in THIS
    # updater's code -- after a roll the follow-up run on the new updater image (step 4) checks against the new release's.
    try {
        $epVer = ''; try { $epVer = "$(Get-Content -LiteralPath (Join-Path $solRoot 'VERSION') -Raw -ErrorAction Stop)".Trim() } catch { $epVer = '' }
        $epAzDefs = -1
        if ("$csSize".Trim() -and (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) {
            try { $epAzDefs = @(Get-PimSqlRows -ConnectionString $csSize -Entity 'PIM-Assignments-Azure-Resources').Count } catch { $epAzDefs = -1 }
        }
        $epGraph = { param($p) Invoke-PimGraph -All -Path ('/' + "$p".TrimStart('/')) }
        $epStore = $null
        if ("$csSize".Trim()) { $epCs = "$csSize"; $epStore = { param($op, $name, $value) if ($op -eq 'get') { return (Get-PimSqlSetting -ConnectionString $epCs -Name $name) } } }
        $ep = Invoke-PimUpdaterEnginePermissionCheck -SubscriptionId $sub -ResourceGroup $rg -TickJob $tickJob -TenantId ("$(if ("$($env:PIM_TenantId)".Trim()) { $env:PIM_TenantId } else { $global:PIM_TenantId })".Trim()) `
                  -Version $epVer -Arm $armSeam -Graph $epGraph -Store $epStore -AzureDelegationCount $epAzDefs -UpdaterName $selfJob
        foreach ($l in @($ep.lines)) { Say ("  " + $l.text) $(if ($l.level -eq 'warn') { 'Yellow' } else { 'DarkGray' }) }
        if ("$($ep.fix)".Trim()) { foreach ($fl in @("$($ep.fix)" -split "`n")) { Say ("    " + $fl) 'Yellow' } }
        Say ("engine permissions ($When): $($ep.headline)") $(switch ($ep.state) { 'missing' { 'Yellow' } 'unknown' { 'Yellow' } default { 'DarkGray' } })
        $script:PimEnginePermissionCheck = $ep.record
    } catch { Say "  engine permissions not checked: $($_.Exception.Message)" 'Yellow' }
    # ---- 2d-bis. CR5 step 1 (framework §12.11c item 6, PIM 100.149) -- THE INSTALL RECORD ------------------------------------
    # pim.Settings 'InstallNames' = the names THIS install runs with, from what the updater was deployed with (its variables)
    # and the as-built job's name. Existing installs record TODAY's names -- nothing is renamed; every reader
    # (Get-PimInstallName) answers the same as before. Written only when it changes. Never fails the update.
    try {
        if ($storeSeam -and (Get-Command New-PimInstallNamesRecord -ErrorAction SilentlyContinue)) {
            $inCur = & $storeSeam 'get' 'InstallNames' $null
            $inNames = @{ web = $managerApp; engine = $tickJob; updater = $selfJob
                          sqlAdminGroup = $(if ("$($env:PIM_SqlAdminGroupName)".Trim()) { "$($env:PIM_SqlAdminGroupName)".Trim() } else { Get-PimInstallName -Role sqlAdminGroup -NoRecord })
                          asbuilt = (Get-PimInstallName -Role asbuilt -Record $inCur); asbuiltIdentity = (Get-PimInstallName -Role asbuiltIdentity -Record $inCur)
                          # OPEN-06: the database job + its dedicated identity (a new-name install: caj-pim-dbinit)
                          dbinit = (Get-PimDbInitJobName -ManagerApp $managerApp -Record $inCur); dbinitIdentity = (Get-PimInstallName -Role dbinitIdentity -Record $inCur) }
            $inRec = New-PimInstallNamesRecord -Names $inNames -Current $inCur
            if ($inRec.changed) {
                & $storeSeam 'set' 'InstallNames' ([pscustomobject]$inRec.record) | Out-Null
                Say ("install record: InstallNames stored (" + ((@($inRec.record.Keys) | Where-Object { $_ -ne 'recordedUtc' } | ForEach-Object { "$_=$($inRec.record[$_])" }) -join ', ') + ")") 'Cyan'
            } else { Say 'install record: InstallNames unchanged' 'DarkGray' }
        }
    } catch { Say "  install record not written: $($_.Exception.Message)" 'Yellow' }
    # ---- 2d-quater. MANAGER-URL-FROM-UPDATER (owner 2026-11-03 via Invardia; framework 8.9) -- THE MANAGER'S ADDRESS --------
    # pim.Settings 'ManagerUrl' was written only by the hosted Manager on its first SIGNED-IN request, so an install nobody had
    # opened yet reported no Manager address in its heartbeat (Invardia's back office showed none). The updater reads ARM on
    # every run: it records the address the same way (Resolve-PimUpdaterManagerUrl: empty -> written; platform FQDN -> the
    # custom hostname once; anything someone set -> kept). Written only on change; the heartbeat sends it. Never fails the update.
    try {
        if ($storeSeam -and (Get-Command Resolve-PimUpdaterManagerUrl -ErrorAction SilentlyContinue)) {
            $muApp = Get-PimAcaApp -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp
            $muCur = "$(& $storeSeam 'get' 'ManagerUrl' $null)"
            $mu = Resolve-PimUpdaterManagerUrl -App $muApp -Current $muCur
            if ($mu.write) {
                & $storeSeam 'set' 'ManagerUrl' $mu.url | Out-Null
                Say "manager address: $($mu.url) stored ($($mu.reason))" 'Cyan'
            } else { Say "manager address: $(if ($mu.url) { $mu.url } else { '(none)' }) -- $($mu.reason)" 'DarkGray' }
        }
    } catch { Say "  manager address not recorded: $($_.Exception.Message)" 'Yellow' }
    # ---- 2d-ter. CR5 item 5 (framework §12.11c item 5, PIM 100.149) -- THE DISPLAY NAMES PEOPLE READ ------------------------
    # "PIM Manager", never "PIM4EntraPS", at EXISTING installs too. OFF until the owner switches it on: pim.Settings
    # 'PIM_Update_RenameDisplayNames' (true), else this job's variable of the same name. Only objects that carry exactly the
    # name PIM gave them; kept: the mailbox address, mailNickname, the Exchange scope. A rename this identity may not do is
    # reported with the permission it needs. Read back, audited, never fails the update (engine/_shared/PIM-DisplayNameRename.ps1).
    try {
        $dnSet = $null; $dnSender = ''
        if ($storeSeam) {
            try { $dnSet = & $storeSeam 'get' 'PIM_Update_RenameDisplayNames' $null } catch { $dnSet = $null }
            try { $dnSender = "$(& $storeSeam 'get' 'MailSender' $null)".Trim() } catch { $dnSender = '' }
        }
        if (-not $dnSender) { $dnSender = "$($env:PIM_MailSender)".Trim() }
        $dnAudit = $null
        if ($storeSeam) { $dnAudit = { param($tgt, $before, $after) & $storeSeam 'audit' "displayname.$tgt" @{ action = 'install.displayname.rename'; before = $before; after = $after } | Out-Null } }
        $dn = Invoke-PimDisplayNameRenames -Enabled (Test-PimRenameDisplayNamesSwitch -Explicit $dnSet) -SenderMailbox $dnSender -Audit $dnAudit
        foreach ($l in @($dn.lines)) { Say ("  " + $l.text) $(switch ($l.level) { 'changed' { 'Cyan' } 'warn' { 'Yellow' } default { 'DarkGray' } }) }
        if ($dn.ran) {
            Say ("display names: $($dn.renamed) renamed, $($dn.current) already current, $(@($dn.cannot).Count) need a permission this identity does not hold") $(if (@($dn.cannot).Count) { 'Yellow' } elseif ($dn.renamed) { 'Cyan' } else { 'DarkGray' })
        }
    } catch { Say "  display names not checked: $($_.Exception.Message)" 'Yellow' }
    # ---- 2e. PIM 100.61 -- THE AS-BUILT JOB ON EXISTING ENVIRONMENTS (no manual Deploy-PimAsBuiltJob) ---------------------
    # Storage (Entra-only), container + 1-day rule, caj-pim-asbuilt on the Manager's image, and -- over this job's own SQL
    # connection, so a PRIVATE SQL server works too -- the view, the job's reader user and the install facts. What needs an
    # Owner (the job's write right, the support custom role) is reported, never failed. Never fails the update.
    try {
        $abSql = $null; $abSqlSkip = ''
        # SCHEMA-QUIESCE-818: the as-built view + procedure are DDL (CREATE OR ALTER). A run that waited for quiet and holds
        # the scheduled jobs goes on; any other run (ahead of its ring, or no hold) reads the executions ONCE and skips the
        # SQL part while a PIM job runs -- it is idempotent, the next update converges it.
        if ("$csSize".Trim() -and -not $script:PimSchemaQuiet) {
            $abQ = Invoke-PimUpdaterSchemaQuiesce -Cs "$csSize" -Once
            if (-not $abQ.go) { $abSqlSkip = "as-built: the view and the job's reader user were not converged this run -- $($abQ.line -replace '^schema quiesce: ', '')" }
        }
        if ("$csSize".Trim() -and -not $abSqlSkip) {
            $abCs = "$csSize"
            $abSql = {
                param($q, $prm)
                $c = New-PimSqlConnection -ConnectionString $abCs
                $c.Open()
                try {
                    $cmd = $c.CreateCommand(); $cmd.CommandText = $q; $cmd.CommandTimeout = 120
                    foreach ($k in @($prm.Keys)) { [void]$cmd.Parameters.AddWithValue("@$k", "$($prm[$k])") }
                    [void]$cmd.ExecuteNonQuery()
                } finally { $c.Close() }
            }
        }
        # Live 2026-10-11: no Graph here any more -- the job runs as the user-assigned identity id-pim-asbuilt, whose clientId
        # (= the database user's SID) this identity reads over ARM; the Graph app-id lookup was refused on every run.
        $ab = Invoke-PimAsBuiltConverge -SubscriptionId $sub -ResourceGroup $rg -ManagerApp $managerApp -Arm $armSeam -Sql $abSql -SqlSkipReason $abSqlSkip
        # The image the converge left caj-pim-asbuilt on THIS run: the job roll (2b) does not PATCH it again (a second write
        # seconds after the converge's was refused "HTTP 409 ContainerAppsJobOperationInProgress" -- NOT FULLY UPDATED).
        $script:PimAsBuiltJobImageThisRun = "$($ab.jobImage)".Trim()
        foreach ($l in @($ab.lines)) { Say ("converge: " + $l.text) $(switch ($l.level) { 'changed' { 'Cyan' } 'warn' { 'Yellow' } default { 'DarkGray' } }) }
        $abChanged = [int]$ab.changed; $abWarnings = [int]$ab.warnings
        $script:PimAsBuiltSetupState = Get-PimAsBuiltSetupState -Result $ab
    } catch { Say "  as-built converge skipped: $($_.Exception.Message)" 'Yellow'; $abWarnings = 1 }
    # FLEET-ASBUILT-REPORT: ONE summary, the as-built warnings counted in "to fix by hand" (a policy-denied store said "0" before)
    $fixByHand = $cvWarnings + $abWarnings
    Say ("converge ($When): $($cvChanged + $abChanged) changed, $fixByHand to fix by hand$(if ($abWarnings) { " (as-built: $abWarnings)" })") $(if ($fixByHand) { 'Yellow' } elseif ($cvChanged + $abChanged) { 'Cyan' } else { 'DarkGray' })
    # ---- 2e-bis. SECPACK-SQL-AUDIT (owner 2026-10-23 "SQL auditing at install") -- AN EXISTING INSTALL AUDITS ITS SQL TOO ----
    # The same converge the installer runs (engine/_shared/PIM-SqlAudit.ps1): auditing on, security events to this install's
    # workspace, 90 days. Contributor on the resource group is enough; a refusal is said, never fails the update.
    try {
        $saSrv = $(if ("$($env:PIM_SqlServer)".Trim()) { "$($env:PIM_SqlServer)".Trim() } else { "$($global:PIM_SqlServer)".Trim() })
        $sa = Invoke-PimSqlAuditConverge -SubscriptionId $sub -ResourceGroup $rg -SqlServer $saSrv -Arm $armSeam
        foreach ($l in @($sa.lines)) { Say ("converge: " + $l.text) $(switch ($l.level) { 'changed' { 'Cyan' } 'warn' { 'Yellow' } default { 'DarkGray' } }) }
    } catch { Say "  SQL auditing not checked: $($_.Exception.Message)" 'Yellow' }
    # ---- 2e-ter. OPEN-06 / NO-PERSON-DB-ADMIN (owner 2026-11-04) -- THE DATABASE JOB ON EVERY INSTALL, PUBLIC ONES TOO ------
    # The in-network database job (ca-pim-dbinit, manual trigger) with a DEDICATED identity (id-pim-dbinit; an existing job
    # keeps its own; the one id-pim-sql identity is reused; an identity an app carries is never chosen). Created ONLY when
    # missing, on the Manager's image; an existing job gets no write here (step 2b rolls its image). This step NEVER starts
    # the job -- the Support app does, when a database change needs an admin. The identity's SQL admin group membership is
    # READ (never written). Warnings count in "to fix by hand". Never fails the update.
    try {
        $dbGraph = { param($p) Invoke-PimGraph -Path $p }
        $db = Invoke-PimDbInitJobConverge -SubscriptionId $sub -ResourceGroup $rg -ManagerApp $managerApp -Arm $armSeam -Graph $dbGraph
        $script:PimDbInitResult = $db
        foreach ($l in @($db.lines)) { Say ("converge: " + $l.text) $(switch ($l.level) { 'changed' { 'Cyan' } 'warn' { 'Yellow' } default { 'DarkGray' } }) }
        $fixByHand += [int]$db.warnings
        Say ("database job ($When): $($db.state) -- $($db.detail)") $(if ($db.state -eq 'ok') { 'DarkGray' } else { 'Yellow' })
        if ([int]$db.warnings) { Say ("converge ($When): $fixByHand to fix by hand in all (database job: $([int]$db.warnings))") 'Yellow' }
    } catch { Say "  db job converge skipped: $($_.Exception.Message)" 'Yellow' }
    # ---- 2e-quater. DBINIT-MEMBERSHIP (framework 4.5 point 5, owner via Invardia 2026-11-05) -- THE DATABASE JOB IDENTITY IN ----
    # THE SQL ADMIN GROUP, BY THE PRODUCT'S OWN UPDATE CODE (never a hand-made Graph call): (a) a direct add, else (b) an ACTIVE
    # PIM-for-Groups member assignment, PERMANENT first, TIME-LIMITED only when the group's policy refuses permanent (said, with
    # the end date); (c) READ BACK; (d) both refused = both errors named and the database job is not started on it. A
    # time-limited membership ending within 30 days is renewed (adminExtend) and read back; a failed renewal is a WARNING with
    # the end date (this line + the heartbeat's db-job detail), never a failed update. REST through this updater's own identity;
    # a refusal NAMES the missing permission and changes nothing -- nothing is granted here (engine/_shared/PIM-DbInitMembership.ps1).
    $dbm = $null; $dbProof = $null; $dbProofGroup = ''
    # the updater's OWN Graph permissions (owner 2026-11-05 "Grant updater the right"; ONE list: Get-PimUpdaterGraphAppRoles):
    # read from the roles in its own Graph token and REPORTED when one is missing -- setup / the Support app grants them, the
    # updater never grants itself.
    $ugMissing = @()
    try {
        $ugTok = "$(Get-PimRestToken -Resource 'graph')"
        $ug = Get-PimUpdaterGraphRoleCheck -Token $ugTok
        if ($ug.known -and @($ug.missing).Count) { $ugMissing = @($ug.missing); $fixByHand += 1; Say "updater permissions: $($ug.reason)" 'Yellow' }
        elseif ($ug.known) { Say "updater permissions: $($ug.reason)" 'DarkGray' }
        else { Say "updater permissions: not checked ($($ug.reason))" 'DarkGray' }
    } catch { Say "  updater permissions not checked: $($_.Exception.Message)" 'DarkGray' }
    try {
        if ($db -and [bool]$db.present -and "$($db.identityPrincipalId)".Trim() -and $db.adminIsGroup -ne $false) {
            $dmSrv = $(if ("$($env:PIM_SqlServer)".Trim()) { "$($env:PIM_SqlServer)".Trim() } else { "$($global:PIM_SqlServer)".Trim() })
            $dmAdm = Get-PimDbInitAdminGroup -Arm $armSeam -ResourceGroupId "/subscriptions/$sub/resourceGroups/$rg" -SqlServer $dmSrv
            if ($dmAdm.isGroup -eq $false) { Say "database job identity: $($dmAdm.reason) -- not put into a group" 'Yellow' }
            elseif (-not $dmAdm.groupId) { Say "database job identity: the SQL admin group is not known ($($dmAdm.reason)) -- nothing written" 'Yellow' }
            else {
                $dmGraph = { param($m, $p, $b) if ($null -ne $b) { Invoke-PimGraph -Method $m -Path $p -Body $b } else { Invoke-PimGraph -Method $m -Path $p } }
                $dbm = Invoke-PimDbInitMembershipEnsure -Graph $dmGraph -GroupId $dmAdm.groupId -GroupName $dmAdm.name -PrincipalId "$($db.identityPrincipalId)" -IdentityName "$($db.identityName)"
                foreach ($l in @($dbm.lines)) { Say ("converge: " + $l.text) $(switch ($l.level) { 'changed' { 'Cyan' } 'warn' { 'Yellow' } default { 'DarkGray' } }) }
                $fixByHand += [int]$dbm.warnings
                # the READ-BACK is the fact the heartbeat reports (a hand-read or an earlier run's proof is replaced by it)
                if ($dbm.readBack) { $db.inAdminGroup = $true; $db.adminIsGroup = $true; $db.membershipReason = "read back by the update: $($dbm.reason)" }
                elseif ($dbm.member -eq $false) { $db.inAdminGroup = $false; $db.adminIsGroup = $true; $db.membershipReason = "$($dbm.reason)" }
                elseif ($db.inAdminGroup -ne $true) {
                    # 3.0.48 (C): NOT READABLE (memberOf and the PIM assignments refused) = unknown, never missing -- right after a
                    # grant the updater's managed-identity token does not carry its new Graph roles yet (token cache, up to ~24 h)
                    $db.inAdminGroup = $null; $db.adminIsGroup = $true
                    $dmLag = @(@($ugMissing) | Where-Object { "$_".Trim() -and "$_" -ne 'Application.ReadWrite.OwnedBy' }); if (-not $dmLag.Count) { $dmLag = @(@($dbm.missing) | Where-Object { "$_".Trim() }) }
                    $db.membershipReason = $(if ($dmLag.Count) { "the updater's Graph token does not carry $($dmLag -join ', ') yet; it refreshes within 24 h" } else { "not readable: $($dbm.reason)" })
                }
                # 3.0.48 (D): a READ-BACK is stored as the proof a later run falls back on when its read is refused (pim.Settings)
                $dbProofNew = New-PimDbInitMembershipProof -Membership $dbm -PrincipalId "$($db.identityPrincipalId)" -GroupId "$($dmAdm.groupId)"
                if ($dbProofNew -and "$csSize".Trim()) {
                    try { Set-PimSqlSetting -ConnectionString $csSize -Name (Get-PimDbInitProofSetting) -ValueJson (ConvertTo-Json -Compress -InputObject $dbProofNew) }
                    catch { Say "  database job identity: the read-back could not be stored as a proof ($($_.Exception.Message))" 'DarkGray' }
                } elseif (-not $dbm.readBack -and $dbm.member -ne $false) {
                    if ("$csSize".Trim()) { try { $dbProof = Get-PimDbInitStoredProof (Get-PimSqlSetting -ConnectionString $csSize -Name (Get-PimDbInitProofSetting)) } catch { $dbProof = $null } }
                    $dbProofGroup = "$($dmAdm.groupId)"
                }
                # framework 4.5 G3a: a FRESH add is recorded (when + who + which group) -- for up to 24 h the identity's token can
                # keep the old group claims, so a job that signs in as it is 'waiting for the token to refresh', not failed. A
                # membership that already existed records nothing (it is never 'waiting').
                if ("$($dbm.addedUtc)".Trim() -and "$csSize".Trim()) {
                    try {
                        Set-PimSqlSetting -ConnectionString $csSize -Name (Get-PimDbInitAddedSetting) -ValueJson (ConvertTo-Json -Compress -InputObject ([ordered]@{ addedUtc = "$($dbm.addedUtc)"; identity = "$($db.identityName)"; principalId = "$($db.identityPrincipalId)"; group = "$($dmAdm.name)"; via = "$($dbm.via)" }))
                        Say "database job identity: fresh membership recorded ($($dbm.addedUtc)) -- its token may keep the old group claims up to $(Get-PimDbInitTokenWaitHours) h (framework 4.5 G3a)" 'DarkGray'
                    } catch { Say "  database job identity: the fresh membership could not be recorded ($($_.Exception.Message))" 'Yellow' }
                }
                $dmNote = "$($dbm.note)"
                if ($ugMissing.Count) { $dmNote = (@($dmNote, "the updater is missing Graph $($ugMissing -join ', ')") | Where-Object { "$_".Trim() }) -join '; ' }
                $db | Add-Member -NotePropertyName membershipNote -NotePropertyValue $dmNote -Force
                $dmS = Get-PimDbInitSetupState -Result $db; $db.state = $dmS.dbJob; $db.detail = $dmS.dbJobDetail
                $script:PimDbInitResult = $db
                Say ("database job identity ($When): $(if ($dbm.ok) { 'member, read back' } else { 'NOT read back as a member -- the database job is not started on it' })$(if ($dbm.note) { " -- $($dbm.note)" })$(if (@($dbm.missing).Count) { " -- the updater's identity is missing: $(@($dbm.missing) -join '; ')" })") $(if ($dbm.ok -and -not $dbm.renewFailed) { 'DarkGray' } else { 'Yellow' })
            }
        }
    } catch { Say "  database job identity membership not checked: $($_.Exception.Message)" 'Yellow' }
    # ---- 2e-quinquies. G3A-COPY-LEFTOVER (PIM 100.156 B, framework 12.23 P5; Invardia 2026-11-07) -- THE PULL JOB'S OWN USER ----
    # A managed-tenant pull job deployed before 100.156 B signs in to SQL as its managed identity with NO database user of its
    # own (it reaches the store only through the SQL admin group). Its own user -- the access catalog's downlink roles, from
    # its app id as SID -- is created THROUGH the signed access procedure (the as-built reader's path) and READ BACK
    # (engine/_shared/PIM-DownlinkSqlUser.ps1). Users / role membership / grants only: the 'grants' kind, safe beside a
    # running PIM job (SCHEMA-QUIESCE-818). The admin group membership is READ and REPORTED (run record setupFacts
    # downlinkDbUser / downlinkInAdminGroup), NEVER removed here -- a support step removes it after one pull ran green on
    # its own user. No pull job = one ARM list read, nothing else. Never fails the update.
    try {
        $dlQ = $null; $dlX = $null; $dlS = $null; $dlSkip = ''
        if ("$csSize".Trim()) {
            $dlCs = "$csSize"
            $dlQ = { param($q) Invoke-PimSqlQuery -ConnectionString $dlCs -Sql $q }
            $dlX = { param($q) [void](Invoke-PimSqlNonQuery -ConnectionString $dlCs -Sql $q) }
            $dlS = { param($q) Invoke-PimSqlScalar -ConnectionString $dlCs -Sql $q }
        } else { $dlSkip = 'no store connection in this run' }
        $dlSrv = $(if ("$($env:PIM_SqlServer)".Trim()) { "$($env:PIM_SqlServer)".Trim() } else { "$($global:PIM_SqlServer)".Trim() })
        $dlG = { param($p) Invoke-PimGraph -Path $p }
        $dlu = Invoke-PimDownlinkSqlUserConverge -SubscriptionId $sub -ResourceGroup $rg -Arm $armSeam -Graph $dlG -Query $dlQ -Exec $dlX -Scalar $dlS -SqlServer $dlSrv -SqlSkipReason $dlSkip
        foreach ($l in @($dlu.lines)) { Say ("converge: " + $l.text) $(switch ($l.level) { 'changed' { 'Cyan' } 'warn' { 'Yellow' } default { 'DarkGray' } }) }
        $fixByHand += [int]$dlu.warnings
        if ("$($dlu.state)" -ne 'n/a') { Say ("pull job database user ($When): $($dlu.state) -- $($dlu.detail)") $(if ($dlu.state -eq 'ok') { 'DarkGray' } else { 'Yellow' }) }
    } catch { Say "  pull job database user not checked: $($_.Exception.Message)" 'Yellow' }
    # ---- 2f. framework 12.23 P8 EXCEPTION (owner 2026-10-18) -- A PRIVATE-SQL INSTALL NEVER CUT OVER MOVES BY ITSELF -----------
    # The Support app has no route to a private database. This updater reads (as dbo, still in the SQL admin group), decides
    # (run 1, later run 2) and STARTS the in-network admin job; the job does the admin SQL and reads it back. No admin SQL
    # here (Test-PimSqlAccess L4). Public SQL: nothing (the Support-app cut-over). Never fails the update.
    try {
        # OPEN-06: a database job on its OWN new identity (id-pim-dbinit) whose SQL admin group membership is not READ as
        # true cannot run the admin cut-over -- it is not started on it (before OPEN-06 such an install had no job at all,
        # and this step did nothing either). A job with its existing identity (e.g. id-pim-sql) is unchanged.
        # DBINIT-MEMBERSHIP (framework 4.5 point 5 (c)): for the dedicated identity the membership must be READ BACK by step
        # 2e-quater of THIS run (Get-PimDbInitJobStartGate). 3.0.48 (D): when that read was REFUSED (not 'not a member'), an
        # EARLIER proof opens it -- the stored read-back of a prior run, else the database job's last successful run (3.0.46
        # proof-by-run). Known absent, or never proven + unreadable = not started.
        if ($db -and [bool]$db.dedicated -and $null -eq $dbProof -and -not ($dbm -and ($dbm.readBack -or $dbm.member -eq $false)) -and "$($db.jobName)".Trim()) {
            $dbProof = Get-PimDbInitJobRunProof -Arm $armSeam -JobPath "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs/$($db.jobName)" -PrincipalId "$($db.identityPrincipalId)"
        }
        $dbGate = if ($db -and [bool]$db.dedicated) { Get-PimDbInitJobStartGate -Membership $dbm -Proof $dbProof -PrincipalId "$($db.identityPrincipalId)" -GroupId $dbProofGroup } else { $null }
        # framework 4.5 G3a: added in THIS run -> the identity's token still carries the old group claims; not started now
        if ($dbGate -and $dbGate.start -and "$($dbm.addedUtc)".Trim()) { $dbGate = @{ start = $false; reason = (Get-PimDbInitTokenWait -AddedUtc "$($dbm.addedUtc)").reason + ' -- the cut-over waits for a later run' } }
        # SCHEMA-QUIESCE-818 (3.0.51, found by the DBINIT-STEP-FILTER build): the cut-over starts the FULL database job (schema,
        # access run 1 / run 2). A run that waited for quiet and holds the scheduled jobs goes on; any other run reads the
        # executions ONCE first and does not start the job while a PIM job runs -- the next update starts it.
        $coQ = $null
        if (-not ($dbGate -and -not $dbGate.start) -and "$csSize".Trim() -and -not $script:PimSchemaQuiet) { $coQ = Invoke-PimUpdaterSchemaQuiesce -Cs "$csSize" -Once }
        if ($dbGate -and -not $dbGate.start) {
            Say "database access cut-over: not started -- $($dbGate.reason)" 'DarkGray'
        } elseif ($coQ -and -not $coQ.go) {
            Say "database access cut-over: not started -- $($coQ.line -replace '^schema quiesce: ', '') -- the cut-over waits for a later run" 'DarkGray'
        } elseif ("$csSize".Trim()) {
            $coCs = "$csSize"
            $coApp = "$((Get-PimJwtPrincipal -Token $global:PIM_SqlAccessToken).appid)".Trim()
            $co = Invoke-PimSqlAccessCutoverStep -SubscriptionId $sub -ResourceGroup $rg -SqlServer "$($global:PIM_SqlServer)" -ConnectionString $coCs `
                      -Query { param($cs, $sql) Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql } -UpdaterJob $selfJob -UpdaterAppId $coApp -Arm $armSeam
            foreach ($l in @($co.lines)) { Say "  database access cut-over: $l" 'DarkGray' }
            Say ("database access cut-over: $($co.step) -- $($co.reason)$(if ($co.started) { " -> $($co.status)" })") $(if ($co.started -and "$($co.status)" -ne 'Succeeded') { 'Yellow' } elseif ($co.started) { 'Cyan' } else { 'DarkGray' })
        }
    } catch { Say "  database access cut-over not checked: $($_.Exception.Message)" 'Yellow' }
    # ---- 2f-bis. APP-REG-OWNER (framework SECAUDIT-1a item 2, Invardia ruling 2026-11-07) -- THE UPDATER OWNS PIM'S APP -----
    # REGISTRATIONS. Per product registration present (engine/_shared/PIM-AppRegOwner.ps1: "PIM Manager" -- the sign-in client id
    # this install recorded first --, "PIM Manager Engine", "PIM Activator", "PIM Manager Deploy", "PIM access request API";
    # never any other): READ whether this updater's identity is an owner and REPORT it (setupFacts appRegOwner). Where it IS and
    # its token carries Application.ReadWrite.OwnedBy, it proves the ownership ONCE by a harmless PATCH it reads back (the notes
    # set to the marker -- only empty or marker notes; a customer's text is never overwritten) and records the proof
    # (pim.Settings AppRegOwnerProof; setupFacts appRegOwnerProof). It NEVER adds itself as an owner, never grants itself a
    # role, never removes an owner: recorded Support-app steps do (tools/setup/_PimAppRegOwner.ps1). Never fails the update.
    $aoR = $null
    try {
        $aoMe = "$((Get-PimJwtPrincipal -Token $ugTok).oid)".Trim()
        $aoFacts = Resolve-PimAppRegOwnerInstallFacts -Arm $armSeam -SubscriptionId $sub -ResourceGroup $rg -ManagerApp $managerApp -TickJob $tickJob -UpdateJob $selfJob
        if (-not (Test-PimAppRegOwnerGuid $aoMe)) { $aoMe = "$($aoFacts.updaterObjectId)" }
        $aoHolds = $null; if ($ug -and $ug.known) { $aoHolds = [bool](@($ug.held) -contains (Get-PimAppRegOwnerOwnedByRole)) }
        $aoStored = $null
        if ("$csSize".Trim()) { try { $aoStored = Get-PimSqlSetting -ConnectionString $csSize -Name (Get-PimAppRegOwnerProofSetting) } catch { $aoStored = $null } }
        $aoGraph = { param($Method, $Path, $Body) if ($null -ne $Body) { Invoke-PimGraph -Method $Method -Path $Path -Body $Body } else { Invoke-PimGraph -Method $Method -Path $Path } }
        # Invardia 2026-11-07 (option 1): a COMMUNITY install's updater owns only its own sign-in registration, never a Pro one sharing the tenant
        $aoRoles = @(Get-PimAppRegOwnerInstallRoles -Edition (Get-PimAppRegOwnerUpdaterEdition -Source "$($env:PIM_UPDATE_SOURCE)" -SourceUrl "$($env:PIM_UPDATE_SOURCE_URL)"))
        $aoR = Invoke-PimAppRegOwnerUpdaterCheck -Graph $aoGraph -UpdaterObjectId $aoMe -HoldsOwnedBy $aoHolds -Recorded $aoFacts.recorded -StoredProof $aoStored -Roles $aoRoles
        foreach ($l in @($aoR.lines)) { Say ("converge: " + $l.text) $(switch ($l.level) { 'changed' { 'Cyan' } 'warn' { 'Yellow' } default { 'DarkGray' } }) }
        if ($aoR.proofChanged -and "$csSize".Trim()) {
            try { Set-PimSqlSetting -ConnectionString $csSize -Name (Get-PimAppRegOwnerProofSetting) -ValueJson (ConvertTo-Json -Compress -Depth 6 -InputObject $aoR.proof) }
            catch { Say "  app registration owner: the proof could not be stored ($($_.Exception.Message)) -- the next run proves it again" 'Yellow'; $aoR.proofState = 'pending'; $aoR.proofDetail = "the proof could not be stored this run; $($aoR.proofDetail)" }
        }
        $fixByHand += [int]$aoR.warnings
        if ("$($aoR.state)" -ne 'n/a') { Say ("app registration owner ($When): $($aoR.state), proof $($aoR.proofState) -- $($aoR.detail)") $(if ($aoR.state -eq 'ok' -and $aoR.proofState -eq 'ok') { 'DarkGray' } else { 'Yellow' }) }
    } catch { Say "  app registration owner not checked: $($_.Exception.Message)" 'Yellow' }
    # ---- 2g. FLEET-SETUPSTEPS (framework contract with Invardia, 2026-11-03) -- THE ONE-TIME STEPS, CHECKED ON EVERY RUN ----
    # READ ONLY (ARM GET + one SQL scalar): private network, the Jobs Operator role + SchedulerTickJobId, CR8 (registry admin
    # user, Key Vault purge protection, no SAS in the update source, SQL auditing), the front's key + schema + private vault,
    # the pull / publish jobs' Reader on themselves, the as-built state. Kept for the run record (UpdateState.setupFacts);
    # the heartbeat turns them into setupSteps (engine/_shared/PIM-SetupSteps.ps1). Never fails the update.
    try {
        $ssSql = $null
        if ("$csSize".Trim()) { $ssCs = "$csSize"; $ssSql = { param($q) Invoke-PimSqlScalar -ConnectionString $ssCs -Sql $q } }
        $ssF = Get-PimSetupStepUpdaterFacts -SubscriptionId $sub -ResourceGroup $rg -ManagerApp $managerApp -Arm $armSeam -SqlScalar $ssSql `
                   -ConvergeLines @(if ($cv) { @($cv.lines) }) -JobSelfId $si -SqlAudit $sa -AsBuilt $ab -DbInit $db -SourceUrl "$($env:PIM_UPDATE_SOURCE_URL)"
        # OPEN-27: the database tier against the product tier, kept in the run record (UpdateState.setupFacts: sqlTier =
        # ok | raised | below | pinned-below | n/a | unknown, sqlTierCurrent, sqlTierDetail) -- support reads it; the agreed setupSteps
        # list is unchanged (a new step key is Invardia's to agree).
        try { $stF = Get-PimSqlTierFact -Result $script:PimSqlTierResult; foreach ($k in @($stF.Keys)) { $ssF[$k] = $stF[$k] } } catch { }
        # G3A-COPY-LEFTOVER: the pull job's own database user + whether its identity is still in the SQL admin group, kept in the
        # run record (downlinkDbUser = ok | missing | n/a | unknown; downlinkInAdminGroup = yes | no | n/a | unknown) -- support
        # reads it before the membership is removed; the agreed setupSteps list is unchanged (a new step key is Invardia's to agree).
        try { $dlF = Get-PimDownlinkSqlUserSetupFact -Result $dlu; foreach ($k in @($dlF.Keys)) { $ssF[$k] = $dlF[$k] } } catch { }
        # APP-REG-OWNER: whether the updater owns PIM's product app registrations and has proven it (appRegOwner = ok | missing |
        # n/a | unknown; appRegOwnerProof = ok | pending | n/a | unknown + utc) -- support reads it before the Support app leaves
        # as an owner; the agreed setupSteps list is unchanged (a new step key is Invardia's to agree).
        try { $aoF = Get-PimAppRegOwnerSetupFact -Result $aoR; foreach ($k in @($aoF.Keys)) { $ssF[$k] = $aoF[$k] } } catch { }
        # NAM-03 / framework 12.11c item 3 + ruling (b) (step key 'identity-names', Invardia 2026-11-07): every role runs as
        # id-pim-<role> AND no OLD identity (a shared id-pim-<token>, a named variant, a system-assigned one) still holds an Azure
        # or Graph right (identityNames = ok | missing | n/a | unknown, identityNamesDetail = "app: identity" pairs + "clean-up
        # pending: <identity> still holds rights"). ARM + Graph GET only; a failed read = not read, never fails the update.
        $inGraph = { param($m, $p, $b) Invoke-PimGraph -Method $m -Path $p }
        try { $inF = Read-PimIdentityNamesFact -Arm $armSeam -Graph $inGraph -SubscriptionId $sub -ResourceGroup $rg; foreach ($k in @($inF.Keys)) { $ssF[$k] = $inF[$k] } } catch { $ssF['identityNames'] = 'unknown'; $ssF['identityNamesDetail'] = 'the identity names were not checked this run' }
        $script:PimSetupFacts = $ssF
        $ssUnk = @(@($ssF.Keys) | Where-Object { $_ -notin @('checkedUtc', 'asBuiltDetail', 'dbJobDetail', 'appRegOwnerDetail', 'appRegOwnerProofUtc', 'appRegOwnerProofDetail', 'sqlTierDetail', 'sqlTierCurrent', 'downlinkDbUserDetail', 'identityNamesDetail') -and ($null -eq $ssF[$_] -or "$($ssF[$_])" -eq 'unknown') })
        Say ("setup steps: facts recorded for the heartbeat$(if ($ssUnk.Count) { " (not readable: $($ssUnk -join ', '))" })") 'DarkGray'
    } catch { Say "  setup steps not checked: $($_.Exception.Message)" 'Yellow' }
    # ---- 2g-bis. KV-POLICY-DENIED-PRIVATE / framework installer rule 11 -- A PRIVATE INSTALL'S KEY VAULT IS PRIVATE ------------
    # Only where the install IS private (its environment is internal, step 2g's fact). Every Key Vault in the install's resource
    # group is PATCHED to the rule-11 shape and READ BACK, then given its private endpoint (beside the SQL endpoint) in
    # privatelink.vaultcore.azure.net (Invoke-PimKeyVaultRule11, the installer's own routine). A public install: nothing.
    # Reported, never fails the update; what the updater may not do (e.g. a central zone it cannot write) is said in yellow.
    try {
        if ($script:PimSetupFacts -and $script:PimSetupFacts['privateNetwork'] -eq $true -and (Get-Command Invoke-PimKeyVaultRule11 -ErrorAction SilentlyContinue)) {
            $kvRgPath = "/subscriptions/$sub/resourceGroups/$rg"
            $kvArm = { param($m, $p, $b)
                try { if ($null -ne $b) { Invoke-PimArm -Method $m -Path $p -Body $b } else { Invoke-PimArm -Method $m -Path $p } }
                catch { if ($m -eq 'GET' -and "$($_.Exception.Message)" -match '(?i)\b404\b|NotFound|ResourceNotFound') { $null } else { throw } } }
            $kvList = @(@((& $kvArm 'GET' "$kvRgPath/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01" $null).value) | Where-Object { $_ })
            $kvSql = ("$(if ("$($env:PIM_SqlServer)".Trim()) { $env:PIM_SqlServer } else { $global:PIM_SqlServer })".Trim() -split '\.')[0]
            foreach ($kvItem in $kvList) {
                $kv11 = Invoke-PimKeyVaultRule11 -Arm $kvArm -VaultId "$kvRgPath/providers/Microsoft.KeyVault/vaults/$($kvItem.name)" -SqlServerName $kvSql
                foreach ($l in @($kv11.lines)) { Say ("private vault: " + $l.text) $(switch ($l.level) { 'changed' { 'Cyan' } 'warn' { 'Yellow' } default { 'DarkGray' } }) }
            }
            if (-not $kvList.Count) { Say 'private vault: no Key Vault in the resource group' 'DarkGray' }
        }
    } catch { Say "  private vault not checked: $($_.Exception.Message)" 'Yellow' }
    # ---- 2g-ter. framework installer rule 11d (2026-11-04) -- THE RETURN ROUTE, REPORTED ONLY -----------------------------
    # Found live at a customer install: without a route for the customer's internal ranges -> the hub firewall on the app
    # subnet, the replies to the LAN leave by Azure's default route and the private web app times out. Only where the install
    # IS private and was given -InternalRanges / -FirewallIp (recorded as tags on its resource group). READ ONLY: GET only --
    # the updater NEVER creates or changes a route (a wrong next hop would cut the LAN off; the network is the customer's
    # decision). A missing route is a yellow line with the network hand-off text. Never fails the update.
    try {
        if ($script:PimSetupFacts -and $script:PimSetupFacts['privateNetwork'] -eq $true -and (Get-Command Get-PimReturnRouteReport -ErrorAction SilentlyContinue)) {
            $rrGet = { param($m, $p, $b)
                if ($m -ne 'GET') { throw "the return-route check is read only (refused $m)" }
                try { Invoke-PimArm -Method GET -Path $p } catch { if ("$($_.Exception.Message)" -match '(?i)\b404\b|NotFound|ResourceNotFound') { $null } else { throw } } }
            $rrRep = Get-PimReturnRouteReport -SubscriptionId $sub -ResourceGroup $rg -ManagerApp $managerApp -Arm $rrGet
            Say $rrRep.text $(switch ($rrRep.state) { 'missing' { 'Yellow' } 'unknown' { 'Yellow' } default { 'DarkGray' } })
        }
    } catch { Say "  return route not checked: $($_.Exception.Message)" 'Yellow' }
}

# 🔴 2026-09-18 (§71.43) -- THE STORE IS NEEDED BEFORE THE FIRST EXIT PATH, NOT ONLY AT THE SCHEMA STEP.
# Every refusal below (no resource group, a ring with no source, nothing approved, a refused downgrade)
# now RECORDS what it decided into pim.Settings so the Manager can show this environment's ring -- and
# those are exactly the runs an operator most needs to see. Without the store resolved here they would
# all have recorded nothing.
# 🪤 Idempotent, and deliberately called again at the schema step: neither phase may depend on the
# other's ordering. One implementation (PIM-UpdateSource.ps1), two call sites.
[void](Use-PimUpdaterStoreEnv)

$sub        = "$($env:PIM_SubscriptionId)".Trim()
$rg         = "$($env:PIM_ResourceGroup)".Trim()
$managerApp = $(if ("$($env:PIM_ManagerApp)".Trim()) { "$($env:PIM_ManagerApp)".Trim() } else { 'ca-pim-manager' })
$tickJob    = $(if ("$($env:PIM_TickJobName)".Trim()) { "$($env:PIM_TickJobName)".Trim() } else { 'ca-pim-tick' })
$selfJob    = $(if ("$($env:PIM_UpdateJobName)".Trim()) { "$($env:PIM_UpdateJobName)".Trim() } else { 'ca-pim-update' })
$targetImg  = "$($env:PIM_UPDATE_TARGET_IMAGE)".Trim()   # e.g. acr.azurecr.io/pim-manager:2.4.295
$container  = $(if ("$($env:PIM_ManagerContainerName)".Trim()) { "$($env:PIM_ManagerContainerName)".Trim() } else { '' })
# CR7 (PIM 100.168): the JOBS keep the configured container name exactly as before; $container (the MANAGER's container) is
# resolved below from the app -- behind the sign-in front the Manager app carries two containers and '' cannot pick one.
$jobContainer = $container

Say "environment $rg (subscription $sub)" 'Cyan'

# ---- §56.6 TELEMETRY -- one record per run, on EVERY exit path ---------------------------------
# 🔑 "so i can see if customer has issues or specific build is not updating" is two queries: is THIS
# customer stuck, and is THIS BUILD failing everywhere. The second cannot be backfilled -- telemetry
# added at customer 80 says nothing about the first 79 -- which is why it ships now, at three.
# 🔴 IT MUST NEVER AFFECT THE UPDATE. Send-PimUpdateTelemetry never throws and is bounded; a
# reporting feature that could stop updates across the fleet would be strictly worse than no
# reporting at all. Silent no-op when PIM_TELEMETRY_URL is unset.
# 🪤 REPORTED FROM A trap-STYLE HELPER CALLED AT EVERY EXIT, not just the happy path. A telemetry
# record written only when the run succeeds answers neither question -- "stuck" and "failing" are
# precisely the runs that end early.
$script:PimUpdateStartedUtc = [datetime]::UtcNow
$script:PimTelemetrySent    = $false
# §71.43 -- what the ring said THIS run, and what was running when it started. Filled in as the run
# learns them; both start empty so a run that exits before reading the channel records '' rather than a
# value carried over from something else.
$script:PimRingApproved       = ''
$script:PimRingApprovedReason = ''
$script:PimRunningVersion     = ''
$script:PimSqlAccessVerdict   = $null   # §33.0 SqlAccess: set by the access converge (schema step); $null = carry the last one
$script:PimSignInLayer        = $null   # framework 8.17 SignIn: read from the Manager app below; $null = carry the last one
$script:PimSetupFacts = $null           # FLEET-SETUPSTEPS: the one-time steps' facts (converge step 2g); $null = carry the last one
$script:PimEnginePermissionCheck = $null # 95.2i: the engine's rights for this version (converge step 2d-perm); $null = carry the last one
$script:PimBuildPoolState = $null        # BUILDPOOL-11G: the build pool as read this run; $null = carry the last one
$script:PimBuildPoolNone  = -not "$($env:PIM_ACR_AGENT_POOL)".Trim()   # no pool (a public install): no BuildPool recorded at all
# OPEN-13 / framework 8.8 UPDATE-TRACK: this run's stage tracker ($null until the update decision starts -- the earlier exits
# report no run) and whether the Manager roll rolled back (the run then ends rollback -> done "rolled back").
$script:PimUpdTrack           = $null
$script:PimUpdTrackRolledBack = $false
function Set-PimUpdTrackStage {
    # BEST EFFORT: a stage report never fails, delays or changes the update (PIM-UpdateTrack.ps1 never throws; this guards it too).
    param([string]$Stage, [string]$Message = '', [ValidateSet('', 'ok', 'warning', 'skipped')][string]$Close = '')
    if (-not $script:PimUpdTrack) { return }
    try {
        if ($Close) { [void](Close-PimUpdateTrackStage -Track $script:PimUpdTrack -State $Close -Message $Message) }
        else { [void](Start-PimUpdateTrackStage -Track $script:PimUpdTrack -Stage $Stage -Message $Message) }
    } catch { }
}
function Get-PimUpdTrackFromVersion {
    # the version the run starts from: what the Manager runs, else what this job last built ('' = the run is not reported)
    $v = "$($script:PimRunningVersion)".Trim(); if (-not $v) { $v = "$($env:PIM_UPDATE_LAST_BUILT)".Trim() }
    return $v
}
function Send-PimUpdateOutcome {
    param(
        [ValidateSet('none','built','rolled','schema','failed')][string]$Action = 'none',
        # 2026-10-09: 'ahead' (runs a newer version than its ring approves -- healthy, nothing changed) and 'attention'
        # (stopped on an operator decision, e.g. the replay watermark's ring is unknown) are recorded as such in the
        # environment's own state, so the Manager never paints them as a failed update.
        # 100.69: 'waiting' = an Invardia run before the engine claimed the install key (exit 0, not a failure).
        [ValidateSet('ok','failed','skipped','ahead','attention','waiting')][string]$Outcome = 'ok',
        [string]$ToVersion, [string]$ErrorText,
        # 100.69: the vendor-telemetry outcome when it must differ from the default mapping (the no-key warning is
        # 'attention' in the Manager but never a FAILED record at Invardia: it is not a product failure).
        [ValidateSet('','ok','failed','skipped')][string]$TelemetryOutcome = '',
        [AllowEmptyString()][string]$WaitingSinceUtc = ''
    )
    # SCHEMA-QUIESCE-818: every exit path records its outcome HERE, so the hold on the scheduled jobs is lifted here too.
    Clear-PimUpdaterSchemaHold
    if ($script:PimTelemetrySent) { return }        # one record per run, never two
    $script:PimTelemetrySent = $true
    # OPEN-13 / framework 8.8: the run's last stage event (done | failed | rollback | waiting) -- every exit path comes here.
    # Best effort: never throws, never changes the outcome below.
    if ($script:PimUpdTrack) {
        try {
            $utTo = "$ToVersion".Trim(); if (-not $utTo) { $utTo = "$($script:PimRingApproved)".Trim() }
            [void](Complete-PimUpdateTrack -Track $script:PimUpdTrack -Outcome $Outcome -ErrorText $ErrorText -FromVersion (Get-PimUpdTrackFromVersion) -ToVersion $utTo -RolledBack:([bool]$script:PimUpdTrackRolledBack))
        } catch { }
    }
    # The vendor telemetry keeps its closed vocabulary: ahead = a good run with nothing to do ('ok'); attention is still
    # something an operator has to act on, so Invardia sees it ('failed', with the actionable text).
    $telOutcome = switch ($Outcome) { 'ahead' { 'ok' } 'attention' { 'failed' } 'waiting' { 'skipped' } default { $Outcome } }
    if ($TelemetryOutcome) { $telOutcome = $TelemetryOutcome }
    try {
        if (-not (Get-Command New-PimUpdateTelemetryRecord -ErrorAction SilentlyContinue)) { return }
        $rec = New-PimUpdateTelemetryRecord -Environment $rg -Ring "$($env:PIM_UPDATE_RING)" `
                    -FromVersion "$($env:PIM_UPDATE_LAST_BUILT)" -ToVersion $ToVersion `
                    -Action $Action -Outcome $telOutcome -ErrorText $ErrorText `
                    -DurationSeconds ([int]([datetime]::UtcNow - $script:PimUpdateStartedUtc).TotalSeconds)
        [void](Send-PimUpdateTelemetry -Record $rec -Log { param($m) Say $m 'DarkGray' })
    } catch { }                                      # telemetry can never break the update

    # ---- §71.43 THE SAME FACTS, RECORDED IN THIS ENVIRONMENT'S OWN STORE ------------------------
    # 🔑 The blob above is WRITE-ONLY from here (PIM-UpdateTelemetry.ps1, header): the environment
    # cannot read back what it reported, so the Manager could never answer "which ring am I on?".
    # This writes the same run to pim.Settings['UpdateState'], where the Manager already reads
    # everything else -- and it is the ONLY place the ring exists inside the environment, because
    # PIM_UPDATE_RING lives on THIS job and not on ca-pim-manager.
    # 🔴 SAME FAIL-SAFE DIRECTION. Save-PimUpdateState never throws; a settings write that did not
    # land is a note in the log and nothing more. An update that succeeded is never reported as
    # failed, or refused, because a reporting write failed.
    try {
        if (-not (Get-Command New-PimUpdateStateRecord -ErrorAction SilentlyContinue)) { return }
        $csState = $null
        try { $csState = Get-PimSqlConnectionString } catch { $csState = $null }
        if (-not "$csState".Trim()) {
            # 🪤 UPD-15 AGAIN, ONE PHASE EARLIER. The store self-heal (Resolve-PimUpdaterStoreSettings)
            # runs at the SCHEMA phase, so an updater that carries no PIM_SqlServer -- the test-tenant
            # shape -- would record nothing on any run that refuses BEFORE it, which is precisely the
            # run whose ring an operator wants to see. $app is the Manager this run already read; it
            # is $null on the earliest exits and that simply yields no store, as before.
            try {
                $heal = Resolve-PimUpdaterStoreSettings -JobServer "$($global:PIM_SqlServer)" -JobDatabase "$($global:PIM_SqlDatabase)" `
                            -ManagerStore (Get-PimAcaStoreSettings -Resource $app) -ManagerApp $managerApp
                if ($heal.source -eq 'manager' -and "$($heal.server)".Trim()) {
                    Set-Variable -Name 'PIM_SqlServer' -Scope Global -Value "$($heal.server)"
                    if ("$($heal.database)".Trim()) { Set-Variable -Name 'PIM_SqlDatabase' -Scope Global -Value "$($heal.database)" }
                    try { $csState = Get-PimSqlConnectionString } catch { $csState = $null }
                }
            } catch { }
        }
        if (-not "$csState".Trim()) {
            Say 'update state: no store to record it in (the ring will show as "not recorded" in the Manager).' 'DarkGray'
            return
        }
        $prev = Read-PimUpdateState -ConnectionString $csState
        $stateRec = New-PimUpdateStateRecord -Environment $rg -Ring "$($env:PIM_UPDATE_RING)" `
                        -Hold ("$($env:PIM_UPDATE_HOLD)".Trim() -eq '1') `
                        -ApprovedVersion $script:PimRingApproved -ApprovedReason $script:PimRingApprovedReason `
                        -RunningVersion $script:PimRunningVersion `
                        -LastBuiltVersion "$($env:PIM_UPDATE_LAST_BUILT)" -TargetVersion $ToVersion `
                        -Action $Action -Outcome $Outcome -ErrorText $ErrorText -Previous $prev `
                        -Source "$($env:PIM_UPDATE_SOURCE)" -WaitingSinceUtc $WaitingSinceUtc -SqlAccess $script:PimSqlAccessVerdict -SignIn $script:PimSignInLayer -EnginePermissions $script:PimEnginePermissionCheck -SetupFacts $script:PimSetupFacts `
                        -BuildPool $script:PimBuildPoolState -NoBuildPool:([bool]$script:PimBuildPoolNone) `
                        -DurationSeconds ([int]([datetime]::UtcNow - $script:PimUpdateStartedUtc).TotalSeconds)
        $saved = Save-PimUpdateState -ConnectionString $csState -Record $stateRec
        if ($saved.ok) { Say "update state: recorded ring '$($stateRec.ring)' / $Outcome in pim.Settings" 'DarkGray' }
        else { Say "update state: NOT recorded (the update itself is unaffected): $($saved.reason)" 'DarkGray' }
        # 2026-10-07 (operator: "maybe it is a good idea to rerun that after each update"): after a successful roll, refresh
        # the tenant cache and then the drift check at the engine's next tick (within 5 minutes) instead of up to 12 h / 4 h
        # later -- a new version reads with new code, so its pages should not show what the old one cached. Queued in
        # order (the tick drains triggers in list order); a trigger already queued for a type is not queued twice.
        if ($Action -eq 'rolled' -and $Outcome -eq 'ok' -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
            try {
                $list = @(@(Get-PimSqlSetting -ConnectionString $csState -Name 'SchedulerTriggers') | Where-Object { $null -ne $_ })
                $added = @()
                foreach ($jt in 'tenant-cache', 'drift-snapshot') {
                    if (@($list | Where-Object { "$($_.type)" -eq $jt }).Count) { continue }
                    $list += [pscustomobject][ordered]@{ type = $jt; scope = 'All'; reason = "run-now:$jt (after the update to $ToVersion)"; requestedUtc = [datetime]::UtcNow.ToString('o'); job = $jt }
                    $added += $jt
                }
                if ($added.Count) {
                    # IMP-39: -ValueJson -- a one-element list through -Value is stored as a bare object, not an array.
                    Set-PimSqlSetting -ConnectionString $csState -Name 'SchedulerTriggers' -ValueJson (ConvertTo-Json -InputObject @($list) -Depth 6 -Compress)
                    Say "after the update: queued $($added -join ' + ') for the engine's next run" 'DarkGray'
                }
            } catch { Say "after the update: the cache refresh could not be queued ($($_.Exception.Message)) -- it runs on its own schedule" 'DarkGray' }
        }
    } catch { }                                      # recording can never break the update
}

# ---- SCHEMA-QUIESCE-818 (framework 8.18; owner 2026-11-05 "it can destroy schema") -- NO DATABASE CHANGE UNDER A RUN -------
# An update never cancels a running run and never changes the database schema under one: before ANY DDL this run makes it
# reads the executions of the install's PIM jobs (the same ARM read as its own, engine/_shared/PIM-SchemaQuiesce.ps1), holds
# the scheduled jobs (pim.Settings UpdateSchemaHold, read by the tick and the pull at their start), waits while one runs
# (bounded) and DEFERS -- outcome 'waiting', no schema step, no roll -- when one is still running at the bound. Unreadable
# executions count as running. Nothing is ever stopped. The hold is lifted when this run records its outcome.
$script:PimSchemaHoldCs   = ''      # the store this run's hold was written to ('' = no hold set by this run)
$script:PimSchemaQuiet    = $false  # this run waited until no PIM job ran AND holds the scheduled jobs
$script:PimSchemaDeferred = $null   # the quiesce result when the schema step was deferred
function Clear-PimUpdaterSchemaHold {
    if (-not "$($script:PimSchemaHoldCs)".Trim()) { return }
    $sqClearCs = "$($script:PimSchemaHoldCs)"; $script:PimSchemaHoldCs = ''; $script:PimSchemaQuiet = $false
    try {
        Set-PimSqlSetting -ConnectionString $sqClearCs -Name (Get-PimSchemaHoldSettingName) -ValueJson (ConvertTo-Json -InputObject (New-PimSchemaHoldClearRecord -By $selfJob) -Compress)
        Say 'schema quiesce: the hold on the scheduled jobs is lifted' 'DarkGray'
    } catch { Say "schema quiesce: the hold could not be lifted ($((("$($_.Exception.Message)") -split "`n")[0])) -- it expires by itself" 'Yellow' }
}
# SCHEMA-QUIESCE-LONG-SNAPSHOT (3): the last log line of a run already past 3x its usual length, from the job's environment
# workspace. READ ONLY (two ARM GETs + one Log Analytics query -- a POST that only reads). Best effort: no right / no workspace /
# no row = $null = the run is NOT called hung. Never stops anything.
$script:PimSqLogCid = ''
function Get-PimUpdaterRunLastLogUtc {
    param([string]$Job, [string]$Execution)
    try {
        if (-not $script:PimSqLogCid) {
            $sqJ = Invoke-PimArm -Method GET -Path "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs/$Job" -ApiVersion $script:PimAcaApi
            $sqE = Invoke-PimArm -Method GET -Path "$($sqJ.properties.environmentId)" -ApiVersion $script:PimAcaApi
            $script:PimSqLogCid = "$($sqE.properties.appLogsConfiguration.logAnalyticsConfiguration.customerId)".Trim()
        }
        if (-not $script:PimSqLogCid) { return $null }
        $sqQ = "ContainerAppConsoleLogs_CL | where ContainerGroupName_s startswith '$("$Execution".Replace("'", "''"))' | summarize last = max(TimeGenerated)"
        $sqR = Invoke-PimRest -Method POST -Url "https://api.loganalytics.io/v1/workspaces/$($script:PimSqLogCid)/query" -Resource 'https://api.loganalytics.io' -Body @{ query = $sqQ; timespan = 'P1D' }
        $v = @(@(@($sqR.tables)[0].rows)[0])[0]
        if ("$v".Trim()) { return (ConvertTo-PimSchemaQuiesceUtc $v) } else { return $null }
    } catch { return $null }
}
function Invoke-PimUpdaterSchemaQuiesce {
    <# -Once: ONE read, no wait, no hold (the as-built converge on a run that did not quiesce): go only when nothing runs. #>
    param([AllowEmptyString()][string]$Cs = '', [switch]$Once)
    $sqRec = $null; if ("$Cs".Trim()) { try { $sqRec = Get-PimSqlSetting -ConnectionString $Cs -Name 'InstallNames' } catch { $sqRec = $null } }
    $sqExisting = $null
    try { $sqList = Invoke-PimArm -Method GET -Path "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs" -ApiVersion $script:PimAcaApi; $sqExisting = @(@($sqList.value) | Where-Object { $_ } | ForEach-Object { "$($_.name)" }) } catch { $sqExisting = $null }
    $sqJobs = @(Get-PimSchemaQuiesceJobNames -Record $sqRec -ManagerApp $managerApp -Existing $sqExisting -Self $selfJob)
    $sqRead = { param($j) Invoke-PimArm -Method GET -Path "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs/$j/executions" -ApiVersion $script:PimAcaApi }
    $sqHold = $null
    if (-not $Once -and "$Cs".Trim()) { $sqHoldCs = "$Cs"; $sqHold = { param($r) Set-PimSqlSetting -ConnectionString $sqHoldCs -Name (Get-PimSchemaHoldSettingName) -ValueJson (ConvertTo-Json -InputObject $r -Compress) } }
    $sqMax = $(if ($Once) { 0 } else { (Get-PimSchemaQuiesceWaitMinutes) * 60 })
    $sqLastLog = { param($j, $x) Get-PimUpdaterRunLastLogUtc -Job $j -Execution $x }   # SCHEMA-QUIESCE-LONG-SNAPSHOT (3): read only
    $q = Invoke-PimSchemaQuiesce -Jobs $sqJobs -ReadExecutions $sqRead -SetHold $sqHold -By $selfJob -NoHold:$Once -MaxWaitSeconds $sqMax -NoLongWait:$Once -LastLog $sqLastLog -Log { param($l) Say $l 'DarkGray' }
    if ($q.held) { $script:PimSchemaHoldCs = "$Cs" }
    if ($q.go -and -not $Once) { $script:PimSchemaQuiet = $true }
    if (-not $Once) { Say "$($q.line) [$($sqJobs.Count) job(s) read$(if ($null -eq $sqExisting) { ', the job list was not readable: every resolved name read' })]" $(if ($q.go) { 'DarkGray' } else { 'Yellow' }) }
    return $q
}

if (-not $sub -or -not $rg) {
    Say 'PIM_SubscriptionId and PIM_ResourceGroup are required -- refusing to guess which environment to roll.' 'Red'
    Send-PimUpdateOutcome -Action 'failed' -Outcome 'failed' -ErrorText 'PIM_SubscriptionId / PIM_ResourceGroup not set'
    exit 2
}
# ---- 0. §55 -- BUILD THE APPROVED VERSION IF THIS ENVIRONMENT HAS TO -----------------------------
# 🔴 THE UPDATER USED TO BE A ROLLER ONLY, AND THAT IS HALF A SOLUTION.
# It moved an environment onto an image SOMEBODY ELSE had put in its registry. For the three
# environments with a build host behind them that is a complete nightly cycle; for a customer with
# no VM, nothing ever puts an image there and the environment can never move. Framework DEPLOY-3.
#
# 🔑 `az acr build` NEVER BUILT LOCALLY -- it uploads source and the REGISTRY builds. So a
# container can do the same over four plain ARM/HTTPS calls with the identity it already has
# (PIM-AcrBuild.ps1), and each environment produces its own image in its own registry. Nothing has
# to distribute images between tenants, and no cross-tenant registry credential has to exist.
#
# 🔒 AND IT IS OFF UNTIL AN ENVIRONMENT IS GIVEN A SOURCE. With no PIM_UPDATE_SOURCE_URL this runs
# exactly as it did before -- roll to what the registry already holds. That is what lets this ship
# without touching the environments that already update themselves every night.
$srcUrlTpl   = "$($env:PIM_UPDATE_SOURCE_URL)".Trim()
$targetVer   = "$($env:PIM_UPDATE_TARGET_VERSION)".Trim()
$lastBuilt   = "$($env:PIM_UPDATE_LAST_BUILT)".Trim()
$imageRepo   = $(if ("$($env:PIM_ImageRepo)".Trim()) { "$($env:PIM_ImageRepo)".Trim() } else { 'pim-manager' })

# Self-configuring: the Manager's CURRENT image already names this environment's registry and
# repository, so nothing has to be told them -- the same trick as inheriting the registry identity.
# 🪤 Get-PimAcaAppImage takes the APP OBJECT (-App), not subscription/group/name. Calling it with
# the wrong parameters threw a binding error that the catch below swallowed into "no registry", and
# the run then failed further on with "Cannot bind argument to parameter 'RegistryName' because it
# is an empty string" -- a message about the SYMPTOM, three steps from the cause. Measured on the
# first live run of §55.
$loginServer = ''
$resolveErr  = ''
$app = $null; $ref = $null
try {
    $app = Get-PimAcaApp -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp
    # CR7: a two-container revision (the sign-in front + the Manager) names the Manager as the one that is not the front.
    # A single-container app (every install not behind the front) resolves to '' -- today's rule, unchanged.
    $container = Resolve-PimManagerContainerName -App $app -Configured $container
    $cur = Get-PimAcaAppImage -App $app -ContainerName $container
    $ref = Split-PimImageReference -Image "$cur"
    if ($ref) {
        $loginServer = $ref.loginServer
        if ($ref.repository) { $imageRepo = $ref.repository }
        # §71.43 -- what this environment was RUNNING when the update run started. Recorded so a
        # failed/no-op run still says which version it was looking at.
        $script:PimRunningVersion = "$($ref.tag)"
    }
    else { $resolveErr = "the Manager's image ('$cur') names no registry" }
} catch { $resolveErr = "$($_.Exception.Message)" }
if ($resolveErr) { Say "  could not read this environment's registry from $managerApp`: $resolveErr" 'Yellow' }
# Framework 8.17 SignIn: the Manager's sign-in layer, read from the RUNNING app (the app above + its auth config), recorded
# in UpdateState so the heartbeat only reads it (the tick reads no ARM). A read that fails records nothing -- the last
# known layer is carried forward. Telemetry only: never changes or stops the update.
try {
    if ($app -and (Get-Command Get-PimSignInLayer -ErrorAction SilentlyContinue)) {
        $siAuth = $null; $siRead = $true
        try { $siAuth = Get-PimAcaAuthConfig -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp }
        catch { if ("$($_.Exception.Message)" -notmatch '404|NotFound') { $siRead = $false } }
        $script:PimSignInLayer = Get-PimSignInLayer -App $app -AuthConfig $siAuth -AuthRead $siRead
    }
} catch { $script:PimSignInLayer = $null }

# ---- CR7 (framework 12.11g, PIM 100.168) -- DOES THIS INSTALL BUILD THE SIGN-IN FRONT IMAGE? ----------------------------
# 🔒 OPT-IN ONLY: the Manager runs behind the front (PIM_HOSTED_AUTH_LAYER=signin-front on its app) or this job carries
# PIM_BUILD_SIGNIN_FRONT=1 (Set-PimManagerSigninFront.ps1 sets it before it moves an environment). Decided from the app
# object read above and this job's own environment -- NO call. Every other install: nothing below runs, nothing is logged,
# nothing is fetched or built: byte for byte today's update.
$sfOpt    = Get-PimSigninFrontOptIn -App $app -BuildFlag "$($env:PIM_BUILD_SIGNIN_FRONT)"
$sfWanted = ''; $sfBuilt = ''; $sfNeed = $false; $sfResult = $null; $sfFrontImage = ''
if ($sfOpt.optIn) {
    $sfWanted = Get-PimSigninFrontPinnedVersion -SolutionRoot $solRoot
    $sfBuilt  = "$($env:PIM_SIGNIN_FRONT_BUILT)".Trim()
    $sfNeed   = [bool]($sfWanted -and $sfBuilt -ne $sfWanted)
    Say ("sign-in front: $($sfOpt.reason); pinned $(if ($sfWanted) { $sfWanted } else { '(none)' }), built here $(if ($sfBuilt) { $sfBuilt } else { '(none yet)' })") 'DarkGray'
}
function Invoke-PimUpdaterSigninFrontStep {
    <#
      CR7: the front image step for THIS run (engine/_shared/PIM-SigninFrontImage.ps1 decides and builds). -ArchivePath = the
      source archive this run already holds; '' = fetch the archive of -Version from the configured source (not for an
      Invardia source -- its verified archive is the only one). NEVER fails the update: the result is logged and returned.
    #>
    param([string]$ArchivePath = '', [string]$Version = '')
    $fetched = ''
    try {
        $arch = "$ArchivePath".Trim()
        # SEC-95: only an updater whose CHOSEN source is the storage container fetches from it (never as a fallback)
        if (-not $arch -and $sfNeed -and "$Version".Trim() -and $srcUrlTpl -and $srcUrlTpl -notmatch '^invardia://' -and $srcMode.mode -eq 'pim-src') {
            $fetched = Join-Path ([IO.Path]::GetTempPath()) ("pim-src-front-{0}.tar.gz" -f "$Version".Trim())
            Say "sign-in front: fetching the source of $Version to build signin-front:$sfWanted" 'DarkGray'
            $gotF = Get-PimUpdateSourceArchive -Url (Resolve-PimUpdateSourceUrl -Template $srcUrlTpl -Version "$Version".Trim()) -OutFile $fetched
            if ($gotF.ok) { $arch = $fetched } else { Say "  sign-in front: source NOT fetched ($($gotF.reason)) -- the front image is not built this run" 'Yellow' }
        }
        $regF = if ($loginServer) { Split-PimImageReference -Image "$loginServer/x:y" } else { $null }
        $poolF = "$($env:PIM_ACR_AGENT_POOL)".Trim()
        $r = Invoke-PimSigninFrontImageStep -OptIn $true -Wanted $sfWanted -Built $sfBuilt -CurrentImage (Get-PimSigninFrontCurrentImage -App $app) `
                -LoginServer $loginServer -ArchivePath $arch `
                -SubscriptionId $sub -ResourceGroup $rg -RegistryName "$($regF.registryName)" -AgentPoolName $poolF -OnPoll { param($s) Say "  front build $s" 'DarkGray' } `
                -Record { param($v) [void](Invoke-PimArmBusyRetry -Write { Set-PimAcaJobEnvValue -SubscriptionId $sub -ResourceGroup $rg -JobName $selfJob -VariableName 'PIM_SIGNIN_FRONT_BUILT' -Value $v }) }
        foreach ($l in @($r.lines)) { Say $l $(if (-not $r.ok) { 'Yellow' } elseif ($r.built) { 'Green' } else { 'DarkGray' }) }
        return $r
    } catch {
        Say "  sign-in front: the image step failed ($($_.Exception.Message)) -- the Manager update is not affected" 'Yellow'
        return @{ ok = $false; action = 'error'; built = $false; version = $sfWanted; image = ''; reason = "$($_.Exception.Message)"; lines = @() }
    } finally {
        if ($fetched) { Remove-Item -LiteralPath $fetched -Force -ErrorAction SilentlyContinue }
    }
}

# A bare version is the modern pin -- one value, identical in every environment. A full image
# reference (PIM_UPDATE_TARGET_IMAGE) is still honoured so nothing already deployed changes meaning.
if (-not $targetVer -and $targetImg) {
    $tref = Split-PimImageReference -Image $targetImg
    if ($tref -and $tref.tag) { $targetVer = $tref.tag }
}

# ---- §60 -- WHAT DOES THIS RING APPROVE? ---------------------------------------------------------
# 🔴 THERE IS NEVER A PUSH TO 1000 CUSTOMERS. The pin has always been the ring enforcement point --
# an environment moves only to the version it is pinned to -- but the pin was PUSHED, so "release
# to ring 2" meant editing every ring-2 environment. That is the same shape as rotating a shared
# credential by touching every holder, and it does not exist at fleet scale.
# 🔑 So the environment READS what its ring approves, from one file beside the source archives,
# using the credential it already holds. Releasing to a ring becomes editing that one file.
# 🔒 THE RING WINS over a locally-set version when a ring is configured -- otherwise adopting the
# channel would require first clearing a pin on every environment, which is the push we are
# removing. To freeze ONE environment, set PIM_UPDATE_HOLD=1; that is an explicit, visible decision
# rather than a stale pin nobody remembers setting.
$ring = "$($env:PIM_UPDATE_RING)".Trim()
# §95.4 -- a Pro install whose updates come from Invardia's update platform (Deploy-PimUpdateJob -UpdateSource Invardia).
# PIM decides the release (framework GOVERNANCE Rule -1); Invardia signs and serves the manifest PIM published for the
# environment's ring (today that ring is still set at Invardia -- moving to this environment's own ring, framework
# UPDATE-1.7). Everything after the version is known -- build, schema, roll, verify, rollback -- is this job's own,
# unchanged. PIM-InvardiaUpdate.ps1 has the rules.
$updSource = "$($env:PIM_UPDATE_SOURCE)".Trim().ToLowerInvariant()
$script:PimInvardiaContext = ''; $script:PimInvardiaSequence = 0; $script:PimInvardiaApplied = 0; $script:PimInvardiaAhead = $false
# SEC-95 (SECAUDIT-1, the cloud updater's half): WHICH source this run may read (PIM-UpdateSource.ps1 Resolve-PimUpdateSourceMode).
# Invardia (signed) is the default; a storage container (channel.json + archives, NO signature) is read only when the job
# names it as its source, and then every run says so -- here, in the outcome and in the Manager's update status. A
# container ADDRESS without that choice is refused (no fallback from Invardia to a container, ever).
$srcMode = Resolve-PimUpdateSourceMode -Source $updSource -SourceUrlTemplate $srcUrlTpl
if ($srcMode.mode -eq 'invardia-community' -and -not $updSource) { $updSource = 'invardia-community' }
elseif ($srcMode.mode -eq 'invardia' -and -not $updSource) { $updSource = 'invardia' }
if ($srcMode.unsigned) {
    Say '!! UNSIGNED UPDATE SOURCE: this environment takes its code from a storage container chosen for it (channel.json +' 'Red'
    Say '!! source archives), not from the signed release service.' 'Red'
    Say '!! Updates from the signed release service: re-run tools/setup/Deploy-PimUpdateJob.ps1 with -UpdateSource Invardia.' 'Red'
} else { Say $srcMode.line 'DarkGray' }

# ---- framework 8.18 UPDATE-NOW -- WHICH KIND OF EXECUTION IS THIS? (engine/_shared/PIM-UpdateNow.ps1 has the rules) ------
# The cron is every 15 minutes once UPDATE NOW is on (PIM_UPDATE_NIGHTLY_UTC keeps the nightly time). The nightly slot and
# a hand-started execution run the normal update EXACTLY as before; every other scheduled execution is a seconds-long
# signal check that exits 0 with one line -- unless the signal says "now" for a version THIS RING approves, and then the
# normal update below runs in this execution. No PIM_UPDATE_NIGHTLY_UTC (an install not converged yet) = 'legacy': a
# full run, as before. Nothing here can fail the run: an unreadable signal, store or execution list = "no signal".
function Get-PimUpdaterStoreCsHealed {
    # The store's connection string (the job's own, else the Manager's -- the test-tenant shape, same self-heal as below).
    $c = $null; try { $c = Get-PimSqlConnectionString } catch { $c = $null }
    if (-not "$c".Trim()) {
        try {
            $heal = Resolve-PimUpdaterStoreSettings -JobServer "$($global:PIM_SqlServer)" -JobDatabase "$($global:PIM_SqlDatabase)" `
                        -ManagerStore (Get-PimAcaStoreSettings -Resource $app) -ManagerApp $managerApp
            if ($heal.source -eq 'manager' -and "$($heal.server)".Trim()) {
                Set-Variable -Name 'PIM_SqlServer' -Scope Global -Value "$($heal.server)"
                if ("$($heal.database)".Trim()) { Set-Variable -Name 'PIM_SqlDatabase' -Scope Global -Value "$($heal.database)" }
                try { $c = Get-PimSqlConnectionString } catch { $c = $null }
            }
        } catch { }
    }
    return $c
}
function Get-PimUpdateNowRingApproval {
    <# The version THIS ring approves right now, read the way the normal run reads it, without downloading anything:
       @{ version; reason }. '' = nothing approved / not readable (the signal then starts nothing). #>
    param([string]$Cs)
    try {
        if ($updSource -eq 'invardia') {
            $lic = ConvertTo-PimInvardiaLicenceText -Value (Get-PimSqlSetting -ConnectionString $Cs -Name 'License')
            $k = Resolve-PimInvardiaInstallKey -GetSetting { param($n) Get-PimSqlSetting -ConnectionString $Cs -Name $n }
            $b = ''; try { $b = "$(Get-PimSqlSetting -ConnectionString $Cs -Name 'LicenceRequestBaseUrl')".Trim() } catch { }
            $ringN = -1; if (-not [int]::TryParse($ring, [ref]$ringN) -or $ringN -lt 0 -or $ringN -gt 3) { return @{ version = ''; reason = "no update ring ('$ring')" } }
            if (-not "$lic".Trim()) { return @{ version = ''; reason = 'no licence in the store' } }
            $seq = Resolve-PimInvardiaAppliedSequence -JobEnv ([Environment]::GetEnvironmentVariables()) -Ring $ring
            # INV-S16: the install's lasting id, READ from the store (the updater never creates one); none = no header
            $iid = ''; if (Get-Command Resolve-PimInvardiaInstallId -ErrorAction SilentlyContinue) { $iid = Resolve-PimInvardiaInstallId -GetSetting { param($n) Get-PimSqlSetting -ConnectionString $Cs -Name $n } }
            $p = Invoke-PimInvardiaManifestPull -Http { param($m, $u, $bd, $h) Invoke-PimLicenceHttp -Method $m -Url $u -Body $bd -Headers $h } `
                     -BaseUrl $b -InstallKey $k -LicenceText $lic -Ring $ringN -InstallId $iid
            if ($p.status -eq 204) { return @{ version = ''; reason = 'Invardia has nothing released for this ring' } }
            if ($p.status -ne 200) { return @{ version = ''; reason = "the ring's manifest could not be read ($($p.reason))" } }
            $v = Test-PimInvardiaManifest -Response $p.body -AppliedSequence ([int]$seq.applied) -RunningVersion "$($script:PimRunningVersion)" -Ring $ringN
            if (-not $v.ok) { return @{ version = ''; reason = "the ring's manifest was refused ($($v.reason))" } }
            if ($v.hold) { return @{ version = ''; reason = "the ring's manifest is held ($($v.reason))" } }
            if ([int]$seq.unprovenLegacy -gt 0 -and $v.sequence -lt [int]$seq.unprovenLegacy) { return @{ version = ''; reason = 'the replay watermark needs a decision (see the nightly run)' } }
            return @{ version = "$($v.version)"; reason = "the signed manifest for ring $ringN" }
        }
        if ($ring -and $srcUrlTpl -and $srcMode.mode -eq 'pim-src') {   # SEC-95: only the CHOSEN (unsigned) container source
            $chUrl = Get-PimUpdateChannelUrl -SourceTemplate $srcUrlTpl
            $chFile = Join-Path ([IO.Path]::GetTempPath()) ("pim-channel-un-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0, 6)))
            try {
                Invoke-WebRequest -Uri $chUrl -OutFile $chFile -UseBasicParsing -TimeoutSec 60
                $rv = Get-PimRingVersion -Channel ((Get-Content -LiteralPath $chFile -Raw) | ConvertFrom-Json) -Ring $ring -CurrentVersion $lastBuilt
                return @{ version = "$($rv.version)".Trim(); reason = "$($rv.reason)" }
            } finally { Remove-Item -LiteralPath $chFile -Force -ErrorAction SilentlyContinue }
        }
        return @{ version = ''; reason = 'this environment has no ring source to approve a version' }
    } catch { return @{ version = ''; reason = "the ring's approval could not be read ($((("$($_.Exception.Message)") -split "`n")[0]))" } }
}
# ---- OPEN-01 (framework "SUPPORT ACCESS" points 1 + 2) -- INVARDIA'S CONSENT CHANNEL, ON EVERY RUN ----------------------
# EVERY execution -- the nightly run, a hand-started one and each 15-minute "update now" check (it exits just below) -- asks
# Invardia for this install's support consent + session, decides (engine/_shared/PIM-SupportConsent.ps1, PURE) and ONLY when
# an action is due starts ONE run of the in-network support SQL job (mode consent, copied from ca-pim-dbinit), waits for it
# and reads the state back. One line; recorded in pim.Settings SupportConsentState for the heartbeat. Doubt changes nothing.
# NEVER the engine. NEVER fails the update: no key / no store / no answer = one line. The SQL that gives or takes a right is
# in the job's script (tools/setup/_PimSupportSqlJob.ps1), run by the database job's identity -- this updater sends only
# the read of the signed state procedure (Test-PimSupportConsent U-tests).
try {
    . (Join-Path $solRoot 'engine\_shared\PIM-SupportConsent.ps1')
    . (Join-Path $solRoot 'engine\_shared\PIM-LicenceRequest.ps1')   # Invoke-PimLicenceHttp (PIM-InvardiaUpdate uses it)
    . (Join-Path $solRoot 'engine\_shared\PIM-InvardiaUpdate.ps1')   # the install key + the 15 s GET seam
    $scCs = Get-PimUpdaterStoreCsHealed
    $scKey = ''; $scBase = ''; $scSql = $null; $scGet = $null; $scSet = $null
    if ("$scCs".Trim()) {
        $scKey = Resolve-PimInvardiaInstallKey -GetSetting { param($n) Get-PimSqlSetting -ConnectionString $scCs -Name $n }
        try { $scBase = "$(Get-PimSqlSetting -ConnectionString $scCs -Name 'LicenceRequestBaseUrl')".Trim() } catch { $scBase = '' }
        $scSql = { param($q) Invoke-PimSqlScalar -ConnectionString $scCs -Sql $q }
        $scGet = { Get-PimSqlSetting -ConnectionString $scCs -Name (Get-PimSupportConsentStateSetting) }
        $scSet = { param($o) Set-PimSqlSetting -ConnectionString $scCs -Name (Get-PimSupportConsentStateSetting) -ValueJson (ConvertTo-Json -InputObject $o -Depth 5 -Compress) }
    } else { $scKey = Resolve-PimInvardiaInstallKey -GetSetting $null }
    $scStart = {
        param($Decision, $Answer)
        # the job builder (tools/setup, in the image): loaded only when an action is due
        . (Join-Path $solRoot 'tools\setup\_PimScriptDoc.ps1'); . (Join-Path $solRoot 'tools\setup\_PimSupportSqlAccess.ps1'); . (Join-Path $solRoot 'tools\setup\_PimSupportSqlJob.ps1')
        $scArm = { param($m, $p, $b) if ($null -ne $b) { Invoke-PimArm -Method $m -Path $p -Body $b } else { Invoke-PimArm -Method $m -Path $p } }
        # CONSENT-AFTER-CONVERGE: the database job by the install resolver (ca-pim-dbinit, or caj-pim-dbinit at a new-name
        # install); when it does not exist YET (the converge creates it later in this run) the job starter says 'not ready'.
        $scTpl = 'ca-pim-dbinit'
        try { $scRec = $null; if ("$scCs".Trim()) { $scRec = Get-PimSqlSetting -ConnectionString $scCs -Name 'InstallNames' }; $scTpl = Get-PimDbInitJobName -ManagerApp $managerApp -Record $scRec } catch { $scTpl = 'ca-pim-dbinit' }
        # DBINIT-MEMBERSHIP (framework 4.5 point 5 (c)/(d)): the consent job runs as the database job's identity -- it is started
        # ONLY when that identity's SQL admin group membership is READ BACK now (Graph, read only; the converge of the full run
        # puts it there). Not read back = NOT started, with the reason. No database job yet = the job starter's own 'not ready'.
        $scGraph = { param($m, $p, $b) if ($null -ne $b) { Invoke-PimGraph -Method $m -Path $p -Body $b } else { Invoke-PimGraph -Method $m -Path $p } }
        # 3.0.48 (D): a REFUSED read (not 'not a member') falls back on an earlier proof -- the stored read-back (pim.Settings),
        # else the database job's last successful run (inside the gate). Known absent / never proven = not started.
        $scProof = $null
        if ("$scCs".Trim()) { try { $scProof = Get-PimDbInitStoredProof (Get-PimSqlSetting -ConnectionString $scCs -Name (Get-PimDbInitProofSetting)) } catch { $scProof = $null } }
        $scGate = Invoke-PimDbInitMembershipGate -Arm $scArm -Graph $scGraph -SubscriptionId $sub -ResourceGroup $rg -JobName $scTpl -Proof $scProof
        if (-not $scGate.absent -and -not $scGate.start) { return @{ ok = $false; skipped = $false; reason = ''; status = ''; problems = @("not started: $($scGate.reason)") } }
        # framework 4.5 G3a: within 24 h of a FRESH add (recorded by the converge) the identity's token can keep the old group
        # claims -- a refused sign-in is 'waiting for the token to refresh' (not failed), tried again at most once an hour. A
        # membership that existed before has no record and is never 'waiting'.
        $scAdded = $null; $scLastWait = $null
        if ("$scCs".Trim()) {
            try { $scA = Get-PimSqlSetting -ConnectionString $scCs -Name (Get-PimDbInitAddedSetting); if ($scA -is [string] -and "$scA".Trim().StartsWith('{')) { $scA = "$scA" | ConvertFrom-Json }; if ($scA) { $scAdded = $scA.addedUtc } } catch { $scAdded = $null }
            try { $scW = Get-PimSqlSetting -ConnectionString $scCs -Name (Get-PimDbInitTokenWaitSetting); if ($scW -is [string] -and "$scW".Trim().StartsWith('{')) { $scW = "$scW" | ConvertFrom-Json }; if ($scW) { $scLastWait = $scW.atUtc } } catch { $scLastWait = $null }
        }
        $scTw = Get-PimDbInitTokenWait -AddedUtc $scAdded -LastWaitUtc $scLastWait
        if ($scTw.hold) { return @{ ok = $true; skipped = $true; reason = $scTw.reason; status = ''; problems = @() } }
        $scJob = Invoke-PimSupportConsentJob -Decision $Decision -Answer $Answer -Arm $scArm -SubscriptionId $sub -ResourceGroup $rg -TemplateJobName $scTpl
        if ($scJob -and -not $scJob.ok -and -not $scJob.skipped) {
            $scTw2 = Get-PimDbInitTokenWait -AddedUtc $scAdded -Problems @($scJob.problems)
            if ($scTw2.wait) {
                $scTwNote = ''
                if ("$scCs".Trim()) {
                    try { Set-PimSqlSetting -ConnectionString $scCs -Name (Get-PimDbInitTokenWaitSetting) -ValueJson (ConvertTo-Json -Compress -InputObject ([ordered]@{ atUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture); addedUtc = "$scAdded" })) }
                    catch { $scTwNote = " (the wait could not be recorded: $((("$($_.Exception.Message)") -split "`n")[0]) -- the next run may start the job again)" }
                }
                return @{ ok = $true; skipped = $true; reason = "$($scTw2.reason)$scTwNote"; status = "$($scJob.status)"; problems = @() }
            }
        }
        $scJob
    }
    $scRun = Invoke-PimSupportConsentStep -BaseUrl $scBase -InstallKey $scKey -Sql $scSql -StartJob $scStart -GetLast $scGet -SetLast $scSet
    # merge review 2026-11-04 (Test-PimUpdateNow I4: the 15-minute check is ONE line): a 'nothing' decision is recorded for the
    # heartbeat and NOT printed; only an action taken or a failed one is a line.
    if (-not $scRun.ok -or "$($scRun.action)" -ne 'nothing') { Say $scRun.line $(if (-not $scRun.ok) { 'Yellow' } else { 'Cyan' }) }
} catch { Say "support consent: not checked ($($_.Exception.Message)) -- the update continues" 'Yellow' }

$script:PimUpdateNowSignal = $null
$unEnabled = Test-PimUpdateNowEnabled -Ring $ring -Value "$($env:PIM_UPDATE_NOW)"
$unNightly = "$($env:PIM_UPDATE_NIGHTLY_UTC)".Trim()
$unOwnExec = "$([Environment]::GetEnvironmentVariable('CONTAINER_APP_JOB_EXECUTION_NAME'))".Trim()
$unExecs = $null
$unKind = @{ kind = 'legacy'; reason = 'the updater runs on its nightly cron (no PIM_UPDATE_NIGHTLY_UTC) -- a full run, as before' }
if ($unNightly -and $unEnabled) {
    # ONE ARM read: the job's executions (the same path the watchdog reads) -- this execution's start time, whether the slot
    # already had its scheduled execution, and whether another execution is running.
    try { $unExecs = ConvertTo-PimUpdateNowExecutions -Items (Invoke-PimArm -Method GET -Path "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs/$selfJob/executions" -ApiVersion $script:PimAcaApi) } catch { $unExecs = $null }
    $unStart = $script:PimUpdateStartedUtc; $unTol = 180
    if ($null -ne $unExecs -and $unOwnExec) {
        $unMine = @($unExecs | Where-Object { "$($_.name)" -eq $unOwnExec }) | Select-Object -First 1
        if ($unMine -and $null -ne $unMine.startUtc) { $unStart = $unMine.startUtc; $unTol = 120 }
    }
    $unKind = Get-PimUpdaterRunKind -NightlyUtc $unNightly -StartUtc $unStart -Executions $unExecs -OwnExecution $unOwnExec -ToleranceSeconds $unTol -Enabled $unEnabled
}
if ($unKind.kind -eq 'quick') {
    $unCs = Get-PimUpdaterStoreCsHealed
    . (Join-Path $solRoot 'engine\_shared\PIM-LicenceRequest.ps1')   # Invoke-PimLicenceHttp (the manifest read of the approval)
    . (Join-Path $solRoot 'engine\_shared\PIM-InvardiaUpdate.ps1')   # the install key + the signal call
    $unKey = ''; $unStrict = $false; $unStrictUntil = ''
    if ("$unCs".Trim()) {
        $unKey = Resolve-PimInvardiaInstallKey -GetSetting { param($n) Get-PimSqlSetting -ConnectionString $unCs -Name $n }
        try { $unSt = ConvertFrom-PimGuardStrictText -Text (Get-PimSqlSettingRaw -ConnectionString $unCs -Name (Get-PimGuardStrictSettingName)); $unStrict = [bool](Test-PimGuardStrictActive -State $unSt); if ($unSt.untilUtc) { $unStrictUntil = $unSt.untilUtc.ToString('u') } } catch { $unStrict = $false }
    } else { $unKey = Resolve-PimInvardiaInstallKey -GetSetting $null }
    $unBase = ''; if ("$unCs".Trim()) { try { $unBase = "$(Get-PimSqlSetting -ConnectionString $unCs -Name 'LicenceRequestBaseUrl')".Trim() } catch { } }
    $unRingN = -1; [void][int]::TryParse($ring, [ref]$unRingN)
    # UPDATE-NOW-HEAD: the quick check is POST /head with the licence text exactly as the manifest pull sends it, and the
    # install's lasting id (READ only, never created here). Neither is ever written to a line.
    $unLic = ''; $unIid = ''
    if ("$unCs".Trim()) {
        try { $unLic = ConvertTo-PimInvardiaLicenceText -Value (Get-PimSqlSetting -ConnectionString $unCs -Name 'License') } catch { $unLic = '' }
        if (Get-Command Resolve-PimInvardiaInstallId -ErrorAction SilentlyContinue) { try { $unIid = Resolve-PimInvardiaInstallId -GetSetting { param($n) Get-PimSqlSetting -ConnectionString $unCs -Name $n } } catch { $unIid = '' } }
    }
    # 🔒 No store = no state = "at most once per raisedAt" cannot be promised: the signal is not acted on (said in the line).
    $unGet = $(if ("$unCs".Trim()) { { Get-PimSqlSetting -ConnectionString $unCs -Name (Get-PimUpdateNowStateName) } } else { $null })
    $unSet = $(if ("$unCs".Trim()) { { param($o) Set-PimSqlSetting -ConnectionString $unCs -Name (Get-PimUpdateNowStateName) -ValueJson (ConvertTo-Json -InputObject $o -Depth 5 -Compress) } } else { $null })
    $unQ = Invoke-PimUpdateNowQuickCheck -Enabled $unEnabled -InstallKey $unKey -Ring $ring -RunningVersion "$($script:PimRunningVersion)" `
               -Hold ("$($env:PIM_UPDATE_HOLD)".Trim() -eq '1') -StrictActive $unStrict -StrictUntil $unStrictUntil `
               -Head { if ($unRingN -lt 0 -or $unRingN -gt 3) { @{ status = 0 } } else { Invoke-PimInvardiaUpdateHead -BaseUrl $unBase -InstallKey $unKey -LicenceText $unLic -Ring $unRingN -InstallId $unIid } } `
               -Signal { param($et) if ($unRingN -lt 0 -or $unRingN -gt 3) { @{ status = 0 } } else { Invoke-PimInvardiaUpdateSignal -BaseUrl $unBase -InstallKey $unKey -Ring $unRingN -ETag $et } } `
               -UpdateWindow "$($env:PIM_UPDATE_WINDOW)" -NightlyUtc $unNightly `
               -GetState $unGet -SetState $unSet `
               -IsRunning { Get-PimUpdateNowOtherRunning -Executions $unExecs -OwnExecution $unOwnExec }
    if (-not $unQ.run) { Say $unQ.line 'DarkGray'; exit 0 }
    if (-not $unSet) { Say 'update now: a signal, but there is no store to record it in (at most one update per signal) -- not started' 'Yellow'; exit 0 }
    $unAp = Get-PimUpdateNowRingApproval -Cs $unCs
    $unAd = Get-PimUpdateNowApprovalDecision -SignalVersion "$($unQ.signal.version)" -ApprovedVersion "$($unAp.version)" -RunningVersion "$($script:PimRunningVersion)" -Ring $ring
    if (-not $unAd.ok) { Say "$($unAd.line) ($($unAp.reason))" 'DarkGray'; exit 0 }
    # Mark FIRST, update second: at most ONE update per raisedAt, whatever happens next (a failed one is the nightly's to retry).
    if (-not (Set-PimUpdateNowHandled -GetState $unGet -SetState $unSet -Signal $unQ.signal)) { Say 'update now: the start could not be recorded -- not started (the nightly run takes it)' 'Yellow'; exit 0 }
    Say $unQ.line 'Cyan'
    Say $unAd.line 'Cyan'
    $script:PimUpdateNowSignal = $unQ.signal
} else {
    Say "execution: $($unKind.kind) -- $($unKind.reason)" 'DarkGray'
    if ($unKind.kind -eq 'nightly' -and (Get-PimUpdateNowOtherRunning -Executions $unExecs -OwnExecution $unOwnExec) -eq $true) {
        # Never two updater executions at once: the one running is an update-now update (or a hand-started one) -- it IS
        # tonight's update. Unreadable executions do not stop the nightly run (as before).
        Say 'nightly: another execution of the updater is running -- it is tonight''s update; this one stops.' 'Yellow'
        exit 0
    }
    # The updater's OWN cron follows the switch: an existing install gets its 15-minute cron here, on its next full run.
    try {
        $unArm = { param($m, $p, $b) if ($null -ne $b) { Invoke-PimArm -Method $m -Path $p -Body $b } else { Invoke-PimArm -Method $m -Path $p } }
        $unCron = Invoke-PimUpdateNowSelfCronUpdate -SubscriptionId $sub -ResourceGroup $rg -JobName $selfJob -Arm $unArm -Enabled $unEnabled -ApiVersion $script:PimAcaApi
        Say $unCron.detail $(if (-not $unCron.ok) { 'Yellow' } elseif ($unCron.changed) { 'Cyan' } else { 'DarkGray' })
    } catch { Say "update now: the updater's cron was not checked: $($_.Exception.Message)" 'Yellow' }
}

# ---- BUILDPOOL-11G (framework rule 11g) -- A PRIVATE INSTALL'S BUILD POOL: S2, 0 instances between builds ----------------
# Only an install whose job carries PIM_ACR_AGENT_POOL (a private registry) has a pool: every other install makes no call
# here and its heartbeat carries no BuildPool. An older S1 pool is made again at S2 only while no run is queued or running;
# a pool left running with no build on is set back to 0. The state goes into UpdateState for the heartbeat (BuildPool).
# Never fails or stops the update.
# BUILDPOOL-11G-RECREATE: a pool the converge DELETES is never left un-made -- the recreate record goes to pim.Settings
# 'BuildPoolRecreate' BEFORE the delete, and a run that finds the pool missing makes it from that record. No store = no
# record (the converge then behaves as before).
$script:PimBuildPoolState = $null
$script:PimBuildPoolNone = -not "$($env:PIM_ACR_AGENT_POOL)".Trim()
$bpSeam = @{}
if (-not $script:PimBuildPoolNone) {
    $bpCs = $null; try { $bpCs = Get-PimUpdaterStoreCsHealed } catch { $bpCs = $null }
    if ("$bpCs".Trim() -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) {
        $bpSeam = @{
            SaveIntent  = { param($o) Set-PimSqlSetting -ConnectionString $bpCs -Name 'BuildPoolRecreate' -ValueJson (ConvertTo-Json -InputObject $o -Depth 8 -Compress) }
            ReadIntent  = { Get-PimSqlSetting -ConnectionString $bpCs -Name 'BuildPoolRecreate' }
            ClearIntent = { Set-PimSqlSetting -ConnectionString $bpCs -Name 'BuildPoolRecreate' -ValueJson '' }
        }
    }
}
if (-not $script:PimBuildPoolNone) {
    try {
        $bpName = "$($env:PIM_ACR_AGENT_POOL)".Trim()
        $bpReg = $(if ($loginServer) { Split-PimImageReference -Image "$loginServer/x:y" } else { $null })
        if (-not $bpReg -or -not "$($bpReg.registryName)".Trim()) { Say "build pool '$bpName': not checked (this environment's registry is not known)" 'Yellow' }
        else {
            $bpCv = Invoke-PimAcrBuildPoolConverge -SubscriptionId $sub -ResourceGroup $rg -RegistryName "$($bpReg.registryName)" -PoolName $bpName @bpSeam
            $script:PimBuildPoolState = $bpCv.state
            Say $bpCv.line $(if (-not $bpCv.ok) { 'Yellow' } elseif ($bpCv.action -in 'recreated', 'scaled-down') { 'Cyan' } else { 'DarkGray' })
        }
    } catch { Say "build pool: not checked ($($_.Exception.Message)) -- the update continues" 'Yellow' }
}

# ---- OPEN-13 / framework 8.8 UPDATE-TRACK -- THIS RUN'S STAGES TO INVARDIA, LIKE A TRACKED INSTALL -------------------------
# A Pro install (it holds an install key) opens an update run at Invardia (POST /api/install/runs, the install key -- the same
# key as the uplink and the update pull) and reports check -> download -> verify -> build -> migrate -> apply -> health ->
# done | failed | rollback. 'check' starts HERE; the run is opened ONLY when the plan moves a version (Test-PimUpdateTrackDue); a run with nothing to do / ahead / held reports NOTHING. BEST
# EFFORT: a failed report stops the tracking with one line and never touches the update. PIM_UPDATE_TRACK=0 = off.
try {
    $utCs = $null; try { $utCs = Get-PimUpdaterStoreCsHealed } catch { $utCs = $null }
    $utGet = $null; if ("$utCs".Trim()) { $utGet = { param($n) Get-PimSqlSetting -ConnectionString $utCs -Name $n } }
    if (-not (Get-Command Resolve-PimInvardiaInstallKey -ErrorAction SilentlyContinue)) {
        . (Join-Path $solRoot 'engine\_shared\PIM-LicenceRequest.ps1')
        . (Join-Path $solRoot 'engine\_shared\PIM-InvardiaUpdate.ps1')
    }
    $utKey = Resolve-PimInvardiaInstallKey -GetSetting $utGet
    $utBase = ''; if ($utGet) { try { $utBase = "$(& $utGet 'LicenceRequestBaseUrl')".Trim() } catch { $utBase = '' } }
    $script:PimUpdTrack = New-PimUpdateTrack -Enabled (Test-PimUpdateTrackOn -Value "$($env:PIM_UPDATE_TRACK)") -InstallKey $utKey -BaseUrl $utBase -Ring $ring -Log { param($l) Say $l 'DarkGray' }
    if ($script:PimUpdTrack.enabled) { Set-PimUpdTrackStage -Stage 'check' }
    else { Say "update track: not reported -- $($script:PimUpdTrack.why)" 'DarkGray'; $script:PimUpdTrack = $null }
} catch { $script:PimUpdTrack = $null; Say "update track: not started ($((("$($_.Exception.Message)") -split "`n")[0])) -- the update continues" 'DarkGray' }

if ("$($env:PIM_UPDATE_HOLD)".Trim() -eq '1') {
    Say "PIM_UPDATE_HOLD=1 -- this environment is frozen; the ring channel is not consulted." 'Yellow'
    # §71.43 -- a held environment has NO approved version to show, and saying so is the point: the
    # Manager must not display the last version some earlier run happened to read as if it still applied.
    $script:PimRingApprovedReason = 'this environment is HELD (PIM_UPDATE_HOLD=1) -- the ring channel was not consulted'
    # 2026-10-09: a ring-managed environment never moves on PIM_UPDATE_TARGET_VERSION. The install writes that pin
    # (Invoke-PimDeployAll / Confirm-PimInstall -> Deploy-PimUpdateJob -TargetVersion = the installed tag) and every ring
    # branch below replaces it -- but a HELD ring environment used to fall through to that stale install pin and try to
    # roll to it (measured: two ring-2 environments still carry 2.4.531 from their install while running 2.4.537).
    if ($ring -or $updSource -in @('invardia', 'invardia-community')) {
        if ($targetVer) { Say "  PIM_UPDATE_TARGET_VERSION=$targetVer is ignored: a ring-managed environment moves only on its ring, and a held one not at all." 'DarkGray' }
        $targetVer = ''
    }
} elseif ($srcMode.refused) {
    # SEC-95: nothing is fetched and nothing moves. NEEDS ATTENTION, not a failure: PIM keeps running, the reason names the
    # one setting to change, and a Failed execution would only feed the watchdog (which cannot fix a source setting).
    Say "  REFUSED: $($srcMode.reason)" 'Yellow'
    $script:PimRingApproved = ''; $script:PimRingApprovedReason = "update source refused: $($srcMode.reason)"
    Send-PimUpdateOutcome -Action 'none' -Outcome 'attention' -ErrorText "update source refused: $($srcMode.reason)"
    exit 0
} elseif ($updSource -in @('invardia', 'invardia-community')) {
    # COMMUNITY-INCLOUD-UPDATER (owner 2026-10-28): 'invardia-community' = the SAME path, the anonymous Community channel
    # (no licence, no install key), kind community, its own replay watermark. Everything after the pull is shared.
    $invCommunity = ($updSource -eq 'invardia-community')
    . (Join-Path $solRoot 'engine\_shared\PIM-LicenceRequest.ps1')   # Invoke-PimLicenceHttp (5.1 + 7, a non-2xx is a status)
    . (Join-Path $solRoot 'engine\_shared\PIM-InvardiaUpdate.ps1')
    $csInv = $null; try { $csInv = Get-PimSqlConnectionString } catch { $csInv = $null }
    if (-not "$csInv".Trim()) {
        try {
            $heal = Resolve-PimUpdaterStoreSettings -JobServer "$($global:PIM_SqlServer)" -JobDatabase "$($global:PIM_SqlDatabase)" `
                        -ManagerStore (Get-PimAcaStoreSettings -Resource $app) -ManagerApp $managerApp
            if ($heal.source -eq 'manager' -and "$($heal.server)".Trim()) {
                Set-Variable -Name 'PIM_SqlServer' -Scope Global -Value "$($heal.server)"
                if ("$($heal.database)".Trim()) { Set-Variable -Name 'PIM_SqlDatabase' -Scope Global -Value "$($heal.database)" }
                try { $csInv = Get-PimSqlConnectionString } catch { $csInv = $null }
            }
        } catch { }
    }
    if (-not "$csInv".Trim()) {
        Say 'Invardia updates: no store -- the licence and the install key live in it. Nothing rolled.' 'Red'
        $script:PimRingApprovedReason = 'Invardia updates: the store could not be reached (licence + install key)'
        Send-PimUpdateOutcome -Action 'none' -Outcome 'failed' -ErrorText 'Invardia updates: no store for the licence and install key'
        exit 1
    }
    # 2026-10-16 (internal, 2.4.639 roll): one licence READ failed and was reported as "no licence is installed" -- the
    # catch hid the real error, and the next run read it fine. A failed read is retried once and, if it still fails, SAID
    # (the Pro pull then stops as before, but the log names the store error, never a missing licence).
    $licText = ''; $invKey = ''; $invId = ''
    if (-not $invCommunity) {   # the Community channel is anonymous: no licence, no install key
        $licRaw = $null; $licErr = ''
        foreach ($try in 1, 2) {
            try { $licRaw = Get-PimSqlSetting -ConnectionString $csInv -Name 'License'; $licErr = ''; break }
            catch { $licErr = (("$($_.Exception.Message)") -split "`n")[0]; if ($try -eq 1) { Start-Sleep -Seconds 5 } }
        }
        if ($licErr) { Say "Invardia: the licence could NOT be read from the store ($licErr) -- this is a store error, not a missing licence; the next run retries" 'Yellow' }
        $licText = ConvertTo-PimInvardiaLicenceText -Value $licRaw
        $invKey = Resolve-PimInvardiaInstallKey -GetSetting { param($n) Get-PimSqlSetting -ConnectionString $csInv -Name $n }
        # INV-S16: the install's lasting id, READ from the store (the updater never creates one); none = no header
        if (Get-Command Resolve-PimInvardiaInstallId -ErrorAction SilentlyContinue) { $invId = Resolve-PimInvardiaInstallId -GetSetting { param($n) Get-PimSqlSetting -ConnectionString $csInv -Name $n } }
    }
    $invBase = ''; try { $invBase = "$(Get-PimSqlSetting -ConnectionString $csInv -Name 'LicenceRequestBaseUrl')".Trim() } catch { }
    # 2026-10-09 -- the replay watermark is PER RING (PIM_UPDATE_INVARDIA_SEQ_R<ring>): Invardia numbers sequences per ring,
    # so one value for the environment refused the home ring's lower sequence forever after a ring move. The legacy single
    # value is honoured only with evidence of its ring (Resolve-PimInvardiaAppliedSequence has the migration rules).
    $seqRes = Resolve-PimInvardiaAppliedSequence -JobEnv ([Environment]::GetEnvironmentVariables()) -Ring $ring -Kind $(if ($invCommunity) { 'community' } else { 'code' })
    $script:PimInvardiaApplied = [int]$seqRes.applied
    Say "Invardia replay watermark: $($seqRes.reason)" 'DarkGray'
    # The highest version this environment is known to have reached: a manifest below it is AHEAD (nothing fetched).
    $highestKnown = ''
    $hk = @(@("$($script:PimRunningVersion)", $lastBuilt, "$($env:PIM_UPDATE_LAST_GOOD)") | ForEach-Object { ConvertTo-PimUpdateVersion -Value $_ } | Where-Object { $_ } | Sort-Object -Descending)
    if ($hk.Count) { $highestKnown = "$($hk[0])" }
    # CR7: an OPTED-IN install whose sign-in front image is not built yet asks for the verified archive even when the Manager
    # is already built ($sfNeed) -- the front is built from it; the Manager plan below still compares PIM_UPDATE_LAST_BUILT
    # and does not rebuild. Every other install passes $lastBuilt exactly as before.
    $allowMajor = ("$($env:PIM_UPDATE_ALLOW_MAJOR)".Trim() -eq '1')   # PUB-8: the owner's planned major, for one run
    if ($invCommunity) {
        $t = Get-PimInvardiaCommunityTarget -BaseUrl $invBase -AppliedSequence $script:PimInvardiaApplied `
                -RunningVersion "$($script:PimRunningVersion)" -LastBuiltVersion $(if ($sfNeed) { '' } else { $lastBuilt }) -Ring $ring `
                -HighestKnownVersion $highestKnown -AllowDowngrade:("$($env:PIM_UPDATE_ALLOW_DOWNGRADE)".Trim() -eq '1') -AllowMajor:$allowMajor
    } else {
    $t = Get-PimInvardiaUpdateTarget -Http { param($m, $u, $b, $h) Invoke-PimLicenceHttp -Method $m -Url $u -Body $b -Headers $h } `
            -InstallKey $invKey -InstallId $invId -LicenceText $licText -BaseUrl $invBase -AppliedSequence $script:PimInvardiaApplied `
            -RunningVersion "$($script:PimRunningVersion)" -LastBuiltVersion $(if ($sfNeed) { '' } else { $lastBuilt }) -Ring $ring `
            -UnprovenLegacySequence ([int]$seqRes.unprovenLegacy) -HighestKnownVersion $highestKnown `
            -AllowDowngrade:("$($env:PIM_UPDATE_ALLOW_DOWNGRADE)".Trim() -eq '1') -AllowMajor:$allowMajor   # UPDATE-1.7: this environment's own ring
    }
    Say "Invardia: $($t.reason)" $(if ($t.ok) { 'DarkGray' } elseif ($t.attention -or $t.noKey) { 'Yellow' } else { 'Red' })
    $script:PimRingApproved = "$($t.version)"; $script:PimRingApprovedReason = "Invardia: $($t.reason)"
    $script:PimInvardiaAhead = [bool]$t.ahead
    if ($t.noKey) {
        # 🔒 100.69 -- NO INSTALL KEY YET IS WAITING, NOT FAILED (a trial environment, 2026-10-11: a run ~5 min after install, before
        # the tick's install-key job claimed the key, exited 1 -> execution Failed + failure telemetry, and nothing was wrong).
        # Exit 0, no failure telemetry ('skipped'); the next scheduled run proceeds. A day after install with still no key,
        # or a claim Invardia refused, IS a problem: 'attention' (a warning naming Settings > Licence) -- still exit 0, still
        # never a failed record at Invardia (it is not a product failure, and a Failed execution would feed the watchdog).
        $prevState = $null; try { $prevState = Read-PimUpdateState -ConnectionString $csInv } catch { $prevState = $null }
        $claimState = $null; try { $claimState = Get-PimSqlSetting -ConnectionString $csInv -Name 'InstallKeyClaimState' } catch { $claimState = $null }
        $installedUtc = ''; try { if ($app -and $app.systemData) { $installedUtc = "$($app.systemData.createdAt)" } } catch { $installedUtc = '' }
        $nk = Get-PimInvardiaNoKeyOutcome -InstalledUtc $installedUtc -PreviousState $prevState -ClaimState $claimState
        Say "Invardia: $($nk.reason)" $(if ($nk.outcome -eq 'waiting') { 'DarkGray' } else { 'Yellow' })
        $script:PimRingApprovedReason = "Invardia: $($nk.reason)"
        Send-PimUpdateOutcome -Action 'none' -Outcome $nk.outcome -ErrorText "Invardia: $($nk.reason)" -TelemetryOutcome 'skipped' -WaitingSinceUtc "$($nk.waitingSinceUtc)"
        exit 0
    }
    if ($t.attention) {
        # 🔒 NEEDS ATTENTION, not a failure: nothing moved, PIM keeps running, and the reason names the one setting to
        # change. Exit 0 -- an operator decision is not a broken updater (a Failed execution would also count toward the
        # watchdog's "restore the last-known-good updater image", which cannot fix a watermark).
        Send-PimUpdateOutcome -Action 'none' -Outcome 'attention' -ErrorText "Invardia: $($t.reason)"
        exit 0
    }
    if (-not $t.ok) {
        # 🔒 Refused or failed = NOTHING moves, and the run is FAILED so the fleet view shows it (never a quiet night).
        Send-PimUpdateOutcome -Action 'none' -Outcome 'failed' -ErrorText "Invardia: $($t.reason)"
        exit 1
    }
    # PIM 100.158 / framework 12.11e CR3: record the wave this environment was SERVED (from the signed manifest) -- or that it
    # was served outside any wave -- so the heartbeat can say it (pim.Settings 'ReleaseWave'). Only after a VERIFIED answer;
    # a write that fails is a plain note, never a failed update.
    if ($t.served) {
        try {
            . (Join-Path $solRoot 'engine\_shared\PIM-ReleaseControl.ps1')
            $waveRec = ConvertTo-PimReleaseWaveRecord -Wave "$($t.wave)" -Version "$($t.manifestVersion)" -Ring $ring -NowUtc ([datetime]::UtcNow)
            Set-PimSqlSetting -ConnectionString $csInv -Name 'ReleaseWave' -ValueJson ($waveRec | ConvertTo-Json -Depth 4 -Compress)
            if ($waveRec.wave) { Say "Invardia: served as wave '$($waveRec.wave.name)' ($($waveRec.wave.version), ring $($waveRec.wave.ring))" 'Cyan' }
        } catch { Say "  release wave not recorded: $($_.Exception.Message)" 'Yellow' }
    }
    $targetVer = "$($t.version)"
    $script:PimInvardiaContext = "$($t.contextPath)"; $script:PimInvardiaSequence = [int]$t.sequence
    # The plan builds only when it has a source; the Invardia archive IS the source (already verified + re-packed above).
    if ($targetVer) { $srcUrlTpl = 'invardia://pim-manager-src-{version}' }
} elseif ($ring -and -not $srcUrlTpl) {
    # 🔴 2026-09-13 -- A RING WITH NO SOURCE USED TO BE SKIPPED IN SILENCE, AND THE PIN WON. The ring
    # branch below needs the source template to find channel.json, so `$ring -and $srcUrlTpl` was false
    # and the run carried on to the pin as if no ring existed: an environment the operator had put on
    # ring 2 would take whatever its pin said, with nothing in the log to say the ring was ignored.
    # 🔒 A ring-managed environment moves ONLY when its ring says so. No readable ring => no move, and a
    # FAILED outcome, so the fleet view shows it rather than a quiet night.
    Say "PIM_UPDATE_RING=$ring is set but PIM_UPDATE_SOURCE_URL is NOT -- the ring channel (channel.json) cannot be read." 'Red'
    Say '  REFUSING to roll: a ring-managed environment moves only when its ring approves a version, never on its pin.' 'Red'
    Say '  Fix: re-run tools/setup/Deploy-PimUpdateJob.ps1 (it writes the source with the ring), or set PIM_UPDATE_SOURCE_URL.' 'Red'
    $script:PimRingApprovedReason = 'this environment has a ring but no update source, so the ring channel cannot be read'
    Send-PimUpdateOutcome -Action 'none' -Outcome 'failed' -ErrorText "PIM_UPDATE_RING=$ring without PIM_UPDATE_SOURCE_URL -- ring not readable, nothing rolled"
    exit 1
} elseif ($ring -and $srcUrlTpl -and $srcMode.mode -eq 'pim-src') {
    # SEC-95: reached ONLY when the job names the storage container as its source (said in red above, recorded below)
    $chUrl = Get-PimUpdateChannelUrl -SourceTemplate $srcUrlTpl
    $chFile = Join-Path ([IO.Path]::GetTempPath()) ("pim-channel-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0,6)))
    try {
        Invoke-WebRequest -Uri $chUrl -OutFile $chFile -UseBasicParsing -TimeoutSec 120
        $channel = (Get-Content -LiteralPath $chFile -Raw) | ConvertFrom-Json
        $rv = Get-PimRingVersion -Channel $channel -Ring $ring -CurrentVersion $lastBuilt
        Say "ring $ring -- $($rv.reason)" 'DarkGray'
        # §71.43 -- the ring's ANSWER, in the ring's own words, recorded for the Manager. This is the
        # only moment it exists: the channel is fetched to a temp file and deleted below.
        $script:PimRingApproved       = "$($rv.version)".Trim()
        $script:PimRingApprovedReason = "$($rv.reason)".Trim()
        # 🪤 An unreadable or empty channel must NOT silently fall back to a local pin: that would
        # let an environment keep taking a version the ring has since withdrawn. No answer means
        # no move.
        if ("$($rv.version)".Trim()) { $targetVer = "$($rv.version)".Trim() }
        else { $targetVer = '' }
    } catch {
        Say "  could not read the ring channel: $($_.Exception.Message)" 'Yellow'
        Say '  refusing to fall back to a local pin -- a ring-managed environment moves only when the ring says so.' 'Yellow'
        $targetVer = ''
        # §71.43 -- an unreadable channel is a REPORTABLE state, not a blank. Recorded with no approved
        # version (so the Manager never claims one) and the reason, redacted: the channel URL carries a SAS.
        $script:PimRingApproved       = ''
        $script:PimRingApprovedReason = 'the ring channel could not be read: ' +
            $(if (Get-Command Remove-PimTelemetrySecret -ErrorAction SilentlyContinue) { Remove-PimTelemetrySecret -Text "$($_.Exception.Message)" } else { 'see the update job log' })
    } finally { Remove-Item -LiteralPath $chFile -Force -ErrorAction SilentlyContinue }
}

$plan = Get-PimUpdateSourcePlan -TargetVersion $targetVer -SourceUrlTemplate $srcUrlTpl `
                                -LastBuiltVersion $lastBuilt -LoginServer $loginServer -Repository $imageRepo

if ($plan.action -eq 'none') {
    Say "plan: $($plan.action) -- $($plan.reason)" 'DarkGray'
    # 🪤 NOT AN ERROR, AND NOT SILENCE EITHER. An environment whose ring has approved nothing new
    # is the NORMAL nightly outcome. Saying so is what makes a quiet log trustworthy.
    Say 'no approved target for this ring. Nothing to do.' 'DarkGray'
    # 🔑 A NO-OP IS A REPORT, NOT A NON-EVENT. "Nothing approved" and "this environment stopped
    # reporting" look identical from the fleet view unless the quiet nights are recorded too --
    # and telling them apart is most of "is THIS customer stuck".
    Send-PimUpdateOutcome -Action 'none' -Outcome 'ok'
    exit 0
}

# ---- 0a. BUG-162 -- NEVER ROLL BACKWARD UNATTENDED -----------------------------------------------
# Checked BEFORE the build: building an older version is the same wasted 20 minutes as rolling to it,
# and the refusal must name the two versions while nothing has changed yet. The ring still decides
# WHETHER this environment moves (Sec.60, untouched above); this decides only that it never moves
# DOWN on its own. PIM_UPDATE_ALLOW_DOWNGRADE=1 is the operator's way back, and it is stated loudly.
$runningVer = if ($ref) { "$($ref.tag)" } else { '' }
$dg = Get-PimUpdateDowngradeDecision -TargetVersion "$($plan.version)" -RunningVersion $runningVer `
          -LastBuiltVersion $lastBuilt -LastGoodImage "$($env:PIM_UPDATE_LAST_GOOD)" -Ring $ring `
          -AllowDowngrade:(("$($env:PIM_UPDATE_ALLOW_DOWNGRADE)".Trim() -eq '1') -or ($script:PimInvardiaSequence -gt $script:PimInvardiaApplied -and $script:PimInvardiaApplied -gt 0)) -UpdateJobName $selfJob
# §95.4: Invardia's rollback is a NEW, HIGHER, SIGNED sequence naming an older version -- the owner's deliberate decision,
# so it may go down. Never on a first pull (nothing applied yet = no proof of what this environment had) and never on a
# replay (a lower sequence is refused before this point).
if ($dg.note) { Say "  $($dg.note)" 'DarkGray' }
# ---- 2026-10-09 -- AHEAD OF THE RING IS HEALTHY, NOT A FAILURE ------------------------------------------------------
# MEASURED (2026-10-09 03:00 UTC, two ring-2 environments the operator had rolled ahead through ring 1):
#     [update] REFUSING TO ROLL BACKWARD: ring 2 approves 2.4.535, but this environment is on 2.4.537
# -> outcome 'failed', exit 1, and the Manager's update badge turned red at customers. The environment was AHEAD on
# purpose. Owner's rule: green when running the latest approved version or newer; red only for a real failure.
# 🔒 BUG-162 is kept exactly: it never rolls backward unattended. The run records 'ahead', changes NOTHING -- no
# fetch, no build (this check sits BEFORE the build step and before the plan is announced), no roll -- and exits 0.
# An UNREADABLE target ('unknown' direction) is still refused and still a failure: that is not "ahead", it is unprovable.
$isAhead = [bool]$script:PimInvardiaAhead -or (-not $dg.allowed -and "$($dg.direction)" -eq 'backward')
if ($isAhead) {
    $aheadFrom = if ("$($dg.from)".Trim()) { "$($dg.from)".Trim() } else { $runningVer }
    $ringWord = if ($ring) { "ring $ring" } else { 'this environment''s pin' }
    Say "ahead of ring: $ringWord approves $($plan.version); this environment runs $aheadFrom (newer). Nothing to do." 'Green'
    Say '  It is NOT rolled back (an unattended update never goes backward -- BUG-162), and nothing is fetched or built.' 'DarkGray'
    Say "  It takes the ring's next release once that is newer than $aheadFrom." 'DarkGray'
    # 100.40: no version moves, but the install defaults still converge (sizing, database, 2d) -- an environment kept ahead
    # of its ring used to exit before any of that ran, so it never got them.
    Invoke-PimUpdaterConvergeStep -When 'ahead of the ring'
    # CR7: an opted-in install that is ahead still gets its front image -- from the source of the version it RUNS (an
    # Invardia source serves only the ring's version: then the next release builds it). Never changes this exit.
    if ($sfOpt.optIn) { [void](Invoke-PimUpdaterSigninFrontStep -Version $aheadFrom) }
    Send-PimUpdateOutcome -Action 'none' -Outcome 'ahead'
    exit 0
}
if (-not $dg.allowed) {
    Say $dg.message 'Red'
    Say "  $($dg.detail)" 'Red'
    Send-PimUpdateOutcome -Action 'none' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText $dg.errorText
    exit 1
}
if ($dg.overridden) {
    Say $dg.message 'Yellow'
    Say "  $($dg.detail)" 'Yellow'
}
Say "plan: $($plan.action) -- $($plan.reason)" 'DarkGray'
# OPEN-13: the target is known. The run is opened at Invardia ONLY when this run moves a version (build / roll to a target
# that is not the running one); nothing to do / ahead / held / the same version reports NOTHING (Complete never opens).
if ($script:PimUpdTrack) { try { if (Test-PimUpdateTrackDue -PlanAction "$($plan.action)" -TargetVersion "$($plan.version)" -RunningVersion (Get-PimUpdTrackFromVersion)) { [void](Open-PimUpdateTrack -Track $script:PimUpdTrack -FromVersion (Get-PimUpdTrackFromVersion) -ToVersion "$($plan.version)") } } catch { } }

if ($plan.action -eq 'build') {
    $ctx    = Join-Path ([IO.Path]::GetTempPath()) ("pim-src-{0}.tar.gz" -f $plan.version)
    if ($script:PimInvardiaContext) {
        # §95.4: already downloaded, SHA-256-checked against the signed manifest and re-packed as the build context.
        $ctx = $script:PimInvardiaContext
        $got = @{ ok = (Test-Path -LiteralPath $ctx); bytes = $(if (Test-Path -LiteralPath $ctx) { (Get-Item -LiteralPath $ctx).Length } else { 0 }); reason = 'the verified Invardia archive is gone' }
        Say "source for $($plan.version): the verified Invardia release archive"
        # OPEN-13: the Invardia pull fetched the archive and checked it against the signed manifest during 'check'.
        Set-PimUpdTrackStage -Stage 'download' -Message 'the release archive named by the signed manifest'
        Set-PimUpdTrackStage -Stage 'verify' -Message 'manifest signature + archive SHA-256'
    } else {
        $srcUrl = Resolve-PimUpdateSourceUrl -Template $srcUrlTpl -Version $plan.version
        Say "fetching source for $($plan.version)$(if ($srcMode.unsigned) { ' from the storage container -- UNSIGNED (only its gzip header is checked)' })" $(if ($srcMode.unsigned) { 'Red' } else { 'Gray' })
        Set-PimUpdTrackStage -Stage 'download'
        $got = Get-PimUpdateSourceArchive -Url $srcUrl -OutFile $ctx
        if ($got.ok) {
            Set-PimUpdTrackStage -Stage 'verify'
            if ($srcMode.unsigned) { Set-PimUpdTrackStage -Close warning -Message 'unsigned source: only its gzip header is checked' }
        }
    }
    if (-not $got.ok) {
        Say "  source NOT fetched: $($got.reason)" 'Red'
        Say '  refusing to roll: an environment that cannot get its approved version must say so, not quietly stay behind.' 'Red'
        Send-PimUpdateOutcome -Action 'failed' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText "source not fetched: $($got.reason)"
        exit 1
    }
    Say ("  fetched {0:N0} bytes" -f $got.bytes) 'DarkGray'
    try {
        $reg = Split-PimImageReference -Image $plan.image
        # 🔴 REFUSE EARLY, NAMING THE CAUSE. Without this the run died several lines later on
        # "Cannot bind argument to parameter 'RegistryName' because it is an empty string" -- a
        # message about the symptom that says nothing about the Manager image it failed to read.
        if (-not $reg -or -not "$($reg.registryName)".Trim()) {
            Say "  cannot tell which registry to build in (resolved image '$($plan.image)')." 'Red'
            Say "  This environment's registry is read from $managerApp's current image; that read failed above." 'Red'
            Send-PimUpdateOutcome -Action 'failed' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText 'cannot resolve which registry to build in'
            exit 1
        }
        # 🔴 PIM_ACR_AGENT_POOL (set on this job by Deploy-PimUpdateJob -AcrAgentPoolName) was read ONLY by the
        # host-side Invoke-PimUpdate. The in-cloud build ignored it, so a registry with public access Disabled
        # refused every nightly build ("client with IP ... is not allowed access") -- measured 2026-09-23.
        $pool = "$($env:PIM_ACR_AGENT_POOL)".Trim()
        Set-PimUpdTrackStage -Stage 'build'
        Say ("building $imageRepo`:$($plan.version) in $($reg.registryName) (the registry builds; this job only asks)" + $(if ($pool) { " on agent pool '$pool'" } else { '' }))
        # UPDATER-ACR-PUSH-RETRY (owner 2026-10-23): a push that failed on the network / a registry 5xx is retried once.
        $b = Invoke-PimAcrRestBuildWithRetry -SubscriptionId $sub -ResourceGroup $rg -RegistryName $reg.registryName `
                -ContextPath $ctx -ImageNames @("$imageRepo`:$($plan.version)") -AgentPoolName $pool `
                -OnPoll { param($s) Say "  build $s" 'DarkGray' } `
                -OnRetry { param($r, $why) Say "  build $($r.status) after $($r.seconds)s (run $($r.runId)): the push to the registry failed ($why) -- a registry-side fault; building once more in 60 s" 'Yellow' }
        if (-not $b.ok) {
            Say "  BUILD $($b.status) after $($b.seconds)s (run $($b.runId))" 'Red'
            if ("$($b.detail)".Trim()) { Say "  $("$($b.detail)".Trim())" 'Red' }
            Say '  not rolling -- there is no new image to roll to.' 'Red'
            # 🔑 action='built' even though it FAILED: the fleet view needs to know WHICH PHASE broke.
            # "the build failed" and "the roll failed" point at completely different causes.
            # A push fault keeps its own words ("the push to the registry failed") -> UPDATE-REGISTRY-PUSH-FAILED pim-upd-0103,
            # transient, never UNCLASSIFIED; any other build failure carries the run's error line for whoever reads it.
            $bErr = "build $($b.status) after $($b.seconds)s"
            if ("$($b.pushFault)".Trim()) { $bErr += ": the push to the registry failed ($($b.pushFault)) on both tries -- the next update run builds again" }
            elseif ("$($b.detail)".Trim()) { $d = "$($b.detail)".Trim() -replace '\s+', ' '; if ($d.Length -gt 300) { $d = $d.Substring(0, 300) }; $bErr += ": $d" }
            Send-PimUpdateOutcome -Action 'built' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText $bErr
            exit 1
        }
        if ([int]$b.attempts -gt 1) { Say "  the second build went through (the first, run $($b.firstRunId), failed on the push)" 'Green' }
        Say "  built in $($b.seconds)s (run $($b.runId))" 'Green'
        # Remember it, so tomorrow night is a roll and not another build. Takes effect on the NEXT
        # run by the same rule the self-stamp does -- this run already knows what it built.
        try {
            [void](Set-PimAcaJobEnvValue -SubscriptionId $sub -ResourceGroup $rg -JobName $selfJob `
                     -VariableName 'PIM_UPDATE_LAST_BUILT' -Value $plan.version)
        } catch { Say "  could not record the built version (it will rebuild next run): $($_.Exception.Message)" 'Yellow' }
        # CR7: an opted-in install builds the sign-in front from the SAME archive, after the Manager (whose build already
        # succeeded -- a front failure is reported and never undoes or fails it).
        if ($sfOpt.optIn) { $sfResult = Invoke-PimUpdaterSigninFrontStep -ArchivePath $ctx -Version "$($plan.version)" }
    } finally {
        Remove-Item -LiteralPath $ctx -Force -ErrorAction SilentlyContinue
    }
}
# CR7: opted in and the Manager was not built this run (already built here, or roll-only) -- the front image is checked /
# built on its own: the verified Invardia archive this run fetched for it, else the configured source of the target version.
$sfArch = $(if ($script:PimInvardiaContext -and (Test-Path -LiteralPath $script:PimInvardiaContext)) { "$script:PimInvardiaContext" } else { '' })
if ($sfOpt.optIn -and -not $sfResult) { try { $sfResult = Invoke-PimUpdaterSigninFrontStep -ArchivePath $sfArch -Version "$($plan.version)" } finally { if ($sfArch) { Remove-Item -LiteralPath $sfArch -Force -ErrorAction SilentlyContinue } } }
# CR7: behind the front, the Manager revision's front container moves to the pinned image TOGETHER with the Manager (one
# write, Invoke-PimAcaRoll -SidecarImages) -- only to an image that exists: built or found this run, or recorded as built.
if ($sfOpt.behindFront -and $loginServer) {
    $sfVer = ''
    if ($sfResult -and $sfResult.ok -and ($sfResult.built -or "$($sfResult.action)" -eq 'present') -and "$($sfResult.version)".Trim()) { $sfVer = "$($sfResult.version)".Trim() }
    elseif ($sfBuilt) { $sfVer = $sfBuilt }
    # front 1.3.0+ refuses to start without its state settings: the front stays where it is until they are on its container
    $sfState = Test-PimSigninFrontStateReady -App $app -Version $sfVer
    if (-not $sfState.ok) { Say "  the sign-in front stays on its current image: $($sfState.reason)" 'Yellow'; $sfVer = '' }
    $sfFrontImage = Get-PimSigninFrontImageRef -LoginServer $loginServer -Version $sfVer
}

# From here on the image exists -- either this run built it, or the registry already held it.
if ($plan.image) { $targetImg = $plan.image }
if (-not $targetImg) {
    Say 'no target image could be resolved -- refusing to guess.' 'Red'
    Send-PimUpdateOutcome -Action 'failed' -Outcome 'failed' -ErrorText 'no target image could be resolved'
    exit 2
}

# ---- 0b. §56.4 -- THE SCHEMA, BEFORE ANY CONTAINER MOVES ---------------------------------------
# 🔴 THIS JOB BUILT AND ROLLED CONTAINERS AND NEVER TOUCHED SQL. An update carrying a schema change
# therefore reached a customer as a container expecting columns its database does not have --
# unattended, at 03:00, with nobody watching. R10 asks for "all phases including container, schema,
# sql backend"; this was the missing phase.
#
# 🔑 ORDER IS THE WHOLE SAFETY PROPERTY. Schema goes FIRST because migrations here are
# ADDITIVE-ONLY (§56.3): the OLD container keeps working against the NEW schema, so the window
# between the two steps is safe in a way the reverse order never is. Rolling first and gating the
# schema behind a health check is §52.18's first-deploy deadlock -- the smoke test could not pass
# until the schema existed, so the schema step was never reached.
#
# 🔒 AND IT NEVER DESTROYS DATA. The conformance builder emits DROP COLUMN for anything the locked
# spec marks deprecated; applying that unattended would delete a column and its data in every
# customer at once, and NO ROLLBACK COULD UNDO IT -- image rollback is safe precisely because
# schema change is additive. A destructive migration is an ATTENDED operation (the cutover
# ceremony owns it, with backups and an abort). Same refusal, same wording, as the host-side path
# in Invoke-PimUpdate.ps1: one rule, now enforced in both places rather than one.
#
# 📌 FAIL-SAFE DIRECTION: if the schema cannot be brought up to date, DO NOT ROLL. A container
# expecting columns that do not exist is a broken environment; staying on the current version is
# not. This is the one step whose failure must stop the update.
# 🪤 THESE LIBS ARE DOT-SOURCED HERE, NOT GUARDED WITH Get-Command. A `if (Get-Command X)` around a
# function this entry point never LOADS is the audit's INERT-CAPABILITY class: the step reports
# "skipped" truthfully and forever, and reads as covered. The first cut of this block did exactly
# that, and it would have shipped a schema step that could never run once.
. (Join-Path $solRoot 'engine/_shared/PIM-SchemaConformance.ps1')   # locked schema + conformance DDL
. (Join-Path $solRoot 'engine/_shared/PIM-UpdateLifecycle.ps1')     # Get-PimSqlUpdatePlan

# 🔑 DDL over the SAME connection path the rest of this container uses. The host-side deploy mints
# an Entra token from a cert/SPN because it runs on the build host; in here the identity is the container's
# MANAGED IDENTITY, which New-PimSqlConnection already handles. Reusing that -- rather than porting
# the host's token minting -- is both less code and more correct: there is exactly one way this
# process talks to SQL, so the schema step cannot authenticate differently from the app it is
# upgrading. GO is a client-side batch separator, so it is split here and never sent to the server.
function Invoke-PimJobSqlDdl {
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Sql)
    $c = New-PimSqlConnection -ConnectionString $ConnectionString
    $c.Open()
    try {
        foreach ($batch in ($Sql -split '(?im)^\s*GO\s*$')) {
            if (-not "$batch".Trim()) { continue }
            $cmd = $c.CreateCommand(); $cmd.CommandText = $batch; $cmd.CommandTimeout = 300
            [void]$cmd.ExecuteNonQuery()
        }
    } finally { $c.Close() }
}
# Actual columns per locked table, straight from INFORMATION_SCHEMA. A table that is absent simply
# yields no rows, which is what the planner reads as "needs CREATE".
function Get-PimJobDeployedColumns {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $out = @{}
    foreach ($t in @((Get-PimLockedSqlSchema).Keys)) {
        $schemaName = ($t -split '\.')[0]; $tableName = ($t -split '\.')[1]
        $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString `
                    -Sql 'SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=@s AND TABLE_NAME=@t' `
                    -Parameters @{ s = $schemaName; t = $tableName })
        if ($rows.Count) { $out[$t] = @($rows | ForEach-Object { "$($_.COLUMN_NAME)" }) }
    }
    return $out
}

# 🔴 2026-09-13 -- THE JOB'S SQL SETTINGS NEVER REACHED THE STORE LIBRARY. Get-PimSqlConnectionString
# reads $global:PIM_SqlServer / $global:PIM_SqlDatabase, and nothing in this entry point copied the
# container's env into them (Invoke-PimEngineCore does, with Use-Cfg). So even an updater that DID carry
# PIM_SqlServer resolved no connection -- and said the environment had no store.
# 📌 Also done at the TOP of this file (§71.43) so the earlier exit paths can record their state. It is
# idempotent, and it stays HERE as well so the schema phase never depends on that having happened.
[void](Use-PimUpdaterStoreEnv)   # SCHEMA-STEP STORE RESOLUTION

# 🔴 2026-09-15 (UPD-15) -- SELF-HEAL THE STORE SETTINGS FROM THE MANAGER, DO NOT ASK A HUMAN.
# both test tenants refused every release for two nights with "updater has no PIM_SqlServer ... re-run
# Deploy-PimUpdateJob" while ca-pim-manager, which this run has ALREADY read ($app, above), named the
# store. The job now takes the Manager's values for this run and records them on its own env for the
# next one. Recording is best-effort: a failed note for tomorrow never fails tonight's update.
# 🔒 Only a copyable value is copied (a server name). An unreadable Manager, or one on a secret / vault
# pointer, resolves to 'none' and the decision below keeps refusing exactly as before.
$sqlAdminGroup = $(if ("$($env:PIM_SqlAdminGroupName)".Trim()) { "$($env:PIM_SqlAdminGroupName)".Trim() } else { 'grp-pim-sql-admins' })
$storeHeal = Resolve-PimUpdaterStoreSettings -JobServer "$($global:PIM_SqlServer)" -JobDatabase "$($global:PIM_SqlDatabase)" `
                -ManagerStore (Get-PimAcaStoreSettings -Resource $app) -ManagerApp $managerApp
if ($storeHeal.source -eq 'manager') {
    Set-Variable -Name 'PIM_SqlServer' -Scope Global -Value "$($storeHeal.server)"
    if ("$($storeHeal.database)".Trim()) { Set-Variable -Name 'PIM_SqlDatabase' -Scope Global -Value "$($storeHeal.database)" }
    Say "  store self-heal: $($storeHeal.reason)" 'Yellow'
    $saved = Save-PimUpdaterStoreSettings -SubscriptionId $sub -ResourceGroup $rg -JobName $selfJob -Writes $storeHeal.persist
    if ($saved.ok) { Say "  store settings recorded on $selfJob ($(@($saved.written) -join ', ')) -- the next run needs no copy" 'DarkGray' }
    else { Say "  NOTE: could not record the store settings on $selfJob ($($saved.reason)); this run continues with the copied values and the next run copies them again." 'Yellow' }
} elseif ($storeHeal.source -eq 'job' -and "$($storeHeal.database)".Trim() -and -not "$($global:PIM_SqlDatabase)".Trim()) {
    Set-Variable -Name 'PIM_SqlDatabase' -Scope Global -Value "$($storeHeal.database)"
}

Set-PimUpdTrackStage -Stage 'migrate'   # OPEN-13: the schema goes BEFORE any container moves (additive-only)
$schemaOk = $true
$schemaRefused = $null
$schemaLoginRefusal = $null
try {
    $csUpd = $null
    try { $csUpd = Get-PimSqlConnectionString } catch { $csUpd = $null }
    # Store-less must be PROVEN from the Manager's own settings, never inferred from this job's gap.
    $tgtVerForSchema = if ("$($plan.version)".Trim()) { "$($plan.version)".Trim() }
                       else { $tr = Split-PimImageReference -Image $targetImg; if ($tr) { "$($tr.tag)" } else { '' } }
    $storeDecision = Get-PimUpdateSchemaStoreDecision -UpdaterConnection "$csUpd" `
                        -ManagerStore (Get-PimAcaStoreSettings -Resource $app) `
                        -CurrentVersion $(if ($ref) { "$($ref.tag)" } else { '' }) -TargetVersion $tgtVerForSchema `
                        -UpdateJobName $selfJob -ManagerApp $managerApp
    if ($storeDecision.mode -eq 'storeless') {
        Say "  $($storeDecision.message)" 'DarkGray'
    } elseif ($storeDecision.mode -eq 'unverified') {
        Say "  $($storeDecision.message)" 'Red'
        Say "  $($storeDecision.detail)" 'Yellow'
    } elseif ($storeDecision.mode -eq 'refuse') {
        Say "  $($storeDecision.message)" 'Red'
        Say "  $($storeDecision.detail)" 'Red'
        $schemaRefused = $storeDecision
        $schemaOk = $false
    } elseif (-not ($script:PimSchemaDeferred = Invoke-PimUpdaterSchemaQuiesce -Cs "$csUpd").go) {
        # SCHEMA-QUIESCE-818: a PIM job is still running at the bound (or its executions could not be read) -- NO DDL here,
        # and the run ends 'waiting' just below, before anything rolls. Nothing was stopped.
        Say '  schema step deferred: a PIM job is running -- the database is not changed under it' 'Yellow'
    } else {
        $script:PimSchemaDeferred = $null
        Say 'applying schema updates BEFORE rolling any container (additive-only)'
        Initialize-PimSqlStore -ConnectionString $csUpd
        $locked  = Get-PimLockedSqlSchema
        # 🔴 2026-09-15 -- THE SHIPPED SCHEMA FILES RUN ON EVERY STORE, NOT ONLY WHEN A TABLE IS ABSENT.
        # They were gated on a LOCKED table being absent. pim.CentralAdmins is not locked, so 2.4.360's
        # guarded `ADD Replicate` never reached either test tenant -- while this step logged "schema up to date"
        # and the release rolled. Every guarded addition in these files is now applied to every existing
        # store, BEFORE the conformance plan, all files checked BEFORE any runs (a refusal applies nothing).
        # 🔒 Store-aware destructive guard (Get-PimSchemaFileApplyPlan): no DROP TABLE / TRUNCATE / DELETE /
        # UPDATE, and a DROP COLUMN only when it is guarded AND that column is absent here (inert). A file
        # that errors throws -- the schema step fails and nothing rolls.
        $colProbe = {
            param([string]$Table, [string]$Column)
            $rows = @(Invoke-PimSqlQuery -ConnectionString $csUpd -Sql 'SELECT CASE WHEN COL_LENGTH(@t, @c) IS NULL THEN 0 ELSE 1 END AS e' `
                          -Parameters @{ t = $Table; c = $Column })
            if (-not $rows.Count) { throw "no answer for COL_LENGTH($Table, $Column)" }
            ([int]"$($rows[0].e)") -eq 1
        }
        $schemaFiles = @()
        # 2026-09-18 (IMP-46): ONE shipped base-schema file. sql/local-schema.sql created only the dead
        # pim.LocalAdmins / pim.LocalResources and was retired; existing stores keep those tables (nothing
        # here drops anything). The locked schema below is now every table THIS file creates, so the
        # "still absent" check after the apply proves a first install really got its base schema.
        foreach ($rel in @('sql/platform-schema.sql')) {
            $sf = Join-Path $solRoot $rel
            if (-not (Test-Path -LiteralPath $sf)) { throw "base schema file '$rel' is missing from this payload." }
            $sqlText = [IO.File]::ReadAllText($sf)
            $fPlan = Get-PimSchemaFileApplyPlan -Sql $sqlText -Name $rel -ColumnExists $colProbe
            if (-not $fPlan.ok) {
                throw ("shipped schema file '$rel' REFUSED for unattended apply: " + (@($fPlan.violations) -join '; ') +
                       '. Nothing from the schema files was applied.')
            }
            $schemaFiles += @{ rel = $rel; sql = $sqlText; drops = @($fPlan.guardedDrops) }
        }
        foreach ($s in $schemaFiles) {
            Invoke-PimJobSqlDdl -ConnectionString $csUpd -Sql $s.sql
            $inert = @($s.drops | ForEach-Object { "$($_.table).$($_.column)" })
            Say ("  applied $($s.rel) (idempotent; guarded additions reach existing stores$(if ($inert.Count) { "; inert guarded drops: $($inert -join ', ')" }))") 'DarkGray'
        }
        # CREATE before ALTER -- planned AFTER the files, against what is now really in the database.
        $depCols = Get-PimJobDeployedColumns -ConnectionString $csUpd
        $sPlan   = Get-PimSqlUpdatePlan -DeployedColumns $depCols -LockedSqlSchema $locked `
                        -PulledSchemaVersion "$($plan.version)" -DeployedSchemaVersion "$($plan.version)"
        $absentT = @($sPlan.tables | Where-Object { $_.exists -eq $false })
        if ($absentT.Count) {
            throw ("the shipped schema was applied but these table(s) are still absent: " + (@($absentT | ForEach-Object { $_.table }) -join ', '))
        }
        foreach ($tp in @($sPlan.tables | Where-Object { $_.exists -and -not $_.conformant })) {
            $actual = @(if ($depCols.ContainsKey($tp.table)) { $depCols[$tp.table] } else { @() })
            $ddl = New-PimSqlConformanceDdl -Table $tp.table -Spec $locked[$tp.table] -ActualColumns $actual
            if (@($ddl.plan.ToDrop).Count) {
                throw ("schema upgrade for $($tp.table) would DROP column(s): " + (@($ddl.plan.ToDrop) -join ', ') +
                       '. An unattended update never destroys data -- no rollback could restore it.')
            }
            Say "  altering $($tp.table)" 'DarkGray'
            Invoke-PimJobSqlDdl -ConnectionString $csUpd -Sql $ddl.ddl
        }
        # Re-preflight against what is NOW really in the database, not against what we planned from.
        $reCols = Get-PimJobDeployedColumns -ConnectionString $csUpd
        $rePlan = Get-PimSqlUpdatePlan -DeployedColumns $reCols -LockedSqlSchema $locked `
                        -PulledSchemaVersion "$($plan.version)" -DeployedSchemaVersion "$($plan.version)"
        if ($rePlan.SqlUpdateRequired) { throw "schema re-preflight still reports drift: $($rePlan.reason)" }
        Say '  schema up to date.' 'Green'
        # Framework §12.23 P4/P9 (PIM 100.156): least-privilege access converges THROUGH THE SIGNED PROCEDURE ONLY -- the
        # updater holds no security right of its own. Not installed yet = nothing changes (the admin run installs it).
        # A failure here is reported and never blocks the update: the broad roles still carry the install.
        try {
            $acc = Invoke-PimSqlAccessConverge -ConnectionString $csUpd
            # PIM 100.156: the line names WHO converged -- "as ca-pim-update (db_owner: no)" is the proof that the updater
            # works as its own least-privilege user (the step before it leaves the SQL admin group); "as dbo" = still admin.
            $accWho = "as $(if ("$($acc.runAs)") { "$($acc.runAs)" } else { '?' }) (db_owner: $(if ($acc.dbOwner) { 'yes' } else { 'no' }); state via $($acc.via))"
            if ($acc.applied) { Say "  database access converged $accWho`: $($acc.statements) statement(s) through the signed procedure ($([int]$acc.alreadyHeld) already held); revoked $($acc.revoked); users $(@($acc.users) -join ', ') ($($acc.visibleUsers) visible)" 'DarkGray' }
            else { Say "  database access $accWho`: $($acc.reason)" 'DarkGray' }
            # §33.0 MORE TELEMETRY (SqlAccess): the verdict goes into UpdateState, so the heartbeat only reads it. run 2 (the
            # runtime users lost their broad roles) is visible only to an updater that is still db_owner -- else unknown.
            try {
                $accBroad = $null; $accFactsRun2 = $null; $accRun2Why = ''
                if ($acc.dbOwner -and (Get-Command Get-PimSqlAccessSetupGateSql -ErrorAction SilentlyContinue)) {
                    $accNm = Get-PimSqlAccessInstallNameMap
                    $accRow = @(Invoke-PimSqlQuery -ConnectionString $csUpd -Sql (Get-PimSqlAccessSetupGateSql -UserNames (@($accNm['pim_web']) + @($accNm['pim_engine']))))[0]
                    if ($accRow) { $accBroad = $accRow.broadUsers }
                } elseif ($acc.applied -and (Get-Command Read-PimAccessFacts -ErrorAction SilentlyContinue)) {
                    # SETUPSTEPS-TRUTH (a): a least-privilege updater does not see the other users' roles -- it asks the
                    # read-only SIGNED procedure (EXECUTE only). Absent / unsigned = $null (unknown), never a guess.
                    $accNm = Get-PimSqlAccessInstallNameMap
                    $accCs = $csUpd
                    $accFacts = Read-PimAccessFacts -Scalar { param($q) Invoke-PimSqlScalar -ConnectionString $accCs -Sql $q } -RuntimeUsers (@($accNm['pim_web']) + @($accNm['pim_engine']))
                    $accFactsRun2 = Get-PimAccessFactsRun2 -Read $accFacts
                    Say ("  database access run 2: $(if ($accFactsRun2 -eq $true) { 'done' } elseif ($accFactsRun2 -eq $false) { 'NOT done (a runtime user still holds a broad role)' } else { "not determined -- $(if ($accFacts.reason) { $accFacts.reason } else { 'none of the runtime users was found' })" }) (through the signed access facts procedure)") 'DarkGray'
                    if ($null -eq $accFactsRun2) { $accRun2Why = "the updater is not a SQL admin; $(if ($accFacts.reason) { $accFacts.reason } else { 'none of the runtime users was found through the access facts procedure' })" }
                }
                # SQLACCESS-STORED (2026-11-05): an updater that left the SQL admin group may not see the other users' roles. When
                # run 2 cannot be read live, the STORED cut-over record (the last UpdateState.sqlAccess that said run 2 done) is
                # carried -- said as stored, with the time of the read it carries and why the live read was not possible.
                $accPrev = $null
                try { $accPrev = Get-PimUpdateStateField -Object (Read-PimUpdateState -ConnectionString $csUpd) -Key 'sqlAccess' } catch { $accPrev = $null }
                $script:PimSqlAccessVerdict = New-PimSqlAccessVerdict -Converge $acc -BroadUsers $accBroad -FactsRun2 $accFactsRun2 -Previous $accPrev -Run2Reason $accRun2Why
                if ("$($script:PimSqlAccessVerdict.run2Source)" -eq 'stored') { Say "  database access run 2: done (the stored cut-over record of $($script:PimSqlAccessVerdict.run2CheckedUtc); not read live: $($script:PimSqlAccessVerdict.run2Reason))" 'DarkGray' }
            } catch { Say "  database access verdict not recorded (telemetry only; the update is unaffected): $($_.Exception.Message)" 'DarkGray' }
        } catch {
            Say "  database access NOT converged (the update continues; the broad roles still apply): $($_.Exception.Message)" 'Yellow'
            try { $script:PimSqlAccessVerdict = New-PimSqlAccessVerdict -ErrorText "$($_.Exception.Message)" } catch { Say "  database access verdict not recorded (telemetry only): $($_.Exception.Message)" 'DarkGray' }
        }
    }
} catch {
    $schemaOk = $false
    $schemaErr = "$($_.Exception.Message)"
    Say "  SCHEMA STEP FAILED: $schemaErr" 'Red'
    # 🔑 A LOGIN FAILURE NAMES THE PRINCIPAL AND THE FIX. The token SQL refused is the one this process
    # presented, so its oid is exactly who to add; the job's own identity is the fallback.
    $who = Get-PimJwtPrincipal -Token $global:PIM_SqlAccessToken
    $whoOid = "$($who.oid)"
    if (-not $whoOid -and $schemaErr -match '(?i)Login failed|18456|token-identified') {
        try {
            $selfIdObj = Invoke-PimArm -Method GET -ApiVersion $script:PimAcaApi `
                            -Path "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs/$selfJob"
            # the identity this job SIGNS IN AS (id-pim-updater after the identity move), not only its system identity
            $whoOid = $(if (Get-Command Resolve-PimUpdPermEngineObjectId -ErrorAction SilentlyContinue) { Resolve-PimUpdPermEngineObjectId -Job $selfIdObj } else { "$($selfIdObj.identity.principalId)" })
        } catch { }
    }
    $schemaLoginRefusal = Get-PimUpdateSchemaLoginRefusal -ErrorText $schemaErr -PrincipalObjectId $whoOid -PrincipalAppId "$($who.appid)" `
                              -SqlServer "$($global:PIM_SqlServer)" -GroupName $sqlAdminGroup -UpdateJobName $selfJob
    if ($schemaLoginRefusal) {
        Say "  $($schemaLoginRefusal.message)" 'Red'
        Say "  $($schemaLoginRefusal.detail)" 'Red'
    }
}
if ($schemaOk -and $script:PimSchemaDeferred -and -not $script:PimSchemaDeferred.go) {
    # SCHEMA-QUIESCE-818: WAITING, not failed -- PIM keeps running its current version; the next update run tries again.
    Say 'NOT ROLLING: a PIM job is still running, and the database is never changed under a run (framework 8.18).' 'Yellow'
    Send-PimUpdateOutcome -Action 'schema' -Outcome 'waiting' -ToVersion "$($plan.version)" -ErrorText "$($script:PimSchemaDeferred.line)"
    exit 0
}
if ($schemaRefused) {
    Say 'NOT ROLLING: this release may need schema changes, and this updater cannot reach the store to' 'Red'
    Say "             verify them: $managerApp could not be read, or names its store through a secret or vault pointer." 'Red'
    Send-PimUpdateOutcome -Action 'schema' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText "$($schemaRefused.errorText)"
    exit 1
}
if ($schemaLoginRefusal) {
    Say "NOT ROLLING: the schema could not be verified -- add the updater's identity to the SQL admin group '$sqlAdminGroup'." 'Red'
    Send-PimUpdateOutcome -Action 'schema' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText "$($schemaLoginRefusal.errorText)"
    exit 1
}
if (-not $schemaOk) {
    Say 'NOT ROLLING: the schema could not be brought up to date, and a container expecting columns' 'Red'
    Say '             that do not exist is worse than staying on the current version.' 'Red'
    Send-PimUpdateOutcome -Action 'schema' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText 'schema step failed; roll refused'
    exit 1
}

# ---- 0b. THE DESIRED-STATE GATE (BUG-231) -----------------------------------------------------
# 🔴 THE BUG-55 GATE EXISTED ONLY ON THE HOST-SIDE PATH, AND THAT IS THE PATH NOBODY RUNS ANY MORE.
# `Update-PimContainers` refuses to roll an image whose policy baseline differs from the one recorded
# on the app, because within one tick the engine starts converging EVERY managed scope onto the new
# baseline -- that is how 217 of 325 production group policies were rewritten overnight. This job
# rolls the same app, unattended, at 03:00, and had no such check at all.
# WHAT IS COMPARED: the templates the TARGET version ships (read out of the source archive, the only
# statement of that version's content this job ever holds) against the fingerprint recorded on the
# Manager app. Same decision function as the host-side gate -- Compare-PimPolicyBaseline -- so there
# is ONE rule, not a second copy that can drift from it.
# 🔒 A CHANGED BASELINE REFUSES. The operator's way past is PIM_UPDATE_ACCEPT_BASELINE_CHANGE=1 on
# THIS environment's update job -- deliberate, per environment, and named in the refusal. Same shape
# as PIM_UPDATE_ALLOW_DOWNGRADE=1 above, for the same reason: an unattended process must not decide
# on its own that a desired-state change is acceptable.
# 🪤 UNKNOWN IS NOT CHANGED. No recording yet (first roll, or a resource older than the gate) and an
# unreadable archive BOTH mean "cannot tell" -- they warn and PROCEED. Blocking on "cannot tell"
# would freeze a fleet at 03:00 over a failed download, and would make the gate impossible to roll
# out in the first place.
Set-PimUpdTrackStage -Stage 'apply'     # OPEN-13: the roll -- its desired-state gate, the Manager, then every job
$blAccept = ("$($env:PIM_UPDATE_ACCEPT_BASELINE_CHANGE)".Trim() -eq '1')
try {
    $tgtBaseline = $null
    if ("$srcUrlTpl".Trim() -and (Get-Command Get-PimPolicyBaselineFromArchive -ErrorAction SilentlyContinue)) {
        $blCtx = Join-Path ([IO.Path]::GetTempPath()) ("pim-bl-src-{0}.tar.gz" -f $plan.version)
        try {
            $blGot = Get-PimUpdateSourceArchive -Url (Resolve-PimUpdateSourceUrl -Template $srcUrlTpl -Version $plan.version) -OutFile $blCtx
            if ($blGot.ok) { $tgtBaseline = Get-PimPolicyBaselineFromArchive -ArchivePath $blCtx }
        } finally { Remove-Item -LiteralPath $blCtx -Force -ErrorAction SilentlyContinue }
    }
    if (-not $tgtBaseline -or -not "$($tgtBaseline.hash)".Trim()) {
        Say '  desired-state check SKIPPED -- the target version''s policy templates could not be read (no source archive, or it could not be opened). Proceeding; the roll is not gated on a check that could not run.' 'Yellow'
    } else {
        $recBl = ''
        try {
            $appObj = Invoke-PimArm -Method GET -ApiVersion $script:PimAcaApi -Path "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/containerApps/$managerApp"
            if ($appObj -and $appObj.tags) { $recBl = "$($appObj.tags.'pim-policy-baseline')".Trim() }
            if ($recBl -eq 'None') { $recBl = '' }
        } catch { $recBl = '' }
        $blV = Compare-PimPolicyBaseline -Current $tgtBaseline -RecordedHash $recBl -RecordedTemplates @{} -Accept:$blAccept
        Say ("desired-state check: {0} policy template(s), fingerprint {1}" -f $tgtBaseline.count, $tgtBaseline.hash) 'DarkGray'
        if ($blV.unknown) {
            Say "  $($blV.reason) -- rolling and RECORDING it, so the next run can answer this." 'Yellow'
        } elseif ($blV.changed -and -not $blV.allowed) {
            Say "NOT ROLLING: $($blV.reason)" 'Red'
            Say '  This image changes what the engine WANTS, not just how it works: within one tick it would start' 'Red'
            Say '  converging every managed scope onto the new baseline (BUG-55 -- 217 of 325 production group' 'Red'
            Say '  policies were rewritten overnight).' 'Red'
            Say "  If that is the point of this release, set PIM_UPDATE_ACCEPT_BASELINE_CHANGE=1 on $selfJob and re-run." 'Yellow'
            Send-PimUpdateOutcome -Action 'none' -Outcome 'failed' -ToVersion "$($plan.version)" `
                -ErrorText "refused: policy baseline would change ($($blV.reason)); set PIM_UPDATE_ACCEPT_BASELINE_CHANGE=1 to accept"
            exit 1
        } elseif ($blV.changed) {
            Say "  $($blV.reason) -- PROCEEDING because PIM_UPDATE_ACCEPT_BASELINE_CHANGE=1. This roll WILL change desired state." 'Yellow'
        } else {
            Say "  $($blV.reason)" 'Green'
        }
    }
} catch {
    Say "  desired-state check could not run ($($_.Exception.Message)) -- proceeding; a check that failed is not a refusal." 'Yellow'
}

# ---- 1. the Manager ---------------------------------------------------------------------------
Say "rolling $managerApp -> $targetImg"
# PIM 100.114 (framework 12.16 CONVERGE-DEFAULTS): the roll is a read-modify-write of the WHOLE template -- whatever size
# the Manager runs goes back unchanged -- and when it is below the product size (4 CPU / 8 GiB, raise only; the customer's
# PIM_Bootstrap_Cpu_Manager / PIM_Bootstrap_Memory_Manager on this job wins) the SAME write raises it: one write, one
# restart, never an image PATCH followed by a size PATCH (the second is refused 409 OperationInProgress).
$mgrSizeEnv = @{}; foreach ($ev in [Environment]::GetEnvironmentVariables().GetEnumerator()) { $mgrSizeEnv["$($ev.Key)"] = "$($ev.Value)" }
# CR7: behind the sign-in front the front container rolls in the same write ($sfFrontImage, decided above); '' = no sidecar.
$mgrSidecars = @{}
if ($sfFrontImage) { $mgrSidecars['signin-front'] = $sfFrontImage; Say "  the sign-in front container moves with it -> $sfFrontImage" 'DarkGray' }
$roll = Invoke-PimAcaRoll -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp -Image $targetImg `
                          -ContainerName $container -Resize { param($rzContainer, $rzApp) Get-PimManagerAppResize -Container $rzContainer -App $rzApp -Environment $mgrSizeEnv } -HealthCheck {
    # Healthy = the app provisioned AND has an active revision the platform reports as running.
    $rev = Get-PimAcaActiveRevision -SubscriptionId $sub -ResourceGroup $rg -Name $managerApp
    if (-not $rev) { return $false }
    $state = "$($rev.properties.runningState)"
    # 🪤 'Running' is NOT the only healthy value: a scaled app reports RunningAtMaxScale, and an
    # app at min-replicas 0 with no traffic reports neither. Treat only the explicitly bad ones as
    # bad, or this check fails every healthy scale-to-zero environment at 03:00.
    ($state -notmatch '(?i)^(Failed|Degraded)$')
} -SidecarImages $mgrSidecars

if ($roll.reason) { Say "  $($roll.reason)" 'DarkGray' }
if ($roll.sidecars -and $roll.sidecars.Count) { Say ("  sign-in front rolled with the Manager: " + (@($roll.sidecars.Keys | ForEach-Object { "$_ -> $($roll.sidecars[$_])" }) -join ', ')) 'DarkGray' }
if ($roll.resized) {
    Say ("  sizing: $($roll.sizeDetail) -- in the same write as the image" + $(if ($roll.sizeConfirmed) { '; read back' } else { '; the size did NOT read back -- checked again below' })) $(if ($roll.sizeConfirmed) { 'Cyan' } else { 'Yellow' })
}
if ($roll.rolled -and $roll.healthy -eq $false) {
    Say "  UNHEALTHY after the roll -- rolled back: $($roll.rolledBack)" 'Red'
    # OPEN-13: the health check failed; a roll back ends the run rollback -> done "rolled back"
    Set-PimUpdTrackStage -Stage 'health'; $script:PimUpdTrackRolledBack = [bool]$roll.rolledBack
    # SUP-2026-00424 (2026-11-05): the reason rides along, so the failure catalog tells a health check that could not READ
    # the app (UPDATE-HEALTH-UNREAD) from a version that really was unhealthy (UPDATE-ROLLED-BACK) -- never UNCLASSIFIED.
    Send-PimUpdateOutcome -Action 'rolled' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText ("unhealthy after the roll; rolledBack=$($roll.rolledBack)" + $(if ("$($roll.reason)".Trim()) { "; $((("$($roll.reason)") -split "`n")[0])" }))
    exit 1
}
if (-not $roll.rolled -and $roll.reason -notmatch 'already on this image') {
    Say "  the Manager did NOT roll: $($roll.reason)" 'Red'
    Send-PimUpdateOutcome -Action 'rolled' -Outcome 'failed' -ToVersion "$($plan.version)" -ErrorText "the Manager did not roll: $($roll.reason)"
    exit 1
}

# ---- 1b. RECORD THE DESIRED-STATE BASELINE THIS ROLL PUT IN PLACE (BUG-229) -------------------
# 🔴 THE SELF-UPDATE PATH NEVER TOUCHED THE BUG-55 RECORDING, AND THAT IS WHY THE HOST-SIDE GATE
# JAMS SHUT. `Update-PimContainers.ps1` writes the `pim-policy-baseline` tag after every verified
# roll; this job rolls the very same app through ARM and wrote nothing -- so on every environment
# that self-updates, the IMAGE moved while the TAG stayed frozen at whatever the last host-side
# roll happened to record.
# Measured 2026-09-20: internal ran 2.4.381 (templates `10b3bf2031bacf0c`) with the tag still at
# `856bb5f1b9b009ec`; both test tenants at `ff26419374c19ebb`. None of those three values matches
# ANY released version -- the fingerprint is taken from the working tree at roll time, so a roll
# from a mid-edit tree records a number no release ever had.
# The consequence is not cosmetic: the host-side nightly then refuses every roll for the rest of
# time. Measured 2026-09-13 on internal -- "recorded ff26419374c19ebb -> current aadd78a1d9338aec",
# deployed=False -- and until BUG-228 there was no parameter with which to tell it to accept.
# ⚠️ A gate that can never go green is a gate people learn to pass reflexively. That is how BUG-55
# happened in the first place, so leaving the recording to rot is itself a safety regression.
#
# WHAT IS RECORDED: the fingerprint the NEWLY ROLLED Manager seeded into its own store
# (`pim.Settings['PolicyTemplates'].fingerprint`) -- i.e. what this environment's desired state now
# IS, which is precisely what the gate compares a tree against. Read AFTER the health check,
# because the Manager writes it while it boots; retried briefly for the same reason.
# 🔒 BEST EFFORT, ALWAYS. A recording that fails must never fail an update that already rolled and
# is healthy -- it degrades to "unknown" on the next host-side roll, which WARNS rather than blocks.
# 📌 STILL OPEN (operator decision): this records, it does not GATE. The BUG-55 refusal exists only
# on the host-side path, so an unattended 03:00 self-update still rolls a baseline change with no
# check at all. Gating here would block the fleet unattended, which is not a call to make silently.
try {
    $blFp = ''
    if ("$csUpd".Trim() -and (Get-Command Invoke-PimSqlQuery -ErrorAction SilentlyContinue)) {
        foreach ($attempt in 1..6) {
            $raw = ''
            try {
                $r = @(Invoke-PimSqlQuery -ConnectionString $csUpd -Sql "SELECT CAST(ValueJson AS nvarchar(max)) AS v FROM pim.Settings WHERE [Name]='PolicyTemplates'")
                if ($r.Count) { $raw = "$($r[0].v)" }
            } catch { $raw = '' }
            if ("$raw".Trim()) { try { $blFp = "$(($raw | ConvertFrom-Json).fingerprint)".Trim() } catch { $blFp = '' } }
            if ($blFp) { break }
            Start-Sleep -Seconds 10
        }
    }
    if (-not $blFp) {
        Say '  policy baseline NOT recorded: no template fingerprint in the store yet (the next host-side roll reports it as UNKNOWN, which warns rather than blocks).' 'Yellow'
    } else {
        $blScope = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/containerApps/$managerApp"
        # 🪤 Merge, never replace: a PATCH that sets `tags` wholesale would silently delete the
        # customer's own cost-centre/owner tags as a side effect of an update. This is the same
        # Microsoft.Resources/tags Merge operation `az tag update --operation Merge` performs.
        [void](Invoke-PimArm -Method PATCH -ApiVersion '2021-04-01' `
                 -Path "$blScope/providers/Microsoft.Resources/tags/default" `
                 -Body @{ operation = 'Merge'; properties = @{ tags = @{ 'pim-policy-baseline' = $blFp } } })
        Say "  recorded policy baseline $blFp on $managerApp" 'DarkGray'
    }
} catch { Say "  could not record the policy baseline (update unaffected): $($_.Exception.Message)" 'Yellow' }

# 🔴 A COMPONENT LEFT ON THE OLD BUILD IS A FAILED UPDATE, NOT A WARNING.
# Every job below used to swallow its own failure and let the run exit 0, so an environment could be
# reported "updated" with its engine still on the previous image -- a skew that is invisible until
# the GUI and the job that does the work behave differently. Counted here and surfaced at the end.
$jobFailed = @()
# B8: kept SEPARATE from $jobFailed on purpose. A job that is still on the previous build is a
# failed update; this job failing to re-stamp ITSELF only defers which image its NEXT run starts
# from, and must not turn a healthy, rolled environment into a red execution.
$selfStampDeferred = ''
# §71.44 -- what this run did to ITSELF, for the follow-up decision at the very end.
$selfImageBefore = ''; $selfStamped = $false

# ---- 2. the tick job --------------------------------------------------------------------------
# Named explicitly rather than left to discovery: it is the one job whose skew from the Manager
# matters most, and it must be rolled even in the odd case where it runs a different repository.
if ($tickJob) {
    try {
        Say "rolling the tick job $tickJob"
        [void](Invoke-PimArmBusyRetry -Write { Set-PimAcaJobImage -SubscriptionId $sub -ResourceGroup $rg -Name $tickJob -Image $targetImg -ContainerName $jobContainer })
    } catch { $jobFailed += $tickJob; Say "  tick job not rolled: $($_.Exception.Message)" 'Yellow' }
    # PIM 100.166 (b) / framework 12.24: a run that started on the OLD image may run for days now (7-day limit) -- stop it,
    # so old code does not keep writing after the roll. Closed as interrupted by the update; it runs again on the new code.
    # Only after a roll that landed; never fails the update.
    if ($tickJob -notin $jobFailed -and "$targetImg".Trim()) {
        try {
            $ov = Stop-PimAcaJobOtherVersionExecutions -SubscriptionId $sub -ResourceGroup $rg -Name $tickJob -KeepImage $targetImg
            Say "  $($ov.detail)" $(if (-not $ov.ok) { 'Yellow' } elseif (@($ov.stopped).Count) { 'Cyan' } else { 'DarkGray' })
        } catch { Say "  old-version runs not checked: $($_.Exception.Message)" 'Yellow' }
    }
}

# ---- 2a + 2d. 100.31 / 100.37 / 100.40 (framework 12.15 + 12.16) -- CONVERGE THE INSTALL DEFAULTS, ON EVERY UPDATE ----
# The tick's size for this tenant (Invoke-PimJobSizingUpdate with the run history = self-correct), the database tier / max
# size (Invoke-PimSqlTierUpdate), then the other install defaults (Invoke-PimUpdateConvergeDefaults). ONE function
# (Invoke-PimUpdaterConvergeStep, top of this file), also run on the 'ahead' exit. Never fails the update.
Invoke-PimUpdaterConvergeStep -When 'after the roll'
# SCHEMA-QUIESCE-818: the last database change of this run is done (schema, access, as-built) -- the scheduled jobs go on.
Clear-PimUpdaterSchemaHold

# ---- 2b. §53.5 -- EVERY OTHER JOB IN THIS ENVIRONMENT THAT RUNS THE SAME IMAGE -----------------
# 🔴 The hardcoded three (Manager, tick, self) left everything else to drift FOREVER. Measured at an
# MSP slave: after a GREEN update execution, `ca-pim-downlink-s6` was still on a digest with NO TAG
# -- a dangling manifest from a build whose tag had since moved, so the job was running code nobody
# could name. MSP topologies are exactly where the extra jobs live, so the set the updater knows
# about by name was never going to be the set the environment actually has.
# 🔒 Same REPOSITORY only. This process holds Contributor on the whole resource group; a customer's
# own job living in it is not ours to retag, and pointing it at the Manager image would break it.
# The decision is in Get-PimAcaJobRollPlan so it is provable offline rather than trusted at 03:00.
$discovered = 0
try {
    $all  = Get-PimAcaJobs -SubscriptionId $sub -ResourceGroup $rg
    $plan = Get-PimAcaJobRollPlan -Jobs $all -TargetImage $targetImg -Exclude @($tickJob, $selfJob)
    foreach ($s in @($plan.skip)) { Say "  skipping $($s.name): $($s.reason)" 'DarkGray' }
    foreach ($r in @($plan.roll)) {
        # 100.61 (live 2026-10-11): the as-built converge (2e, above) already moved caj-pim-asbuilt to the target image THIS run;
        # PATCHing it again seconds later was refused 409 ContainerAppsJobOperationInProgress and reported the job as still on
        # the previous build. It is on the target -- counted, not written twice.
        if (Test-PimAsBuiltRollSkip -JobName "$($r.name)" -ConvergedImage "$script:PimAsBuiltJobImageThisRun" -TargetImage "$targetImg") {
            Say "  $($r.name): already moved to $targetImg by the as-built converge this run -- not written again" 'DarkGray'
            $discovered++
            continue
        }
        # 2026-10-24 (SUP-2026-00307): a job already on the target is counted, never PATCHed again (Test-PimAcaRollNoop).
        if (Test-PimAcaRollNoop -From "$($r.from)" -TargetImage "$targetImg") {
            Say "  $($r.name): already on $targetImg -- nothing to roll" 'DarkGray'
            $discovered++
            continue
        }
        try {
            Say "rolling $($r.name) (same image as the Manager)"
            # A job still provisioning a write from earlier in this run answers 409 OperationInProgress: wait it out (bounded,
            # Invoke-PimArmBusyRetry -- the GET inside Set-PimAcaJobImage is repeated on each attempt), never a failed update.
            [void](Invoke-PimArmBusyRetry -NetworkWaits @(5, 15, 30) -Write { Set-PimAcaJobImage -SubscriptionId $sub -ResourceGroup $rg -Name $r.name -Image $targetImg })
            $discovered++
        } catch { $jobFailed += $r.name; Say "  $($r.name) NOT rolled: $($_.Exception.Message)" 'Yellow' }
    }
} catch {
    # 🪤 Enumeration failing is NOT "there was nothing else". Saying so is the difference between a
    # quiet log that means "nothing to do" and one that means "I could not look".
    $jobFailed += '<job enumeration>'
    Say "  could not enumerate the jobs in $rg -- only the NAMED jobs were rolled: $($_.Exception.Message)" 'Yellow'
}
# OPEN-06: the database job's version for setupSteps 'db-job' is READ BACK after the roll above (the converge step read it
# before the roll). An ARM GET only; nothing is written or started. Never fails the update.
try {
    if ($script:PimDbInitResult -and [bool]$script:PimDbInitResult.present -and -not [bool]$script:PimDbInitResult.onVersion -and "$($script:PimDbInitResult.jobName)".Trim()) {
        $dbBack = Invoke-PimArm -Method GET -Path "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs/$($script:PimDbInitResult.jobName)?api-version=2024-03-01"
        $script:PimDbInitResult = Update-PimDbInitResultImage -Result $script:PimDbInitResult -Job $dbBack
        if ($script:PimSetupFacts) {
            $dbF = Get-PimSetupStepDbJobFacts -DbInitResult $script:PimDbInitResult
            $script:PimSetupFacts['dbJob'] = $dbF.dbJob; $script:PimSetupFacts['dbJobDetail'] = (ConvertTo-PimSetupStepDetail -Text $dbF.dbJobDetail)
        }
        Say "database job after the roll: $($script:PimDbInitResult.state) -- $($script:PimDbInitResult.detail)" 'DarkGray'
    }
} catch { Say "  database job version not read back after the roll: $($_.Exception.Message)" 'Yellow' }

# ---- 2c. 2026-10-02 -- every other CONTAINER APP that runs the same image ------------------------
# The access request broker (ca-pim-rfa) is an app on the Manager's image; only the Manager was rolled by name, so the
# broker stayed behind (internal: 2.4.478 while ring 1 ran 2.4.481). Same rule as the jobs (Get-PimAcaJobRollPlan:
# same REPOSITORY, single container), the Manager excluded -- it was rolled above, with its health gate.
try {
    $apps = Get-PimAcaApps -SubscriptionId $sub -ResourceGroup $rg
    $aplan = Get-PimAcaJobRollPlan -Jobs $apps -TargetImage $targetImg -Exclude @($managerApp)
    foreach ($s in @($aplan.skip | Where-Object { $_.reason -ne 'rolled separately' })) { Say "  skipping app $($s.name): $($s.reason)" 'DarkGray' }
    foreach ($r in @($aplan.roll)) {
        if (Test-PimAcaRollNoop -From "$($r.from)" -TargetImage "$targetImg") {
            Say "  app $($r.name): already on $targetImg -- nothing to roll" 'DarkGray'
            $discovered++
            continue
        }
        try {
            Say "rolling app $($r.name) (same image as the Manager)"
            # 2.4.649 (live 2026-10-18, internal: "GET .../ca-pim-rfa -> HTTP 0 : Cannot assign requested address" made a healthy
            # update report "still on the previous build"): a busy app is waited out and a request that never reached ARM is asked
            # again (the image PATCH is idempotent), as for the jobs above.
            [void](Invoke-PimArmBusyRetry -NetworkWaits @(5, 15, 30) -Write { Set-PimAcaAppImage -SubscriptionId $sub -ResourceGroup $rg -Name $r.name -Image $targetImg })
            $discovered++
        } catch { $jobFailed += $r.name; Say "  app $($r.name) NOT rolled: $($_.Exception.Message)" 'Yellow' }
    }
} catch {
    $jobFailed += '<app enumeration>'
    Say "  could not enumerate the container apps in $rg -- only the Manager was rolled: $($_.Exception.Message)" 'Yellow'
}

# ---- 3. itself, LAST --------------------------------------------------------------------------
if ($selfJob) {
    try {
        # 🔴 §56.5 -- RECORD WHAT KNOWN-GOOD MEANS, BEFORE MOVING OFF IT.
        # The image this job is running RIGHT NOW has just carried a whole update to completion:
        # it fetched, built, rolled the Manager, and passed the health gate. That is the strongest
        # possible evidence an image can produce about itself, and it is only available here, at
        # the end of a successful run, one line before the job abandons it.
        # 🪤 The Manager health gate does NOT prove the updater works -- they are different entry
        # points in the same image (2.4.296-2.4.301 booted the Manager fine and broke the updater).
        # So the image being adopted below is UNPROVEN as an updater, and the watchdog in the tick
        # job needs somewhere to fall back to when it turns out not to run.
        $selfNow = ''
        try {
            $selfJobObj = Invoke-PimArm -Method GET -ApiVersion $script:PimAcaApi `
                            -Path "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.App/jobs/$selfJob"
            $sc = @($selfJobObj.properties.template.containers)
            if ($sc.Count -eq 1) { $selfNow = "$($sc[0].image)" }
        } catch { }
        # §56.5 last-known-good + §95.4 the Invardia sequence this environment APPLIED (a lower one is refused from now on --
        # no replay). 2026-10-09: PER RING -- PIM_UPDATE_INVARDIA_SEQ_R<ring> is the watermark this ring's next pull is
        # checked against; the legacy pair (PIM_UPDATE_INVARDIA_SEQ + PIM_UPDATE_INVARDIA_SEQ_RING) is written beside it, so
        # the single value always says which ring it belongs to (an older updater image still reads the value).
        # 🔴 100.50 (live 2026-10-10, every ring-1 run): these were FOUR back-to-back PATCHes of this job, and every PATCH
        # starts a provisioning operation -- the next one was refused "HTTP 409 ContainerAppsJobOperationInProgress", so the
        # watermark was never (fully) written: "could not record the applied Invardia sequence". Now ONE PATCH carries all
        # of them (Get-PimUpdaterSelfRecordWrites -> Set-PimAcaJobEnvValues, which waits out a busy job and reads back).
        $selfRec = Get-PimUpdaterSelfRecordWrites -SelfImageNow $selfNow -TargetImage $targetImg -Ring $ring `
                       -Sequence $script:PimInvardiaSequence -AppliedSequence $script:PimInvardiaApplied -Kind $(if ($updSource -eq 'invardia-community') { 'community' } else { 'code' })
        $seqVar = $selfRec.variable
        if ($selfRec.writes.Count) {
            try {
                [void](Set-PimAcaJobEnvValues -SubscriptionId $sub -ResourceGroup $rg -JobName $selfJob -Values $selfRec.writes)
                if ($selfRec.lastGood) { Say "  recorded last-known-good updater image: $selfNow" 'DarkGray' }
                if ($selfRec.sequence) { Say "  recorded the applied Invardia sequence for ring $ring`: $($script:PimInvardiaSequence) ($seqVar)" 'DarkGray' }
            } catch {
                if ($selfRec.lastGood) { Say "  could not record the last-known-good image: $($_.Exception.Message)" 'Yellow' }
                if ($selfRec.sequence) { Say "  could not record the applied Invardia sequence (the same release is simply seen again next run): $($_.Exception.Message)" 'Yellow' }
            }
        }
        Say "stamping $selfJob (takes effect on the NEXT run, by design)"
        # 🔴 B8 (2026-09-10) -- AN ARM OPERATION ALREADY IN FLIGHT IS A WAIT, NOT A FAILURE.
        # A customer environment's SUCCESSFUL update ended:
        #     update job not stamped: PATCH ... -> HTTP 409 : ContainerAppsJobOperationInProgress
        #     NOT FULLY UPDATED -- these are still on the previous build: ca-pim-update
        # The Manager had already rolled and was healthy. Only this job's stamp of ITSELF lost a
        # race with another ARM operation on the same resource -- most often the roll we just did.
        # 🪤 §53.4 gave the build-host-side pin advance exactly this bounded backoff and this reasoning.
        # The cloud copy never got it: one defect, two implementations, one of them fixed. That is
        # the split-brain shape this audit keeps finding, so the wait lives here too rather than
        # being "the same idea" written once somewhere neither path loads.
        $stamped = $false; $lastErr = ''
        foreach ($wait in @(0, 10, 20, 40, 60)) {
            if ($wait) { Say "  an operation is still in flight -- retrying in ${wait}s" 'DarkGray'; Start-Sleep -Seconds $wait }
            try {
                [void](Set-PimAcaJobImage -SubscriptionId $sub -ResourceGroup $rg -Name $selfJob -Image $targetImg -ContainerName $jobContainer)
                $stamped = $true; break
            } catch {
                $lastErr = "$($_.Exception.Message)"
                # Only the in-flight case is worth waiting out. Anything else is a real failure and
                # retrying it just delays the report by two minutes.
                if ($lastErr -notmatch '(?i)OperationInProgress|active provisioning operation|\b409\b') { break }
            }
        }
        if (-not $stamped) { throw $lastErr }
        $selfImageBefore = $selfNow; $selfStamped = $true
    } catch {
        # 🔑 AND IT MUST NOT CALL A ROLLED ENVIRONMENT "FAILED".
        # This stamp only decides which image the NEXT run of this job starts from; the update that
        # just completed is unaffected by it. Reporting the whole execution as Failed sent an
        # operator to investigate an environment that had updated correctly and was healthy -- and
        # taught them to distrust a red result, which is the expensive part.
        # The job stays on its current image and will re-stamp on its next run, so this is
        # self-correcting; it is reported as a deferred item, loudly, and does NOT set the exit code.
        $selfStampDeferred = "$($_.Exception.Message)"
        Say "  NOTE: $selfJob could not stamp ITSELF this run: $selfStampDeferred" 'Yellow'
        Say "        The environment DID update and is healthy. This job stays on its current image" 'Yellow'
        Say "        and re-stamps on its next run -- no action needed." 'Yellow'
    }
}

Say "done: $($roll.from) -> $($roll.to) (healthy=$($roll.healthy)); jobs rolled by discovery: $discovered" 'Green'
if ($jobFailed.Count) {
    Say "NOT FULLY UPDATED -- these are still on the previous build: $($jobFailed -join ', ')" 'Red'
    Send-PimUpdateOutcome -Action 'rolled' -Outcome 'failed' -ToVersion "$($roll.to)" -ErrorText "still on the previous build: $($jobFailed -join ', ')"
    exit 1
}
# B8: a deferred SELF-stamp is reported, but it is not a failed update -- see the block above.
if ("$selfStampDeferred".Trim()) {
    Say "UPDATED. One deferred item: this job re-stamps itself on its next run." 'Yellow'
}
# 🔑 THE SUCCESS RECORD IS THE ONE THAT ANSWERS "is this customer stuck?". A fleet view built only
# from failures cannot distinguish an environment that is healthy and current from one whose job
# stopped running altogether -- both are simply absent from it. The last SUCCESS timestamp is the
# signal; that is why 'ok' is reported as loudly as 'failed'.
# 📌 A deferred self-stamp (B8) is still an OK outcome: the environment rolled and is healthy.
# OPEN-13: health = the Manager reached a healthy running revision (checked by the roll) and every job is on the new build.
Set-PimUpdTrackStage -Stage 'health' -Message 'the Manager runs a healthy revision; every job is on the new build'
Send-PimUpdateOutcome -Action 'rolled' -Outcome 'ok' -ToVersion "$($roll.to)"

# ---- 4. §71.44 -- ONE FOLLOW-UP RUN ON THE NEW UPDATER -------------------------------------------
# 🔴 This run was executed by the PREVIOUS updater image, so whatever the new release changed in the
# updater has not happened yet. Measured 2026-09-18: the 2.4.367 updater rolled three environments to
# 2.4.369, whose new ring record (§71.43) therefore never got written, and every Manager said
# "update ring: not recorded" until the next scheduled run. One follow-up on the NEW image does that
# work now: it finds the version already running (no build, no roll) and records/reports as the new
# release does. It can never chain -- its own image already equals the target (see the decision).
# AFTER the outcome above on purpose: the follow-up's record is then the latest one. Never changes the
# exit code -- a follow-up that could not start costs one night's delay, not a failed update.
$fu = Get-PimUpdaterFollowUpDecision -SelfImageBefore $selfImageBefore -TargetImage $targetImg `
        -Stamped $selfStamped -Disable "$($env:PIM_UPDATE_NO_FOLLOWUP)"
if ($fu.start) {
    Say "follow-up: $($fu.reason)" 'Cyan'
    $st = Start-PimAcaJobExecution -SubscriptionId $sub -ResourceGroup $rg -Name $selfJob
    if ($st.ok) { Say "follow-up: started $selfJob execution $($st.execution) on the new updater image" 'Cyan' }
    else {
        Say "  NOTE: the follow-up run could not be started: $($st.reason)" 'Yellow'
        Say "        The environment DID update and is healthy; the new updater runs at its next schedule instead." 'Yellow'
    }
} else { Say "follow-up: none ($($fu.reason))" 'DarkGray' }
exit 0
