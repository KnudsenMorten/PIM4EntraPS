#Requires -Version 5.1
<#
  PIM4EntraPS -- NO-PERSON-DB-ADMIN part D (install time), slices D1 + D2 (framework 12.23 / SEC-08, owner 2026-11-03 "make
  it the rule"; Invardia decision A 2026-11-20). Dot-sourced by tools/setup/Invoke-PimDeployAll.ps1; offline-tested by
  tests/Test-PimDbAdminWindow.ps1.

  THE RULE THIS FILE DECIDES
    A signed-in person running the installer is made a member of the SQL admin group ONLY in the one allowed window: a
    brand-new install, before its database job (ca-pim-dbinit / caj-pim-dbinit, its own identity) exists. There the person
    is added for the run, removed at the end, and the removal is READ BACK; a removal that is refused or cannot be read back
    STOPS the run loudly, naming the step 'sql-admin-release' (never a silent standing admin).
    On an EXISTING install (the database job exists -- or could not be read: an unreadable job is never taken as "absent")
    the person is not added for:
      features  -> NOT written from here (decision A): the gates live in the store, changed in PIM Manager > Settings >
                   Features. A re-run that asks for other gates says so (Get-PimDbAdminSettingsChange, a read-only compare).
      access    -> the same for the SuperAdmins: PIM Manager > Settings > Manager access & roles.
      updater   -> Deploy-PimUpdateJob's database-job route (its database user is made by the job)
      alerting  -> not written from here (PIM Manager > Settings > Alerting; it was never fatal)
      verify-install -> the store is not read as the person (Confirm-PimInstall through the Support app)
      schema    -> (D2) ONE execution of the database job, EMPTY start body, nothing written on the job: the job's own
                   definition (PIM_DBINIT_SCHEMA) upgrades an existing store (engine/_shared/PIM-DbInitSchemaUpgrade.ps1) on its
                   OWN image -- so only when that image carries THIS deploy's version (Get-PimDbAdminSchemaJobFit); otherwise
                   schema stays in the window, named
      code      -> (D2) built and rolled WITHOUT a store connection (Invoke-PimUpdate -StoreViaDatabaseJob) when an update ring
                   governs the roll; with NO ring the roll's ring gate reads the edition from the store (window, named)
    THE EMPTY-START RULE (ACA-START-OVERRIDE + Invardia point 8, decision A): a job start sends the EMPTY body, and the
    deploy writes NO setting on the database job's definition -- no exception.
    STILL OPEN (docs/REQUIREMENTS.md NO-PERSON-DB-ADMIN D2): infra (contained users) and licence still connect as the person.
    A caller that runs its own SQL after the deploy (-SkipInstallVerify / -KeepSetupIdentityInSqlAdminGroup: the guided
    install, the MSP build) keeps the window too and owns its release (Install-PimManager: the same hard stop).

  RULES OF THIS FILE (Test-PimDbAdminWindow Z): ASCII only; PS 5.1 + 7; no modules, no az; no group membership write and no
  job definition write anywhere in it (it only DECIDES, starts the database job with the empty body and reads results).
#>
Set-StrictMode -Off

function Get-PimDbAdminReleaseStepId { <# PURE. LITERAL. The step a refused removal is named by. #> return 'sql-admin-release' }
function Get-PimDbAdminJobRoutedSteps { <# PURE. LITERAL. The deploy steps that do NOT connect as the person on an existing install (D1 + D2). #> return @('features', 'access', 'updater', 'alerting', 'verify-install', 'schema', 'code') }
function Get-PimDbAdminWindowSteps { <# PURE. LITERAL. The deploy steps that still connect as the person (D2 open) -- the window is used only when one RUNS. #> return @('infra', 'licence') }
function Get-PimDbAdminJobApi { <# PURE. LITERAL. #> return '2024-03-01' }
function Get-PimDbAdminSettingsPage {
    <# PURE. LITERAL. Where a setting the deploy no longer writes on an existing install is changed (decision A). #>
    param([Parameter(Mandatory)][ValidateSet('features', 'access')][string]$Kind)
    if ($Kind -eq 'features') { return 'PIM Manager > Settings > Features' }
    return 'PIM Manager > Settings > Manager access & roles'
}

function Get-PimDbAdminCodeNeedsStore {
    <#
      PURE. Does the deploy's 'code' step still need the store (D2)? Its roll's ring gate reads the install's EDITION from the
      store only when NO ring governs the roll -- so: the updater carries a PIM_UPDATE_RING, or this run installs one
      (-PendingRing >= 0) -> $false (the code step runs without the store, nobody added); no ring, or the updater could not be
      read (-UpdaterReadable $false) -> $true (the window, named). Returns @{ needsStore; reason }.
    #>
    param([AllowEmptyString()][string]$UpdaterRing = '', [int]$PendingRing = -1, [bool]$UpdaterReadable = $true)
    if (-not $UpdaterReadable) { return @{ needsStore = $true; reason = "the updater job could not be read, so the roll's ring is not known -- the code step reads the install's edition from the store" } }
    if ("$UpdaterRing".Trim() -match '^\d+$') { return @{ needsStore = $false; reason = "ring $("$UpdaterRing".Trim()) governs the roll -- the code step needs no store read" } }
    if ($PendingRing -ge 0) { return @{ needsStore = $false; reason = "this run installs ring $PendingRing -- the code step needs no store read" } }
    return @{ needsStore = $true; reason = "no update ring on this install -- the roll's ring gate reads the install's edition from the store" }
}

function Get-PimDbAdminSchemaJobFit {
    <#
      PURE. May the deploy's 'schema' step go through the database job (D2, decision A)? The job is started with the EMPTY body
      and nothing is written on it, so it runs its OWN image -- the schema it applies is the schema of THAT version. Through the
      job only when the job's image TAG is this deploy's version (a re-run of the installed version). A digest-pinned image, an
      image of another version, or no job read -> $false (schema stays in the window, named). Returns @{ viaJob; reason }.
    #>
    param([AllowNull()][object]$Job, [AllowEmptyString()][string]$DeployTag = '')
    $c = $null; if ($Job -and $Job.properties -and $Job.properties.template) { $c = @($Job.properties.template.containers) | Select-Object -First 1 }
    $img = "$($c.image)".Trim(); $t = "$DeployTag".Trim()
    if (-not $img) { return @{ viaJob = $false; reason = "the database job's image could not be read -- the schema of this deploy cannot be proven to be in it" } }
    if (-not $t) { return @{ viaJob = $false; reason = "this deploy's version is not known" } }
    $m = [regex]::Match($img, ':(?<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$')
    if (-not $m.Success -or $img -match '@sha256:') { return @{ viaJob = $false; reason = "the database job runs '$img' (no version tag) -- it cannot be proven to carry the schema of $t" } }
    if ("$($m.Groups['tag'].Value)" -ne $t) { return @{ viaJob = $false; reason = "the database job runs version $($m.Groups['tag'].Value), this deploy installs $t -- the job can only apply its own version's schema (an UPDATE through the installer)" } }
    return @{ viaJob = $true; reason = "the database job runs $t, the version this deploy installs" }
}

function Get-PimDbAdminSettingsChange {
    <#
      PURE. Decision A: on an existing install the deploy does NOT write the feature gates / the SuperAdmins. When a re-run
      ASKS for them (-Asked / -AskedDisable non-empty), compare with what the store holds (-Store = a READ-ONLY read
      @{ ok; value; reason }) and SAY when they differ -- never a silent drop, never a write.
        features: differs when an asked gate is not ON in the store, or an asked-to-disable gate IS on. The store value is
                  resolved with Resolve-PimFeatureGate when it is loaded (catalog defaults), else its 'gates' node.
        access  : differs when an asked SuperAdmin is not a SuperAdmin in the store's managerAccess list.
      Returns @{ asked; differs; unknown; lines; detail }  (lines empty = nothing to say).
    #>
    param([Parameter(Mandatory)][ValidateSet('features', 'access')][string]$Kind, [string[]]$Asked = @(), [string[]]$AskedDisable = @(), [AllowNull()][object]$Store)
    $page = Get-PimDbAdminSettingsPage -Kind $Kind
    $what = $(if ($Kind -eq 'features') { 'feature gates' } else { 'Manager SuperAdmins' })
    $ask = @(@($Asked) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $dis = @(@($AskedDisable) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $o = [ordered]@{ asked = [bool]($ask.Count -or $dis.Count); differs = $false; unknown = $false; lines = @(); detail = '' }
    if (-not $o.asked) { $o.detail = "an existing install: the $what are kept as stored and are not written from here ($page)"; return [pscustomobject]$o }
    $askText = $(if ($Kind -eq 'features') { "on: $($ask -join ', ')$(if ($dis.Count) { "; off: $($dis -join ', ')" })" } else { $ask -join ', ' })
    if ($null -eq $Store -or -not $Store.ok) {
        $o.unknown = $true
        $why = $(if ($Store -and "$($Store.reason)".Trim()) { " ($("$($Store.reason)".Trim()))" } else { '' })
        $o.lines = @("NOT APPLIED: this run was given $what ($askText), but on an existing install the deploy does not write them, and the stored $what could not be read to compare$why. If they should change, change them in $page.")
        $o.detail = "not written (existing install); the store could not be read to compare -- $page"
        return [pscustomobject]$o
    }
    $v = $Store.value
    if ($v -is [string]) { $s = "$v".Trim(); $v = $null; if ($s) { try { $v = $s | ConvertFrom-Json } catch { $v = $null } } }
    $diff = @()
    if ($Kind -eq 'features') {
        $on = @{}
        $gates = $null
        if (Get-Command Resolve-PimFeatureGate -ErrorAction SilentlyContinue) { try { $gates = (Resolve-PimFeatureGate -Raw $v).gates } catch { $gates = $null } }
        if ($null -eq $gates -and $v) { $gates = $(if ($v.PSObject.Properties['gates']) { $v.gates } else { $v }) }
        if ($gates -is [System.Collections.IDictionary]) { foreach ($k in @($gates.Keys)) { $g = $gates[$k]; $en = $(if ($g -is [bool]) { $g } elseif ($g -and $g.PSObject.Properties['enabled']) { [bool]$g.enabled } else { [bool]$g }); if ($en) { $on["$k".ToLowerInvariant()] = $true } } }
        elseif ($gates) { foreach ($p in @($gates.PSObject.Properties)) { $g = $p.Value; $en = $(if ($g -is [bool]) { $g } elseif ($g -and $g.PSObject.Properties['enabled']) { [bool]$g.enabled } else { [bool]$g }); if ($en) { $on["$($p.Name)".ToLowerInvariant()] = $true } } }
        foreach ($a in $ask) { if (-not $on.ContainsKey($a.ToLowerInvariant())) { $diff += "$a is OFF in the store" } }
        foreach ($d in $dis) { if ($on.ContainsKey($d.ToLowerInvariant())) { $diff += "$d is ON in the store" } }
    } else {
        $list = @(if ($v -and $v.PSObject.Properties['managerAccess']) { $v.managerAccess } elseif ($v) { $v })
        $have = @($list | Where-Object { $_ -and "$($_.role)" -ieq 'SuperAdmin' } | ForEach-Object { "$($_.identity)".Trim().ToLowerInvariant() } | Where-Object { $_ })
        foreach ($a in $ask) { if ($have -notcontains $a.ToLowerInvariant()) { $diff += "$a is not a SuperAdmin in the store" } }
    }
    if (-not $diff.Count) { $o.detail = "an existing install: the stored $what already match what this run was given (read only; nothing written)"; return [pscustomobject]$o }
    $o.differs = $true
    $o.lines = @("NOT APPLIED: this run asks for $what that differ from the store ($($diff -join '; ')). On an existing install the deploy does not change them -- change them in $page.")
    $o.detail = "differs from the store, NOT written (existing install) -- change it in $page"
    return [pscustomobject]$o
}

function Get-PimDbAdminStepRoute {
    <#
      PURE. Where ONE deploy step's database work goes in a mode.
        mode 'database-job': features / access / alerting -> 'manager'; updater / schema -> 'database-job' (schema only when the
                             job's own image fits); code -> 'no-store' under a ring; verify-install -> 'not-read'; infra /
                             licence (and schema / code when they do not fit) -> 'window'; others -> 'none'
        mode 'window'      : every SQL step -> 'window'
        mode 'none'        : 'none'
      Returns @{ step; route; text }.
    #>
    param([Parameter(Mandatory)][string]$Step, [ValidateSet('none', 'database-job', 'window')][string]$Mode = 'none', [string]$DbJobName = 'ca-pim-dbinit',
          [bool]$CodeNeedsStore = $true, [bool]$SchemaViaJob = $false)
    $k = "$Step".Trim().ToLowerInvariant()
    $sql = @(@(Get-PimDbAdminJobRoutedSteps) + @(Get-PimDbAdminWindowSteps))
    if ($Mode -eq 'none' -or $sql -notcontains $k) { return @{ step = $k; route = 'none'; text = "$k -- no database admin needed" } }
    if ($Mode -eq 'window') { return @{ step = $k; route = 'window'; text = "$k -- as the signed-in person inside the time-boxed window" } }
    switch ($k) {
        'features'       { return @{ step = $k; route = 'manager'; text = "features -- not written from here: $(Get-PimDbAdminSettingsPage -Kind 'features') (the stored gates are kept; a different ask is SAID)" } }
        'access'         { return @{ step = $k; route = 'manager'; text = "access -- not written from here: $(Get-PimDbAdminSettingsPage -Kind 'access') (the stored SuperAdmins are kept; a different ask is SAID)" } }
        'updater'        { return @{ step = $k; route = 'database-job'; text = "updater -- the updater's database user through the database job '$DbJobName' (Deploy-PimUpdateJob's database-job route)" } }
        'alerting'       { return @{ step = $k; route = 'manager'; text = 'alerting -- not written from here: PIM Manager > Settings > Alerting (an existing list is kept)' } }
        'verify-install' { return @{ step = $k; route = 'not-read'; text = 'verify-install -- the store is not read as the person: Confirm-PimInstall.ps1 through the Invardia Support app' } }
        'schema'         { if ($SchemaViaJob) { return @{ step = $k; route = 'database-job'; text = "schema -- through the database job '$DbJobName' (one execution, the EMPTY start body: its own definition upgrades the store on its own image, this deploy's version; its own identity)" } }
                           return @{ step = $k; route = 'window'; text = "schema -- STILL as the signed-in person (NO-PERSON-DB-ADMIN D2): the database job's image is not this deploy's version, and nothing may be written on the job -- the time-boxed window, removed at the end, read back" } }
        'code'           { if (-not $CodeNeedsStore) { return @{ step = $k; route = 'no-store'; text = 'code -- built and rolled WITHOUT a store connection (the update ring governs the roll)' } }
                           return @{ step = $k; route = 'window'; text = 'code -- STILL as the signed-in person (NO-PERSON-DB-ADMIN D2): no update ring on this install, so the roll reads its edition from the store -- the time-boxed window, removed at the end, read back' } }
    }
    return @{ step = $k; route = 'window'; text = "$k -- STILL as the signed-in person (NO-PERSON-DB-ADMIN D2 open): the time-boxed window -- added for this run, removed at the end, read back" }
}

function ConvertTo-PimDbJobState {
    <#
      PURE. The database job's state from one read: -Job = the job object ($null = not found); -ReadError = the read's error
      text ('' = the read worked). A read that FAILED is 'unknown' -- never 'absent', so a refused read can never open the
      new-install window on an existing install. Returns 'present' | 'absent' | 'unknown'.
    #>
    param([AllowNull()][object]$Job, [AllowEmptyString()][string]$ReadError = '')
    if ("$ReadError".Trim()) { return 'unknown' }
    if ($null -ne $Job -and "$($Job.name)".Trim()) { return 'present' }
    return 'absent'
}

function Get-PimDeployDbAdminPlan {
    <#
      PURE. NO-PERSON-DB-ADMIN D1 + D2 -- what THIS deploy does about the SQL admin group for the signed-in person.
        -SignedIn         : the deploy runs as a signed-in person (-UseSignedInAccount)
        -PublicSql        : a public SQL endpoint this host connects to (private SQL never adds the person -- the job does it all)
        -DbJobState       : ConvertTo-PimDbJobState's answer
        -RunSteps         : the deploy steps that RUN this time (plan steps with do = $true)
        -CallerOwnsWindow : the caller runs its own SQL after the deploy and releases the person itself
        -CodeNeedsStore   : Get-PimDbAdminCodeNeedsStore's answer ($true, the default, keeps 'code' in the window)
        -SchemaViaJob     : Get-PimDbAdminSchemaJobFit's answer ($false, the default, keeps 'schema' in the window)
      Returns @{ mode; addPerson; windowSteps; jobSteps; releaseAtEnd; lines; codeNeedsStore; schemaViaJob }.
    #>
    param([bool]$SignedIn, [bool]$PublicSql, [ValidateSet('present', 'absent', 'unknown')][string]$DbJobState = 'unknown',
          [string[]]$RunSteps = @(), [bool]$CallerOwnsWindow = $false, [string]$DbJobName = 'ca-pim-dbinit',
          [bool]$CodeNeedsStore = $true, [bool]$SchemaViaJob = $false)
    $run = @(@($RunSteps) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
    $sqlSteps = @(@(Get-PimDbAdminJobRoutedSteps) + @(Get-PimDbAdminWindowSteps))
    $o = [ordered]@{ mode = 'none'; addPerson = $false; windowSteps = @(); jobSteps = @(); releaseAtEnd = $false; lines = @(); codeNeedsStore = [bool]$CodeNeedsStore; schemaViaJob = [bool]$SchemaViaJob }
    if (-not $SignedIn) { $o.lines = @('SQL admin group: not a signed-in deploy -- no person is added'); return [pscustomobject]$o }
    if (-not $PublicSql) { $o.lines = @('SQL admin group: private SQL -- the signed-in person is never added (the database job does the database work from inside)'); return [pscustomobject]$o }
    $runSql = @($run | Where-Object { $sqlSteps -contains $_ })
    $rel = Get-PimDbAdminReleaseStepId
    if ($CallerOwnsWindow -or $DbJobState -eq 'absent') {
        $o.mode = 'window'
        $o.windowSteps = @($runSql)
        $o.addPerson = [bool]$runSql.Count
        $o.releaseAtEnd = [bool]$runSql.Count
        $why = $(if ($DbJobState -eq 'absent') { "a brand-new install: the database job '$DbJobName' does not exist yet" } else { 'the caller runs its own database steps after this deploy and releases you itself (NO-PERSON-DB-ADMIN D2 open)' })
        $l = New-Object System.Collections.Generic.List[string]
        if ($runSql.Count) {
            $l.Add("SQL admin group: the time-boxed window -- $why. You are added for this run (steps $($runSql -join ', ')), removed at the end and the removal read back; a refused removal STOPS the run at step '$rel'.")
        } else { $l.Add("SQL admin group: no database step runs -- you are not added ($why)") }
        $o.lines = @($l.ToArray())
        return [pscustomobject]$o
    }
    # an EXISTING install (present), or one whose database job could not be read (unknown: never taken as new)
    $inWindow = { param($s) (@(Get-PimDbAdminWindowSteps) -contains $s) -or ($s -eq 'code' -and $CodeNeedsStore) -or ($s -eq 'schema' -and -not $SchemaViaJob) }
    $o.mode = 'database-job'
    $o.jobSteps = @($runSql | Where-Object { @(Get-PimDbAdminJobRoutedSteps) -contains $_ -and -not (& $inWindow $_) })
    $o.windowSteps = @($runSql | Where-Object { & $inWindow $_ })
    $o.addPerson = [bool]$o.windowSteps.Count
    $o.releaseAtEnd = $true
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add($(if ($DbJobState -eq 'present') { "SQL admin group: an EXISTING install -- the database job '$DbJobName' exists, so no step connects as you unless named below" }
             else { "SQL admin group: the database job '$DbJobName' could not be read -- treated as an EXISTING install (an unreadable job never opens the new-install window)" }))
    foreach ($s in @(@($o.jobSteps) + @($o.windowSteps))) { $l.Add("  $((Get-PimDbAdminStepRoute -Step $s -Mode 'database-job' -DbJobName $DbJobName -CodeNeedsStore $CodeNeedsStore -SchemaViaJob $SchemaViaJob).text)") }
    if ($o.windowSteps.Count) { $l.Add("  -> you are added ONLY for $($o.windowSteps -join ', '); removed at the end and read back; a refused removal STOPS the run at step '$rel'") }
    else { $l.Add('  -> the signed-in person is NOT added to the SQL admin group by this run') }
    $o.lines = @($l.ToArray())
    return [pscustomobject]$o
}

function Test-PimDbAdminAddAllowed {
    <#
      PURE. May the deploy make the signed-in person a member of the SQL admin group BEFORE this step? No plan = today's
      behaviour ($true; the caller decides). mode 'none' = $false (nothing to add); 'window' = $true; 'database-job' = only
      for a step in the plan's window this run really runs.
    #>
    param([AllowNull()][object]$Plan, [AllowEmptyString()][string]$Step = '')
    if ($null -eq $Plan) { return $true }
    switch ("$($Plan.mode)") {
        'window'       { return $true }
        'database-job' { return (@($Plan.windowSteps) -contains "$Step".Trim().ToLowerInvariant()) }
    }
    return $false
}

function Test-PimDbAdminJobRoute {
    <# PURE. Does this step NOT connect as the person in this plan (the database job, the Manager, no store, not read)? #>
    param([AllowNull()][object]$Plan, [Parameter(Mandatory)][string]$Step)
    if ($null -eq $Plan -or "$($Plan.mode)" -ne 'database-job') { return $false }
    $k = "$Step".Trim().ToLowerInvariant()
    if (@($Plan.windowSteps) -contains $k) { return $false }
    # code / schema only when the plan SAID they fit (an absent answer = the window side)
    if ($k -eq 'code' -and -not ($Plan.PSObject.Properties['codeNeedsStore'] -and $Plan.codeNeedsStore -eq $false)) { return $false }
    if ($k -eq 'schema' -and -not ($Plan.PSObject.Properties['schemaViaJob'] -and $Plan.schemaViaJob -eq $true)) { return $false }
    return (@(Get-PimDbAdminJobRoutedSteps) -contains $k)
}

function Get-PimDbJobIdentityPrincipal {
    <#
      PURE. The database job's OWN identity: the user-assigned identity whose client id is the job's PIM_DBINIT_MI_CLIENT_ID.
      Returns @{ ok; principalId; resourceId; reason }.
    #>
    param([AllowNull()][object]$Job)
    $c = $null; if ($Job -and $Job.properties -and $Job.properties.template) { $c = @($Job.properties.template.containers) | Select-Object -First 1 }
    $cid = "$((@(@($c.env) | Where-Object { $_ -and "$($_.name)" -ceq 'PIM_DBINIT_MI_CLIENT_ID' }) | Select-Object -First 1).value)".Trim()
    if (-not $cid) { return @{ ok = $false; principalId = ''; resourceId = ''; reason = 'the database job names no identity of its own (PIM_DBINIT_MI_CLIENT_ID)' } }
    $ua = $null; if ($Job.identity -and $Job.identity.PSObject.Properties['userAssignedIdentities']) { $ua = $Job.identity.userAssignedIdentities }
    if ($ua) {
        foreach ($p in @($ua.PSObject.Properties)) {
            if ("$($p.Value.clientId)".Trim() -ieq $cid) { return @{ ok = $true; principalId = "$($p.Value.principalId)".Trim(); resourceId = "$($p.Name)"; reason = '' } }
        }
    }
    return @{ ok = $false; principalId = ''; resourceId = ''; reason = "the identity $cid the database job signs in as is not attached to it" }
}

function Invoke-PimDeployDbJobRun {
    <#
      ONE execution of an EXISTING database job for the deploy (NO-PERSON-DB-ADMIN D2, decision A): read the job, its identity
      read back as a member of the SQL admin group (Invoke-PimDbInitMembershipBeforeStart, the same gate setup uses -- the JOB
      identity, never the person), start it with the EMPTY body (ACA-START-OVERRIDE; nothing is written on the job), wait,
      read the status. The job runs what its own definition says. Never throws.
        -Arm / -Graph : param($Method, $Path, $Body) invokers (New-PimSqlAdminGroupInvokers); -Sleep: param($Seconds)
        -SqlResourceGroupId : /subscriptions/<sub>/resourceGroups/<the SQL server's group>
      Returns @{ ok; execution; status; reason }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [AllowNull()][scriptblock]$Graph, [Parameter(Mandatory)][string]$SubscriptionId,
          [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$JobName, [Parameter(Mandatory)][string]$SqlServerFqdn,
          [string]$SqlResourceGroupId = '', [scriptblock]$Sleep = { param([int]$Seconds) Start-Sleep -Seconds $Seconds },
          [int]$PollSeconds = 10, [int]$MaxPolls = 60, [switch]$SkipMembershipGate)
    $o = [ordered]@{ ok = $false; execution = ''; status = ''; reason = '' }
    $api = Get-PimDbAdminJobApi
    $jobPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName"
    try {
        $job = $null
        try { $job = & $Arm 'GET' "$jobPath`?api-version=$api" $null } catch { $o.reason = "the database job '$JobName' could not be read: $($_.Exception.Message)"; return [pscustomobject]$o }
        if (-not $job -or -not "$($job.name)".Trim()) { $o.reason = "the database job '$JobName' was not found -- not started"; return [pscustomobject]$o }
        if (-not $SkipMembershipGate) {
            if (-not (Get-Command Invoke-PimDbInitMembershipBeforeStart -ErrorAction SilentlyContinue)) { $o.reason = 'the membership gate (engine/_shared/PIM-DbInitMembership.ps1) is not loaded -- the database job is not started'; return [pscustomobject]$o }
            $idp = Get-PimDbJobIdentityPrincipal -Job $job
            if (-not $idp.ok) { $o.reason = "$($idp.reason) -- the database job is not started"; return [pscustomobject]$o }
            $rgId = $(if ("$SqlResourceGroupId".Trim()) { "$SqlResourceGroupId".Trim() } else { "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup" })
            $gate = Invoke-PimDbInitMembershipBeforeStart -Arm $Arm -Graph $Graph -ResourceGroupId $rgId -SqlServer $SqlServerFqdn -IdentityResourceId $idp.resourceId -IdentityPrincipalId $idp.principalId -Sleep $Sleep
            if (-not $gate.start) { $o.reason = "the database job's identity is not read back in the SQL admin group -- not started: $($gate.reason)"; return [pscustomobject]$o }
        }
        $exec = ''
        foreach ($try in 1, 2) {
            try {
                $st = & $Arm 'POST' "$jobPath/start?api-version=$api" @{}
                $exec = "$($st.name)"; if (-not $exec -and $st -and $st.PSObject.Properties['id']) { $exec = ("$($st.id)" -split '/')[-1] }
                if ($exec) { break }
            } catch { if ($try -eq 2) { $o.reason = "the database job '$JobName' could not be started: $($_.Exception.Message)"; return [pscustomobject]$o }; & $Sleep 10 }
        }
        if (-not $exec) { $o.reason = "the database job '$JobName' did not start (no execution name)"; return [pscustomobject]$o }
        $o.execution = $exec
        $status = ''
        for ($i = 0; $i -lt [Math]::Max(1, $MaxPolls); $i++) {
            & $Sleep $PollSeconds
            try { $status = "$((& $Arm 'GET' "$jobPath/executions/$exec`?api-version=$api" $null).properties.status)".Trim() } catch { $status = '' }
            if ($status -in @('Succeeded', 'Failed', 'Degraded', 'Stopped')) { break }
        }
        $o.status = $status
        if ($status -eq 'Succeeded') { $o.ok = $true; $o.reason = "the database job '$JobName' ran $exec -- Succeeded (its own definition and identity; you were not added)" }
        else { $o.reason = "the database job '$JobName' execution $exec ended '$(if ($status) { $status } else { 'not finished' })' -- its log is in the environment's Log Analytics workspace (ContainerAppConsoleLogs_CL, ContainerGroupName_s startswith '$exec')" }
    } catch { $o.ok = $false; $o.reason = "the database job run stopped: $($_.Exception.Message)" }
    return [pscustomobject]$o
}

function Get-PimDbAdminReleaseVerdict {
    <#
      PURE. After the signed-in person's release (Invoke-PimSqlAdminGroupSetupRelease's result; $null = it threw or never
      answered): STOP or not. A removal that was refused, could not be checked or is not read back = STOP, naming the step
      -- never a silent standing admin. -Applies $false (no signed-in person) = never a stop from here.
      Returns @{ stop; step; message }.
    #>
    param([AllowNull()][object]$Release, [bool]$Applies = $true, [AllowEmptyString()][string]$ErrorText = '')
    $step = Get-PimDbAdminReleaseStepId
    if (-not $Applies) { return @{ stop = $false; step = $step; message = '' } }
    if ($null -eq $Release) {
        return @{ stop = $true; step = $step; message = "STOPPED at step '$step': your membership of the SQL admin group could not be checked or removed$(if ("$ErrorText".Trim()) { " ($ErrorText)" }). You may still be a database admin -- a Privileged Role Administrator removes you (Entra admin center > Groups > the SQL admin group > Members), then run this again." }
    }
    $ok = $false; $reason = ''
    if ($Release -is [System.Collections.IDictionary]) { $ok = [bool]$Release['ok']; $reason = "$($Release['reason'])" } else { $ok = [bool]$Release.ok; $reason = "$($Release.reason)" }
    if ($ok) { return @{ stop = $false; step = $step; message = "step '$step': $reason" } }
    return @{ stop = $true; step = $step; message = "STOPPED at step '$step': $reason" }
}
