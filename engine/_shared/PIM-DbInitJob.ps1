#Requires -Version 5.1
<#
.SYNOPSIS
    PIM OPEN-06 / NO-PERSON-DB-ADMIN -- the in-network database job (ca-pim-dbinit, manual trigger) on EVERY install, public
    ones included, maintained by the in-cloud UPDATER with a DEDICATED identity. The updater creates it when it is missing
    and NEVER starts it; the setup step 'db-job' reports what is really in place (job, version, identity in the SQL admin
    group). No person needs database admin: the Support app starts the job when a database change needs an admin.

.DESCRIPTION
    PURE first (Get-PimDbInitJobSpec, Resolve-PimDbInitIdentity, Get-PimDbInitSetupState), then the one converge the updater
    calls (Invoke-PimDbInitJobConverge: ARM + Graph through seams; never throws; never starts the job).
    RULES OF THIS FILE (Test-PimDbInitJob Z):
      * no role assignment and no group membership write anywhere in it (Test-PimScriptDocs B2; the rule in the header of
        engine/_shared/PIM-JobSelfId.ps1): the membership of the SQL admin group is READ, never written;
      * an existing job gets NO write here (its image is rolled by the updater's job roll, step 2b);
      * the job definition the updater writes carries no PIM_DBINIT_SQL_ACCESS and no PIM_DBINIT_MANAGER_ACCESS.
    ASCII only; PS 5.1 + 7; no modules, no az.
#>
Set-StrictMode -Off

function Get-PimDbInitJobEntryPath { return '/app/PIM4EntraPS/tools/pim-engine/dbinit-job-entry.ps1' }
function Get-PimDbInitIdentityNameDefault { if (Get-Command Get-PimInstallName -ErrorAction SilentlyContinue) { return (Get-PimInstallName -Role dbinitIdentity) }; return 'id-pim-dbinit' }
function Get-PimDbInitEnvAllowList {
    # PURE. The only settings a database job definition may carry (a literal-returning function: child-scope safe).
    return @('PIM_SqlServer', 'PIM_SqlDatabase', 'PIM_DBINIT_PRINCIPALS', 'PIM_DBINIT_SCHEMA', 'PIM_DBINIT_SQL_ACCESS', 'PIM_DBINIT_MI_CLIENT_ID',
             'PIM_DBINIT_FEATURE_GATES', 'PIM_DBINIT_FEATURE_DISABLE', 'PIM_DBINIT_MANAGER_ACCESS', 'PIM_DBINIT_UPDATE_SEED')
}

function Get-PimDbInitJobName {
    <#
      PURE (with -Record). THE name of this install's database job: the install record's 'dbinit' when it names one; else a
      new-name install (its web app is the CR5 name) -> the CR5 job name; else today's name.
    #>
    param([AllowEmptyString()][string]$ManagerApp = '', [AllowNull()][object]$Record = $null)
    $today = 'ca-pim-dbinit'; $new = 'caj-pim-dbinit'; $newWeb = 'ca-pim-web'
    if (Get-Command Get-PimInstallNameDefaults -ErrorAction SilentlyContinue) {
        $d = Get-PimInstallNameDefaults; $n = Get-PimInstallNameNewDefaults
        if ($d.Contains('dbinit')) { $today = "$($d['dbinit'])" }; if ($n.Contains('dbinit')) { $new = "$($n['dbinit'])" }; $newWeb = "$($n['web'])"
    }
    if ($null -ne $Record) {
        $v = ''
        if ($Record -is [System.Collections.IDictionary]) { if ($Record.Contains('dbinit')) { $v = "$($Record['dbinit'])".Trim() } }
        elseif ($Record.PSObject.Properties['dbinit']) { $v = "$($Record.dbinit)".Trim() }
        if ($v -match '^[A-Za-z0-9][A-Za-z0-9._-]{1,89}$') { return $v }
    }
    if ("$ManagerApp".Trim() -ieq $newWeb) { return $new }
    return $today
}

function Get-PimDbInitJobSpec {
    <#
      PURE. The database job (ca-pim-dbinit): MANUAL trigger, one replica, no retry, 7 days (framework 12.24), 0.5 CPU / 1.0Gi.
      Command = @('pwsh') and args = the token list IN THE ARM BODY -- never a multi-token --command (the az-era trap:
          az exit 2: ERROR: unrecognized arguments: -NoProfile,-File,/app/.../dbinit-job-entry.ps1
      az took only the FIRST token after --command; the worker containers, Deploy-PimUpdateJob and this job each learned it).
      Identity: 'SystemAssigned,UserAssigned' as ONE value with -IdentityResourceIds (the YAML era lost the second half and ARM
      refused the ids); no ids = SystemAssigned. The identity block is written on CREATE only (-Exists: an update carrying it
      failed "Request requires identities to be assigned").
      -Env: an ordered map from a CLOSED allow-list (Get-PimDbInitEnvAllowList); PIM_DBINIT_MANAGER_ACCESS is REFUSED unless
      -SetupManagerAccess (only setup writes it -- the updater never does); a value that looks like a credential is REFUSED.
      Returns @{ ok; reason; env; resource }.
    #>
    param(
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][string]$Image,
        [Parameter(Mandatory)][string]$EnvironmentId,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$RegistryServer,
        [string]$RegistryIdentity = 'system',
        [AllowNull()][System.Collections.IDictionary]$Env = $null,
        [switch]$Exists,
        [string[]]$IdentityResourceIds = @(),
        [string]$EntryPath = (Get-PimDbInitJobEntryPath),
        [switch]$SetupManagerAccess
    )
    $allow = Get-PimDbInitEnvAllowList
    $envOut = [ordered]@{}
    if ($Env) {
        foreach ($k in @($Env.Keys)) {
            $kn = "$k".Trim()
            if ($kn -cnotin $allow) { return @{ ok = $false; reason = "REFUSED: '$kn' is not a setting of the database job (allowed: $($allow -join ', '))" } }
            if ($kn -ceq 'PIM_DBINIT_MANAGER_ACCESS' -and -not $SetupManagerAccess) { return @{ ok = $false; reason = 'REFUSED: PIM_DBINIT_MANAGER_ACCESS is written by setup only (-SetupManagerAccess) -- the updater never names who is a SuperAdmin' } }
            $v = "$($Env[$k])"
            if ($v -match '(?i)([?&]sig=|AccountKey=|SharedAccessKey=|-----BEGIN|secretref:|client_secret|password\s*=)') {
                return @{ ok = $false; reason = "REFUSED: '$kn' looks like a credential -- the database job runs as its managed identity and carries none" }
            }
            $envOut[$kn] = $v
        }
    }
    $ids = @(@($IdentityResourceIds) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    foreach ($i in $ids) {
        if ($i -notmatch '(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/[A-Za-z0-9][A-Za-z0-9_-]{2,127}$') { return @{ ok = $false; reason = "'$i' is not a user-assigned identity resource id" } }
    }
    $identity = @{ type = 'SystemAssigned' }
    if ($ids.Count) {
        $uaMap = [ordered]@{}; foreach ($u in $ids) { $uaMap[$u] = @{} }
        $identity = @{ type = 'SystemAssigned,UserAssigned'; userAssignedIdentities = $uaMap }
    }
    $regId = "$RegistryIdentity".Trim(); if (-not $regId) { $regId = 'system' }
    $envList = @(foreach ($k in @($envOut.Keys)) { @{ name = $k; value = "$($envOut[$k])" } })
    $props = @{
        environmentId = $EnvironmentId
        configuration = @{
            triggerType         = 'Manual'
            replicaTimeout      = 604800   # framework 12.24 JOB-RUN-LIMIT: 7 days
            replicaRetryLimit   = 0
            manualTriggerConfig = @{ parallelism = 1; replicaCompletionCount = 1 }
            registries          = @(@{ server = $RegistryServer; identity = $regId })
        }
        template = @{
            containers = @(@{
                name      = $JobName
                image     = $Image
                command   = @('pwsh')
                args      = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $EntryPath)
                env       = @($envList)
                resources = @{ cpu = 0.5; memory = '1.0Gi' }
            })
        }
    }
    $res = @{ location = $Location; properties = $props }
    if (-not $Exists) { $res['identity'] = $identity }
    return @{ ok = $true; reason = ''; env = $envOut; resource = $res }
}

function Get-PimDbInitObjField {
    # PURE. A property of an object or a dictionary ($null when absent).
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Get-PimDbInitUaMap {
    # PURE. A resource's userAssignedIdentities as @( @{ id; clientId; principalId } ) (objects from ARM or dictionaries).
    param([AllowNull()][object]$Resource)
    $ua = Get-PimDbInitObjField (Get-PimDbInitObjField $Resource 'identity') 'userAssignedIdentities'
    if ($null -eq $ua) { return @() }
    $pairs = if ($ua -is [System.Collections.IDictionary]) { @($ua.Keys | ForEach-Object { @{ k = "$_"; v = $ua[$_] } }) } else { @($ua.PSObject.Properties | ForEach-Object { @{ k = "$($_.Name)"; v = $_.Value } }) }
    return @($pairs | ForEach-Object { @{ id = $_.k; clientId = "$(Get-PimDbInitObjField $_.v 'clientId')".Trim(); principalId = "$(Get-PimDbInitObjField $_.v 'principalId')".Trim() } })
}

function Get-PimDbInitJobEnv {
    # PURE. The job's settings (first container) as a hashtable.
    param([AllowNull()][object]$Job)
    $h = @{}
    $c = @(@((Get-PimDbInitObjField (Get-PimDbInitObjField (Get-PimDbInitObjField $Job 'properties') 'template') 'containers')) | Where-Object { $_ })[0]
    foreach ($e in @((Get-PimDbInitObjField $c 'env'))) { $n = "$(Get-PimDbInitObjField $e 'name')"; if ($n) { $h[$n] = "$(Get-PimDbInitObjField $e 'value')" } }
    return $h
}

function Resolve-PimDbInitIdentity {
    <#
      PURE. Which identity the database job runs as:
        keep    the job EXISTS -> its identities are untouched (the one it signs in with: PIM_DBINIT_MI_CLIENT_ID among the
                user-assigned identities it carries)
        reuse   -DedicatedName (id-pim-dbinit) already in the resource group, or EXACTLY ONE ^id-pim-sql(-|$) identity there
        create  -DedicatedName
        refuse  the dedicated identity exists but an app carries it -- nothing is chosen
      An identity the Manager app or ANY container app carries (-Carried: resource ids) is NEVER chosen (internal's shared
      app identity is that case): the job would sign in to the database as the web app.
      -Identities: the user-assigned identities in the resource group (ARM list: id; name; properties.clientId/principalId).
      Returns @{ action; name; resourceId; clientId; principalId; dedicated; reason; notes }.
    #>
    param([AllowNull()][object]$Job, [object[]]$Identities = @(), [string[]]$Carried = @(),
          [Parameter(Mandatory)][string]$ResourceGroupId, [string]$DedicatedName = (Get-PimDbInitIdentityNameDefault))
    $leaf = { param($id) (("$id" -split '/') | Where-Object { $_ })[-1] }
    $carriedSet = @{}; foreach ($c in @($Carried | Where-Object { "$_".Trim() })) { $carriedSet["$c".Trim().ToLowerInvariant()] = $true; $carriedSet[("name:" + (& $leaf $c)).ToLowerInvariant()] = $true }
    $isCarried = { param($id) $carriedSet.ContainsKey("$id".Trim().ToLowerInvariant()) -or $carriedSet.ContainsKey(("name:" + (& $leaf $id)).ToLowerInvariant()) }
    $notes = New-Object System.Collections.Generic.List[string]
    $out = [ordered]@{ action = ''; name = ''; resourceId = ''; clientId = ''; principalId = ''; dedicated = $false; reason = ''; notes = $null }
    $fin = { $out.notes = @($notes.ToArray()); return $out }
    if ($Job) {
        $out.action = 'keep'
        $cid = "$((Get-PimDbInitJobEnv -Job $Job)['PIM_DBINIT_MI_CLIENT_ID'])".Trim()
        $m = @(Get-PimDbInitUaMap -Resource $Job | Where-Object { $cid -and $_.clientId -ieq $cid })[0]
        if ($m) { $out.name = & $leaf $m.id; $out.resourceId = $m.id; $out.clientId = $m.clientId; $out.principalId = $m.principalId; $out.reason = "the existing job's identity $($out.name) is kept (untouched)" }
        else { $out.reason = 'the existing job names no user-assigned identity it signs in to the database with (PIM_DBINIT_MI_CLIENT_ID) -- kept as it is' }
        $out.dedicated = ($out.name -and $out.name -ieq $DedicatedName)
        return (& $fin)
    }
    $ids = @(@($Identities) | Where-Object { $_ -and "$(Get-PimDbInitObjField $_ 'id')".Trim() })
    $pick = { param($o, $why) $out.name = "$(Get-PimDbInitObjField $o 'name')"; if (-not $out.name) { $out.name = & $leaf (Get-PimDbInitObjField $o 'id') }
              $out.resourceId = "$(Get-PimDbInitObjField $o 'id')"; $p = Get-PimDbInitObjField $o 'properties'
              $out.clientId = "$(Get-PimDbInitObjField $p 'clientId')".Trim(); $out.principalId = "$(Get-PimDbInitObjField $p 'principalId')".Trim(); $out.reason = $why }
    $ded = @($ids | Where-Object { (& $leaf (Get-PimDbInitObjField $_ 'id')) -ieq $DedicatedName })[0]
    if ($ded) {
        if (& $isCarried (Get-PimDbInitObjField $ded 'id')) {
            $out.action = 'refuse'; $out.name = $DedicatedName; $out.reason = "REFUSED: $DedicatedName is carried by a container app -- the database job never shares an app's identity"
            return (& $fin)
        }
        $out.action = 'reuse'; $out.dedicated = $true; & $pick $ded "the dedicated identity $DedicatedName already exists"
        return (& $fin)
    }
    $sql = @($ids | Where-Object { (& $leaf (Get-PimDbInitObjField $_ 'id')) -match '^(?i)id-pim-sql(-|$)' })
    if ($sql.Count -eq 1) {
        if (& $isCarried (Get-PimDbInitObjField $sql[0] 'id')) { [void]$notes.Add("$(& $leaf (Get-PimDbInitObjField $sql[0] 'id')) is carried by a container app -- not used") }
        else { $out.action = 'reuse'; & $pick $sql[0] "the install's one SQL identity $(& $leaf (Get-PimDbInitObjField $sql[0] 'id')) is reused"; return (& $fin) }
    } elseif ($sql.Count -gt 1) { [void]$notes.Add("$($sql.Count) id-pim-sql identities in the resource group -- none is guessed") }
    $out.action = 'create'; $out.dedicated = $true; $out.name = $DedicatedName
    $out.resourceId = "$("$ResourceGroupId".TrimEnd('/'))/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$DedicatedName"
    $out.reason = "the dedicated identity $DedicatedName is created"
    return (& $fin)
}

function Get-PimDbInitImageTag {
    # PURE. The tag of an image reference ('' when none).
    param([AllowEmptyString()][string]$Image)
    if ("$Image".Trim() -notmatch ':([^:/@]+)$') { return '' }
    return $Matches[1]
}

function Get-PimDbInitSetupState {
    <#
      PURE. The setup step 'db-job' from Invoke-PimDbInitJobConverge's result. A state is READ, never inferred:
        ok       the job is there, on the Manager's version, and its identity is a member of the SQL admin group (read)
        missing  WHICH: no job (+ why) / the identity not a member of the group / the SQL Entra admin is not a group /
                 the job on another version
        unknown  no result (not converged this run), or the membership could not be read
      An existing job that still carries PIM_DBINIT_MANAGER_ACCESS on its definition is SAID (report only; never removed here).
      Returns [ordered]@{ dbJob; dbJobDetail } (detail <= 200 characters).
    #>
    param([AllowNull()][object]$Result)
    $f = { param($n) Get-PimDbInitObjField $Result $n }
    $cut = { param($t) $t = ("$t" -replace '[\r\n\t]+', ' ').Trim(); if ($t.Length -gt 200) { $t = $t.Substring(0, 197) + '...' }; $t }
    if ($null -eq $Result) { return [ordered]@{ dbJob = 'unknown'; dbJobDetail = 'database job: not checked this run' } }
    $job = "$(& $f 'jobName')"; if (-not $job) { $job = 'the database job' }
    $idn = "$(& $f 'identityName')"
    $grp = "$(& $f 'adminName')"
    $miss = New-Object System.Collections.Generic.List[string]
    if (-not [bool](& $f 'present')) {
        $why = "$(& $f 'reason')".Trim()
        return [ordered]@{ dbJob = 'missing'; dbJobDetail = (& $cut ("no $job$(if ($why) { ": $why" })")) }
    }
    $state = 'ok'
    if ((& $f 'onVersion') -ne $true) { [void]$miss.Add("$job runs $(if ("$(& $f 'imageTag')") { "$(& $f 'imageTag')" } else { 'an unreadable image' }), the Manager $(& $f 'managerImageTag')") }
    $aig = & $f 'adminIsGroup'; $iag = & $f 'inAdminGroup'
    if ($aig -eq $false) { [void]$miss.Add('the SQL Entra admin is not a group') }
    elseif ($iag -eq $false) { [void]$miss.Add("identity $(if ($idn) { $idn } else { '(none named)' }) is not a member of the SQL admin group$(if ($grp) { " $grp" })") }
    $note = if ([bool](& $f 'managerAccessOnDefinition')) { "; $job still carries PIM_DBINIT_MANAGER_ACCESS on its definition (report only)" } else { '' }
    if ($miss.Count) { return [ordered]@{ dbJob = 'missing'; dbJobDetail = (& $cut ("missing: $($miss -join '; ')$note")) } }
    if ($null -eq $aig -or $null -eq $iag) {
        $why = "$(& $f 'membershipReason')".Trim()
        return [ordered]@{ dbJob = 'unknown'; dbJobDetail = (& $cut ("$job is there; the SQL admin group membership of $(if ($idn) { $idn } else { 'its identity' }) could not be read$(if ($why) { " ($why)" })$note")) }
    }
    return [ordered]@{ dbJob = $state; dbJobDetail = (& $cut ("$job on $(& $f 'imageTag'), identity $idn in the SQL admin group$(if ($grp) { " $grp" })$note")) }
}

function Read-PimDbInitAdminMembership {
    <#
      READ ONLY. Is -PrincipalId a member of the SQL server's Entra admin group? ARM GET of the server's administrators;
      principalType not Group -> adminIsGroup $false; else Graph GET of the group's service-principal members (paged).
      Any failure -> $null (unknown). Never writes, never throws. Returns @{ adminIsGroup; inAdminGroup; adminName; reason }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [AllowNull()][scriptblock]$Graph, [Parameter(Mandatory)][string]$ResourceGroupId,
          [AllowEmptyString()][string]$SqlServer, [AllowEmptyString()][string]$PrincipalId)
    $o = @{ adminIsGroup = $null; inAdminGroup = $null; adminName = ''; reason = '' }
    $srv = ("$SqlServer".Trim() -split '\.')[0]
    if ($srv -notmatch '^[a-z0-9][a-z0-9-]{0,62}$') { $o.reason = 'the SQL server is not named'; return $o }
    $adm = $null
    try {
        $r = & $Arm 'GET' "$("$ResourceGroupId".TrimEnd('/'))/providers/Microsoft.Sql/servers/$srv/administrators?api-version=2021-11-01" $null
        $adm = if ($r -and $r.PSObject.Properties['value']) { @(@($r.value) | Where-Object { $_ })[0] } else { $r }
    } catch { $o.reason = "the SQL server's Entra admin could not be read: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim())"; return $o }
    if (-not $adm) { $o.adminIsGroup = $false; $o.inAdminGroup = $false; $o.reason = 'the SQL server has no Entra admin'; return $o }
    $p = Get-PimDbInitObjField $adm 'properties'
    $o.adminName = "$(Get-PimDbInitObjField $p 'login')".Trim()
    $pt = "$(Get-PimDbInitObjField $p 'principalType')".Trim()
    if ($pt -and $pt -ine 'Group') { $o.adminIsGroup = $false; $o.inAdminGroup = $false; $o.reason = "the SQL Entra admin is a $pt, not a group"; return $o }
    $sid = "$(Get-PimDbInitObjField $p 'sid')".Trim()
    $g = [guid]::Empty
    if (-not [guid]::TryParse($sid, [ref]$g)) { $o.reason = "the SQL admin group's object id could not be read"; return $o }
    $g2 = [guid]::Empty
    if (-not [guid]::TryParse("$PrincipalId".Trim(), [ref]$g2)) { $o.reason = "the job identity's object id is not known"; return $o }
    if (-not $Graph) { $o.reason = 'Microsoft Graph was not asked'; if ($pt) { $o.adminIsGroup = $true }; return $o }
    # 2026-11-04 (merge review): an admin set over REST can carry NO principalType (a test install after its admin move) -- then ask Graph
    # whether the admin's object id IS a group (read), instead of reporting the type as unreadable.
    if (-not $pt) {
        try { $gg = & $Graph "/groups/$sid`?`$select=id"; if ("$(Get-PimDbInitObjField $gg 'id')".Trim() -ieq $sid) { $pt = 'Group' } }
        catch { $o.reason = "the SQL Entra admin's type could not be read: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim())"; return $o }
        if (-not $pt) { $o.reason = "the SQL Entra admin's type could not be read"; return $o }
    }
    $o.adminIsGroup = $true
    try {
        # 2026-11-04 (merge review): read from the MEMBER's side. The group's own member list hides service principals from
        # some callers (a test install 2026-11-04: 0 members listed while the member side showed it; also 2026-10-18) -- a false "not a
        # member" would be reported as missing, which is worse than unknown.
        $path = "/servicePrincipals/$PrincipalId/memberOf/microsoft.graph.group" + '?$select=id&$top=999'
        $guard = 0; $found = $false
        while ($path -and $guard -lt 50 -and -not $found) {
            $guard++
            $page = & $Graph $path
            foreach ($m in @((Get-PimDbInitObjField $page 'value'))) { if ("$(Get-PimDbInitObjField $m 'id')".Trim() -ieq $sid) { $found = $true; break } }
            $next = "$(Get-PimDbInitObjField $page '@odata.nextLink')".Trim()
            $path = $next
        }
        $o.inAdminGroup = $found
    } catch { $o.reason = "the job identity's group memberships could not be read: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim())" }
    return $o
}

function Invoke-PimDbInitJobConverge {
    <#
      OPEN-06 (owner 2026-11-04): the in-cloud UPDATER gives EVERY install its database job, and reports it.
        * reads the Manager app (image, environment, location, registry, SQL server + database);
        * finds the job (Get-PimDbInitJobName first, then every name the role can carry);
        * the identity (Resolve-PimDbInitIdentity): keep / reuse / create id-pim-dbinit (PUT, tagged pim-component=dbinit) /
          refuse one an app carries;
        * the job is PUT ONLY when it is MISSING -- on the Manager's current image, through the busy-retry writer, settings
          PIM_SqlServer, PIM_SqlDatabase, PIM_DBINIT_MI_CLIENT_ID (the identity's client id, from ARM), PIM_DBINIT_PRINCIPALS
          = [] and PIM_DBINIT_SCHEMA = 1. Never PIM_DBINIT_SQL_ACCESS, never PIM_DBINIT_MANAGER_ACCESS. An existing job gets
          NO write (its image is rolled by the job roll, step 2b);
        * the image pull keeps the Manager's registry identity (pull only; the SQL sign-in is pinned by
          PIM_DBINIT_MI_CLIENT_ID). A Manager that pulls with its SYSTEM identity (or a password): nothing is created -- the
          Support app gives id-pim-dbinit AcrPull;
        * the SQL admin group membership of the identity is READ (Read-PimDbInitAdminMembership) -- never written.
      NEVER starts the job. NEVER throws: a refused write is a warn line.
      Seams: -Arm { param($method, $path, $body) } (path WITH api-version; a GET of an absent resource may throw or return
      $null), -Graph { param($path) } (one page), -Sleep { param($seconds) }, -BusyWaits.
      Returns @{ lines; changed; warnings; present; created; jobName; imageTag; managerImageTag; onVersion; identityName;
                 identityPrincipalId; identityClientId; dedicated; adminIsGroup; adminName; inAdminGroup; membershipReason;
                 managerAccessOnDefinition; reason; state; detail }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$ManagerApp = 'ca-pim-manager', [string]$JobName = '',
          [Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Graph = $null,
          [scriptblock]$Sleep = $null, [int[]]$BusyWaits = @(10, 20, 30, 30, 30))
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($level, $text) $lines.Add([pscustomobject]@{ id = 'dbinit'; level = $level; text = "database job: $text" }) }
    $o = [ordered]@{ lines = $null; changed = 0; warnings = 0; present = $false; created = $false; jobName = ''; imageTag = ''; managerImageTag = ''; onVersion = $false
                     identityName = ''; identityPrincipalId = ''; identityClientId = ''; dedicated = $false; adminIsGroup = $null; adminName = ''; inAdminGroup = $null
                     membershipReason = ''; managerAccessOnDefinition = $false; reason = ''; state = 'unknown'; detail = '' }
    $fin = {
        $o.lines = @($lines.ToArray())
        $o.changed = @($lines | Where-Object { $_.level -eq 'changed' }).Count; $o.warnings = @($lines | Where-Object { $_.level -eq 'warn' }).Count
        $s = Get-PimDbInitSetupState -Result ([pscustomobject]$o); $o.state = $s.dbJob; $o.detail = $s.dbJobDetail
        return [pscustomobject]$o
    }
    $get = { param($p) try { & $Arm 'GET' $p $null } catch { $null } }
    $first = { param($e) ((("$($e.Exception.Message)") -split "`n")[0]).Trim() }
    $busyWrite = {
        param($bm, $bp, $bb)
        $bn = 0
        while ($true) {
            try { return (& $Arm $bm $bp $bb) }
            catch {
                if ("$($_.Exception.Message)" -notmatch '(?i)OperationInProgress|active provisioning operation' -or $bn -ge @($BusyWaits).Count) { throw }
                $bw = [int]@($BusyWaits)[$bn]; $bn++
                if ($bw -gt 0) { & $Sleep $bw }
            }
        }
    }
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $aca = 'api-version=2024-03-01'; $msi = 'api-version=2023-01-31'
    try {
        # ---- the Manager app (as the as-built converge reads it) -------------------------------------------------------
        $mgr = & $get "$rg/providers/Microsoft.App/containerApps/$ManagerApp`?$aca"
        if (-not $mgr) { & $add 'warn' "the Manager app '$ManagerApp' could not be read -- nothing converged"; $o.reason = 'the Manager app could not be read'; $o.present = $false; $r = & $fin; $r.state = 'unknown'; $r.detail = 'database job: the Manager app could not be read -- not checked'; return $r }
        $mc = @(@($mgr.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -ne 'signin-front' })[0]
        $image = "$($mc.image)".Trim()
        $menv = @{}; foreach ($e in @($mc.env)) { if ($e -and "$($e.name)") { $menv["$($e.name)"] = "$($e.value)" } }
        $reg = @($mgr.properties.configuration.registries)[0]
        $envId = "$($mgr.properties.environmentId)".Trim(); if (-not $envId) { $envId = "$($mgr.properties.managedEnvironmentId)".Trim() }
        $location = "$($mgr.location)".Trim()
        $sqlSrv = "$($menv['PIM_SqlServer'])".Trim(); $sqlDb = $(if ("$($menv['PIM_SqlDatabase'])".Trim()) { "$($menv['PIM_SqlDatabase'])".Trim() } else { 'PimPlatform' })
        $o.managerImageTag = Get-PimDbInitImageTag -Image $image

        # ---- the job: the install's name first, then every name the role can carry ------------------------------------
        $want = "$JobName".Trim(); if (-not $want) { $want = Get-PimDbInitJobName -ManagerApp $ManagerApp }
        $cands = New-Object System.Collections.Generic.List[string]
        foreach ($n in @($want, 'ca-pim-dbinit', 'caj-pim-dbinit')) { if ($n -and -not @($cands | Where-Object { $_ -ieq $n }).Count) { [void]$cands.Add($n) } }
        if (Get-Command Get-PimInstallNameCandidates -ErrorAction SilentlyContinue) {
            try { foreach ($n in @(Get-PimInstallNameCandidates -Role dbinit -Preferred $want)) { if (-not @($cands | Where-Object { $_ -ieq $n }).Count) { [void]$cands.Add($n) } } } catch { }
        }
        $job = $null; $o.jobName = $want
        foreach ($n in $cands) { $j = & $get "$rg/providers/Microsoft.App/jobs/$n`?$aca"; if ($j) { $job = $j; $o.jobName = $n; break } }

        # ---- the identity ------------------------------------------------------------------------------------------------
        $carried = New-Object System.Collections.Generic.List[string]
        foreach ($u in @(Get-PimDbInitUaMap -Resource $mgr)) { [void]$carried.Add($u.id) }
        $apps = & $get "$rg/providers/Microsoft.App/containerApps?$aca"
        foreach ($ap in @(@(Get-PimDbInitObjField $apps 'value') | Where-Object { $_ })) { foreach ($u in @(Get-PimDbInitUaMap -Resource $ap)) { [void]$carried.Add($u.id) } }
        $idList = & $get "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities?$msi"
        $idents = @(@(Get-PimDbInitObjField $idList 'value') | Where-Object { $_ })
        $ded = Get-PimDbInitIdentityNameDefault
        if (-not $job -and -not @($idents | Where-Object { "$($_.name)" -ieq $ded }).Count) {
            # the list may be unreadable or late: ask for the dedicated identity by name too (a second run after a failed job PUT)
            $dd = & $get "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$ded`?$msi"
            if ($dd) { $idents += $dd }
        }
        $pickId = Resolve-PimDbInitIdentity -Job $job -Identities $idents -Carried @($carried.ToArray()) -ResourceGroupId $rg -DedicatedName $ded
        foreach ($nt in @($pickId.notes)) { & $add 'info' $nt }
        $o.identityName = "$($pickId.name)"; $o.identityClientId = "$($pickId.clientId)"; $o.identityPrincipalId = "$($pickId.principalId)"; $o.dedicated = [bool]$pickId.dedicated

        if ($job) {
            # ---- an EXISTING job: read only (no PUT, no PATCH) ----------------------------------------------------------
            $o.present = $true
            $jimg = "$(@(@($job.properties.template.containers) | Where-Object { $_ })[0].image)".Trim()
            $o.imageTag = Get-PimDbInitImageTag -Image $jimg
            $o.onVersion = [bool]($o.imageTag -and $o.imageTag -eq $o.managerImageTag)
            $jenv = Get-PimDbInitJobEnv -Job $job
            $o.managerAccessOnDefinition = [bool]("$($jenv['PIM_DBINIT_MANAGER_ACCESS'])".Trim())
            & $add 'info' "$($o.jobName) present ($(if ($o.imageTag) { $o.imageTag } else { 'image unreadable' }); $($pickId.reason)) -- not written"
            if ($o.managerAccessOnDefinition) { & $add 'info' "$($o.jobName) still carries PIM_DBINIT_MANAGER_ACCESS on its definition (report only -- not removed)" }
        } elseif ($pickId.action -eq 'refuse') {
            $o.reason = "$($pickId.reason)"; & $add 'warn' "$($o.jobName) not created: $($pickId.reason)"
        } elseif (-not $image -or -not $envId -or -not $reg -or $sqlSrv -notmatch '\.database\.') {
            $o.reason = "the Manager's image / environment / registry / SQL server could not be read"
            & $add 'warn' "$($o.jobName) not created: $($o.reason)"
        } elseif ("$($reg.passwordSecretRef)".Trim() -or "$($reg.username)".Trim() -or -not "$($reg.identity)".Trim() -or "$($reg.identity)".Trim() -ieq 'system') {
            # Pull only with a user-assigned identity the Manager already pulls with: a new job's system identity has no right
            # on the registry, and a password is never copied.
            $o.reason = "the Manager pulls its image with $(if ("$($reg.username)".Trim() -or "$($reg.passwordSecretRef)".Trim()) { 'a registry password' } else { 'its system identity' }) -- the Support app gives $ded AcrPull, then the next update creates the job"
            & $add 'warn' "$($o.jobName) not created: $($o.reason)"
        } else {
            $regId = "$($reg.identity)".Trim()
            # ---- the identity: created when it is the dedicated one and missing ----------------------------------------
            $idRes = "$($pickId.resourceId)"
            if ($pickId.action -eq 'create') {
                try {
                    [void](& $Arm 'PUT' "$idRes`?$msi" @{ location = $location; tags = @{ 'pim-component' = 'dbinit' } })
                    & $add 'changed' "user-assigned identity $ded created (the database job's own identity)"
                    $ui = & $get "$idRes`?$msi"
                    if ($ui) { $o.identityClientId = "$($ui.properties.clientId)".Trim(); $o.identityPrincipalId = "$($ui.properties.principalId)".Trim() }
                } catch { $o.reason = "the identity $ded could not be created ($(& $first $_))"; & $add 'warn' "$($o.jobName) not created: $($o.reason)" }
            }
            $gtmp = [guid]::Empty
            if (-not $o.reason -and -not [guid]::TryParse("$($o.identityClientId)", [ref]$gtmp)) {
                $o.reason = "the client id of $($o.identityName) is not readable yet -- the next update creates the job"
                & $add 'warn' "$($o.jobName) not created: $($o.reason)"
            }
            if (-not $o.reason) {
                $jenvNew = [ordered]@{ PIM_SqlServer = $sqlSrv; PIM_SqlDatabase = $sqlDb; PIM_DBINIT_MI_CLIENT_ID = "$($o.identityClientId)".ToLowerInvariant()
                                      PIM_DBINIT_PRINCIPALS = '[]'; PIM_DBINIT_SCHEMA = '1' }
                $spec = Get-PimDbInitJobSpec -JobName $o.jobName -Image $image -EnvironmentId $envId -Location $location -RegistryServer "$($reg.server)" `
                            -RegistryIdentity $regId -Env $jenvNew -IdentityResourceIds @($idRes, $regId)
                if (-not $spec.ok) { $o.reason = "$($spec.reason)"; & $add 'warn' "$($o.jobName) not created: $($spec.reason)" }
                else {
                    try {
                        [void](& $busyWrite 'PUT' "$rg/providers/Microsoft.App/jobs/$($o.jobName)`?$aca" $spec.resource)
                        $o.created = $true; $o.present = $true; $o.imageTag = $o.managerImageTag; $o.onVersion = [bool]$o.imageTag
                        & $add 'changed' "$($o.jobName) created (manual trigger, never started by the updater) on $image as $($o.identityName)"
                        $back = & $get "$rg/providers/Microsoft.App/jobs/$($o.jobName)`?$aca"
                        if ($back) { $bi = "$(@(@($back.properties.template.containers) | Where-Object { $_ })[0].image)".Trim(); if ($bi) { $o.imageTag = Get-PimDbInitImageTag -Image $bi; $o.onVersion = [bool]($o.imageTag -and $o.imageTag -eq $o.managerImageTag) } }
                    } catch { $o.reason = "the job could not be created ($(& $first $_))"; & $add 'warn' "$($o.jobName) not created: $($o.reason) -- the next update retries" }
                }
            }
        }

        # ---- the SQL admin group membership of the identity: READ only ---------------------------------------------------
        if ($o.present) {
            $mem = Read-PimDbInitAdminMembership -Arm $Arm -Graph $Graph -ResourceGroupId $rg -SqlServer $sqlSrv -PrincipalId $o.identityPrincipalId
            $o.adminIsGroup = $mem.adminIsGroup; $o.inAdminGroup = $mem.inAdminGroup; $o.adminName = "$($mem.adminName)"; $o.membershipReason = "$($mem.reason)"
            # 2026-11-04 live (internal): the updater's identity holds no Graph read, so the membership is unknown there. The
            # job's LAST EXECUTION (ARM, readable) is the proof instead: the job's identity has no database user of its own,
            # so a run that Succeeded logged in THROUGH the SQL admin group. A failed run / no run stays unknown (said).
            if ($null -eq $mem.inAdminGroup -and $mem.adminIsGroup -ne $false) {
                try {
                    $ex = & $Arm 'GET' "$rg/providers/Microsoft.App/jobs/$($o.jobName)/executions?$aca" $null
                    $last = @(@($ex.value) | Where-Object { $_ } | Sort-Object { "$($_.properties.startTime)" } -Descending)[0]
                    if ($last -and "$($last.properties.status)" -eq 'Succeeded') {
                        $o.inAdminGroup = $true; $o.adminIsGroup = $true
                        $o.membershipReason = "proven by the job's run $($last.name) (Succeeded $("$($last.properties.startTime)")): its identity has no database user of its own, so it signed in through the SQL admin group"
                        & $add 'info' $o.membershipReason
                    } elseif ($last) { $o.membershipReason = "$($mem.reason); the job's last run $($last.name) is $("$($last.properties.status)") -- not a proof" }
                    else { $o.membershipReason = "$($mem.reason); the job has not run yet -- the first run (after the Support app reads the membership back) proves it" }
                } catch { }
            }
            if ($o.inAdminGroup -eq $false -and $o.adminIsGroup -eq $true) { & $add 'warn' "$($o.identityName) is not a member of the SQL admin group $($o.adminName) -- the Support app adds it (the updater never writes a membership)" }
            elseif ($mem.adminIsGroup -eq $false) { & $add 'warn' "$($mem.reason) -- the database job cannot act as an admin through a group" }
            elseif ($null -eq $o.inAdminGroup) { & $add 'info' "the SQL admin group membership could not be read ($($mem.reason))" }
        }
    } catch { & $add 'warn' "not checked: $(& $first $_)"; if (-not $o.reason) { $o.reason = 'not checked' } }
    return (& $fin)
}

function Update-PimDbInitResultImage {
    <#
      PURE. After the updater's job roll (step 2b) moved the job: the converge result with the image READ BACK from the job
      (-Job, an ARM GET) -- imageTag / onVersion recomputed, state + detail again. Anything unreadable leaves it unchanged.
    #>
    param([AllowNull()][object]$Result, [AllowNull()][object]$Job)
    if ($null -eq $Result -or $null -eq $Job) { return $Result }
    $img = "$(@(@((Get-PimDbInitObjField (Get-PimDbInitObjField (Get-PimDbInitObjField $Job 'properties') 'template') 'containers')) | Where-Object { $_ })[0].image)".Trim()
    $tag = Get-PimDbInitImageTag -Image $img
    if (-not $tag) { return $Result }
    $Result.imageTag = $tag
    $Result.onVersion = [bool]($tag -eq "$($Result.managerImageTag)")
    $s = Get-PimDbInitSetupState -Result $Result
    $Result.state = $s.dbJob; $Result.detail = $s.dbJobDetail
    return $Result
}
