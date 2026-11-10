#Requires -Version 5.1
<#
.SYNOPSIS
    NAM-03 / framework §12.11c item 3 + CR8 (owner 2026-11-04, CRITICAL): ONE user-assigned identity per ROLE, named
    id-pim-<role>, at every install -- the move of each app's / job's role off its system-assigned identity and off the
    shared id-pim-<token>, with the SAME rights, proven, before the old rights are removed.

.DESCRIPTION
    PIM picks the identity a container signs in with from PIM_ManagedIdentityClientId (engine/_shared/PIM-Rest.ps1 -- the
    IDENTITY_ENDPOINT client_id). So a role moves in steps, each read back, each idempotent (a re-run continues):
      1 ensure   the user-assigned identity id-pim-<role> exists in the install's resource group
      2 rights   copy the SOURCE identity's rights to it: Azure role assignments (the same role at the same scope -- Key Vault
                 RBAC, the resource group, the root, a job), Microsoft Graph application roles, PIM's own group memberships
                 (the SQL admin group, the Power BI admin-API group); the SQL contained user is the caller's (in-network on
                 a private install)
      3 attach   the identity is attached to the app / job (SystemAssigned kept until the cleanup)
      4 switch   PIM_ManagedIdentityClientId on that app / job = the new identity's client id (a new revision / the next run)
      5 prove    the caller proves the role works (the next tick / update run succeeds, the web app answers)
      6 cleanup  ONLY after every role at the install is proven: the old identities' rights are removed and the shared
                 id-pim-<token> detached (a separate, later call -- never in the same run as the switch)
    Only Azure RESOURCE names (ca-pim-tick, ...) keep their names.

      Get-PimIdentityRoleOf            PURE: an app / job name -> its role word ('' = not a PIM role)
      Get-PimIdentitySplitPlan         PURE: the apps + jobs + user-assigned identities of the rg -> one row per app/job
      Get-PimIdentityRightsToCopy      PURE: the source's rights minus what the target already holds
      Get-PimIdentityRoleWords         PURE: the role / purpose words of the standard (the words Get-PimIdentityRoleOf returns)
      Test-PimIdentityStandardName     PURE: is a user-assigned identity's name id-pim-<role word>?
      Get-PimIdentityNamesFact         PURE: the setup fact identityNames (heartbeat step 'identity-names', 3.0.57)
      Get-PimIdentityNamesOld          PURE: the install's OLD identities (non-standard user-assigned + every system-assigned)
      Read-PimIdentityNamesFact        READ: apps + jobs + identities + the old identities' rights (ARM / Graph GET only) -> that fact
#>

function Get-PimIdentityRoleWords {
    <#
      PURE. THE role / purpose words of the identity standard id-pim-<role> (NAM-03, framework 12.11c item 3; 'dbinit' is a
      standard purpose word -- Invardia 2026-11-04). Exactly the words Get-PimIdentityRoleOf below returns (Test-PimIdentityNamesStep
      R2 holds the two together). A literal: child-scope safe.
    #>
    return @('engine', 'web', 'updater', 'mcp', 'downlink', 'publish', 'requests', 'dbinit', 'asbuilt')
}

function Test-PimIdentityStandardName {
    <# PURE. A user-assigned identity's name meets the standard: id-pim-<one role word>, nothing before or after. #>
    param([AllowEmptyString()][string]$Name)
    $n = "$Name".Trim()
    if ($n -notmatch '^(?i)id-pim-([a-z0-9]+)$') { return $false }
    # 'docs': the docs job's identity is id-pim-docs (owner 2026-11-09) while its ROLE key stays 'asbuilt' -- the identity move's
    # rights switch reads that key, so it is added to the NAME test only, never to the role map.
    return ($Matches[1].ToLowerInvariant() -in @(@(Get-PimIdentityRoleWords) + 'docs'))
}

function Get-PimIdentityRoleOf {
    <# PURE. The role an app / job of a PIM install plays, from its resource name (today's names and §12.11c's new ones). #>
    param([AllowEmptyString()][string]$Name)
    $n = "$Name".Trim().ToLowerInvariant()
    switch -Regex ($n) {
        '^ca-pim-(manager|web)$'                  { return 'web' }
        '^ca-pim-tick$|^ca(j)?-pim-engine$'       { return 'engine' }
        '^ca-pim-update$|^caj-pim-updater$'       { return 'updater' }
        '^ca(j)?-pim-downlink(-s\d+)?$'           { return 'downlink' }
        '^ca(j)?-pim-publish$'                    { return 'publish' }
        '^ca-pim-rfa$|^ca-pim-requests$'          { return 'requests' }
        '^ca(j)?-pim-mcp$'                        { return 'mcp' }
        '^ca(j)?-pim-dbinit$'                     { return 'dbinit' }
        '^caj-pim-(asbuilt|docs)$'                { return 'asbuilt' }   # JOB-RENAME 3.0.68: caj-pim-docs ("Installation documentation")
        default                                   { return '' }
    }
}

function Get-PimIdentitySplitPlan {
    <#
      PURE. -Apps / -Jobs: the ARM objects of the install's container apps / jobs; -Identities: the user-assigned identities
      in the resource group (ARM objects: name, properties.clientId, properties.principalId, id).
      -> one row per PIM app / job: @{ resource; kind (app|job); role; target ('id-pim-<role>'); targetExists; targetId;
         sourceKind (system|user|none); sourcePrincipalId; sourceName; sourceShared (the same identity serves another role);
         state ('ok' = already signs in as the target | 'move') }
      The identity a container signs in with = the user-assigned one whose clientId is its PIM_ManagedIdentityClientId; none
      set = the system-assigned one.
    #>
    param([AllowEmptyCollection()][object[]]$Apps = @(), [AllowEmptyCollection()][object[]]$Jobs = @(), [AllowEmptyCollection()][object[]]$Identities = @())
    $byClient = @{}; $byName = @{}
    foreach ($u in @($Identities | Where-Object { $_ })) {
        $cid = "$($u.properties.clientId)".Trim().ToLowerInvariant(); if ($cid) { $byClient[$cid] = $u }
        $byName["$($u.name)".Trim().ToLowerInvariant()] = $u
    }
    $rows = New-Object System.Collections.Generic.List[object]
    $all = @(@($Apps | Where-Object { $_ } | ForEach-Object { @{ o = $_; kind = 'app' } }) + @($Jobs | Where-Object { $_ } | ForEach-Object { @{ o = $_; kind = 'job' } }))
    foreach ($x in $all) {
        $o = $x.o; $role = Get-PimIdentityRoleOf -Name "$($o.name)"
        if (-not $role) { continue }
        $target = "id-pim-$role"
        $cid = ''
        foreach ($c in @($o.properties.template.containers)) {
            if (-not $c -or "$($c.name)" -eq 'signin-front') { continue }
            foreach ($e in @($c.env)) { if ($e -and "$($e.name)" -eq 'PIM_ManagedIdentityClientId' -and "$($e.value)".Trim()) { $cid = "$($e.value)".Trim().ToLowerInvariant() } }
            if ($cid) { break }
        }
        $src = $null; $srcKind = 'none'; $srcName = ''; $srcPid = ''
        if ($cid -and $byClient.ContainsKey($cid)) { $src = $byClient[$cid]; $srcKind = 'user'; $srcName = "$($src.name)"; $srcPid = "$($src.properties.principalId)" }
        elseif ("$($o.identity.principalId)".Trim()) { $srcKind = 'system'; $srcName = "$($o.name)"; $srcPid = "$($o.identity.principalId)".Trim() }
        $tgt = $byName[$target]
        $rows.Add([pscustomobject]@{
            resource = "$($o.name)"; resourceId = "$($o.id)"; kind = $x.kind; role = $role; target = $target
            targetExists = [bool]$tgt; targetId = $(if ($tgt) { "$($tgt.id)" } else { '' }); targetClientId = $(if ($tgt) { "$($tgt.properties.clientId)" } else { '' })
            targetPrincipalId = $(if ($tgt) { "$($tgt.properties.principalId)" } else { '' })
            sourceKind = $srcKind; sourceName = $srcName; sourcePrincipalId = $srcPid; sourceShared = $false
            state = $(if ($srcKind -eq 'user' -and $srcName -ieq $target) { 'ok' } else { 'move' })
        })
    }
    # a user-assigned SOURCE that several roles use is shared (CR8): its rights are removed only after every role moved
    $groups = @($rows | Where-Object { $_.sourceKind -eq 'user' } | Group-Object sourceName | Where-Object { @($_.Group | ForEach-Object role | Select-Object -Unique).Count -gt 1 })
    foreach ($g in $groups) { foreach ($r in $g.Group) { $r.sourceShared = $true } }
    return @($rows.ToArray())
}

function Get-PimIdentityRightsToCopy {
    <#
      PURE. What the target must still get so it holds what the source holds.
        -SourceAzure / -TargetAzure : role assignments @{ roleDefinitionId; scope } (ARM properties)
        -SourceGraph / -TargetGraph : app role assignments @{ resourceId; appRoleId }
        -SourceGroups / -TargetGroups : group object ids PIM itself manages (the SQL admin group, the Power BI admin-API group)
      -> @{ azure = @(missing); graph = @(missing); groups = @(missing) } -- nothing the target already holds, nothing new.
    #>
    param([AllowEmptyCollection()][object[]]$SourceAzure = @(), [AllowEmptyCollection()][object[]]$TargetAzure = @(),
          [AllowEmptyCollection()][object[]]$SourceGraph = @(), [AllowEmptyCollection()][object[]]$TargetGraph = @(),
          [AllowEmptyCollection()][string[]]$SourceGroups = @(), [AllowEmptyCollection()][string[]]$TargetGroups = @())
    $ak = { param($a) ("$($a.roleDefinitionId)".Trim().ToLowerInvariant() -replace '^.*/roledefinitions/', '') + '|' + "$($a.scope)".Trim().TrimEnd('/').ToLowerInvariant() }
    $gk = { param($a) "$($a.resourceId)".Trim().ToLowerInvariant() + '|' + "$($a.appRoleId)".Trim().ToLowerInvariant() }
    $haveA = @{}; foreach ($a in @($TargetAzure | Where-Object { $_ })) { $haveA[(& $ak $a)] = $true }
    $haveG = @{}; foreach ($a in @($TargetGraph | Where-Object { $_ })) { $haveG[(& $gk $a)] = $true }
    $haveM = @{}; foreach ($g in @($TargetGroups | Where-Object { "$_".Trim() })) { $haveM["$g".Trim().ToLowerInvariant()] = $true }
    $seenA = @{}; $seenG = @{}; $seenM = @{}
    $az = @(foreach ($a in @($SourceAzure | Where-Object { $_ })) { $k = & $ak $a; if (-not $haveA.ContainsKey($k) -and -not $seenA.ContainsKey($k)) { $seenA[$k] = $true; $a } })
    $gr = @(foreach ($a in @($SourceGraph | Where-Object { $_ })) { $k = & $gk $a; if (-not $haveG.ContainsKey($k) -and -not $seenG.ContainsKey($k)) { $seenG[$k] = $true; $a } })
    $gp = @(foreach ($g in @($SourceGroups | Where-Object { "$_".Trim() })) { $k = "$g".Trim().ToLowerInvariant(); if (-not $haveM.ContainsKey($k) -and -not $seenM.ContainsKey($k)) { $seenM[$k] = $true; $k } })
    return @{ azure = $az; graph = $gr; groups = $gp }
}

# ---------------------------------------------------------------------------------------------------------------------
# FLEET-SETUPSTEPS 'identity-names' (Invardia 2026-11-07, owns the setupSteps key list; NAM-03 / framework 12.11c item 3 and
# its ruling (b) of 2026-11-07): ok ONLY when every role runs as id-pim-<role> AND no OLD identity still holds rights. The
# updater keeps the fact in its run record (UpdateState.setupFacts identityNames + identityNamesDetail); the heartbeat maps
# it (PIM-SetupSteps.ps1). READ ONLY.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimIdentityNamesField {
    <# PURE. A field of a hashtable or an object ($null when absent). #>
    param([AllowNull()][object]$Object, [string]$Name)
    if ($null -eq $Object -or $Object -is [string]) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }; return $null
}

function Get-PimIdentityNamesMapPairs {
    <# PURE. The key/value pairs of a hashtable or an object (ARM identity.userAssignedIdentities). #>
    param([AllowNull()][object]$Map)
    if ($null -eq $Map -or $Map -is [string]) { return @() }
    if ($Map -is [System.Collections.IDictionary]) { return @($Map.Keys | ForEach-Object { @{ key = "$_"; value = $Map[$_] } }) }
    return @($Map.PSObject.Properties | ForEach-Object { @{ key = "$($_.Name)"; value = $_.Value } })
}

function Get-PimIdentityNamesLastSegment {
    <# PURE. The name of a resource from its id (the last segment). #>
    param([AllowEmptyString()][AllowNull()][string]$Id)
    return ((("$Id".Trim().TrimEnd('/')) -split '/')[-1])
}

function Test-PimIdentityNamesHasSystem {
    <# PURE. Does an app / job have its system-assigned identity enabled? #>
    param([AllowNull()][object]$Resource)
    $idn = Get-PimIdentityNamesField $Resource 'identity'
    $type = "$(Get-PimIdentityNamesField $idn 'type')"
    return [bool](($type -match '(?i)SystemAssigned') -or (-not $type.Trim() -and "$(Get-PimIdentityNamesField $idn 'principalId')".Trim()))
}

function Get-PimIdentityNamesOld {
    <#
      PURE. The OLD identities of an install (framework 12.11c ruling (b)): every user-assigned identity in the resource group
      (-Identities) or attached to an app / job whose name is not the standard (a shared id-pim-<token>, a named variant), and
      every system-assigned identity on an app / job -- attached or not, used or not. Once per principal.
      -> @( @{ principalId; label; kind = user | system } )   (principalId '' = not known -> its rights cannot be read)
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Apps = @(), [AllowNull()][AllowEmptyCollection()][object[]]$Jobs = @(),
          [AllowNull()][AllowEmptyCollection()][object[]]$Identities = @())
    $out = New-Object System.Collections.Generic.List[object]; $seen = @{}
    $add = { param($pid1, $label, $kind)
        $k = $(if ("$pid1".Trim()) { 'p:' + "$pid1".Trim().ToLowerInvariant() } else { 'n:' + "$label".ToLowerInvariant() })
        if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $out.Add(@{ principalId = "$pid1".Trim().ToLowerInvariant(); label = "$label"; kind = $kind }) } }
    foreach ($u in @($Identities | Where-Object { $null -ne $_ })) {
        $nm = "$(Get-PimIdentityNamesField $u 'name')".Trim(); if (-not $nm) { $nm = Get-PimIdentityNamesLastSegment "$(Get-PimIdentityNamesField $u 'id')" }
        if (-not $nm -or (Test-PimIdentityStandardName -Name $nm)) { continue }
        & $add "$(Get-PimIdentityNamesField (Get-PimIdentityNamesField $u 'properties') 'principalId')" $nm 'user'
    }
    foreach ($o in @(@($Apps) + @($Jobs) | Where-Object { $null -ne $_ })) {
        $res = "$(Get-PimIdentityNamesField $o 'name')".Trim(); if (-not $res) { $res = Get-PimIdentityNamesLastSegment "$(Get-PimIdentityNamesField $o 'id')" }
        $idn = Get-PimIdentityNamesField $o 'identity'
        foreach ($pr in @(Get-PimIdentityNamesMapPairs (Get-PimIdentityNamesField $idn 'userAssignedIdentities'))) {
            $nm = Get-PimIdentityNamesLastSegment $pr.key
            if ($nm -and -not (Test-PimIdentityStandardName -Name $nm)) { & $add "$(Get-PimIdentityNamesField $pr.value 'principalId')" $nm 'user' }
        }
        if (Test-PimIdentityNamesHasSystem $o) { & $add "$(Get-PimIdentityNamesField $idn 'principalId')" "$res (system-assigned)" 'system' }
    }
    return @($out.ToArray())
}

function Get-PimIdentityNamesFact {
    <#
      PURE (already-read data in, the fact out). Framework 12.11c ruling (b), 2026-11-07: ok ONLY when every role runs as
      id-pim-<role> AND no OLD identity still holds rights.
        -Apps / -Jobs      the ARM objects of the container apps / jobs in the install's resource group
        -Identities        the user-assigned identities in the resource group (ARM objects)
        -Rights            @{ <principalId lower> = @{ azure = $true | $false | $null; graph = $true | $false | $null } } -- what
                           the reader found for each old identity ($null = that read failed; absent = not read)
        -GraphRead         $false = the caller had no Graph seam: Azure rights only (said in the detail)
        -IdentitiesError   the identity list could not be read (its message)
        -ReadError         the apps / jobs could not be read (its message) -> unknown
      RUNS AS, per app / job: the user-assigned identity its PIM_ManagedIdentityClientId names (none named + the system-assigned
      identity enabled = system-assigned), and every identity its registry / Key Vault secret references use. Anything but
      id-pim-<role word> (Test-PimIdentityStandardName) -> "app: identity". OLD IDENTITIES (Get-PimIdentityNamesOld): one
      holding a right -> "clean-up pending: <identity> still holds rights"; one whose rights could not be read -> "not read".
      missing = any of the first two; unknown = nothing could be decided; n/a = nothing to read; else ok.
      -> [ordered]@{ identityNames; identityNamesDetail } -- the detail one line, within Get-PimSetupStepDetailMax.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Apps = @(), [AllowNull()][AllowEmptyCollection()][object[]]$Jobs = @(),
          [AllowNull()][AllowEmptyCollection()][object[]]$Identities = @(), [AllowNull()][hashtable]$Rights = @{},
          [bool]$GraphRead = $true, [AllowNull()][AllowEmptyString()][string]$IdentitiesError = '',
          [AllowNull()][AllowEmptyString()][string]$ReadError = '')
    $max = 200; if (Get-Command Get-PimSetupStepDetailMax -ErrorAction SilentlyContinue) { $max = [int](Get-PimSetupStepDetailMax) }
    $line1 = { param($t) (((("$t") -split "`n")[0]) -replace '[\r\t]+', ' ').Trim() }
    $cut = { param($t) $t = ("$t" -replace '[\r\n\t]+', ' ' -replace '\s{2,}', ' ').Trim(); if ($t.Length -gt $max) { $t = $t.Substring(0, $max - 3) + '...' }; $t }
    # as many items as fit after the head, the rest counted "(+N more)"
    $fit = { param($head, $items)
        $txt = $head; $shown = 0; $n = @($items).Count
        for ($i = 0; $i -lt $n; $i++) {
            $cand = $(if ($shown -eq 0) { $head + $items[$i] } else { $txt + ', ' + $items[$i] })
            $rest = $n - ($i + 1); $tail = $(if ($rest -gt 0) { " (+$rest more)" } else { '' })
            if (($cand + $tail).Length -le $max) { $txt = $cand; $shown++ } else { break }
        }
        if ($shown -lt $n) { $txt = $txt.TrimEnd() + " (+$($n - $shown) more)" }
        & $cut $txt }
    if ("$ReadError".Trim()) { return [ordered]@{ identityNames = 'unknown'; identityNamesDetail = (& $cut ("the container apps / jobs could not be read: " + (& $line1 $ReadError))) } }
    if ($null -eq $Rights) { $Rights = @{} }
    $all = @(@($Apps) + @($Jobs) | Where-Object { $null -ne $_ })
    $ids = @($Identities | Where-Object { $null -ne $_ })
    $old = @(Get-PimIdentityNamesOld -Apps $all -Identities $ids)
    if (-not $all.Count -and -not $old.Count -and -not "$IdentitiesError".Trim()) { return [ordered]@{ identityNames = 'n/a'; identityNamesDetail = 'no container app, job or managed identity in the resource group' } }
    # the identity names by client id and by resource id (the resource group's list + what each app / job has attached)
    $byCid = @{}; $byRid = @{}
    foreach ($u in $ids) {
        $nm = "$(Get-PimIdentityNamesField $u 'name')".Trim(); if (-not $nm) { $nm = Get-PimIdentityNamesLastSegment "$(Get-PimIdentityNamesField $u 'id')" }
        $c = "$(Get-PimIdentityNamesField (Get-PimIdentityNamesField $u 'properties') 'clientId')".Trim().ToLowerInvariant(); if ($c -and $nm) { $byCid[$c] = $nm }
        $r = "$(Get-PimIdentityNamesField $u 'id')".Trim().TrimEnd('/').ToLowerInvariant(); if ($r -and $nm) { $byRid[$r] = $nm }
    }
    $bad = New-Object System.Collections.Generic.List[string]; $seenBad = @{}
    $addBad = { param($t) $k = "$t".ToLowerInvariant(); if (-not $seenBad.ContainsKey($k)) { $seenBad[$k] = $true; $bad.Add("$t") } }
    $roles = 0
    # OWNER-APPROVED EXCEPTION (owner 2026-11-08 via Invardia: "you must fix. otherwise leave old identity as exception" /
    # "approved"; for a tenant where the Support app cannot copy the engine's root User Access Administrator). An app / job
    # whose container env PIM_IdentityNamesException reads "owner-approved exception <yyyy-mm-dd> (<why>)" keeps its old
    # identity: that resource and the old identities it uses are not counted against the step, and the ok detail SAYS so
    # ("<role> on the old identity: <text>") -- never a silent skip. Any other text there is NOT an exception (said as missing).
    $excRes = @{}; $excPid = @{}; $excSaid = New-Object System.Collections.Generic.List[string]
    foreach ($o in $all) {
        $res = "$(Get-PimIdentityNamesField $o 'name')".Trim(); if (-not $res) { $res = Get-PimIdentityNamesLastSegment "$(Get-PimIdentityNamesField $o 'id')" }
        $mark = ''
        foreach ($ct in @(Get-PimIdentityNamesField (Get-PimIdentityNamesField (Get-PimIdentityNamesField $o 'properties') 'template') 'containers')) {
            foreach ($e in @(Get-PimIdentityNamesField $ct 'env')) { if ($null -ne $e -and "$(Get-PimIdentityNamesField $e 'name')" -eq 'PIM_IdentityNamesException' -and "$(Get-PimIdentityNamesField $e 'value')".Trim()) { $mark = "$(Get-PimIdentityNamesField $e 'value')".Trim() } }
        }
        if (-not $mark) { continue }
        if ($mark -notmatch '^owner-approved exception \d{4}-\d{2}-\d{2}\b') { & $addBad "${res}: PIM_IdentityNamesException is not an owner-approved exception <date>"; continue }
        $excRes[$res.ToLowerInvariant()] = $true
        $rw = "$(Get-PimIdentityRoleOf -Name $res)"; if (-not $rw) { $rw = $res }
        $excSaid.Add("$rw on the old identity: $mark")
        $idnX = Get-PimIdentityNamesField $o 'identity'
        $sp = "$(Get-PimIdentityNamesField $idnX 'principalId')".Trim().ToLowerInvariant(); if ($sp) { $excPid[$sp] = $true }
        foreach ($pr in @(Get-PimIdentityNamesMapPairs (Get-PimIdentityNamesField $idnX 'userAssignedIdentities'))) { $up = "$(Get-PimIdentityNamesField $pr.value 'principalId')".Trim().ToLowerInvariant(); if ($up) { $excPid[$up] = $true } }
    }
    foreach ($o in $all) {
        $res = "$(Get-PimIdentityNamesField $o 'name')".Trim(); if (-not $res) { $res = Get-PimIdentityNamesLastSegment "$(Get-PimIdentityNamesField $o 'id')" }
        if ($excRes.ContainsKey($res.ToLowerInvariant())) { $roles++; continue }
        $idn = Get-PimIdentityNamesField $o 'identity'
        $hasSystem = Test-PimIdentityNamesHasSystem $o
        $mine = @{}
        foreach ($pr in @(Get-PimIdentityNamesMapPairs (Get-PimIdentityNamesField $idn 'userAssignedIdentities'))) {
            $nm = Get-PimIdentityNamesLastSegment $pr.key; if (-not $nm) { continue }
            $c = "$(Get-PimIdentityNamesField $pr.value 'clientId')".Trim().ToLowerInvariant(); if ($c) { $mine[$c] = $nm }
            $byRid["$($pr.key)".Trim().TrimEnd('/').ToLowerInvariant()] = $nm
        }
        $props = Get-PimIdentityNamesField $o 'properties'
        $cids = @()
        foreach ($ct in @(Get-PimIdentityNamesField (Get-PimIdentityNamesField $props 'template') 'containers')) {
            if ($null -eq $ct -or "$(Get-PimIdentityNamesField $ct 'name')" -eq 'signin-front') { continue }
            foreach ($e in @(Get-PimIdentityNamesField $ct 'env')) {
                if ($null -ne $e -and "$(Get-PimIdentityNamesField $e 'name')" -eq 'PIM_ManagedIdentityClientId' -and "$(Get-PimIdentityNamesField $e 'value')".Trim()) { $cids += "$(Get-PimIdentityNamesField $e 'value')".Trim().ToLowerInvariant() }
            }
        }
        foreach ($c in @($cids | Select-Object -Unique)) {
            $roles++
            $nm = $(if ($mine.ContainsKey($c)) { $mine[$c] } elseif ($byCid.ContainsKey($c)) { $byCid[$c] } else { '' })
            if (-not $nm) { & $addBad "${res}: a client id no attached identity has" }
            elseif (-not (Test-PimIdentityStandardName -Name $nm)) { & $addBad "${res}: $nm" }
        }
        if (-not $cids.Count -and $hasSystem) { $roles++; & $addBad "${res}: system-assigned" }
        # the registry pull + Key Vault secret references: 'system' or a user-assigned identity's resource id
        $cfg = Get-PimIdentityNamesField $props 'configuration'
        foreach ($ref in @(@(Get-PimIdentityNamesField $cfg 'registries') + @(Get-PimIdentityNamesField $cfg 'secrets') | Where-Object { $null -ne $_ })) {
            $ri = "$(Get-PimIdentityNamesField $ref 'identity')".Trim(); if (-not $ri) { continue }
            if ($ri -ieq 'system') { if ($hasSystem) { & $addBad "${res}: system-assigned" }; continue }
            $nm = $(if ($byRid.ContainsKey($ri.TrimEnd('/').ToLowerInvariant())) { $byRid[$ri.TrimEnd('/').ToLowerInvariant()] } else { Get-PimIdentityNamesLastSegment $ri })
            if ($nm -and -not (Test-PimIdentityStandardName -Name $nm)) { & $addBad "${res}: $nm" }
        }
    }
    # the old identities: any right left = the clean-up is pending
    $notRead = New-Object System.Collections.Generic.List[string]; $decided = 0
    foreach ($x in $old) {
        if ($x.principalId -and $excPid.ContainsKey($x.principalId)) { $decided++; continue }   # used by an owner-approved exception (said in the detail)
        $r = $null; if ($x.principalId -and $Rights.ContainsKey($x.principalId)) { $r = $Rights[$x.principalId] }
        if ($null -eq $r) { $notRead.Add($x.label); continue }
        $az = Get-PimIdentityNamesField $r 'azure'; $gr = Get-PimIdentityNamesField $r 'graph'
        if ($az -eq $true -or ($GraphRead -and $gr -eq $true)) { $decided++; & $addBad "clean-up pending: $($x.label) still holds rights" }
        elseif ($az -eq $false -and (-not $GraphRead -or $gr -eq $false)) { $decided++ }
        else { $notRead.Add($x.label) }
    }
    if ("$IdentitiesError".Trim()) { $notRead.Add('the user-assigned identity list') }
    $head0 = $(if ($GraphRead) { '' } else { 'Azure rights only; ' })
    $nr = @($notRead | ForEach-Object { "not read: $_" })
    if ($bad.Count) { return [ordered]@{ identityNames = 'missing'; identityNamesDetail = (& $fit ($head0 + 'not the standard: ') (@($bad) + $nr)) } }
    if (-not $roles -and -not $decided) {
        if ($nr.Count) { return [ordered]@{ identityNames = 'unknown'; identityNamesDetail = (& $fit ($head0 + 'nothing could be decided: ') $nr) } }
        return [ordered]@{ identityNames = 'n/a'; identityNamesDetail = 'no container app or job uses a managed identity' }
    }
    $okHead = $head0 + "every role runs as id-pim-<role> and no old identity holds rights ($($all.Count) apps / jobs read; $decided old identities hold none)"
    if ($excSaid.Count) { $okHead = (@($excSaid) -join '; ') + '; every other role runs as id-pim-<role>, no other old identity holds rights' }
    # every role is standard, but an old identity's rights could not be read: NOT proven clean -> unknown (never ok on a gap)
    if ($nr.Count) { return [ordered]@{ identityNames = 'unknown'; identityNamesDetail = (& $fit ($head0 + 'every role runs as id-pim-<role>; old identities not proven clean: ') $nr) } }
    return [ordered]@{ identityNames = 'ok'; identityNamesDetail = (& $cut $okHead) }
}

function Get-PimIdentityNamesList {
    <# READ. One list through a seam: .value unwrapped, nextLink / @odata.nextLink followed (at most 50 pages). Throws what the seam throws. #>
    param([Parameter(Mandatory)][scriptblock]$Seam, [Parameter(Mandatory)][string]$Path)
    $out = New-Object System.Collections.Generic.List[object]
    $next = $Path; $guard = 0
    while ($next -and $guard -lt 50) {
        $guard++
        $r = & $Seam 'GET' $next $null
        $next = $null
        if ($null -eq $r) { break }
        $hasValue = $(if ($r -is [System.Collections.IDictionary]) { $r.Contains('value') } elseif ($r -is [System.Array]) { $false } else { [bool]$r.PSObject.Properties['value'] })
        if ($hasValue) { foreach ($x in @(Get-PimIdentityNamesField $r 'value')) { if ($null -ne $x) { $out.Add($x) } } }
        elseif ($r -is [System.Array]) { foreach ($x in $r) { if ($null -ne $x) { $out.Add($x) } } }
        else { $out.Add($r) }
        if ($r -isnot [System.Array]) {
            $nl = Get-PimIdentityNamesField $r '@odata.nextLink'; if (-not $nl) { $nl = Get-PimIdentityNamesField $r 'nextLink' }
            if ($nl) { $next = "$nl" }
        }
    }
    return @($out.ToArray())
}

function Get-PimIdentityNamesOldMax { <# PURE. At most this many old identities have their rights read per run (a literal). #> return 40 }

function Read-PimIdentityNamesFact {
    <#
      READ ONLY (the updater, step 2g). Through -Arm { param($method, $path, $body) } and -Graph (the same shape; $null = no
      Graph seam -> Azure rights only), both called with 'GET' only:
        the container apps + jobs + user-assigned identities of the install's resource group; then, for each OLD identity
        (Get-PimIdentityNamesOld, at most Get-PimIdentityNamesOldMax), its Azure role assignments (principalId filter) at the
        resource group and at the subscription, and -- when no Azure right was found -- its Microsoft Graph app role
        assignments. A failed read leaves that identity not read. -> Get-PimIdentityNamesFact. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [AllowNull()][scriptblock]$Graph = $null,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$ApiVersion = '2024-03-01', [string]$MsiApiVersion = '2023-01-31', [string]$AuthApiVersion = '2022-04-01')
    $sub = "/subscriptions/$SubscriptionId"; $rg = "$sub/resourceGroups/$ResourceGroup"
    try {
        $apps = @(Get-PimIdentityNamesList -Seam $Arm -Path "$rg/providers/Microsoft.App/containerApps?api-version=$ApiVersion")
        $jobs = @(Get-PimIdentityNamesList -Seam $Arm -Path "$rg/providers/Microsoft.App/jobs?api-version=$ApiVersion")
    } catch {
        $m = "$($_.Exception.Message)"; if (-not $m.Trim()) { $m = 'the read failed' }
        return (Get-PimIdentityNamesFact -ReadError $m)
    }
    try {
        $ids = @(); $idErr = ''
        try { $ids = @(Get-PimIdentityNamesList -Seam $Arm -Path "$rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=$MsiApiVersion") }
        catch { $idErr = "$($_.Exception.Message)"; if (-not $idErr.Trim()) { $idErr = 'the read failed' } }
        $rights = @{}; $n = 0
        foreach ($x in @(Get-PimIdentityNamesOld -Apps $apps -Jobs $jobs -Identities $ids)) {
            if (-not $x.principalId) { continue }
            if ($n -ge (Get-PimIdentityNamesOldMax)) { break }
            $n++
            $pidX = $x.principalId
            $r = @{ azure = $null; graph = $null }
            try {
                $f = [uri]::EscapeDataString("principalId eq '$pidX'")
                $mineRa = { param($a) "$(Get-PimIdentityNamesField (Get-PimIdentityNamesField $a 'properties') 'principalId')".Trim() -ieq $pidX }
                $atRg = @(Get-PimIdentityNamesList -Seam $Arm -Path "$rg/providers/Microsoft.Authorization/roleAssignments?api-version=$AuthApiVersion&`$filter=$f" | Where-Object { & $mineRa $_ })
                $atSub = @(Get-PimIdentityNamesList -Seam $Arm -Path "$sub/providers/Microsoft.Authorization/roleAssignments?api-version=$AuthApiVersion&`$filter=$f" | Where-Object { & $mineRa $_ })
                $r.azure = [bool](($atRg.Count + $atSub.Count) -gt 0)
            } catch { $r.azure = $null }
            if ($Graph -and $r.azure -ne $true) {
                try { $r.graph = [bool](@(Get-PimIdentityNamesList -Seam $Graph -Path "/servicePrincipals/$pidX/appRoleAssignments").Count -gt 0) } catch { $r.graph = $null }
            }
            $rights[$pidX] = $r
        }
        return (Get-PimIdentityNamesFact -Apps $apps -Jobs $jobs -Identities $ids -Rights $rights -GraphRead ([bool]$Graph) -IdentitiesError $idErr)
    } catch { return [ordered]@{ identityNames = 'unknown'; identityNamesDetail = 'the identity names could not be worked out from the apps / jobs read' } }
}
