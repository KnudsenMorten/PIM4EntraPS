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
#>

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
        '^caj-pim-asbuilt$'                       { return 'asbuilt' }
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
