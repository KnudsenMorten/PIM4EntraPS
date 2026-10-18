#Requires -Version 5.1
<#
.SYNOPSIS
    REQ-U (prereqs) -- the LIVE half of Initialize-PimWorkloadPrereqs.ps1: gathers each prerequisite's facts from
    Graph / ARM / Fabric, fixes what an API can fix (read back every time), and hands the facts to the PURE verdicts
    in engine\_shared\PIM-WorkloadPrereqs.ps1.

.DESCRIPTION
    Every call goes through Invoke-PimGraph / Invoke-PimArm / Invoke-PimRest (engine\_shared\PIM-Rest.ps1) as the
    CALLER's identity -- the certificate identity or the signed-in user Connect-PimSetupStore set up -- so there is no
    command-line tool, no second identity and nothing interactive. tests\Test-PimWorkloadPrereqs.ps1 dot-sources this file and
    replaces those three functions with stubs, so the whole run is proven offline.

    The APIs used (all documented; cited per call below):
      Graph v1.0  servicePrincipals/{id}/appRoleAssignments (read + POST)  -- learn.microsoft.com/graph/api/serviceprincipal-post-approleassignments
      Graph beta  roleManagement/defender/roleDefinitions                  -- the engine's own Defender surface (beta only)
      Graph v1.0  deviceManagement/roleDefinitions                         -- the engine's Intune surface
      Graph v1.0  groups (GET/POST), groups/{id}/members/$ref (POST)       -- learn.microsoft.com/graph/api/group-post-groups
      Graph v1.0  servicePrincipals/{id}/memberOf                          -- the membership, read from the IDENTITY's side (PIM 100.108:
                                                                              groups/{id}/members leaves managed identities out for an app-only caller)
      Graph v1.0  subscribedSkus                                           -- learn.microsoft.com/graph/api/subscribedsku-list
      ARM         Microsoft.SecurityInsights/onboardingStates/default      -- learn.microsoft.com/rest/api/securityinsights/sentinel-onboarding-states/get
      ARM         Microsoft.ResourceGraph/resources (workspaces)            -- the same ARG call PIM-Rest.ps1 already makes
      ARM         Microsoft.Authorization/roleAssignments (atScope() and assignedTo) + PUT
      ARM         Microsoft.App/jobs/{name} (identity.principalId)
      Fabric      GET /v1/admin/tenantsettings, POST /v1/admin/tenantsettings/{name}/update
                                                                           -- learn.microsoft.com/rest/api/fabric/admin/tenants/*
      Power BI    GET /v1.0/myorg/admin/groups (as the ENGINE, only with its certificate here)
    What has NO API (said so in the catalog, reported as a portal step): activating Defender Unified RBAC workloads,
    connecting a Sentinel workspace to the Defender portal / onboarding the Sentinel data lake.
#>

function ConvertFrom-PimPrereqJwt {
    # PURE: a JWT's claims (never validates the signature -- only used to read what the CALLER may do).
    param([string]$Token)
    try {
        $seg = "$Token".Split('.')[1].Replace('-', '+').Replace('_', '/')
        while ($seg.Length % 4) { $seg += '=' }
        return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json)
    } catch { return $null }
}

function Invoke-PimPrereqProbe {
    # Run one call; never throw. Returns @{ ok; code; value; error }.
    param([Parameter(Mandatory)][scriptblock]$Call)
    try { $v = & $Call; return @{ ok = $true; code = 200; value = $v; error = '' } }
    catch { $m = "$($_.Exception.Message)"; return @{ ok = $false; code = (Get-PimPrereqHttpCode -Message $m); value = $null; error = $m } }
}

function Test-PimPrereqShould {
    # The ShouldProcess gate the script passes in (-WhatIf / -Confirm). Absent = allowed (tests pass their own).
    # 97.1: the engine's SELF-CHECK (Ctx.selfCheck) never changes anything -- it only reads, as the engine.
    param([hashtable]$Ctx, [string]$Target, [string]$Action)
    if ($Ctx.ContainsKey('selfCheck') -and $Ctx.selfCheck) { return $false }
    if ($Ctx.ContainsKey('should') -and $Ctx.should) { return [bool](& $Ctx.should $Target $Action) }
    return $true
}

function Get-PimPrereqNotDoneReason {
    # Why a fix was NOT made, in the words of the run: the person's -WhatIf / declined prompt, or the engine's
    # self-check, which never grants or creates anything (97.1).
    param([hashtable]$Ctx, [string]$Verb = 'changed')
    if ($Ctx.ContainsKey('selfCheck') -and $Ctx.selfCheck) { return "not $Verb -- PIM only checks; an administrator fixes it with the command PIM Manager shows" }
    return "not ${Verb}: -WhatIf or declined"
}

function Get-PimPrereqNotPreviewable {
    # Framework 12.7: under -WhatIf, a step that depends on an earlier fix that was NOT made says so -- '' otherwise.
    param([hashtable]$Ctx, [Parameter(Mandatory)][string]$Steps)
    if ($Ctx.ContainsKey('whatIf') -and $Ctx.whatIf) { return "; $Steps cannot be previewed -- run without -WhatIf to apply" }
    return ''
}

function Resolve-PimPrereqEngineIdentity {
    <#
      The ENGINE identity whose prerequisites are checked (not the caller). One of, in order:
        -EngineObjectId (service principal object id) | -EngineAppId | the hosted tick job's system identity
        (ARM GET Microsoft.App/jobs/{TickJobName} -> identity.principalId).
      Returns @{ objectId; appId; displayName; kind } or throws -- a prerequisite run against no identity is worthless.
    #>
    # PIM 100.108 (d): the hosted tick job can carry TWO identities (system-assigned + user-assigned). The engine signs in
    # as ONE of them for every call, Power BI included (Select-PimPrereqTickJobIdentity: the one PIM_ManagedIdentityClientId
    # names, else the system-assigned). That one is returned -- identityKind says which, notUsed lists the other(s).
    param([string]$EngineObjectId, [string]$EngineAppId, [string]$SubscriptionId, [string]$ResourceGroup, [string]$TickJobName = 'ca-pim-tick')
    $sp = $null; $pick = $null
    $sel = 'id,appId,displayName,servicePrincipalType,alternativeNames'
    if ("$EngineObjectId".Trim()) {
        $sp = Invoke-PimGraph -Path "/servicePrincipals/$("$EngineObjectId".Trim())?`$select=$sel"
    } elseif ("$EngineAppId".Trim()) {
        $sp = @(Invoke-PimGraph -All -Path "/servicePrincipals?`$filter=appId eq '$("$EngineAppId".Trim())'&`$select=$sel") | Select-Object -First 1
    } else {
        if (-not "$SubscriptionId".Trim() -or -not "$ResourceGroup".Trim()) { throw 'no engine identity: give -EngineObjectId, -EngineAppId, or -SubscriptionId + -ResourceGroup (+ -TickJobName) of the hosted tick job.' }
        # CR5 step 2 (PIM 100.149): the engine job is ca-pim-tick at every install made before the new names and ca-pim-engine
        # at a new one -- a name of the engine role that is not there falls to the role's other name (never to anything else)
        $jobNames = @($TickJobName)
        if ((Get-Command Test-PimInstallNameIsRole -ErrorAction SilentlyContinue) -and (Test-PimInstallNameIsRole -Role engine -Name $TickJobName)) { $jobNames = @(Get-PimInstallNameCandidates -Role engine -Preferred $TickJobName) }
        $job = $null
        for ($ji = 0; $ji -lt $jobNames.Count; $ji++) {
            try { $job = Invoke-PimArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$($jobNames[$ji])" -ApiVersion '2024-03-01'; $TickJobName = $jobNames[$ji]; break }
            catch { if ($ji -lt ($jobNames.Count - 1) -and "$($_.Exception.Message)" -match '(?i)\b404\b|NotFound|was not found') { continue }; throw }
        }
        $pick = Select-PimPrereqTickJobIdentity -Job $job -JobName $TickJobName
        $sp = Invoke-PimGraph -Path "/servicePrincipals/$($pick.objectId)`?`$select=$sel"
    }
    if (-not $sp -or -not "$($sp.id)".Trim()) { throw 'the engine identity was not found in this tenant.' }
    $kind = if ("$($sp.servicePrincipalType)" -ieq 'ManagedIdentity') { 'managedIdentity' } else { 'application' }
    $ik = Get-PimPrereqIdentityKind -ServicePrincipal $sp -Fallback $(if ($pick) { "$($pick.identityKind)" } else { '' })
    $out = @{ objectId = "$($sp.id)"; appId = "$($sp.appId)"; displayName = "$($sp.displayName)"; kind = $kind; identityKind = $ik; why = ''; notUsed = @() }
    if ($pick) { $out.why = "$($pick.why)"; $out.notUsed = @($pick.notUsed) }
    return $out
}

function Get-PimPrereqGraphSp {
    # The tenant's Microsoft Graph service principal (id + application appRoles), cached on the context.
    param([hashtable]$Ctx)
    if (-not $Ctx.graphSp) {
        $ids = Get-PimWorkloadPrereqGraphRoleIds
        $Ctx.graphSp = @(Invoke-PimGraph -All -Path "/servicePrincipals?`$filter=appId eq '$($ids.graphAppId)'&`$select=id,appRoles") | Select-Object -First 1
        if (-not $Ctx.graphSp) { throw 'the Microsoft Graph service principal was not found in this tenant.' }
    }
    return $Ctx.graphSp
}

function Get-PimPrereqEngineAssignments {
    # The engine identity's app-role assignments (all resources). Cached; -Refresh re-reads (read-back after a grant).
    param([hashtable]$Ctx, [switch]$Refresh)
    if ($Refresh -or $null -eq $Ctx.engineAssignments) {
        $Ctx.engineAssignments = @(Invoke-PimGraph -All -Path "/servicePrincipals/$($Ctx.engine.objectId)/appRoleAssignments")
    }
    return $Ctx.engineAssignments
}

function Get-PimPrereqEngineGraphRoleNames {
    param([hashtable]$Ctx, [switch]$Refresh)
    $gsp = Get-PimPrereqGraphSp -Ctx $Ctx
    $byId = @{}; foreach ($r in @($gsp.appRoles)) { $byId["$($r.id)"] = "$($r.value)" }
    return @(Get-PimPrereqEngineAssignments -Ctx $Ctx -Refresh:$Refresh | Where-Object { "$($_.resourceId)" -eq "$($gsp.id)" } | ForEach-Object { $byId["$($_.appRoleId)"] } | Where-Object { $_ })
}

function Invoke-PimPrereqGraphRoleCheck {
    <#
      Check that the engine identity holds every Graph application role in -Required; grant the missing ones (POST
      appRoleAssignments) and READ BACK. SEC-18: a role is only granted when the role map's id IS the live id.
    #>
    param([hashtable]$Ctx, [Parameter(Mandatory)][string]$CheckId, [Parameter(Mandatory)][string[]]$Required)
    $r = Invoke-PimPrereqProbe { Get-PimPrereqEngineGraphRoleNames -Ctx $Ctx }
    $src = ''
    if (-not $r.ok -and $Ctx.ContainsKey('tokenRoles') -and @($Ctx.tokenRoles | Where-Object { "$_".Trim() }).Count) {
        # 97.1 self-check: the engine's OWN token lists the application roles it holds -- no read permission needed.
        # A grant made in the last hour may not be in the token yet (Entra token caching): it shows on the next check.
        $r = @{ ok = $true; value = @($Ctx.tokenRoles | Where-Object { "$_".Trim() }); error = '' }; $src = ' (read from the engine''s own token)'
    }
    if (-not $r.ok) {
        return (New-PimWorkloadPrereqCheck -Id $CheckId -Status 'notChecked' -Detail "could not read the engine identity's app-role assignments: $($r.error) (the caller needs Application.Read.All or Directory.Read.All)")
    }
    $v = Test-PimPrereqGraphRoles -Held @($r.value) -Required $Required
    if ($v.ok) { return (New-PimWorkloadPrereqCheck -Id $CheckId -Status 'ok' -Detail "holds all $(@($Required).Count): $(@($Required) -join ', ')$src") }
    if ($Ctx.ContainsKey('selfCheck') -and $Ctx.selfCheck) {
        return (New-PimWorkloadPrereqCheck -Id $CheckId -Status 'failed' -Data @{ missingRoles = @($v.missing) } `
                  -Detail "missing: $(@($v.missing) -join ', ')$src -- PIM never grants itself a permission: an administrator grants it with the published Grant-PimEnginePermissions.ps1 (browser sign-in)")
    }
    $gsp = Get-PimPrereqGraphSp -Ctx $Ctx
    $live = @{}; foreach ($ar in @($gsp.appRoles)) { if (@($ar.allowedMemberTypes) -contains 'Application') { $live["$($ar.value)"] = "$($ar.id)" } }
    $problems = New-Object System.Collections.Generic.List[string]
    $attempted = 0
    foreach ($name in @($v.missing)) {
        $lid = $live[$name]
        if (-not $lid) { $problems.Add("$name is not a Graph application role in this tenant"); continue }
        if ($Ctx.roleMap -and $Ctx.roleMap.ContainsKey($name) -and "$($Ctx.roleMap[$name])" -ne $lid) { $problems.Add("$name -- the role map id $($Ctx.roleMap[$name]) is not the live id $lid (fix _PimSetupShared.ps1); NOT granted"); continue }
        if (-not (Test-PimPrereqShould -Ctx $Ctx -Target $Ctx.engine.displayName -Action "grant Graph application role $name")) { continue }
        $attempted++
        $p = Invoke-PimPrereqProbe { Invoke-PimGraph -Method POST -Path "/servicePrincipals/$($Ctx.engine.objectId)/appRoleAssignments" -Body @{ principalId = $Ctx.engine.objectId; resourceId = "$($gsp.id)"; appRoleId = $lid } }
        if (-not $p.ok) { $problems.Add("$name grant failed: $($p.error)") }
    }
    if (-not $attempted) {
        $why = if ($problems.Count) { " ($($problems -join '; '))" } else { " ($(Get-PimPrereqNotDoneReason -Ctx $Ctx -Verb 'granted'))" }
        return (New-PimWorkloadPrereqCheck -Id $CheckId -Status 'failed' -Data @{ missingRoles = @($v.missing) } -Detail "missing: $(@($v.missing) -join ', ')$why")
    }
    $back = Test-PimPrereqGraphRoles -Held @(Get-PimPrereqEngineGraphRoleNames -Ctx $Ctx -Refresh) -Required $Required
    if ($back.ok) { return (New-PimWorkloadPrereqCheck -Id $CheckId -Status 'fixed' -Detail "granted $(@($v.missing) -join ', ') and read back (a running engine picks new roles up with its next token)") }
    return (New-PimWorkloadPrereqCheck -Id $CheckId -Status 'failed' -Data @{ missingRoles = @($back.missing) } -Detail "still missing after the grant: $(@($back.missing) -join ', ')$(if ($problems.Count) { ' -- ' + ($problems -join '; ') })")
}

function Get-PimPrereqSentinelWorkspaceId {
    # The workspace -EnableSentinel acts on: -SentinelWorkspaceId, else a DEDICATED one in the hosting resource group,
    # named after it (rg-automateit-wa678 -> law-sentinel-wa678).
    param([hashtable]$Ctx)
    if ("$($Ctx.sentinelWorkspaceId)".Trim()) { return "$($Ctx.sentinelWorkspaceId)".Trim().TrimEnd('/') }
    if (-not "$($Ctx.hostingSubscriptionId)".Trim() -or -not "$($Ctx.hostingResourceGroup)".Trim()) { return '' }
    $suffix = ("$($Ctx.hostingResourceGroup)" -split '-')[-1]
    $name = if ($suffix -and $suffix -ne "$($Ctx.hostingResourceGroup)") { "law-sentinel-$suffix" } else { 'law-pim-sentinel' }
    return "/subscriptions/$($Ctx.hostingSubscriptionId)/resourceGroups/$($Ctx.hostingResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$name"
}

function Enable-PimPrereqSentinel {
    # -EnableSentinel (operator 2026-09-19: "you must setup all" / "add to prereq script to enable"). OPT-IN, because
    # Sentinel bills per GB the workspace ingests. So it goes on a DEDICATED security workspace -- created empty when
    # missing (PerGB2018, 30 days) -- and NEVER on PIM's own log workspace (law-pim-*), where it would bill every
    # container log line. Every step is ShouldProcess-gated and read back.
    param([hashtable]$Ctx)
    $id = Get-PimPrereqSentinelWorkspaceId -Ctx $Ctx
    if (-not $id) { return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail '-EnableSentinel: no workspace to act on -- pass -SentinelWorkspaceId or -ResourceGroup.') }
    $name = ($id -split '/')[-1]
    if ($name -match '(?i)^law-pim-' -and $name -ne 'law-pim-sentinel') {
        return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "-EnableSentinel REFUSED on '$name': that is PIM's own log workspace, where Sentinel would bill every container log line. Omit -SentinelWorkspaceId to use a dedicated workspace, or name your security workspace.")
    }
    if ($id -notmatch '(?i)^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/Microsoft\.OperationalInsights/workspaces/[^/]+$') {
        return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "-EnableSentinel: '$id' is not a Log Analytics workspace resource id.")
    }
    $rgId = ($id -split '/providers/')[0]
    $done = New-Object System.Collections.Generic.List[string]
    # 1. The workspace (created when missing).
    $w = Invoke-PimPrereqProbe { Invoke-PimArm -Path $id -ApiVersion '2023-09-01' }
    if (-not $w.ok -and $w.code -ne 404) { return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'notChecked' -Detail "could not read workspace '$name': $($w.error)") }
    if (-not $w.ok) {
        if (-not (Test-PimPrereqShould -Ctx $Ctx -Target $name -Action 'create Log Analytics workspace (PerGB2018, 30 days retention)')) {
            return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "workspace '$name' does not exist (not created: -WhatIf or declined)$(Get-PimPrereqNotPreviewable -Ctx $Ctx -Steps 'registering Microsoft.OperationsManagement + Microsoft.SecurityInsights and enabling Microsoft Sentinel on it')")
        }
        $rg = Invoke-PimPrereqProbe { Invoke-PimArm -Path $rgId -ApiVersion '2021-04-01' }
        if (-not $rg.ok) { return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "could not read resource group for '$name': $($rg.error)") }
        $c = Invoke-PimPrereqProbe { Invoke-PimArm -Method PUT -Path $id -ApiVersion '2023-09-01' -Body @{ location = "$($rg.value.location)"
                tags = @{ purpose = 'PIM4EntraPS: Microsoft Sentinel for Defender Data Operations roles' }
                properties = @{ sku = @{ name = 'PerGB2018' }; retentionInDays = 30 } } }
        if (-not $c.ok) { return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "could not create workspace '$name': $($c.error)") }
        $done.Add("created workspace '$name' ($($rg.value.location))")
    }
    # 2. The resource providers Sentinel needs, registered on the workspace's subscription. Measured 2026-09-19 on EFIF
    #    and RIDE: Microsoft.SecurityInsights + Microsoft.OperationsManagement were NotRegistered and the tenant had no
    #    "Azure Security Insights" first-party service principal -- the onboarding PUT then answered 401 "Unauthorized
    #    access while trying to fetch workspace details", which reads like a permission problem and is not one.
    $subId = ($id -split '/')[2]
    foreach ($rp in 'Microsoft.OperationsManagement', 'Microsoft.SecurityInsights') {
        $st = Invoke-PimPrereqProbe { Invoke-PimArm -Path "/subscriptions/$subId/providers/$rp" -ApiVersion '2021-04-01' }
        if ($st.ok -and "$($st.value.registrationState)" -eq 'Registered') { continue }
        if (-not (Test-PimPrereqShould -Ctx $Ctx -Target "subscription $subId" -Action "register resource provider $rp")) {
            return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "resource provider $rp is not registered (not registered: -WhatIf or declined)$(if ($done.Count) { '; ' + ($done -join '; ') })$(Get-PimPrereqNotPreviewable -Ctx $Ctx -Steps 'enabling Microsoft Sentinel on the workspace')")
        }
        $r = Invoke-PimPrereqProbe { Invoke-PimArm -Method POST -Path "/subscriptions/$subId/providers/$rp/register" -ApiVersion '2021-04-01' }
        if (-not $r.ok) { return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "could not register resource provider ${rp}: $($r.error)$(if ($done.Count) { '; ' + ($done -join '; ') })") }
        $state = ''
        for ($i = 0; $i -lt 36; $i++) {
            $st = Invoke-PimPrereqProbe { Invoke-PimArm -Path "/subscriptions/$subId/providers/$rp" -ApiVersion '2021-04-01' }
            $state = if ($st.ok) { "$($st.value.registrationState)" } else { '' }
            if ($state -eq 'Registered') { break }
            Start-Sleep -Seconds ([int]$Ctx.pollSeconds)
        }
        if ($state -ne 'Registered') { return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "resource provider $rp is still '$state' after registering -- re-run in a few minutes$(if ($done.Count) { '; ' + ($done -join '; ') })") }
        $done.Add("registered resource provider $rp")
    }
    # 3. Sentinel on it (Microsoft.SecurityInsights onboardingStates/default).
    $osPath = "$id/providers/Microsoft.SecurityInsights/onboardingStates/default"
    if (-not (Test-PimPrereqShould -Ctx $Ctx -Target $name -Action 'enable Microsoft Sentinel (billed per GB ingested)')) {
        return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "Sentinel not enabled on '$name' (-WhatIf or declined)$(if ($done.Count) { '; ' + ($done -join '; ') })")
    }
    # A 401 right after registering = Sentinel's first-party principal still propagating: retried, then reported as is.
    for ($i = 0; $i -lt 6; $i++) {
        $p = Invoke-PimPrereqProbe { Invoke-PimArm -Method PUT -Path $osPath -ApiVersion '2024-09-01' -Body @{ properties = @{} } }
        if ($p.ok -or $p.code -ne 401) { break }
        Start-Sleep -Seconds ([int]$Ctx.pollSeconds * 2)
    }
    if (-not $p.ok) { return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "could not enable Sentinel on '$name': $($p.error)$(if ($done.Count) { '; ' + ($done -join '; ') })") }
    $back = Invoke-PimPrereqProbe { Invoke-PimArm -Path $osPath -ApiVersion '2024-09-01' }
    if (-not $back.ok) { return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "enabled Sentinel on '$name' but the read-back failed: $($back.error)") }
    $done.Add("enabled Sentinel on '$name' and read it back")
    return (New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'fixed' -Detail (($done -join '; ') + '. Next: connect it to the Defender portal (next check).'))
}

function Invoke-PimPrereqDefenderXdr {
    param([hashtable]$Ctx)
    $out = New-Object System.Collections.Generic.List[object]
    $out.Add((Invoke-PimPrereqGraphRoleCheck -Ctx $Ctx -CheckId 'defender.engineRole' -Required @('RoleManagement.ReadWrite.Defender')))

    # Unified RBAC reachable. Beta only: v1.0 answers 400 for this surface (REQ-U investigation, PIM-Discovery.ps1).
    $roles = Invoke-PimPrereqProbe { @(Invoke-PimGraph -Beta -All -Path '/roleManagement/defender/roleDefinitions') }
    $has = Test-PimPrereqTokenHasRole -Claims $Ctx.callerClaims -AnyOf @('RoleManagement.Read.Defender', 'RoleManagement.ReadWrite.Defender')
    $code = if ($roles.ok) { 200 } else { $roles.code }
    $pv = Get-PimPrereqProbeVerdict -StatusCode $code -CallerHasPermission $has -What 'GET beta/roleManagement/defender/roleDefinitions' -Needs 'RoleManagement.Read.Defender' -ErrorText $roles.error
    if ($roles.ok) { $pv.detail = "$($pv.detail) $(@($roles.value).Count) role definition(s)." }
    $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.urbacReachable' -Status $pv.status -Detail $pv.detail))

    # Activated workloads: portal only; INFERRED from the live roles when they are readable.
    $inf = if ($roles.ok) { (Get-PimDefenderUrbacInference -RoleDefinitions @($roles.value)).detail } else { 'cannot infer: the role definitions could not be read.' }
    $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.urbacWorkloads' -Status 'manual' -Detail "portal only -- $inf"))

    if ($Ctx.skipDataOperations) {
        foreach ($id in @('defender.dataOpsCatalog', 'defender.sentinelEnabled', 'defender.sentinelInDefender')) {
            $out.Add((New-PimWorkloadPrereqCheck -Id $id -Status 'skipped' -Detail 'Data Operations roles not used (-SkipDataOperations).'))
        }
        return $out.ToArray()
    }
    # Data Operations in the permission CATALOG (lead, measured 2026-09-19: a tenant without the Sentinel prerequisite
    # still lists the actions, so this alone is not enough -- the Sentinel checks below complete it). READ-ONLY: a role
    # is never created to probe it.
    $nsp = Invoke-PimPrereqProbe { @(Invoke-PimGraph -Beta -All -Path '/roleManagement/defender/resourceNamespaces?$expand=resourceActions') }
    if ($nsp.ok) {
        # The ACTION STRING is the resourceAction's `id` (microsoft.xdr/dataops/*/read); `name` is display text
        # ("DataOperations - All read-only permissions"). Matching `name` never found it (measured on internal 2026-09-19).
        $acts = @($nsp.value | ForEach-Object { @($_.resourceActions) } | ForEach-Object { if ("$($_.id)") { "$($_.id)" } else { "$($_.name)" } } | Where-Object { $_ })
        $dataOps = @($acts | Where-Object { $_ -match '(?i)^microsoft\.xdr/dataops/' })
        if ($dataOps.Count) { $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.dataOpsCatalog' -Status 'ok' -Detail "the catalog lists $($dataOps.Count) Data Operations action(s) ($($dataOps -join ', ')) of $($acts.Count)")) }
        else { $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.dataOpsCatalog' -Status 'failed' -Detail "the catalog ($($acts.Count) actions) lists no microsoft.xdr/dataops/ action")) }
    } else {
        $v = Get-PimPrereqProbeVerdict -StatusCode $nsp.code -CallerHasPermission $has -What 'GET beta/roleManagement/defender/resourceNamespaces' -Needs 'RoleManagement.Read.Defender' -ErrorText $nsp.error
        $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.dataOpsCatalog' -Status $v.status -Detail $v.detail))
    }
    # Sentinel enabled: the named workspace, else every workspace the caller can see (ARG), each asked for its
    # Sentinel onboarding state.
    $ws = @()
    if ("$($Ctx.sentinelWorkspaceId)".Trim()) { $ws = @([pscustomobject]@{ id = "$($Ctx.sentinelWorkspaceId)".Trim().TrimEnd('/'); name = ("$($Ctx.sentinelWorkspaceId)".TrimEnd('/') -split '/')[-1] }) }
    else {
        $q = Invoke-PimPrereqProbe {
            Invoke-PimArm -Method POST -Path '/providers/Microsoft.ResourceGraph/resources' -ApiVersion '2021-03-01' -Body @{
                query = "resources | where type =~ 'microsoft.operationalinsights/workspaces' | project id, name | take 200"; options = @{ resultFormat = 'objectArray' } }
        }
        if ($q.ok) { $ws = @($q.value.data | Where-Object { $_ }) }
        else { $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'notChecked' -Detail "could not list Log Analytics workspaces (Azure Resource Graph): $($q.error). Pass -SentinelWorkspaceId.")) }
    }
    if ($ws.Count -or "$($Ctx.sentinelWorkspaceId)".Trim()) {
        $on = New-Object System.Collections.Generic.List[string]; $unreadable = New-Object System.Collections.Generic.List[string]
        foreach ($w in $ws) {
            $s = Invoke-PimPrereqProbe { Invoke-PimArm -Path "$($w.id)/providers/Microsoft.SecurityInsights/onboardingStates/default" -ApiVersion '2024-09-01' }
            if ($s.ok) { $on.Add("$($w.name)") }
            elseif ($s.code -ne 404) { $unreadable.Add("$($w.name) ($($s.code))") }
        }
        if ($on.Count) { $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'ok' -Detail "Sentinel is enabled on: $($on -join ', ')")) }
        elseif ($unreadable.Count) { $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'notChecked' -Detail "the onboarding state could not be read for: $($unreadable -join ', ') (the caller needs Reader on the workspace)")) }
        elseif ($Ctx.enableSentinel) { $out.Add((Enable-PimPrereqSentinel -Ctx $Ctx)) }
        elseif ($Ctx.ContainsKey('selfCheck') -and $Ctx.selfCheck) {
            # 97.1: the engine only sees the workspaces it has Reader on -- "none of those" is not "none in the tenant".
            $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'notChecked' -Detail "none of the $($ws.Count) Log Analytics workspace(s) the engine can see has Sentinel enabled -- it may not have Reader on your security workspace. Sentinel enabled there? Press Confirm."))
        }
        else { $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'failed' -Detail "no Sentinel-enabled workspace among the $($ws.Count) workspace(s) the caller can see (run with -EnableSentinel to enable it on a dedicated workspace)")) }
    } elseif ($Ctx.enableSentinel -and -not @($out | Where-Object { $_.id -eq 'defender.sentinelEnabled' }).Count) {
        $out.Add((Enable-PimPrereqSentinel -Ctx $Ctx))
    } elseif (-not @($out | Where-Object { $_.id -eq 'defender.sentinelEnabled' }).Count) {
        $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.sentinelEnabled' -Status 'notChecked' -Detail 'the caller can see no Log Analytics workspace -- pass -SentinelWorkspaceId <workspace resource id>.'))
    }
    $out.Add((New-PimWorkloadPrereqCheck -Id 'defender.sentinelInDefender' -Status 'manual' -Detail 'portal only (no public API connects a workspace to the Defender portal).'))
    return $out.ToArray()
}

function Invoke-PimPrereqIntune {
    param([hashtable]$Ctx)
    $out = New-Object System.Collections.Generic.List[object]
    $out.Add((Invoke-PimPrereqGraphRoleCheck -Ctx $Ctx -CheckId 'intune.engineRole' -Required @('DeviceManagementRBAC.ReadWrite.All')))
    $p = Invoke-PimPrereqProbe { @(Invoke-PimGraph -Path '/deviceManagement/roleDefinitions?$select=id,displayName&$top=5') }
    $has = Test-PimPrereqTokenHasRole -Claims $Ctx.callerClaims -AnyOf @('DeviceManagementRBAC.Read.All', 'DeviceManagementRBAC.ReadWrite.All')
    $v = Get-PimPrereqProbeVerdict -StatusCode $(if ($p.ok) { 200 } else { $p.code }) -CallerHasPermission $has -What 'GET deviceManagement/roleDefinitions' -Needs 'DeviceManagementRBAC.Read.All' -ErrorText $p.error
    $out.Add((New-PimWorkloadPrereqCheck -Id 'intune.rbacReadable' -Status $v.status -Detail $v.detail))
    return $out.ToArray()
}

function Get-PimPrereqFabricTenantSettings {
    # GET /v1/admin/tenantsettings, following continuationUri (Invoke-PimRest -All follows nextLink only).
    $all = New-Object System.Collections.Generic.List[object]
    $url = 'https://api.fabric.microsoft.com/v1/admin/tenantsettings'
    $guard = 0
    while ($url -and $guard -lt 20) {
        $guard++
        $r = Invoke-PimRest -Url $url -Resource 'https://api.fabric.microsoft.com'
        foreach ($s in @($r.value)) { if ($s) { $all.Add($s) } }
        $url = if ($r -and $r.PSObject.Properties['continuationUri'] -and "$($r.continuationUri)".Trim()) { "$($r.continuationUri)" } else { $null }
    }
    return $all.ToArray()
}

function Invoke-PimPrereqAsEngine {
    # One GET AS THE ENGINE -- only possible where the engine's own certificate is on this host (an engine
    # application; a managed identity can never be signed in as from here). Returns a probe result.
    param([hashtable]$Ctx, [Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Resource)
    # 97.1: in the engine's self-check the caller IS the engine -- the call needs no second sign-in.
    if ($Ctx.ContainsKey('selfCheck') -and $Ctx.selfCheck) { return (Invoke-PimPrereqProbe { Invoke-PimRest -Url $Url -Resource $Resource }) }
    if (-not "$($Ctx.engineCertThumbprint)".Trim() -or -not "$($Ctx.engine.appId)".Trim()) {
        return @{ ok = $false; code = 0; value = $null; error = 'not run: the engine is a managed identity or its certificate is not on this host (-EngineAppId + -EngineCertThumbprint)'; skipped = $true }
    }
    return (Invoke-PimPrereqProbe {
        $t = Get-PimRestToken -Resource $Resource -TenantId $Ctx.tenantId -ClientId $Ctx.engine.appId -CertThumbprint $Ctx.engineCertThumbprint -Force
        Invoke-RestMethod -Method GET -Uri $Url -Headers @{ Authorization = "Bearer $t" }
    })
}

function Get-PimPrereqFabricAdminRole {
    <#
      PIM 100.142. The Entra built-in directory role "Fabric Administrator", LOOKED UP by its display name (never a
      hard-coded id): GET roleManagement/directory/roleDefinitions?$filter=displayName eq '...'. Its roleTemplateId is the
      templateId (the id for a built-in role). Older tenants may still show the former name "Power BI Administrator" --
      looked up second. Returns @{ id; displayName } or $null when neither exists.
    #>
    foreach ($name in @('Fabric Administrator', 'Power BI Administrator')) {
        $r = @(Invoke-PimGraph -All -Path "/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$name'&`$select=id,displayName,templateId,isBuiltIn")
        $hit = @($r | Where-Object { $_ -and "$($_.displayName)" -ieq $name }) | Select-Object -First 1
        if ($hit) {
            $rid = if ("$($hit.templateId)".Trim()) { "$($hit.templateId)".Trim() } else { "$($hit.id)".Trim() }
            if ($rid) { return @{ id = $rid; displayName = "$($hit.displayName)" } }
        }
    }
    return $null
}

function Get-PimPrereqFabricAdminAssignments {
    # The engine identity's ACTIVE assignments of that role at the directory scope ('/'): roleManagement/directory/roleAssignments.
    param([hashtable]$Ctx, [Parameter(Mandatory)][string]$RoleId)
    $oid = "$($Ctx.engine.objectId)".Trim()
    $rows = @(Invoke-PimGraph -All -Path "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$oid' and roleDefinitionId eq '$RoleId'&`$select=id,principalId,roleDefinitionId,directoryScopeId")
    return @($rows | Where-Object { $_ -and "$($_.principalId)" -ieq $oid -and "$($_.roleDefinitionId)" -ieq $RoleId -and ("$($_.directoryScopeId)" -eq '/' -or -not "$($_.directoryScopeId)".Trim()) })
}

function Invoke-PimPrereqFabricAdmin {
    <#
      PIM 100.142 (owner 2026-10-13: "Admin API, no membership"). Check -- and with -GrantFabricAdministrator, assign -- the
      Entra directory role Fabric Administrator to the ENGINE identity as a PERMANENT ACTIVE assignment at the directory
      scope ('/'): POST roleManagement/directory/roleAssignments { principalId; roleDefinitionId; directoryScopeId = '/' },
      then read back. Idempotent: an existing active assignment is left as it is, nothing is posted twice. Without the
      switch (and in the engine's own self-check) nothing is ever assigned -- the check only reports.
    #>
    param([hashtable]$Ctx)
    $who = Get-PimPowerBiPrereqIdentityText -Identity $Ctx.engine
    $grant = ($Ctx.ContainsKey('grantFabricAdmin') -and [bool]$Ctx.grantFabricAdmin)
    $delay = if ("$env:PIM_PREREQ_READBACK_SECONDS".Trim()) { [int]$env:PIM_PREREQ_READBACK_SECONDS } else { 5 }
    $role = Invoke-PimPrereqProbe { Get-PimPrereqFabricAdminRole }
    if (-not $role.ok) { return (New-PimWorkloadPrereqCheck -Id 'powerbi.fabricAdmin' -Status 'notChecked' -Detail "could not look the role 'Fabric Administrator' up: $($role.error) (the caller needs RoleManagement.Read.Directory)") }
    if (-not $role.value) { return (New-PimWorkloadPrereqCheck -Id 'powerbi.fabricAdmin' -Status 'notChecked' -Detail "this tenant lists no directory role named 'Fabric Administrator'") }
    $rid = "$($role.value.id)"; $rname = "$($role.value.displayName)"
    $have = Invoke-PimPrereqProbe { Get-PimPrereqFabricAdminAssignments -Ctx $Ctx -RoleId $rid }
    if (-not $have.ok) { return (New-PimWorkloadPrereqCheck -Id 'powerbi.fabricAdmin' -Status 'notChecked' -Detail "could not read the role assignments of ${who}: $($have.error) (the caller needs RoleManagement.Read.Directory)") }
    if (@($have.value).Count) { return (New-PimWorkloadPrereqCheck -Id 'powerbi.fabricAdmin' -Status 'ok' -Detail "$who holds the directory role '$rname' (active, directory scope)" -Data @{ roleDefinitionId = $rid }) }
    if ($Ctx.ContainsKey('selfCheck') -and $Ctx.selfCheck) {
        return (New-PimWorkloadPrereqCheck -Id 'powerbi.fabricAdmin' -Status 'failed' -Data @{ roleDefinitionId = $rid } -Detail "$who does not hold the directory role '$rname' -- PIM never grants itself a role: a Global Administrator runs Initialize-PimWorkloadPrereqs.ps1 -Workload PowerBI -GrantFabricAdministrator once")
    }
    if (-not $grant) {
        return (New-PimWorkloadPrereqCheck -Id 'powerbi.fabricAdmin' -Status 'failed' -Data @{ roleDefinitionId = $rid } -Detail "$who does not hold the directory role '$rname' (not assigned: run again with -GrantFabricAdministrator to assign it)")
    }
    if (-not (Test-PimPrereqShould -Ctx $Ctx -Target $Ctx.engine.displayName -Action "assign the Entra directory role '$rname' (permanent, active, directory scope)")) {
        return (New-PimWorkloadPrereqCheck -Id 'powerbi.fabricAdmin' -Status 'failed' -Data @{ roleDefinitionId = $rid } -Detail "$who does not hold the directory role '$rname' ($(Get-PimPrereqNotDoneReason -Ctx $Ctx -Verb 'assigned'))")
    }
    $body = [ordered]@{ '@odata.type' = '#microsoft.graph.unifiedRoleAssignment'; principalId = "$($Ctx.engine.objectId)"; roleDefinitionId = $rid; directoryScopeId = '/' }
    $p = Invoke-PimPrereqProbe { Invoke-PimGraph -Method POST -Path '/roleManagement/directory/roleAssignments' -Body $body }
    if (-not $p.ok -and [int]$p.code -eq 403) {
        return (New-PimWorkloadPrereqCheck -Id 'powerbi.fabricAdmin' -Status 'failed' -Data @{ roleDefinitionId = $rid; refused = 403 } `
            -Detail "Graph refused to assign the directory role '$rname' to $who (HTTP 403: the identity signed in here may not assign directory roles -- sign in as a Global Administrator or Privileged Role Administrator)")
    }
    if (-not $p.ok -and "$($p.error)" -notmatch '(?i)already exist|conflicting object') {
        return (New-PimWorkloadPrereqCheck -Id 'powerbi.fabricAdmin' -Status 'failed' -Data @{ roleDefinitionId = $rid } -Detail "could not assign the directory role '$rname' to ${who}: $($p.error)")
    }
    for ($try = 1; $try -le 6; $try++) {
        $back = Invoke-PimPrereqProbe { Get-PimPrereqFabricAdminAssignments -Ctx $Ctx -RoleId $rid }
        if ($back.ok -and @($back.value).Count) {
            return (New-PimWorkloadPrereqCheck -Id 'powerbi.fabricAdmin' -Status 'fixed' -Data @{ roleDefinitionId = $rid } -Detail "assigned the directory role '$rname' to $who (permanent, active, directory scope) and read it back. Power BI honours it after a short while (up to about 30 minutes).")
        }
        if ($try -lt 6 -and $delay -gt 0) { Start-Sleep -Seconds $delay }
    }
    return (New-PimWorkloadPrereqCheck -Id 'powerbi.fabricAdmin' -Status 'notChecked' -Data @{ roleDefinitionId = $rid } -Detail "assigned the directory role '$rname' to $who, but the read-back does not show it yet (Entra can take a few minutes) -- press Check again in PIM Manager")
}

function Invoke-PimPrereqPowerBI {
    param([hashtable]$Ctx)
    $out = New-Object System.Collections.Generic.List[object]
    $gname = "$($Ctx.powerBiGroupName)".Trim()
    $gid = ''
    # PIM 100.108: every text NAMES the group and the ONE identity that must be in it (the identity the engine signs in
    # as for the Power BI call -- Resolve-PimPrereqEngineIdentity / the engine's own token in the self-check).
    $who = Get-PimPowerBiPrereqIdentityText -Identity $Ctx.engine
    $member = @{ displayName = "$($Ctx.engine.displayName)"; objectId = "$($Ctx.engine.objectId)"; identityKind = "$($Ctx.engine.identityKind)" }
    $delay = if ("$env:PIM_PREREQ_READBACK_SECONDS".Trim()) { [int]$env:PIM_PREREQ_READBACK_SECONDS } else { 5 }
    # 1. The security group.
    $g = Invoke-PimPrereqProbe { @(Invoke-PimGraph -All -Path "/groups?`$filter=displayName eq '$($gname.Replace("'", "''"))'&`$select=id,displayName,securityEnabled,mailEnabled") }
    $st0 = Get-PimPowerBiPrereqSteps -GroupName $gname -Identity $Ctx.engine
    if (-not $g.ok) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.group' -Status 'notChecked' -Detail "could not look the group '$gname' up: $($g.error)" -Data @{ groupName = $gname; members = @($member) } -ManualStep $st0.group)) }
    elseif (@($g.value).Count -gt 1) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.group' -Status 'failed' -Detail "$(@($g.value).Count) groups are named '$gname' -- ambiguous; rename one or pass -PowerBiSecurityGroupName" -Data @{ groupName = $gname; members = @($member) } -ManualStep $st0.group)) }
    elseif (@($g.value).Count -eq 1) {
        $gid = "$(@($g.value)[0].id)"
        if (-not [bool]@($g.value)[0].securityEnabled) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.group' -Status 'failed' -Detail "'$gname' ($gid) exists but is not a security group" -Data @{ groupName = $gname; members = @($member) } -ManualStep $st0.group)); $gid = '' }
        else { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.group' -Status 'ok' -Detail "'$gname' ($gid)" -Data @{ groupName = $gname; groupId = $gid })) }
    } else {
        if (Test-PimPrereqShould -Ctx $Ctx -Target $gname -Action 'create security group') {
            $nick = ($gname -replace '[^A-Za-z0-9]', '')
            if (-not $nick) { $nick = 'pimpowerbiadminapi' }
            $c = Invoke-PimPrereqProbe { Invoke-PimGraph -Method POST -Path '/groups' -Body @{ displayName = $gname; mailEnabled = $false; mailNickname = $nick; securityEnabled = $true
                    description = 'PIM4EntraPS: service principals allowed to call the Power BI read-only admin APIs (Fabric tenant setting).' } }
            # A new group is not readable at once (Entra replication), so the read-back RETRIES: by id when the POST returned
            # one, else by name. Measured 2026-09-19 on all three ring-1 tenants: an immediate single read-back "failed" while
            # the group had been created.
            $back = $null
            if ($c.ok) {
                $newId = "$(@($c.value)[0].id)"
                for ($try = 1; $try -le 6; $try++) {
                    $back = if ($newId) { Invoke-PimPrereqProbe { Invoke-PimGraph -Path "/groups/$newId`?`$select=id,securityEnabled" } }
                            else { $byName = Invoke-PimPrereqProbe { @(Invoke-PimGraph -All -Path "/groups?`$filter=displayName eq '$($gname.Replace("'", "''"))'&`$select=id,securityEnabled") }
                                   if ($byName.ok -and @($byName.value).Count -eq 1) { [pscustomobject]@{ ok = $true; value = @($byName.value)[0] } } else { $byName } }
                    if ($back -and $back.ok -and "$(@($back.value)[0].id)") { $back = [pscustomobject]@{ ok = $true; value = @($back.value)[0] }; break }
                    if ($try -lt 6 -and $delay -gt 0) { Start-Sleep -Seconds $delay }
                }
            }
            if ($back -and $back.ok -and [bool]$back.value.securityEnabled) { $gid = "$($back.value.id)"; $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.group' -Status 'fixed' -Detail "created '$gname' ($gid) and read it back" -Data @{ groupName = $gname; groupId = $gid })) }
            elseif (-not $c.ok -and [int]$c.code -eq 403) {
                # PIM 100.108 (d): a refusal is never left without the step -- say exactly what to create and who goes in it.
                $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.group' -Status 'failed' -Data @{ groupName = $gname; members = @($member); refused = 403 } -ManualStep $st0.group `
                    -Detail "the security group '$gname' does not exist, and Graph refused to create it (HTTP 403: the identity signed in here may not create groups -- it needs Group.Create or Group.ReadWrite.All). Create it yourself: a security group named '$gname', with this member: $who."))
            }
            else { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.group' -Status 'failed' -Detail "could not create '$gname': $(if ($c.ok) { 'read-back failed' } else { $c.error }). Create it yourself: a security group named '$gname', with this member: $who." -Data @{ groupName = $gname; members = @($member) } -ManualStep $st0.group)) }
        } else { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.group' -Status 'failed' -Detail "the security group '$gname' does not exist ($(Get-PimPrereqNotDoneReason -Ctx $Ctx -Verb 'created'))" -Data @{ groupName = $gname; members = @($member) } -ManualStep $st0.group)) }
    }
    # 2. The engine identity is a member -- read from the IDENTITY's side (its memberOf).
    #    PIM 100.108 (b): GET /groups/{id}/members does not list a managed identity for an app-only caller (measured on the
    #    vendor's own environment 2026-10-12: an empty list while servicePrincipals/{id}/memberOf showed the group), so
    #    "is it a member" is asked of the identity, never of the group.
    $steps = Get-PimPowerBiPrereqSteps -GroupName $gname -GroupId $gid -Identity $Ctx.engine
    $mdata = @{ groupName = $gname; groupId = $gid; members = @($member) }
    if (-not $gid) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.groupMember' -Status 'notChecked' -Detail "no usable group yet, so the membership of $who cannot be checked$(Get-PimPrereqNotPreviewable -Ctx $Ctx -Steps "adding $($Ctx.engine.displayName) to '$gname'")" -Data $mdata -ManualStep $steps.groupMember)) }
    else {
        $readMemberOf = { @(Invoke-PimGraph -All -Path "/servicePrincipals/$($Ctx.engine.objectId)/memberOf?`$select=id") | ForEach-Object { "$($_.id)" } }
        $m = Invoke-PimPrereqProbe $readMemberOf
        if (-not $m.ok) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.groupMember' -Status 'notChecked' -Detail "could not read which groups $who is a member of: $($m.error)" -Data $mdata -ManualStep $steps.groupMember)) }
        elseif (@($m.value) -contains $gid) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.groupMember' -Status 'ok' -Detail "$who is a member of '$gname'" -Data $mdata)) }
        elseif (Test-PimPrereqShould -Ctx $Ctx -Target $gname -Action "add member $($Ctx.engine.displayName)") {
            $a = Invoke-PimPrereqProbe { Invoke-PimGraph -Method POST -Path "/groups/$gid/members/`$ref" -Body @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($Ctx.engine.objectId)" } }
            # "already a member" (400, references already exist) is the wanted state -- the read-back decides.
            $sent = ($a.ok -or "$($a.error)" -match '(?i)already exist')
            $seen = $false
            if ($sent) {
                # A new membership is not in memberOf at once (Entra replication): the read-back RETRIES, like the group's.
                for ($try = 1; $try -le 6 -and -not $seen; $try++) {
                    $m2 = Invoke-PimPrereqProbe $readMemberOf
                    if ($m2.ok -and @($m2.value) -contains $gid) { $seen = $true; break }
                    if ($try -lt 6 -and $delay -gt 0) { Start-Sleep -Seconds $delay }
                }
            }
            if ($seen) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.groupMember' -Status 'fixed' -Detail "added $who to '$gname' and read it back from the identity's own group list" -Data $mdata)) }
            elseif ($sent) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.groupMember' -Status 'notChecked' -Detail "added $who to '$gname', but the identity's own group list does not show it yet (Entra can take a few minutes) -- press Check again in PIM Manager" -Data $mdata -ManualStep $steps.groupMember)) }
            elseif ([int]$a.code -eq 403) {
                $d403 = @{ groupName = $gname; groupId = $gid; members = @($member); refused = 403 }
                $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.groupMember' -Status 'failed' -Data $d403 -ManualStep $steps.groupMember `
                    -Detail "the group '$gname' exists but the engine identity is not a member, and Graph refused to add it (HTTP 403: the identity signed in here may not change group members -- it needs GroupMember.ReadWrite.All). $($steps.addYourself)"))
            }
            else { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.groupMember' -Status 'failed' -Detail "the group '$gname' exists but the engine identity is not a member, and adding it failed: $($a.error). $($steps.addYourself)" -Data $mdata -ManualStep $steps.groupMember)) }
        } else { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.groupMember' -Status 'failed' -Detail "the group '$gname' exists but the engine identity is not a member: $who is not in it ($(Get-PimPrereqNotDoneReason -Ctx $Ctx -Verb 'added'))" -Data $mdata -ManualStep $steps.groupMember)) }
    }
    # 3. No admin-consent Power BI application permission on the engine identity.
    $ids = Get-PimWorkloadPrereqGraphRoleIds
    $pbi = Invoke-PimPrereqProbe { @(Invoke-PimGraph -All -Path "/servicePrincipals?`$filter=appId eq '$($ids.powerBiAppId)'&`$select=id,appRoles") | Select-Object -First 1 }
    $asg = Invoke-PimPrereqProbe { Get-PimPrereqEngineAssignments -Ctx $Ctx }
    if (-not $pbi.ok -or -not $asg.ok) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.noAdminConsent' -Status 'notChecked' -Detail "could not read the grants: $($pbi.error) $($asg.error)".Trim())) }
    else {
        $names = @{}; foreach ($r in @($pbi.value.appRoles)) { $names["$($r.id)"] = "$($r.value)" }
        $v = Test-PimPowerBiAdminConsentGrants -Assignments @($asg.value) -PowerBiSpId "$($pbi.value.id)" -RoleNames $names
        $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.noAdminConsent' -Status $(if ($v.ok) { 'ok' } else { 'failed' }) -Detail $v.detail))
    }
    # 4. The Fabric tenant setting.
    $ts = Invoke-PimPrereqProbe { Get-PimPrereqFabricTenantSettings }
    if (-not $ts.ok) {
        $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.tenantSetting' -ManualStep $steps.tenantSetting -Status 'notChecked' -Detail "the caller may not read Fabric tenant settings (HTTP $($ts.code)) -- it must be a Fabric administrator or a service principal an admin-API setting allows. Do the portal step, then re-run. $($ts.error)".Trim()))
    } elseif (-not $gid) {
        $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.tenantSetting' -ManualStep $steps.tenantSetting -Status 'notChecked' -Detail "no usable group yet, so the setting cannot be scoped to it$(Get-PimPrereqNotPreviewable -Ctx $Ctx -Steps "enabling 'Service principals can access read-only admin APIs' for '$gname'")"))
    } else {
        $v = Test-PimFabricReadOnlyAdminSetting -Settings @($ts.value) -GroupId $gid
        if ($v.ok) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.tenantSetting' -ManualStep $steps.tenantSetting -Status 'ok' -Detail $v.detail)) }
        elseif (-not $v.found) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.tenantSetting' -ManualStep $steps.tenantSetting -Status 'failed' -Detail $v.detail)) }
        elseif (Test-PimPrereqShould -Ctx $Ctx -Target 'Fabric tenant setting AllowServicePrincipalsUseReadAdminAPIs' -Action "enable for '$gname'") {
            $cur = Find-PimFabricReadOnlyAdminSetting -Settings @($ts.value)
            $body = New-PimFabricReadOnlyAdminSettingUpdate -Current $cur -GroupId $gid -GroupName $gname
            $u = Invoke-PimPrereqProbe { Invoke-PimRest -Method POST -Url "https://api.fabric.microsoft.com/v1/admin/tenantsettings/$($cur.settingName)/update" -Resource 'https://api.fabric.microsoft.com' -Body $body }
            $back = Invoke-PimPrereqProbe { Get-PimPrereqFabricTenantSettings }
            $bv = if ($back.ok) { Test-PimFabricReadOnlyAdminSetting -Settings @($back.value) -GroupId $gid } else { @{ ok = $false; detail = $back.error } }
            if ($bv.ok) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.tenantSetting' -ManualStep $steps.tenantSetting -Status 'fixed' -Detail "enabled for '$gname' (existing groups kept) and read back")) }
            else { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.tenantSetting' -ManualStep $steps.tenantSetting -Status 'failed' -Detail "could not enable it: $(if ($u.ok) { $bv.detail } else { $u.error })")) }
        } else { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.tenantSetting' -ManualStep $steps.tenantSetting -Status 'failed' -Detail "$($v.detail) ($(Get-PimPrereqNotDoneReason -Ctx $Ctx -Verb 'changed'))")) }
    }
    # 4b. PIM 100.142: the engine identity holds the Entra directory role Fabric Administrator (the Power BI admin API's
    #     AddUserAsAdmin / DeleteUserAsAdmin need it). Assigned only with -GrantFabricAdministrator (opt-in: standing privilege).
    $out.Add((Invoke-PimPrereqFabricAdmin -Ctx $Ctx))
    # 5. Confirmation: the admin API as the engine. It does not decide the stored state (optional), but PIM 100.108 (e): the
    #    Manager counts Power BI as READY only when this answered 200 (Get-PimWorkloadPrereqView).
    $e = Invoke-PimPrereqAsEngine -Ctx $Ctx -Url 'https://api.powerbi.com/v1.0/myorg/admin/groups?$top=1' -Resource 'powerbi'
    if ($e.ok) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.adminApi' -Status 'ok' -Detail "GET admin/groups answered 200 as the engine ($who)")) }
    elseif ($e.skipped) { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.adminApi' -Status 'notChecked' -Detail $e.error)) }
    else { $out.Add((New-PimWorkloadPrereqCheck -Id 'powerbi.adminApi' -Status 'failed' -Detail "GET admin/groups as the engine ($who): $($e.error)")) }
    return $out.ToArray()
}

function Get-PimPrereqPowerBiCallerClaims {
    # The claims of the CALLER's Power BI token (https://analysis.windows.net/powerbi/api) -- $Ctx.powerBiCallerClaims wins
    # (tests). $null when no token can be had.
    param([hashtable]$Ctx)
    if ($Ctx.ContainsKey('powerBiCallerClaims') -and $null -ne $Ctx.powerBiCallerClaims) { return $Ctx.powerBiCallerClaims }
    try { return (ConvertFrom-PimPrereqJwt -Token (Get-PimRestToken -Resource 'powerbi' -TenantId $Ctx.tenantId)) } catch { return $null }
}

function Test-PimPrereqClaimsArePerson {
    # PURE. TRUE for a delegated token of a PERSON (a scp claim, and not idtyp 'app'); an app-only token has roles, no scp.
    param([AllowNull()][object]$Claims)
    if (-not $Claims) { return $false }
    if ("$($Claims.idtyp)" -ieq 'app') { return $false }
    return [bool]("$($Claims.scp)".Trim())
}

function Get-PimPrereqPowerBiWorkspaceUsers {
    # GET /v1.0/myorg/admin/groups/{ws}/users AS THE CALLER (the person's Power BI token) -> the users (value[]).
    param([Parameter(Mandatory)][string]$WorkspaceId)
    return @(Invoke-PimRest -Method 'GET' -Url "https://api.powerbi.com/v1.0/myorg/admin/groups/$WorkspaceId/users" -Resource 'powerbi' -All)
}

function Invoke-PimPrereqPowerBiWorkspaces {
    <#
      PIM 100.142b (owner 2026-10-14, "One script run"). For every distinct workspace PIM has Power BI rows for (the store's
      PIM-Assignments-Workloads rows, $Ctx.workloadRows) plus -WorkspaceId ($Ctx.workspaceIds):
        GET  https://api.powerbi.com/v1.0/myorg/admin/groups/{ws}/users                       (GetGroupUsersAsAdmin)
        -- the engine identity (object id or app id) already Admin -> left alone;
        -- otherwise, ONLY with -AddEngineToWorkspaces ($Ctx.addEngineToWorkspaces) and a PERSON signed in:
        POST https://api.powerbi.com/v1.0/myorg/admin/groups/{ws}/users                       (AddUserAsAdmin)
             { identifier = <engine service principal object id>; principalType = 'App'; groupUserAccessRight = 'Admin' }
        then read back (retried through a short lag). Power BI accepts a person's delegated token for AddUserAsAdmin; it answers
        401 to a service principal, so the Support app / a certificate identity never adds (reported, nothing sent).
      Idempotent, NEVER removes anyone (no DELETE anywhere), -WhatIf / a declined prompt adds nothing. Without the switch it only
      REPORTS. Returns @{ rows = @(@{ workspaceId; before; after; result; detail }); added; already; missing; failed; invalid }.
    #>
    param([hashtable]$Ctx)
    $add = ($Ctx.ContainsKey('addEngineToWorkspaces') -and [bool]$Ctx.addEngineToWorkspaces)
    $delay = if ("$env:PIM_PREREQ_READBACK_SECONDS".Trim()) { [int]$env:PIM_PREREQ_READBACK_SECONDS } else { 5 }
    $who = Get-PimPowerBiPrereqIdentityText -Identity $Ctx.engine
    $ws = @(Get-PimPowerBiWorkspaceIdsFromRows -Rows @($Ctx.workloadRows) -Extra @($Ctx.workspaceIds))
    $invalid = @(Get-PimPowerBiWorkspaceIdsFromRows -Rows @($Ctx.workloadRows) -Extra @($Ctx.workspaceIds) -Invalid)
    $rows = New-Object System.Collections.Generic.List[object]
    $person = $true; $personWhy = ''
    if ($add -and $ws.Count) {
        $cl = Get-PimPrereqPowerBiCallerClaims -Ctx $Ctx
        $person = Test-PimPrereqClaimsArePerson -Claims $cl
        if (-not $person) { $personWhy = 'not added: Power BI accepts this add only from a PERSON signed in in the browser (a Fabric administrator) -- run the script without -UseSignedInAccount / -ClientId' }
    }
    $mk = { param($w, $b, $a, $r, $d) [pscustomobject]@{ workspaceId = $w; before = $b; after = $a; result = $r; detail = $d } }
    foreach ($w in $ws) {
        $g = Invoke-PimPrereqProbe { Get-PimPrereqPowerBiWorkspaceUsers -WorkspaceId $w }
        if (-not $g.ok) {
            $why = switch ([int]$g.code) {
                401 { 'Power BI refused the read (HTTP 401): the person signed in here must be a Fabric administrator' }
                403 { 'Power BI refused the read (HTTP 403): the person signed in here must be a Fabric administrator' }
                404 { 'no workspace has this id (HTTP 404) -- correct the Workloads row' }
                default { "the workspace's users could not be read: $($g.error)" }
            }
            $rows.Add((& $mk $w '?' '?' 'not read' $why)); continue
        }
        $before = Find-PimPowerBiEngineWorkspaceAccess -Users @($g.value) -Engine $Ctx.engine
        $bText = if ($before) { $before } else { 'none' }
        if ($before -ieq 'Admin') { $rows.Add((& $mk $w 'Admin' 'Admin' 'already Admin' "$who is Admin of the workspace")); continue }
        if (-not $add) { $rows.Add((& $mk $w $bText $bText 'missing' 'report only: run again with -AddEngineToWorkspaces to add it as Admin')); continue }
        if (-not $person) { $rows.Add((& $mk $w $bText $bText 'missing' $personWhy)); continue }
        if (-not (Test-PimPrereqShould -Ctx $Ctx -Target "Power BI workspace $w" -Action "add $($Ctx.engine.displayName) as Admin")) {
            $rows.Add((& $mk $w $bText $bText 'missing' (Get-PimPrereqNotDoneReason -Ctx $Ctx -Verb 'added'))); continue
        }
        $body = [ordered]@{ identifier = "$($Ctx.engine.objectId)"; principalType = 'App'; groupUserAccessRight = 'Admin' }
        $p = Invoke-PimPrereqProbe { Invoke-PimRest -Method 'POST' -Url "https://api.powerbi.com/v1.0/myorg/admin/groups/$w/users" -Resource 'powerbi' -Body $body }
        if (-not $p.ok -and [int]$p.code -in @(401, 403)) {
            $rows.Add((& $mk $w $bText $bText 'failed' "Power BI refused the add (HTTP $($p.code)): the person signed in here must be a Fabric administrator. $($p.error)")); continue
        }
        if (-not $p.ok -and "$($p.error)" -notmatch '(?i)already') {
            $rows.Add((& $mk $w $bText $bText 'failed' "could not add ${who}: $($p.error)")); continue
        }
        $after = ''
        for ($try = 1; $try -le 6; $try++) {
            $back = Invoke-PimPrereqProbe { Get-PimPrereqPowerBiWorkspaceUsers -WorkspaceId $w }
            if ($back.ok) { $after = Find-PimPowerBiEngineWorkspaceAccess -Users @($back.value) -Engine $Ctx.engine; if ($after -ieq 'Admin') { break } }
            if ($try -lt 6 -and $delay -gt 0) { Start-Sleep -Seconds $delay }
        }
        if ($after -ieq 'Admin') { $rows.Add((& $mk $w $bText 'Admin' 'added' "added $who as Admin and read it back")) }
        elseif ($before) { $rows.Add((& $mk $w $bText $(if ($after) { $after } else { $bText }) 'failed' "Power BI kept $who as $before -- change it to Admin in the workspace's Manage access (PIM Manager never removes or downgrades anyone)")) }
        else { $rows.Add((& $mk $w 'none' $(if ($after) { $after } else { 'none' }) 'failed' "added $who, but the read-back does not show it as Admin yet -- run the same command again in a few minutes")) }
    }
    $count = { param($r) @($rows | Where-Object { $_.result -eq $r }).Count }
    return [pscustomobject]@{
        rows = @($rows.ToArray()); invalid = @($invalid)
        added = (& $count 'added'); already = (& $count 'already Admin'); missing = (& $count 'missing'); failed = (& $count 'failed') + (& $count 'not read')
    }
}

function Invoke-PimPrereqAzureRbac {
    param([hashtable]$Ctx)
    $out = New-Object System.Collections.Generic.List[object]
    $scopes = @(Get-PimAzureManagedScopes -Rows @($Ctx.azureRows) -Extra @($Ctx.azureScopes))
    if (-not $scopes.Count) {
        $out.Add((New-PimWorkloadPrereqCheck -Id 'azure.scopesKnown' -Status 'notChecked' -Detail 'no PIM-Assignments-Azure-Resources row names a real scope yet, and no -AzureScope was given'))
        $out.Add((New-PimWorkloadPrereqCheck -Id 'azure.uaa' -Status 'notChecked' -Detail 'no scope to check'))
        return $out.ToArray()
    }
    $out.Add((New-PimWorkloadPrereqCheck -Id 'azure.scopesKnown' -Status 'ok' -Detail "$($scopes.Count) scope(s): $($scopes -join ', ')"))
    $oid = $Ctx.engine.objectId
    $ids = Get-PimWorkloadPrereqGraphRoleIds
    $readAt = { param($s) @(Invoke-PimArm -All -Path "$s/providers/Microsoft.Authorization/roleAssignments?`$filter=atScope() and assignedTo('$oid')" -ApiVersion '2022-04-01') }
    $covered = New-Object System.Collections.Generic.List[string]; $missing = New-Object System.Collections.Generic.List[string]
    $unread = New-Object System.Collections.Generic.List[string]; $fixed = New-Object System.Collections.Generic.List[string]; $notes = New-Object System.Collections.Generic.List[string]
    $missingScopes = New-Object System.Collections.Generic.List[string]   # 97.1: the bare scopes, for the fix command
    foreach ($s in $scopes) {
        $r = Invoke-PimPrereqProbe { & $readAt $s }
        # 97.1 self-check: the ENGINE reading its own assignments. Any role at (or above) the scope includes the read, so a
        # 403 for the engine itself means it holds nothing there -- in particular no User Access Administrator / Owner.
        $selfMiss = ($Ctx.ContainsKey('selfCheck') -and $Ctx.selfCheck -and $r.code -eq 403)
        if (-not $r.ok -and $selfMiss) { $missing.Add($s); $missingScopes.Add($s); $notes.Add("$s answered 403 to the engine itself (it holds no role there)"); continue }
        if (-not $r.ok) { $unread.Add("$s (HTTP $($r.code))"); continue }
        # atScope() already limits the rows to assignments AT or ABOVE this scope (management groups included), so
        # every row applies; the scope itself is passed as the "within" target for each of them.
        $rows = @($r.value | ForEach-Object { $p = if ($_.PSObject.Properties['properties']) { $_.properties } else { $_ }; [pscustomobject]@{ roleDefinitionId = "$($p.roleDefinitionId)"; scope = '' } })
        $v = Test-PimAzureScopeCoverage -Scope $s -Assignments $rows
        if ($v.covered) { $covered.Add($s); continue }
        if ($v.rbacAdminOnly) { $notes.Add("$s has only Role Based Access Control Administrator") }
        if ($Ctx.grantUaa -and (Test-PimPrereqShould -Ctx $Ctx -Target $s -Action "assign User Access Administrator to $($Ctx.engine.displayName)")) {
            $body = @{ properties = @{ roleDefinitionId = "$s/providers/Microsoft.Authorization/roleDefinitions/$($ids.userAccessAdmin)"; principalId = $oid; principalType = 'ServicePrincipal' } }
            $p = Invoke-PimPrereqProbe { Invoke-PimArm -Method PUT -Path "$s/providers/Microsoft.Authorization/roleAssignments/$([guid]::NewGuid())" -ApiVersion '2022-04-01' -Body $body }
            $b = Invoke-PimPrereqProbe { & $readAt $s }
            $brows = if ($b.ok) { @($b.value | ForEach-Object { $q = if ($_.PSObject.Properties['properties']) { $_.properties } else { $_ }; [pscustomobject]@{ roleDefinitionId = "$($q.roleDefinitionId)"; scope = '' } }) } else { @() }
            if ($b.ok -and (Test-PimAzureScopeCoverage -Scope $s -Assignments $brows).covered) { $fixed.Add($s) }
            else { $missing.Add("$s (assignment failed: $(if ($p.ok) { 'read-back did not show it' } else { $p.error }))"); $missingScopes.Add($s) }
        } else { $missing.Add($s); $missingScopes.Add($s) }
    }
    $parts = @()
    if ($covered.Count) { $parts += "covered: $($covered -join ', ')" }
    if ($fixed.Count)   { $parts += "assigned + read back: $($fixed -join ', ')" }
    if ($missing.Count) { $parts += "MISSING: $($missing -join ', ')$(if ($Ctx.ContainsKey('selfCheck') -and $Ctx.selfCheck) { ' (an administrator assigns User Access Administrator there with the published Grant-PimEnginePermissions.ps1 -- PIM never grants itself a role)' } elseif (-not $Ctx.grantUaa) { ' (re-run with -GrantAzureUserAccessAdministrator to assign it, or use the portal step)' })" }
    if ($unread.Count)  { $parts += "not readable by the caller: $($unread -join ', ')" }
    if ($notes.Count)   { $parts += ($notes -join '; ') }
    $status = if ($missing.Count) { 'failed' } elseif ($unread.Count) { 'notChecked' } elseif ($fixed.Count) { 'fixed' } else { 'ok' }
    $out.Add((New-PimWorkloadPrereqCheck -Id 'azure.uaa' -Status $status -Detail ($parts -join ' | ') -Data $(if ($missingScopes.Count) { @{ missingScopes = @($missingScopes.ToArray()) } } else { @{} })))
    return $out.ToArray()
}

function Invoke-PimPrereqEntraRoles {
    param([hashtable]$Ctx)
    $out = New-Object System.Collections.Generic.List[object]
    $req = @($Ctx.engineRoleNames)
    if (-not $req.Count) { $out.Add((New-PimWorkloadPrereqCheck -Id 'entra.engineRoles' -Status 'notChecked' -Detail 'the role map was not loaded')) }
    else { $out.Add((Invoke-PimPrereqGraphRoleCheck -Ctx $Ctx -CheckId 'entra.engineRoles' -Required $req)) }
    $p = Invoke-PimPrereqProbe { @(Invoke-PimGraph -All -Path '/subscribedSkus?$select=skuPartNumber,capabilityStatus,servicePlans') }
    if (-not $p.ok) {
        $has = Test-PimPrereqTokenHasRole -Claims $Ctx.callerClaims -AnyOf @('Organization.Read.All', 'Directory.Read.All', 'LicenseAssignment.Read.All')
        $v = Get-PimPrereqProbeVerdict -StatusCode $p.code -CallerHasPermission $has -What 'GET subscribedSkus' -Needs 'Organization.Read.All' -ErrorText $p.error
        if ($v.status -eq 'failed') { $v.status = 'notChecked' }   # a licence list that cannot be read proves nothing about the licence
        $out.Add((New-PimWorkloadPrereqCheck -Id 'entra.p2License' -Status $v.status -Detail $v.detail))
    } else {
        $hit = @($p.value | Where-Object { "$($_.capabilityStatus)" -ieq 'Enabled' } | ForEach-Object { @($_.servicePlans) } | Where-Object { "$($_.servicePlanName)" -ieq 'AAD_PREMIUM_P2' -and "$($_.provisioningStatus)" -ieq 'Success' })
        if ($hit.Count) { $out.Add((New-PimWorkloadPrereqCheck -Id 'entra.p2License' -Status 'ok' -Detail 'AAD_PREMIUM_P2 service plan present and provisioned')) }
        else { $out.Add((New-PimWorkloadPrereqCheck -Id 'entra.p2License' -Status 'failed' -Detail "no enabled SKU carries the AAD_PREMIUM_P2 service plan ($(@($p.value).Count) SKU(s) read)")) }
    }
    return $out.ToArray()
}

function Invoke-PimWorkloadPrereqRun {
    <#
      Run one workload's checks and apply the operator's -ConfirmPortalStep attestations: a check whose id was
      confirmed becomes 'confirmed' (its detail says it was attested, not verified) -- ONLY where
      Test-PimWorkloadPrereqConfirmable allows it. An API-verified failure is never attested away; a confirmation of a
      check that cannot take one is reported in its detail rather than silently ignored.
    #>
    param([Parameter(Mandatory)][string]$Workload, [Parameter(Mandatory)][hashtable]$Ctx)
    $checks = switch ($Workload) {
        'DefenderXdr' { Invoke-PimPrereqDefenderXdr -Ctx $Ctx }
        'Intune'      { Invoke-PimPrereqIntune -Ctx $Ctx }
        'PowerBI'     { Invoke-PimPrereqPowerBI -Ctx $Ctx }
        'AzureRbac'   { Invoke-PimPrereqAzureRbac -Ctx $Ctx }
        'EntraRoles'  { Invoke-PimPrereqEntraRoles -Ctx $Ctx }
        default       { throw "unknown workload '$Workload'" }
    }
    $confirm = @($Ctx.confirm | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    $final = foreach ($c in @($checks)) {
        if ($confirm -contains $c.id.ToLowerInvariant() -and -not $c.ok) {
            if (Test-PimWorkloadPrereqConfirmable -Id $c.id -Status $c.status) {
                New-PimWorkloadPrereqCheck -Id $c.id -Status 'confirmed' -Detail "confirmed by $($Ctx.ranBy) with -ConfirmPortalStep (attested, not API-verified). Before: $($c.detail)"
            } else {
                $c.detail = "$($c.detail) [-ConfirmPortalStep $($c.id) IGNORED: this result was verified through an API and cannot be attested away]"
                $c
            }
        } else { $c }
    }
    return @($final)
}
