#Requires -Version 5.1
<#
.SYNOPSIS
    WEB-TRIM-1 (REQUIREMENTS 102, owner 2026-11-16 "Auto-remove excess") -- on EVERY update the updater trims the
    INTERNET-FACING web identity (id-pim-web, the user-assigned identity the Manager signs in as) to its APPROVED set.
    REMOVALS ONLY: it never adds, never grants, never touches another identity.

.DESCRIPTION
    THE APPROVED SET is read from the code's own rights list (engine\_shared\PIM-RightsList.ps1 Get-PimApprovedRightsList,
    identity 'web'; its Graph part is tools\setup\_PimSetupShared.ps1 $script:PimGraphAppRolesManager = Get-PimGraphAppRoleMap
    -RoleSet Manager): Graph User.ReadBasic.All + GroupMember.Read.All; Reader on the PIM resource group; Storage Blob Data
    Contributor on the container pim-auth-tokens; Storage Queue Data Message Sender on the queue pim-wake; AcrPull on the
    registry the Manager pulls from; Cognitive Services OpenAI User on the AI chat's account only while the AI chat is on.
    A 'kept' row of the list (a retired right an OLD version still used) is NOT approved here: this code is past it.

    EVERYTHING ELSE the web identity holds is EXCESS, in four classes:
      graph-app-role    an app role on Microsoft Graph outside the set, or ANY app role on another resource
      azure-rbac        a role assignment held by the identity itself, visible from the PIM resource group (at it, below it,
                        or inherited from above it: a subscription-wide Reader is seen here) outside the set
      group-membership  a DIRECT membership of any group (e.g. the SQL admin group, a Power BI admin-API group)
      directory-role    an activated Entra directory role (memberOf)

    REMOVED vs REPORTED -- decided by the rights the UPDATER ALREADY HOLDS, read at run time, never assumed and never added:
      azure-rbac        removed only where the updater's own permissions at THAT scope allow
                        Microsoft.Authorization/roleAssignments/delete (ARM .../providers/Microsoft.Authorization/permissions).
                        The updater's standard right is Contributor on the PIM resource group, whose notActions exclude
                        Microsoft.Authorization/*/Delete -- so on a standard install every Azure item is REPORTED.
      graph-app-role    removed only with AppRoleAssignment.ReadWrite.All in the updater's Graph token, or as an OWNER of the
                        resource's service principal with Application.ReadWrite.OwnedBy. The updater's standard Graph set
                        (engine\_shared\PIM-UpdaterGraphRoles.ps1) holds neither for Microsoft Graph -> REPORTED.
      group-membership  removed only with GroupMember.ReadWrite.All or Group.ReadWrite.All (a role-assignable group also
                        needs RoleManagement.ReadWrite.Directory). The standard set has GroupMember.Read.All only -> REPORTED.
      directory-role    removed only with RoleManagement.ReadWrite.Directory. Not in the standard set -> REPORTED.
    A REPORTED item = a run warning line, ONE admin mail (only when something was removed or an item is NEW), and ONE fix
    request to Invardia per item (the register-once / sent-once run report, PIM-JobLanes.ps1 Register-PimTrustStaleReport;
    also remembered in pim.Settings 'WebIdentityTrim', so a held item never opens a second request on the next run).

    FAIL CLOSED: the approved set unreadable = NOTHING removed (a warning); a class that cannot be read = nothing of it
    removed; an approved row whose scope this code cannot place (a registry list not read, the AI chat state not read, a
    new key) = KEPT. The identity is resolved from the Manager app itself (PIM_ManagedIdentityClientId -> the attached
    user-assigned identity named id-pim-web), never by name alone; a Manager not moved to it (the system identity, another
    identity) = nothing done. An identity also attached to another app or job of the install = nothing done (shared).

    THE DATABASE HALF (coordinator addition 2026-11-16; Invoke-PimSqlLeastPrivilegeCheck) -- REPORT ONLY in this release:
      * the Support app's database user in db_owner OUTSIDE an open support session (no open time-limited grant marker,
        [pimsupport].[usp_SupportState]) = REPORTED (warning, one mail, one fix request). The updater cannot remove it with
        what it holds: only a db_owner member changes db_owner membership (the updater is pim_updater + db_ddladmin), the
        update path sends no security statement (tests\Test-PimSqlAccess.ps1 L2), and the signed revoke removes only a
        db_owner its own grant added. State unreadable = not judged (fail closed).
      * database users of identities that no longer exist (the pre-move system identities, an old id-pim-<role>) = LISTED in
        the run detail and ONCE in the admin mail; never removed here (that is a later release, after review).

    PURE core + Invoke-PimWebIdentityTrim with seams (-Arm, -Graph, -Store, -QueueMail, -FixRequest): no modules, no az.
    ASCII only; PS 5.1 + 7.

      Get-PimWebTrimMode                 PIM_WEB_TRIM -> on | off | dryrun (default on)
      Get-PimWebTrimApprovedSet          the web rows of the rights list -> @{ ok; graph; azure; reason }
      Resolve-PimWebTrimIdentity         the Manager app -> the web identity it signs in as (moved / not moved / shared)
      Get-PimWebTrimAzureVerdict         one role assignment -> approved | excess | keep
      Test-PimWebTrimArmActionAllowed    ARM permissions (actions / notActions) -> is an action allowed
      Get-PimWebTrimTokenFacts           a bearer token -> @{ known; oid; roles }
      Get-PimWebTrimItemPart             an item -> its fix-request part ([a-z0-9.-], stable)
      New-PimWebTrimMailPayload          the run's findings -> ONE queued notify-mail payload (alert-notice)
      Invoke-PimWebIdentityTrim          the step (read, classify, remove what may be removed, read back, report)
#>
Set-StrictMode -Off
function Get-PimWebTrimGraphAppId { <# PURE. LITERAL. Microsoft Graph's application id. #> return '00000003-0000-0000-c000-000000000000' }
function Get-PimWebTrimSettingName { <# PURE. LITERAL. The pim.Settings row this step remembers its reported items in. #> return 'WebIdentityTrim' }
function Get-PimWebTrimFixCode { <# PURE. LITERAL. The fix request's error class (lower case on the wire). #> return 'WEB-IDENTITY-EXCESS' }
function Get-PimWebTrimFixJob { <# PURE. LITERAL. The uplink job id the fix request is filed under (the updater's own run). #> return 'pim-update' }

function Get-PimWebTrimField {
    # A field of a hashtable OR an object; $null when absent.
    param([AllowNull()][object]$Item, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { return $Item[$Name] }; return $null }
    $p = $Item.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Get-PimWebTrimMode {
    <#
      PURE. The switch PIM_WEB_TRIM on the updater job (read like the other updater settings: the job's environment).
      off / 0 / false / no / disabled = 'off' (nothing read, nothing removed); dryrun / dry-run / plan / whatif = 'dryrun'
      (everything read and classified, NOTHING removed, no mail, no fix request); anything else, or nothing = 'on'.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $v = "$Value".Trim().ToLowerInvariant()
    if ($v -match '^(off|0|false|no|disabled?)$') { return 'off' }
    if ($v -match '^(dry-?run|plan|whatif)$') { return 'dryrun' }
    return 'on'
}

function Get-PimWebTrimApprovedSet {
    <#
      PURE (reads the code's grant files through the rights list). The web identity's APPROVED rights:
        @{ ok; reason; graph = <appRoleId -> name> (Microsoft Graph); azure = @(@{ key; roleId; role }) }
      -List: an already built rights list (tests); else Get-PimApprovedRightsList -Version. ANY doubt = ok $false (the
      caller then removes NOTHING): no web identity, an empty Graph or Azure part, a Graph row on another resource, a
      directory-role row (the web never holds one), an unknown kind.
    #>
    param([string]$Version = '', [AllowNull()][object]$List = $null)
    $o = [ordered]@{ ok = $false; reason = ''; graph = [ordered]@{}; azure = @() }
    try {
        if ($null -eq $List) {
            if (-not (Get-Command Get-PimApprovedRightsList -ErrorAction SilentlyContinue)) { throw 'the rights list (engine\_shared\PIM-RightsList.ps1) is not loaded' }
            $List = Get-PimApprovedRightsList -Version $Version
        }
        $web = @(@(Get-PimWebTrimField $List 'identities') | Where-Object { "$(Get-PimWebTrimField $_ 'role')" -eq 'web' })[0]
        if (-not $web) { throw 'the rights list carries no web identity' }
        $az = New-Object System.Collections.Generic.List[object]
        foreach ($r in @(Get-PimWebTrimField $web 'rights')) {
            if ($null -eq $r) { continue }
            # a 'kept' row is a retired right an OLD version still used (e.g. AccessReview.Read.All before 3.0.71) -- not approved
            if ("$(Get-PimWebTrimField $r 'when')" -eq 'kept') { continue }
            $kind = "$(Get-PimWebTrimField $r 'kind')"
            $rid = "$(Get-PimWebTrimField $r 'roleId')".Trim().ToLowerInvariant()
            if ($rid -notmatch '^[0-9a-f-]{36}$') { throw "the approved right $(Get-PimWebTrimField $r 'id') has no role id" }
            switch ($kind) {
                'graph-app-role' {
                    if ("$(Get-PimWebTrimField $r 'resourceAppId')" -ne (Get-PimWebTrimGraphAppId)) { throw "the approved Graph right $(Get-PimWebTrimField $r 'id') is not on Microsoft Graph" }
                    $o.graph[$rid] = "$(Get-PimWebTrimField $r 'role')"
                }
                'azure-rbac' {
                    $id = "$(Get-PimWebTrimField $r 'id')"
                    $key = if ($id -match '^web\.azure\.(.+)$') { $Matches[1] } else { '' }
                    if (-not $key) { throw "the approved Azure right '$id' has no key" }
                    $az.Add([ordered]@{ key = $key; roleId = $rid; role = "$(Get-PimWebTrimField $r 'role')" })
                }
                default { throw "the approved right $(Get-PimWebTrimField $r 'id') has a kind this step does not place ($kind)" }
            }
        }
        if (-not $o.graph.Count) { throw 'the approved set has no Graph right' }
        if (-not $az.Count) { throw 'the approved set has no Azure right' }
        $o.azure = @($az.ToArray()); $o.ok = $true
    } catch { $o.ok = $false; $o.reason = ((("$($_.Exception.Message)") -split "`n")[0]).Trim(); $o.graph = [ordered]@{}; $o.azure = @() }
    return $o
}

function Get-PimWebTrimIdentitiesOf {
    # PURE. A container app / job -> @{ pids = @{ principalId(lower) = name }; ua = @{ resourceId(lower) = @{ name; principalId; clientId } }; system }
    param([AllowNull()][object]$Resource)
    $o = @{ pids = @{}; ua = @{}; system = '' }
    $ident = Get-PimWebTrimField $Resource 'identity'
    if (-not $ident) { return $o }
    $sp = "$(Get-PimWebTrimField $ident 'principalId')".Trim().ToLowerInvariant()
    if ($sp) { $o.pids[$sp] = 'system'; $o.system = $sp }
    $uam = Get-PimWebTrimField $ident 'userAssignedIdentities'
    if ($uam) {
        $pairs = if ($uam -is [System.Collections.IDictionary]) { @($uam.Keys | ForEach-Object { @{ k = "$_"; v = $uam[$_] } }) } else { @($uam.PSObject.Properties | ForEach-Object { @{ k = "$($_.Name)"; v = $_.Value } }) }
        foreach ($pp in $pairs) {
            $rid = "$($pp.k)".Trim().TrimEnd('/').ToLowerInvariant()
            $nm = @(@("$($pp.k)" -split '/') | Where-Object { $_ })[-1]
            $pid0 = "$(Get-PimWebTrimField $pp.v 'principalId')".Trim().ToLowerInvariant()
            $o.ua[$rid] = @{ name = "$nm"; principalId = $pid0; clientId = "$(Get-PimWebTrimField $pp.v 'clientId')".Trim().ToLowerInvariant() }
            if ($pid0) { $o.pids[$pid0] = "$nm" }
        }
    }
    return $o
}

function Resolve-PimWebTrimIdentity {
    <#
      PURE. The identity the Manager SIGNS IN AS -- resolved from the app, never by a name alone:
        PIM_ManagedIdentityClientId on a Manager container -> the ATTACHED user-assigned identity with that client id, and
        its resource name must be -WebName (id-pim-web). Anything else = moved $false (nothing is trimmed):
        no client id (the system identity), a client id no attached identity carries, another name.
      Then FAIL CLOSED on a shared identity: the same identity (resource id or principal) attached to any other app or job
      of the install (-Others; $null = they could not be read -> not checked = nothing trimmed), or equal to the updater's
      own principal (-UpdaterObjectId).
      Returns @{ moved; ok; principalId; clientId; resourceId; name; reason }. ok = trim may go ahead.
    #>
    param([AllowNull()][object]$App, [AllowNull()][object[]]$Others, [string]$UpdaterObjectId = '', [string]$WebName = 'id-pim-web', [string]$ManagerApp = 'ca-pim-manager')
    $o = [ordered]@{ moved = $false; ok = $false; principalId = ''; clientId = ''; resourceId = ''; name = ''; reason = '' }
    if ($null -eq $App) { $o.reason = "the Manager app $ManagerApp could not be read"; return $o }
    $cid = ''
    $tpl = Get-PimWebTrimField (Get-PimWebTrimField $App 'properties') 'template'
    foreach ($c in @(Get-PimWebTrimField $tpl 'containers')) {
        if ($null -eq $c) { continue }
        foreach ($e in @(Get-PimWebTrimField $c 'env')) {
            if ($e -and "$(Get-PimWebTrimField $e 'name')" -ceq 'PIM_ManagedIdentityClientId' -and "$(Get-PimWebTrimField $e 'value')".Trim()) { $cid = "$(Get-PimWebTrimField $e 'value')".Trim().ToLowerInvariant(); break }
        }
        if ($cid) { break }
    }
    if (-not $cid) { $o.reason = "$ManagerApp signs in as its system identity, not $WebName -- not moved yet, nothing trimmed"; return $o }
    $ids = Get-PimWebTrimIdentitiesOf -Resource $App
    $hit = $null; $hitId = ''
    foreach ($k in @($ids.ua.Keys)) { if ($ids.ua[$k].clientId -eq $cid) { $hit = $ids.ua[$k]; $hitId = $k } }
    if (-not $hit) { $o.reason = "$ManagerApp names client id $cid, which no attached identity carries -- not trimmed"; return $o }
    if ("$($hit.name)" -ine "$WebName") { $o.reason = "$ManagerApp signs in as $($hit.name), not $WebName -- not moved yet, nothing trimmed"; return $o }
    if ("$($hit.principalId)" -notmatch '^[0-9a-f-]{36}$') { $o.reason = "$WebName has no principal id on $ManagerApp -- not trimmed"; return $o }
    $o.moved = $true; $o.principalId = "$($hit.principalId)"; $o.clientId = $cid; $o.resourceId = $hitId; $o.name = "$($hit.name)"
    if ("$UpdaterObjectId".Trim() -and "$UpdaterObjectId".Trim().ToLowerInvariant() -eq $o.principalId) { $o.reason = "the updater itself signs in as $WebName -- not trimmed (shared identity)"; return $o }
    if ($null -eq $Others) { $o.reason = "the install's other apps and jobs could not be read, so a shared $WebName cannot be ruled out -- not trimmed"; return $o }
    foreach ($r in @($Others)) {
        if ($null -eq $r) { continue }
        if ("$(Get-PimWebTrimField $r 'name')" -ieq $ManagerApp -and "$(Get-PimWebTrimField $r 'type')" -match '(?i)containerApps$') { continue }
        $oi = Get-PimWebTrimIdentitiesOf -Resource $r
        if ($oi.ua.ContainsKey($o.resourceId) -or $oi.pids.ContainsKey($o.principalId)) {
            $o.reason = "$WebName is also attached to $(Get-PimWebTrimField $r 'name') -- a shared identity is not trimmed (its rights may serve that resource)"; return $o
        }
    }
    $o.ok = $true; $o.reason = "$ManagerApp signs in as $WebName ($($o.principalId))"
    return $o
}

function Get-PimWebTrimRegistryNames {
    # PURE. The registries the Manager pulls from (properties.configuration.registries[].server) -> lower-case names.
    param([AllowNull()][object]$App)
    $cfg = Get-PimWebTrimField (Get-PimWebTrimField $App 'properties') 'configuration'
    return , @(@(Get-PimWebTrimField $cfg 'registries') | Where-Object { $_ } | ForEach-Object { ("$(Get-PimWebTrimField $_ 'server')".Trim() -split '\.')[0].ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)
}

function Get-PimWebTrimAzureVerdict {
    <#
      PURE. One role assignment of the web identity -> @{ verdict = approved | excess | keep; key; why }.
      -RoleId: the role definition guid; -Scope: the assignment scope. -RgScope: /subscriptions/<sub>/resourceGroups/<rg>.
      -RegistryNames: the Manager's registries ($null = not read -> an AcrPull is KEPT). -AiChat: @{ known; enabled; host }
      ($null / known $false -> an OpenAI User is KEPT). A key this code cannot place = KEPT (fail closed).
    #>
    param([Parameter(Mandatory)][string]$RoleId, [AllowEmptyString()][string]$Scope, [Parameter(Mandatory)][object[]]$Approved,
          [Parameter(Mandatory)][string]$RgScope, [AllowNull()][string[]]$RegistryNames = $null, [AllowNull()][object]$AiChat = $null)
    $rid = ("$RoleId".Trim().TrimEnd('/') -split '/')[-1].ToLowerInvariant()
    $s = "$Scope".Trim().TrimEnd('/').ToLowerInvariant()
    $rg = "$RgScope".Trim().TrimEnd('/').ToLowerInvariant()
    $rows = @($Approved | Where-Object { "$(Get-PimWebTrimField $_ 'roleId')" -eq $rid })
    if (-not $rows.Count) { return @{ verdict = 'excess'; key = ''; why = 'the role is not in the approved set' } }
    $keep = ''
    $rgRx = [regex]::Escape($rg)
    foreach ($row in $rows) {
        $k = "$(Get-PimWebTrimField $row 'key')"
        switch ($k) {
            'reader@install-rg' { if ($s -eq $rg) { return @{ verdict = 'approved'; key = $k; why = '' } } }
            'storage-blob-data-contributor@token-store-container' { if ($s -match "^$rgRx/providers/microsoft\.storage/storageaccounts/[^/]+/blobservices/default/containers/pim-auth-tokens$") { return @{ verdict = 'approved'; key = $k; why = '' } } }
            'storage-queue-data-message-sender@wake-queue' { if ($s -match "^$rgRx/providers/microsoft\.storage/storageaccounts/[^/]+/queueservices/default/queues/pim-wake$") { return @{ verdict = 'approved'; key = $k; why = '' } } }
            'acrpull@registry' {
                if ($s -match '/providers/microsoft\.containerregistry/registries/([^/]+)$') {
                    $rn = $Matches[1]
                    if ($null -eq $RegistryNames) { $keep = 'the registries the Manager pulls from were not read' }
                    elseif (@($RegistryNames) -contains $rn) { return @{ verdict = 'approved'; key = $k; why = '' } }
                }
            }
            'cognitive-services-openai-user@ai-chat-resource' {
                if ($s -match '/providers/microsoft\.cognitiveservices/accounts/([^/]+)$') {
                    $an = $Matches[1]
                    if ($null -eq $AiChat -or -not [bool](Get-PimWebTrimField $AiChat 'known')) { $keep = 'the AI chat setting was not read' }
                    elseif ([bool](Get-PimWebTrimField $AiChat 'enabled')) {
                        $hl = ("$(Get-PimWebTrimField $AiChat 'host')".Trim().ToLowerInvariant() -split '\.')[0]
                        if ($hl -and $hl -eq $an) { return @{ verdict = 'approved'; key = $k; why = '' } }
                        $keep = 'the AI chat is on and its endpoint does not name this account (it may use a custom name)'
                    }
                }
            }
            default { $keep = "the approved set names a scope this step cannot place ($k)" }
        }
    }
    if ($keep) { return @{ verdict = 'keep'; key = ''; why = $keep } }
    return @{ verdict = 'excess'; key = ''; why = 'outside its approved scope' }
}

function Test-PimWebTrimArmActionMatch {
    # PURE. An ARM action pattern ('*', 'Microsoft.Authorization/*/Delete', ...) against an action, case-insensitive.
    param([AllowEmptyString()][string]$Pattern, [Parameter(Mandatory)][string]$Action)
    $p = "$Pattern".Trim(); if (-not $p) { return $false }
    $rx = '^' + ([regex]::Escape($p) -replace '\\\*', '.*') + '$'
    return ("$Action" -match "(?i)$rx")
}

function Test-PimWebTrimArmActionAllowed {
    <#
      PURE. ARM's permissions read (GET <scope>/providers/Microsoft.Authorization/permissions: value[] of { actions;
      notActions }) -> is -Action allowed? Allowed when ONE entry grants it and that entry's notActions do not exclude it.
      $null / nothing = not allowed.
    #>
    param([AllowNull()][object[]]$Permissions, [string]$Action = 'Microsoft.Authorization/roleAssignments/delete')
    foreach ($p in @($Permissions)) {
        if ($null -eq $p) { continue }
        $hit = $false; foreach ($a in @(Get-PimWebTrimField $p 'actions')) { if (Test-PimWebTrimArmActionMatch -Pattern "$a" -Action $Action) { $hit = $true; break } }
        if (-not $hit) { continue }
        $blocked = $false; foreach ($n in @(Get-PimWebTrimField $p 'notActions')) { if (Test-PimWebTrimArmActionMatch -Pattern "$n" -Action $Action) { $blocked = $true; break } }
        if (-not $blocked) { return $true }
    }
    return $false
}

function Get-PimWebTrimTokenFacts {
    <# PURE. A bearer token (JWT; only its payload is read, never logged) -> @{ known; oid; roles }. #>
    param([AllowNull()][AllowEmptyString()][string]$Token)
    $o = @{ known = $false; oid = ''; roles = @() }
    try {
        $parts = "$Token".Split('.')
        if ($parts.Count -lt 2) { return $o }
        $p = $parts[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }
        $c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
        $o.oid = "$(Get-PimWebTrimField $c 'oid')".Trim().ToLowerInvariant()
        $o.roles = @(@(Get-PimWebTrimField $c 'roles') | Where-Object { $_ } | ForEach-Object { "$_" })
        $o.known = $true
    } catch { $o.known = $false }
    return $o
}

function Get-PimWebTrimItemPart {
    <# PURE. The fix-request part of an item: '<class>.<12 hex of SHA-256 of its stable key>' ([a-z0-9.-], <= 60). #>
    param([Parameter(Mandatory)][string]$Class, [Parameter(Mandatory)][string]$Key)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Key".ToLowerInvariant())) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    $c = ("$Class".ToLowerInvariant() -replace '[^a-z0-9-]', '-').Trim('-')
    return ('{0}.{1}' -f $c, $h.Substring(0, 12))
}

function Get-PimWebTrimArmList {
    # ARM list through the seam: value[] + nextLink.
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path)
    $out = New-Object System.Collections.Generic.List[object]
    $n = $Path; $guard = 0
    while ($n -and $guard -lt 50) {
        $guard++
        $r = & $Arm 'GET' $n $null
        foreach ($v in @(Get-PimWebTrimField $r 'value')) { if ($null -ne $v) { $out.Add($v) } }
        $n = "$(Get-PimWebTrimField $r 'nextLink')".Trim()
    }
    return $out.ToArray()   # no unary comma: the callers wrap in @() (a comma nests the list)
}

function Get-PimWebTrimGraphList {
    # Graph list through the seam: value[] + @odata.nextLink.
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$Path)
    $out = New-Object System.Collections.Generic.List[object]
    $n = $Path; $guard = 0
    while ($n -and $guard -lt 50) {
        $guard++
        $r = & $Graph 'GET' $n $null
        foreach ($v in @(Get-PimWebTrimField $r 'value')) { if ($null -ne $v) { $out.Add($v) } }
        $n = "$(Get-PimWebTrimField $r '@odata.nextLink')".Trim()
    }
    return $out.ToArray()
}

function Test-PimWebTrimNotFound {
    # PURE. Does an error message say 404 / not found?
    param([AllowNull()][string]$Message)
    return ("$Message" -match '(?i)\b404\b|NotFound|does not exist|Request_ResourceNotFound')
}

function New-PimWebTrimMailPayload {
    <#
      PURE. ONE queued notify request for the admins (the SECURE-WEB-1 path: pim.ChangeQueue, Kind Action, type
      'notify-mail' -- the SAME shape as engine\_shared\PIM-Notify.ps1 New-PimNotifyMailAction; the ENGINE sends it as its own
      identity, Invoke-PimQueueNotifyMail). Template 'alert-notice'; the findings are the removed and the reported items.
      Returns $null when there is no recipient or nothing to say.
    #>
    param([AllowEmptyCollection()][object[]]$Removed = @(), [AllowEmptyCollection()][object[]]$Reported = @(), [AllowEmptyCollection()][object[]]$Listed = @(),
          [AllowEmptyCollection()][string[]]$Recipients = @(), [string]$Identity = 'id-pim-web', [string]$RaisedBy = 'update', [datetime]$NowUtc = [datetime]::UtcNow)
    $to = @(@($Recipients) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $to.Count) { return $null }
    $rm = @($Removed | Where-Object { $_ }); $rp = @($Reported | Where-Object { $_ }); $ls = @($Listed | Where-Object { $_ })
    if (-not $rm.Count -and -not $rp.Count -and -not $ls.Count) { return $null }
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($x in $rm) { $lines.Add('Removed: ' + (& $enc $x.text)) }
    foreach ($x in $rp) { $lines.Add('Reported, not removed: ' + (& $enc $x.text) + ' -- ' + (& $enc $x.reason)) }
    foreach ($x in $ls) { $lines.Add('Listed only (not removed in this release): ' + (& $enc $x.text)) }
    $webRp = @($rp | Where-Object { "$($_.class)" -notlike 'sql-*' })
    $title = if ($webRp.Count) { "The internet-facing web identity $Identity holds rights outside its approved set" }
             elseif ($rm.Count) { "The internet-facing web identity $Identity was trimmed to its approved set" }
             else { 'The update found database access outside the approved set' }
    $find = @(@($rm | ForEach-Object { @{ kind = 'Removed by the update'; name = "$($_.text)" } }) +
              @($rp | ForEach-Object { @{ kind = 'Held, reported to PIM Manager support'; name = "$($_.text)" } }) +
              @($ls | ForEach-Object { @{ kind = 'Database users of identities that no longer exist (listed only)'; name = "$($_.text)" } }))
    $act = $rp.Count
    $tokens = [ordered]@{
        AlertTitle    = $title
        AlertEvent    = 'drift'
        AlertDetail   = ($lines.ToArray() -join '<br>')
        AlertTab      = 'settings'
        Instance      = 'update'
        WhenUtc       = $NowUtc.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
        AlertHeadline = "The update removed $($rm.Count) right(s) from $Identity, reported $($rp.Count) it may not remove itself and listed $($ls.Count) database user(s) of identities that no longer exist."
        AlertAction   = $(if ($act) { 'No action is needed from you: PIM Manager support removes the reported rights. Contact support if you granted one of them on purpose.' } else { 'No action is needed. Contact PIM Manager support if you granted one of these rights on purpose.' })
        AlertWho      = $(if ($act) { 'PIM Manager team' } else { 'Customer' })
        AlertStatus   = $(if ($act) { 'Warning' } else { 'Information' })
        AlertProblem  = $title
        AlertTodo     = $(if ($act) { 'PIM Manager support removes the reported rights.' } else { 'Nothing.' })
        AlertFindings = $find
    }
    return [ordered]@{ type = 'notify-mail'; mailType = 'alert-notice'; tokens = $tokens; recipients = $to; attachments = @()
                       event = 'web-identity-trim'; raisedBy = "$RaisedBy"; raisedUtc = $NowUtc.ToUniversalTime().ToString('o') }
}

function Get-PimWebTrimCandidateUsers {
    <#
      PURE. The database user names the database half looks up (the updater may not LIST database users -- no VIEW DEFINITION,
      by design -- so it asks the signed facts procedure about each NAME): every name a component's user has carried at any
      install (the pre-move system identity names: -NameMap, engine\_shared\PIM-SqlAccess.ps1 Get-PimSqlAccessInstallNameMap)
      and the id-pim-<role> names (-IdentityNames + -RoleWords). A user under another name is not seen here.
    #>
    param([AllowNull()][System.Collections.IDictionary]$NameMap = $null, [AllowEmptyCollection()][string[]]$IdentityNames = @(), [AllowEmptyCollection()][string[]]$RoleWords = @())
    $out = New-Object System.Collections.Generic.List[string]
    $add = { param($n) $t = "$n".Trim(); if ($t -match '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$' -and -not @($out | Where-Object { $_ -ieq $t }).Count) { $out.Add($t) } }
    if ($NameMap) { foreach ($k in @($NameMap.Keys)) { foreach ($n in @($NameMap[$k])) { & $add $n } } }
    foreach ($n in @($IdentityNames)) { & $add $n }
    foreach ($w in @($RoleWords)) { if ("$w".Trim()) { & $add ("id-pim-" + "$w".Trim().ToLowerInvariant()) } }
    return $out.ToArray()
}

function ConvertFrom-PimWebTrimSid {
    <# PURE. A contained Entra user's SID ('0x' + 16 bytes, Guid.ToByteArray order) -> its app (client) id, '' when not one. #>
    param([AllowEmptyString()][AllowNull()][string]$Sid)
    $h = "$Sid".Trim() -replace '^0x', ''
    if ($h -notmatch '^[0-9A-Fa-f]{32}$') { return '' }
    $b = New-Object byte[] 16
    for ($i = 0; $i -lt 16; $i++) { $b[$i] = [Convert]::ToByte($h.Substring($i * 2, 2), 16) }
    return ([guid]::new($b)).ToString()
}

function Invoke-PimSqlLeastPrivilegeCheck {
    <#
      The DATABASE half of the step -- REPORT ONLY, it changes NOTHING in the database (coordinator, 2026-11-16).
      Every read goes through the updater's own database user and the SIGNED read procedures it already holds EXECUTE on
      (the update path sends no security statement -- tests\Test-PimSqlAccess.ps1 L2):
        (a) the Support app's database user in db_owner OUTSIDE an open support session: [pimsupport].[usp_SupportState]
            (inOwner, jitOpen = an open time-limited grant marker, at most 8 h) -- a held db_owner without an open marker is
            REPORTED (run warning, one admin mail, one fix request). NOT removed: only a db_owner member can change db_owner
            membership (the updater is pim_updater + db_ddladmin), the update path carries no security statement, and the
            signed revoke procedure removes only a db_owner ITS OWN grant added -- a standing one is outside it. Without the
            support module, [pim].[usp_AccessFacts] @AppIds answers whether the Support app's user is in db_owner (then no
            session can be open). State unreadable = NOT judged, a warning (fail closed).
        (b) database users of identities that NO LONGER EXIST: each candidate name through [pim].[usp_AccessFacts] @DbUserName
            (its SID), the SID's app id looked up in Graph (GET only); no service principal = LISTED (run detail, once in the
            admin mail), never removed in this release and no fix request. A Graph read that fails = not judged.
      -SqlScalar param($Sql, $Parameters) -> one scalar. -Graph param($Method, $Path, $Body).
      Returns @{ supportOwner = held | clean | in-session | n/a | unread; reported = @(); orphans = @(); readClasses = @(); lines = @() }.
    #>
    param([Parameter(Mandatory)][scriptblock]$SqlScalar, [Parameter(Mandatory)][scriptblock]$Graph, [string]$SupportAppId = '',
          [AllowEmptyCollection()][string[]]$CandidateUsers = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $o = [ordered]@{ supportOwner = 'unread'; reported = @(); orphans = @(); readClasses = @(); lines = @() }
    $lines = New-Object System.Collections.Generic.List[object]
    $short = { param($e) ((("$($e.Exception.Message)") -split "`n")[0]).Trim() }
    $why = 'not removed: the updater''s database user (pim_updater + db_ddladmin) cannot change db_owner membership, the update path sends no security statement, and the signed revoke removes only a db_owner its own support grant added'
    # ---- (a) the Support app's user in db_owner outside an open support session
    $st = $null
    try {
        $raw = & $SqlScalar 'EXEC [pimsupport].[usp_SupportState];' @{}
        if (Get-Command ConvertFrom-PimSupportConsentState -ErrorAction SilentlyContinue) { $st = ConvertFrom-PimSupportConsentState $raw }
        else { throw 'the support state reader (ConvertFrom-PimSupportConsentState, loaded by the updater) is not loaded' }
    } catch {
        $m = & $short $_
        if ($m -match '(?i)Could not find stored procedure|Msg 2812|Invalid object name .pimsupport') { $st = [pscustomobject]@{ installed = $false; read = $true } }
        else { $st = [pscustomobject]@{ installed = $null; read = $false; problem = $m } }
    }
    $held = $null; $appId = "$SupportAppId".Trim().ToLowerInvariant()
    if ($st.read -and $st.installed -ne $false) {
        if ("$($st.appId)".Trim()) { $appId = "$($st.appId)".Trim().ToLowerInvariant() }
        if ($null -eq $st.inOwner) { $o.supportOwner = 'unread'; $lines.Add(@{ level = 'warn'; text = 'the support access state does not say whether the Support user holds db_owner -- not judged (nothing changes)' }) }
        elseif (-not $st.inOwner) { $o.supportOwner = 'clean'; $o.readClasses += 'sql-support-owner'; $lines.Add(@{ level = 'info'; text = 'the Support user holds no db_owner' }) }
        elseif ($st.jitOpen) { $o.supportOwner = 'in-session'; $o.readClasses += 'sql-support-owner'; $lines.Add(@{ level = 'info'; text = "the Support user holds db_owner inside an open support session (until $($st.jitUntil)) -- as agreed" }) }
        else { $held = 'outside any open support session (no open time-limited grant)'; $o.readClasses += 'sql-support-owner' }
    } elseif ($st.read -and $st.installed -eq $false) {
        # no support module here: no time-limited grant can exist, so a db_owner of the Support app's user is standing
        if ($appId -notmatch '^[0-9a-f-]{36}$') { $o.supportOwner = 'n/a'; $lines.Add(@{ level = 'info'; text = 'no support access module and no Support app known -- the Support user was not checked' }) }
        else {
            try {
                $f = "$(& $SqlScalar 'EXEC [pim].[usp_AccessFacts] @AppIds = @a;' @{ a = $appId })".Split('|')
                if ($f.Count -lt 4 -or $f[0] -ne 'v1' -or $f[1] -ne '1') { $o.supportOwner = 'unread'; $lines.Add(@{ level = 'warn'; text = 'the access facts could not see the database users -- the Support user was not judged (nothing changes)' }) }
                elseif ([int]$f[3] -gt 0) { $held = 'and this install has no time-limited support access (no session can be open)'; $o.readClasses += 'sql-support-owner' }
                else { $o.supportOwner = 'clean'; $o.readClasses += 'sql-support-owner'; $lines.Add(@{ level = 'info'; text = 'the Support user holds no db_owner' }) }
            } catch { $o.supportOwner = 'unread'; $lines.Add(@{ level = 'warn'; text = "the access facts could not be read ($(& $short $_)) -- the Support user was not judged (nothing changes)" }) }
        }
    } else {
        $o.supportOwner = 'unread'
        $lines.Add(@{ level = 'warn'; text = "the support session state could not be read ($("$($st.problem)")) -- the Support user's db_owner was not judged; nothing changes" })
    }
    if ($held) {
        $o.supportOwner = 'held'
        $k = "sql-support-owner|$appId"
        $o.reported += @{ class = 'sql-support-owner'; key = $k; code = 'SQL-SUPPORT-OWNER'; text = "the Support app's database user holds db_owner $held"; reason = $why; part = (Get-PimWebTrimItemPart -Class 'sql-support-owner' -Key $k) }
        $lines.Add(@{ level = 'warn'; text = "REPORTED (not removed) the Support app's database user holds db_owner $held -- $why" })
    }
    # ---- (b) database users of identities that no longer exist (LISTED only)
    $seeOk = $true; $checked = 0
    foreach ($n in @($CandidateUsers)) {
        if (-not "$n".Trim()) { continue }
        $f = $null
        try { $f = "$(& $SqlScalar 'EXEC [pim].[usp_AccessFacts] @DbUserName = @n;' @{ n = "$n" })".Split('|') }
        catch { $seeOk = $false; $lines.Add(@{ level = 'warn'; text = "the database users could not be looked up ($(& $short $_)) -- none listed this run" }); break }
        if ($f.Count -lt 6 -or $f[0] -ne 'v1' -or $f[1] -ne '1') { $seeOk = $false; $lines.Add(@{ level = 'warn'; text = 'the access facts procedure could not see the database users -- none listed this run' }); break }
        $checked++
        $aid = ConvertFrom-PimWebTrimSid -Sid $f[4]
        if (-not $aid) { continue }
        $gone = $null
        try { $gone = (@(Get-PimWebTrimGraphList -Graph $Graph -Path "/servicePrincipals?`$filter=appId eq '$aid'&`$select=id")).Count -eq 0 } catch { $gone = $null; $lines.Add(@{ level = 'info'; text = "the database user $n (app id $aid): whether its identity exists could not be read -- not listed" }) }
        if ($gone) {
            $own = $(if ("$($f[5])" -match '^[1-9]') { ', in db_owner' } else { '' })
            $o.orphans += @{ class = 'sql-orphan'; key = "sql-orphan|$("$n".ToLowerInvariant())|$aid"; text = "database user $n (app id $aid$own): its identity no longer exists" }
        }
    }
    if ($seeOk) { $o.readClasses += 'sql-orphan' }
    foreach ($x in @($o.orphans)) { $lines.Add(@{ level = 'info'; text = "LISTED (not removed in this release) $($x.text)" }) }
    if ($seeOk -and -not @($o.orphans).Count) { $lines.Add(@{ level = 'info'; text = "no database user of an identity that no longer exists among the $checked name(s) looked up" }) }
    $o.lines = @($lines.ToArray())
    return [pscustomobject]$o
}

function Invoke-PimWebIdentityTrim {
    <#
      The step. Never throws. Returns
        @{ state; mode; identity; removed = @(); reported = @(); failed = @(); kept = @(); approved = @(); unread = @();
           newReported = @(); fixRequests = @(); mail = @{ queued; reason }; lines = @(@{ level; text }); warnings; detail }
      state: off | not-moved | shared | approved-unread | unread | clean | trimmed | reported | partial | dry-run
      -Arm / -Graph   param($Method, $Path, $Body) -> the parsed answer; throws on an error (404 = gone on a read-back)
      -Store          param($op, $name, $value): 'get' / 'set' of pim.Settings ($null = no record: every reported item counts
                      as new for the fix request, which is register-once on its own; the mail then goes on removals only)
      -QueueMail      param($payload) -> @{ queued; id; reason }       -FixRequest  param($part, $code) -> @{ registered; reason }
      -UpdaterObjectId / -UpdaterGraphRoles: the updater's own principal and the roles in its Graph token (read, not assumed)
      -AiChat @{ known; enabled; host } ($null = not read). -ApprovedList: a built rights list (tests); else the code's own.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$Graph,
        [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$ManagerApp = 'ca-pim-manager',
        [string]$Mode = 'on', [string]$Version = '', [AllowNull()][object]$ApprovedList = $null,
        [string]$UpdaterObjectId = '', [AllowEmptyCollection()][string[]]$UpdaterGraphRoles = @(), [AllowNull()][object]$AiChat = $null,
        [scriptblock]$Store = $null, [scriptblock]$QueueMail = $null, [scriptblock]$FixRequest = $null,
        [AllowEmptyCollection()][string[]]$Recipients = @(), [string]$WebName = 'id-pim-web', [string]$AcaApi = '2024-03-01',
        # the database half (step 7, REPORT ONLY): ONE scalar as the updater's own database user ($null = no database session),
        # the Support app id the consent step knows, and the database user names to look up (Get-PimWebTrimCandidateUsers)
        [scriptblock]$SqlScalar = $null, [string]$SupportAppId = '', [AllowEmptyCollection()][string[]]$CandidateUsers = @(),
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $res = [ordered]@{ state = ''; mode = ''; identity = ''; removed = @(); reported = @(); failed = @(); kept = @(); approved = @(); unread = @()
                       newReported = @(); fixRequests = @(); mail = @{ queued = $false; reason = '' }; lines = @(); warnings = 0; detail = ''
                       sql = $null; listed = @(); newListed = @(); readClasses = @() }
    $lines = New-Object System.Collections.Generic.List[object]
    $say = { param($lv, $t) $lines.Add(@{ level = $lv; text = "web identity: $t" }) }
    $short = { param($e) ((("$($e.Exception.Message)") -split "`n")[0]).Trim() }
    # one pass; an early stop is a 'break' (a 'return' inside try would skip the result below)
    try { do {
        $res.mode = Get-PimWebTrimMode -Value $Mode
        $dry = ($res.mode -eq 'dryrun')
        if ($res.mode -eq 'off') { $res.state = 'off'; & $say 'info' 'trim switched off (PIM_WEB_TRIM=off) -- nothing read, nothing removed'; break }

        # ---- 1. the approved set (FAIL CLOSED)
        $ap = Get-PimWebTrimApprovedSet -Version $Version -List $ApprovedList
        if (-not $ap.ok) { $res.state = 'approved-unread'; & $say 'warn' "the approved set could not be read ($($ap.reason)) -- NOTHING removed this run"; break }

        # ---- 2. the identity, from the Manager app (never by a name alone)
        $rgScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        $app = $null; try { $app = & $Arm 'GET' "$rgScope/providers/Microsoft.App/containerApps/$($ManagerApp)?api-version=$AcaApi" $null } catch { $app = $null }
        $others = $null
        try { $others = @(@(Get-PimWebTrimArmList -Arm $Arm -Path "$rgScope/providers/Microsoft.App/containerApps?api-version=$AcaApi") + @(Get-PimWebTrimArmList -Arm $Arm -Path "$rgScope/providers/Microsoft.App/jobs?api-version=$AcaApi")) } catch { $others = $null }
        $wi = Resolve-PimWebTrimIdentity -App $app -Others $others -UpdaterObjectId $UpdaterObjectId -WebName $WebName -ManagerApp $ManagerApp
        $res.identity = "$($wi.principalId)"
        if (-not $wi.moved) { $res.state = 'not-moved'; & $say $(if ($null -eq $app) { 'warn' } else { 'info' }) "$($wi.reason)"; break }
        if (-not $wi.ok) { $res.state = 'shared'; & $say 'warn' "$($wi.reason)"; break }
        $oid = $wi.principalId
        $regNames = Get-PimWebTrimRegistryNames -App $app

        # ---- 3. what the web identity holds (each class read on its own; an unread class removes nothing)
        $items = New-Object System.Collections.Generic.List[object]
        $graphSpId = ''
        try { $graphSpId = "$((@(Get-PimWebTrimGraphList -Graph $Graph -Path "/servicePrincipals?`$filter=appId eq '$(Get-PimWebTrimGraphAppId)'&`$select=id,appId"))[0].id)".Trim() } catch { $graphSpId = '' }
        $ara = $null
        try { $ara = @(Get-PimWebTrimGraphList -Graph $Graph -Path "/servicePrincipals/$oid/appRoleAssignments") } catch { $res.unread += "Graph app roles ($(& $short $_))" }
        if ($null -ne $ara) {
            if (-not $graphSpId) { $res.unread += 'Graph app roles (the Microsoft Graph service principal could not be read)' }
            else {
                $res.readClasses += 'graph-app-role'
                foreach ($a in $ara) {
                    $resId = "$(Get-PimWebTrimField $a 'resourceId')".Trim(); $roleId = "$(Get-PimWebTrimField $a 'appRoleId')".Trim().ToLowerInvariant()
                    $onGraph = ($resId -ieq $graphSpId)
                    $nm = if ($onGraph -and $ap.graph.Contains($roleId)) { $ap.graph[$roleId] } else { "app role $roleId" }
                    $txt = "Graph app role $nm on $(Get-PimWebTrimField $a 'resourceDisplayName')"
                    $it = [ordered]@{ class = 'graph-app-role'; key = "graph|$($resId.ToLowerInvariant())|$roleId"; id = "$(Get-PimWebTrimField $a 'id')"; resourceId = $resId; text = $txt; verdict = ''; why = '' }
                    if ($onGraph -and $ap.graph.Contains($roleId)) { $it.verdict = 'approved' } else { $it.verdict = 'excess'; $it.why = $(if ($onGraph) { 'not in the approved Graph set' } else { 'an app role on another resource (the web holds Graph roles only)' }) }
                    $items.Add($it)
                }
            }
        }
        $mo = $null
        try { $mo = @(Get-PimWebTrimGraphList -Graph $Graph -Path "/servicePrincipals/$oid/memberOf") } catch { $res.unread += "group memberships and directory roles ($(& $short $_))" }
        if ($null -ne $mo) { $res.readClasses += @('group-membership', 'directory-role') }
        foreach ($m in @($mo)) {
            if ($null -eq $m) { continue }
            $t = "$(Get-PimWebTrimField $m '@odata.type')" -replace '^#microsoft\.graph\.', ''
            $mid = "$(Get-PimWebTrimField $m 'id')".Trim()
            if ($t -eq 'group') {
                $ra = [bool](Get-PimWebTrimField $m 'isAssignableToRole')
                $items.Add([ordered]@{ class = 'group-membership'; key = "group|$($mid.ToLowerInvariant())"; id = $mid; roleAssignable = $ra; text = "member of the group $(Get-PimWebTrimField $m 'displayName') ($mid)$(if ($ra) { ', role-assignable' })"; verdict = 'excess'; why = 'the web identity is a member of no group' })
            } elseif ($t -eq 'directoryRole') {
                $items.Add([ordered]@{ class = 'directory-role'; key = "directory-role|$($mid.ToLowerInvariant())"; id = $mid; text = "the directory role $(Get-PimWebTrimField $m 'displayName') ($mid)"; verdict = 'excess'; why = 'the web identity holds no directory role' })
            }
        }
        $azr = $null
        try { $azr = @(Get-PimWebTrimArmList -Arm $Arm -Path "$rgScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=assignedTo('$oid')") } catch { $res.unread += "Azure role assignments ($(& $short $_))" }
        if ($null -ne $azr) { $res.readClasses += 'azure-rbac' }
        foreach ($r in @($azr)) {
            if ($null -eq $r) { continue }
            $pr = Get-PimWebTrimField $r 'properties'
            if ("$(Get-PimWebTrimField $pr 'principalId')".Trim().ToLowerInvariant() -ne $oid) { continue }   # held through a group: the group membership is the item
            $rd = "$(Get-PimWebTrimField $pr 'roleDefinitionId')"; $sc = "$(Get-PimWebTrimField $pr 'scope')"
            $rguid = ($rd.Trim().TrimEnd('/') -split '/')[-1].ToLowerInvariant()
            $v = Get-PimWebTrimAzureVerdict -RoleId $rguid -Scope $sc -Approved $ap.azure -RgScope $rgScope -RegistryNames $regNames -AiChat $AiChat
            $rn = @($ap.azure | Where-Object { "$(Get-PimWebTrimField $_ 'roleId')" -eq $rguid } | ForEach-Object { "$(Get-PimWebTrimField $_ 'role')" })[0]
            if (-not $rn) { $rn = "role $rguid" }
            $items.Add([ordered]@{ class = 'azure-rbac'; key = "azure|$rguid|$($sc.Trim().TrimEnd('/').ToLowerInvariant())"; id = "$(Get-PimWebTrimField $r 'id')"; scope = $sc; text = "Azure $rn at $sc"; verdict = $v.verdict; why = $v.why })
        }
        foreach ($u in @($res.unread)) { & $say 'warn' "not read: $u -- nothing of it removed" }

        # ---- 4. may the UPDATER remove it? (its own rights, read now; nothing is ever granted)
        $roles = @($UpdaterGraphRoles | ForEach-Object { "$_" })
        $permCache = @{}; $ownerCache = @{}
        $azAllowed = {
            param($scope)
            $k = "$scope".ToLowerInvariant()
            if (-not $permCache.ContainsKey($k)) {
                $ok = $false
                if ($k -match '^/subscriptions/[^/]+') {
                    try { $ok = Test-PimWebTrimArmActionAllowed -Permissions @(Get-PimWebTrimArmList -Arm $Arm -Path "$scope/providers/Microsoft.Authorization/permissions?api-version=2022-04-01") } catch { $ok = $false }
                }
                $permCache[$k] = $ok
            }
            return $permCache[$k]
        }
        $isOwner = {
            param($spId)
            $k = "$spId".ToLowerInvariant()
            if (-not $ownerCache.ContainsKey($k)) {
                $ok = $false
                if ("$UpdaterObjectId".Trim()) { try { $ok = [bool](@(Get-PimWebTrimGraphList -Graph $Graph -Path "/servicePrincipals/$spId/owners?`$select=id") | Where-Object { "$(Get-PimWebTrimField $_ 'id')" -ieq "$UpdaterObjectId".Trim() }).Count } catch { $ok = $false } }
                $ownerCache[$k] = $ok
            }
            return $ownerCache[$k]
        }
        foreach ($it in $items) {
            if ($it.verdict -eq 'approved') { $res.approved += $it.text; continue }
            if ($it.verdict -eq 'keep') { $res.kept += "$($it.text) ($($it.why))"; continue }
            $can = $false; $need = ''
            switch ($it.class) {
                'graph-app-role' {
                    if ($roles -contains 'AppRoleAssignment.ReadWrite.All') { $can = $true }
                    elseif ($roles -contains 'Application.ReadWrite.OwnedBy' -and (& $isOwner $it.resourceId)) { $can = $true }
                    else { $need = 'the updater holds no app-role write right (AppRoleAssignment.ReadWrite.All, or owner of the resource with Application.ReadWrite.OwnedBy)' }
                }
                'group-membership' {
                    $w = ($roles -contains 'GroupMember.ReadWrite.All' -or $roles -contains 'Group.ReadWrite.All')
                    if ($w -and (-not $it.roleAssignable -or $roles -contains 'RoleManagement.ReadWrite.Directory')) { $can = $true }
                    else { $need = $(if ($w) { 'a role-assignable group also needs RoleManagement.ReadWrite.Directory, which the updater does not hold' } else { 'the updater holds no group write right (GroupMember.ReadWrite.All)' }) }
                }
                'directory-role' { if ($roles -contains 'RoleManagement.ReadWrite.Directory') { $can = $true } else { $need = 'the updater holds no directory-role right (RoleManagement.ReadWrite.Directory)' } }
                'azure-rbac' { if (& $azAllowed $it.scope) { $can = $true } else { $need = 'the updater may not delete role assignments at that scope (its Contributor excludes Microsoft.Authorization/*/Delete)' } }
            }
            $it['can'] = $can; $it['reason'] = $need
        }

        # ---- 5. remove (never in a dry run), then read back
        $excess = @($items | Where-Object { $_.verdict -eq 'excess' })
        $done = New-Object System.Collections.Generic.List[object]
        foreach ($it in $excess) {
            if (-not $it.can) { continue }
            if ($dry) { & $say 'info' "dry run: would remove $($it.text)"; continue }
            try {
                switch ($it.class) {
                    'graph-app-role'   { [void](& $Graph 'DELETE' "/servicePrincipals/$($it.resourceId)/appRoleAssignedTo/$($it.id)" $null) }
                    'group-membership' { [void](& $Graph 'DELETE' "/groups/$($it.id)/members/$oid/`$ref" $null) }
                    'directory-role'   { [void](& $Graph 'DELETE' "/directoryRoles/$($it.id)/members/$oid/`$ref" $null) }
                    'azure-rbac'       { [void](& $Arm 'DELETE' "$($it.id)?api-version=2022-04-01" $null) }
                }
                $done.Add($it)
            } catch {
                if (Test-PimWebTrimNotFound (& $short $_)) { $done.Add($it) }
                else { $it['can'] = $false; $it['reason'] = "the removal was refused ($(& $short $_))"; $res.failed += $it.text }
            }
        }
        if ($done.Count) {
            # read back: each class listed again; an item still there is NOT removed
            $still = @{}
            $reread = {
                param($cls)
                switch ($cls) {
                    'graph-app-role'   { foreach ($a in @(Get-PimWebTrimGraphList -Graph $Graph -Path "/servicePrincipals/$oid/appRoleAssignments")) { $still["graph-app-role|$(Get-PimWebTrimField $a 'id')"] = 1 } }
                    'group-membership' { foreach ($m in @(Get-PimWebTrimGraphList -Graph $Graph -Path "/servicePrincipals/$oid/memberOf")) { $still["group-membership|$(Get-PimWebTrimField $m 'id')"] = 1; $still["directory-role|$(Get-PimWebTrimField $m 'id')"] = 1 } }
                    'directory-role'   { foreach ($m in @(Get-PimWebTrimGraphList -Graph $Graph -Path "/servicePrincipals/$oid/memberOf")) { $still["group-membership|$(Get-PimWebTrimField $m 'id')"] = 1; $still["directory-role|$(Get-PimWebTrimField $m 'id')"] = 1 } }
                    'azure-rbac'       { foreach ($r in @(Get-PimWebTrimArmList -Arm $Arm -Path "$rgScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=assignedTo('$oid')")) { $still["azure-rbac|$("$(Get-PimWebTrimField $r 'id')".ToLowerInvariant())"] = 1 } }
                }
            }
            $readOk = @{}
            foreach ($cls in @($done | ForEach-Object { $_.class } | Select-Object -Unique)) { try { & $reread $cls; $readOk[$cls] = $true } catch { $readOk[$cls] = $false } }
            foreach ($it in $done) {
                $sk = if ($it.class -eq 'azure-rbac') { "azure-rbac|$("$($it.id)".ToLowerInvariant())" } else { "$($it.class)|$($it.id)" }
                if (-not $readOk[$it.class]) { $it['can'] = $false; $it['reason'] = 'removed, but the read-back failed -- checked again on the next update'; $res.failed += $it.text }
                elseif ($still.ContainsKey($sk)) { $it['can'] = $false; $it['reason'] = 'the removal did not read back'; $res.failed += $it.text }
                else { $it['removed'] = $true; $res.removed += @{ class = $it.class; key = $it.key; text = $it.text }; & $say 'changed' "REMOVED $($it.text) (read back)" }
            }
        }
        $reportedItems = @($excess | Where-Object { -not $_['removed'] -and -not ($dry -and $_.can) })
        foreach ($it in $reportedItems) {
            $res.reported += @{ class = $it.class; key = $it.key; text = $it.text; reason = "$($it.reason)"; part = (Get-PimWebTrimItemPart -Class $it.class -Key $it.key) }
            & $say 'warn' "REPORTED (not removed) $($it.text) -- $($it.reason)"
        }
        foreach ($k in @($res.kept)) { & $say 'info' "kept, not provably excess: $k" }
        if (-not @($excess).Count -and -not @($res.unread).Count) { & $say 'info' "$WebName holds its approved set only ($(@($res.approved).Count) right(s))" }
        $res.state = if ($dry) { 'dry-run' }
                     elseif (@($res.unread).Count -and -not @($res.removed).Count -and -not @($res.reported).Count) { 'unread' }
                     elseif (@($res.removed).Count -and (@($res.reported).Count -or @($res.unread).Count)) { 'partial' }
                     elseif (@($res.removed).Count) { 'trimmed' }
                     elseif (@($res.reported).Count) { 'reported' }
                     elseif (@($res.unread).Count) { 'unread' }
                     else { 'clean' }
    } while ($false) } catch {
        $res.state = 'failed'; & $say 'warn' "not trimmed: $(& $short $_) -- the update is unaffected"
    }

    # ---- 7. the DATABASE half (coordinator addition 2026-11-16): REPORT ONLY -- nothing is ever removed here
    try {
        if ($res.mode -ne 'off' -and $SqlScalar) {
            $sq = Invoke-PimSqlLeastPrivilegeCheck -SqlScalar $SqlScalar -Graph $Graph -SupportAppId $SupportAppId -CandidateUsers $CandidateUsers -NowUtc $NowUtc
            $res.sql = $sq
            foreach ($l in @($sq.lines)) { $lines.Add(@{ level = $l.level; text = "database: $($l.text)" }) }
            foreach ($x in @($sq.reported)) { $res.reported += $x }
            $res.readClasses += @($sq.readClasses)
            $res.listed = @($sq.orphans)
        } elseif ($res.mode -ne 'off') { $lines.Add(@{ level = 'info'; text = 'database: no database session in this run -- the Support user and the old database users were not checked' }) }
    } catch { $lines.Add(@{ level = 'warn'; text = "database: not checked ($(& $short $_)) -- nothing changes" }) }

    # ---- 6. once per item: the record, the fix request, the mail (never in a dry run, never when switched off)
    try {
        if ($res.mode -eq 'off' -or $res.mode -eq 'dryrun') { } else {
            $oid = "$($res.identity)"
            $prev = $null; $storeOk = $false
            if ($Store) { try { $prev = & $Store 'get' (Get-PimWebTrimSettingName) $null; if ($prev -is [string]) { $prev = $(if ("$prev".Trim()) { $prev | ConvertFrom-Json } else { $null }) }; $storeOk = $true } catch { $storeOk = $false } }
            $known = @{}
            $pr = Get-PimWebTrimField $prev 'reported'
            if ($pr) { $names = if ($pr -is [System.Collections.IDictionary]) { @($pr.Keys) } else { @($pr.PSObject.Properties | ForEach-Object { $_.Name }) }; foreach ($n in $names) { $known["$n"] = Get-PimWebTrimField $pr "$n" } }
            $knownListed = @{}
            $pl0 = Get-PimWebTrimField $prev 'listed'
            if ($pl0) { $names = if ($pl0 -is [System.Collections.IDictionary]) { @($pl0.Keys) } else { @($pl0.PSObject.Properties | ForEach-Object { $_.Name }) }; foreach ($n in $names) { $knownListed["$n"] = Get-PimWebTrimField $pl0 "$n" } }
            $newRep = @($res.reported | Where-Object { -not $known.ContainsKey("$($_.key)") })
            $newListed = @($res.listed | Where-Object { -not $knownListed.ContainsKey("$($_.key)") })
            $res.newReported = @($newRep | ForEach-Object { $_.text })
            $res.newListed = @($newListed | ForEach-Object { $_.text })
            foreach ($x in $newRep) {
                $fr = $null
                $code = if ("$($x.code)") { "$($x.code)" } else { Get-PimWebTrimFixCode }
                if ($FixRequest) { try { $fr = & $FixRequest "$($x.part)" $code } catch { $fr = @{ registered = $false; reason = (& $short $_) } } }
                $res.fixRequests += @{ part = "$($x.part)"; registered = [bool](Get-PimWebTrimField $fr 'registered'); reason = "$(Get-PimWebTrimField $fr 'reason')" }
            }
            if ($newRep.Count) { & $say 'info' ("fix request to PIM Manager support for $($newRep.Count) new item(s): " + (@($res.fixRequests | ForEach-Object { "$($_.part)$(if (-not $_.registered -and $_.reason) { " ($($_.reason))" })" }) -join ', ')) }
            # the mail: on a removal, or on an item reported for the first time -- never the same held item every night
            $mailNew = $(if ($storeOk) { @($newRep) + @($newListed) } else { @() })
            if (@($res.removed).Count -or @($mailNew).Count) {
                # the old database users are listed ONCE (the mail that first finds them), never again while they stay
                $pl = New-PimWebTrimMailPayload -Removed @($res.removed) -Reported @($res.reported) -Listed @($newListed) -Recipients $Recipients -Identity $WebName -NowUtc $NowUtc
                if ($null -eq $pl) { $res.mail = @{ queued = $false; reason = 'no alert recipient is configured' } }
                elseif (-not $QueueMail) { $res.mail = @{ queued = $false; reason = 'no mail queue in this process' } }
                else { try { $q = & $QueueMail $pl; $res.mail = @{ queued = [bool](Get-PimWebTrimField $q 'queued'); reason = "$(Get-PimWebTrimField $q 'reason')" } } catch { $res.mail = @{ queued = $false; reason = (& $short $_) } } }
                & $say $(if ($res.mail.queued) { 'info' } else { 'warn' }) $(if ($res.mail.queued) { "the admins are mailed (queued; the engine sends it at its next run)" } else { "the admin mail was NOT queued: $($res.mail.reason)" })
            }
            if ($Store) {
                $rec = [ordered]@{}
                foreach ($x in @($res.reported)) { $first = $NowUtc.ToUniversalTime().ToString('o'); if ($known.ContainsKey("$($x.key)")) { $f0 = "$(Get-PimWebTrimField $known["$($x.key)"] 'firstUtc')"; if ($f0) { $first = $f0 } }; $rec["$($x.key)"] = [ordered]@{ firstUtc = $first; part = "$($x.part)"; text = "$($x.text)" } }
                # an entry of a class NOT read this run is kept as it was (an unread class never makes a held item "new" again)
                $clsOf = { param($k) switch -regex ("$k") { '^graph\|' { 'graph-app-role' } '^group\|' { 'group-membership' } '^directory-role\|' { 'directory-role' } '^azure\|' { 'azure-rbac' } '^sql-support-owner\|' { 'sql-support-owner' } '^sql-orphan\|' { 'sql-orphan' } default { '' } } }
                foreach ($k in @($known.Keys)) { if (-not $rec.Contains($k) -and @($res.readClasses) -notcontains (& $clsOf $k)) { $rec[$k] = $known[$k] } }
                $lst = [ordered]@{}
                foreach ($x in @($res.listed)) { $first = $NowUtc.ToUniversalTime().ToString('o'); if ($knownListed.ContainsKey("$($x.key)")) { $f0 = "$(Get-PimWebTrimField $knownListed["$($x.key)"] 'firstUtc')"; if ($f0) { $first = $f0 } }; $lst["$($x.key)"] = [ordered]@{ firstUtc = $first; text = "$($x.text)" } }
                foreach ($k in @($knownListed.Keys)) { if (-not $lst.Contains($k) -and @($res.readClasses) -notcontains (& $clsOf $k)) { $lst[$k] = $knownListed[$k] } }
                $val = [ordered]@{ lastUtc = $NowUtc.ToUniversalTime().ToString('o'); identity = $oid; removed = @($res.removed | ForEach-Object { $_.text }); reported = $rec; listed = $lst }
                try { [void](& $Store 'set' (Get-PimWebTrimSettingName) $val) } catch { & $say 'warn' "the trim record could not be stored ($(& $short $_)) -- the next run reports its items again" }
            }
        }
    } catch { & $say 'warn' "the report could not be completed ($(& $short $_)) -- the update is unaffected" }
    $res.lines = @($lines.ToArray())
    $res.warnings = @($res.lines | Where-Object { $_.level -eq 'warn' }).Count
    $sqlTxt = if ($res.sql) { "; database: Support db_owner $($res.sql.supportOwner), $(@($res.listed).Count) user(s) of identities that no longer exist (listed, not removed)" } else { '' }
    $res.detail = "state $($res.state); removed $(@($res.removed).Count), reported $(@($res.reported).Count), kept $(@($res.kept).Count), unread $(@($res.unread).Count)$sqlTxt"
    return [pscustomobject]$res
}
