# PIM4EntraPS -- queued DIRECTORY ACTIONS (§65).
# Dot-sourced by PIM-Functions.psm1 and standalone by the scheduler.
#
# WHY THIS FILE EXISTS
# --------------------
# The Manager must be READ-ONLY (operator, 2026-09-12: *"remember to reduce the pim manager
# permissions to read only"* / *"as the engine/queue must do the actual change"*). So the five
# places the GUI wrote straight to Graph now ENQUEUE, and the ENGINE performs the change -- using
# the engine's own identity, auth and logging.
#
# 🔑 THE SEPARATION THAT MATTERS. pim.ChangeQueue carries two Kinds (§65.2):
#     DesiredState -> the payload IS a pim.Rows row      -> drained by Invoke-PimSqlCommit
#     Action       -> an imperative directory operation  -> drained HERE, never written to pim.Rows
# A revoke/TAP/session-revoke is not desired state; inventing a row for it was the trap that made an
# earlier draft of this design wrong.
#
# 🪤 EVERY ACTION MUST BE IDEMPOTENT. §65.8 requires retries, so an action WILL be re-run after a
# partial failure. "Already gone" is SUCCESS for a removal, never an error -- otherwise the first
# retry of a half-applied batch turns a recovered state into a permanent 'failed'.

Set-StrictMode -Off

# 🔒 The ONE break-glass reader (pim.Settings['BreakGlassAccounts'] unioned with the legacy global/env).
# The drain re-checks every revoke / session revoke against it at EXECUTION time (see
# Get-PimQueueActionBreakGlassRefusal) -- so it must be loaded wherever this file is, not only in the Manager.
if (-not (Get-Command Get-PimBreakGlassAccountStatus -ErrorAction SilentlyContinue)) {
    $__qaBgLib = Join-Path $PSScriptRoot 'PIM-BreakGlassAccounts.ps1'
    if (Test-Path -LiteralPath $__qaBgLib) { . $__qaBgLib }
}

# ---------------------------------------------------------------------------
# The action catalog. One entry per thing the Manager can ask the engine to do.
#
# 🔑 `verifiable` IS A CONTRACT, NOT A CONVENIENCE. §65.8 says "applied" means re-read and
# confirmed -- but `revokeSignInSessions` has no post-state to read: Graph exposes no "are this
# user's sessions revoked?" query. Pretending otherwise would mean either (a) reporting an
# unverified action as verified, or (b) retrying it forever because verification never passes.
# Both are worse than saying so. An unverifiable action is recorded `applied` with
# verification='none', and that fact is RETAINED on the entry so a reader can see which actions
# carry proof and which carry only an API acknowledgement.
# ---------------------------------------------------------------------------
function Get-PimQueueActionCatalog {
    @(
        @{ type='entra-role-revoke'
           description='Remove an Entra directory role assignment (ACTIVE; ELIGIBLE when the payload says assignmentType=Eligible)'
           verifiable=$true }
        @{ type='group-assignment-revoke'
           description='Remove a PIM-for-Groups assignment (ACTIVE; ELIGIBLE when the payload says assignmentType=Eligible)'
           verifiable=$true }
        @{ type='azure-rbac-revoke'
           description='Remove an Azure RBAC role assignment (ACTIVE by assignment id; ELIGIBLE PIM assignment when the payload says assignmentType=Eligible)'
           verifiable=$true }
        @{ type='tap-reset'
           description='Replace a Temporary Access Pass (delivered by mail, never shown in the GUI)'
           verifiable=$true }
        @{ type='session-revoke'
           description='Revoke all sign-in sessions for an account'
           # No Graph read exists to confirm this. See the note above -- declared, not pretended.
           verifiable=$false }
        # BUG-203 (§33.28): the Manager QUEUES a B2B guest invitation (New-PimGuestInviteAction); the engine sends it.
        @{ type='guest-invite'
           description='Invite an external person as a B2B guest (POST /invitations; verified by the invited user object)'
           verifiable=$true }
    ) | ForEach-Object { [pscustomobject]$_ }
}

function Get-PimQueueActionType {
    param([Parameter(Mandatory)][string]$Type)
    return @(Get-PimQueueActionCatalog | Where-Object { $_.type -eq $Type })[0]
}

# ---------------------------------------------------------------------------
# Apply ONE action. Pure dispatch over injected invokers so the whole matrix is testable offline
# (the house pattern -- a default invoker in production, a fake in the gates).
#
# Returns @{ ok; verification (verified|none|indeterminate); detail }.
#   ok=$false                      -> retryable failure, the entry goes back on the queue
#   verification='indeterminate'   -> the CALL looked fine but the read-back could not be done.
#                                     🪤 NEVER collapse this into success: "cannot answer" reported
#                                     as "all good" is the exact conflation behind BUG-134 (§61.7).
# ---------------------------------------------------------------------------
function Resolve-PimQueuedTapRecipient {
    # The recipient is resolved at APPLY time from the CURRENT admin row (the office-user email may
    # have been corrected after the reset was queued), with the rule every other admin mail uses
    # (Get-PimAdminMailRecipient). The recipient captured at queue time is the fallback only.
    param([Parameter(Mandatory)][object]$Payload)
    $upn = "$($Payload.userPrincipalName)".Trim()
    if ($upn -and (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue) -and (Get-Command Get-PimAdminMailRecipient -ErrorAction SilentlyContinue)) {
        try {
            $row = @(Get-PimDesiredRows -Entity 'Account-Definitions-Admins') |
                Where-Object { "$($_.UserPrincipalName)".Trim() -ieq $upn } | Select-Object -First 1
            if ($row) { $r = Get-PimAdminMailRecipient -Row $row; if ("$r".Trim()) { return "$r".Trim() } }
        } catch { Write-Verbose "tap-reset recipient lookup ($upn): $($_.Exception.Message)" }
    }
    return "$($Payload.recipient)".Trim()
}

function Send-PimTapMail {
    <#
      Delivers a TAP minted by the queued 'tap-reset' action through the SAME template and send path
      the AdminTap provider uses (tap-delivery via Send-PimNotifyMail).
      🔴 This function did not exist. Invoke-PimQueueAction called it behind a Get-Command gate, so the
      gate was always false, $mailed stayed $false, and EVERY queued TAP reset deleted the old pass,
      minted a new one and then failed as "could NOT be mailed" -- a lockout manufactured by a missing
      name (found 2026-09-12). Returns $true ONLY when the send reports sent=true.
    #>
    param([Parameter(Mandatory)][object]$Payload, [Parameter(Mandatory)][object]$Tap)
    if (-not (Get-Command Send-PimNotifyMail -ErrorAction SilentlyContinue)) {
        Write-Warning "  [queue] tap-reset: the mail library (PIM-Notify.ps1) is not loaded in this host -- the TAP cannot be delivered."
        return $false
    }
    $rcpt = Resolve-PimQueuedTapRecipient -Payload $Payload
    if (-not $rcpt) { Write-Warning "  [queue] tap-reset $($Payload.userPrincipalName): no recipient (office user email / manager)."; return $false }
    $mins = 0; [void][int]::TryParse("$($Tap.lifetimeInMinutes)", [ref]$mins)
    $start = $null
    if ("$($Tap.startDateTime)".Trim()) {
        try { $start = [datetime]::Parse("$($Tap.startDateTime)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() } catch { $start = $null }
    }
    if (-not $start) { $start = [datetime]::UtcNow }
    $expires = if ($mins -gt 0) { $start.AddMinutes($mins).ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' } else { '' }
    $toks = @{ UserPrincipalName = "$($Payload.userPrincipalName)"; TapCode = "$($Tap.temporaryAccessPass)"
               TapStartLocal = "$($Tap.startDateTime)"; TapStartUtc = "$($Tap.startDateTime)"
               TapLifetimeMinutes = "$($Tap.lifetimeInMinutes)"; TapExpiresUtc = $expires }
    $res = $null
    try { $res = Send-PimNotifyMail -Type 'tap-delivery' -Tokens $toks -Recipient $rcpt } catch { $res = @{ sent = $false; reason = "$($_.Exception.Message)" } }
    if ("$($res.sent)" -match '(?i)true') { return $true }
    Write-Warning "  [queue] tap-reset $($Payload.userPrincipalName): mail to '$rcpt' did NOT go out: $($res.reason)"
    return $false
}

function Invoke-PimQueueEligibleRevoke {
    <#
      ELIGIBLE revoke for the three revoke types (68.6 row 27 a), with the same contract as the active
      path: issue the removal, then RE-READ and report verified / indeterminate.
        entra-role-revoke       payload: principalId, roleDefinitionId, directoryScopeId ('/' default)
        group-assignment-revoke payload: principalId, groupId, accessId ('member' default)
        azure-rbac-revoke       payload: principalId, roleDefinitionId (full id or GUID), scope
      "Already gone" on the removal call is not a failure: the read-back decides (idempotence, see the
      header of this file). A missing field is terminal -- retrying cannot supply it.
    #>
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][object]$Payload, [string]$Justification,
          [Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][scriptblock]$Arm)
    $p = $Payload
    $just = if ("$Justification".Trim()) { "$Justification" } else { 'revoked via PIM queue' }
    $isAbsent = { param($m) "$m" -match '(?i)RoleAssignmentDoesNotExist|DoesNotExist|ResourceNotFound|\b404\b|not\s*found' }
    $prin = "$($p.principalId)".Trim()
    if (-not $prin) { return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; detail="$Type (eligible) has no principalId" } }
    switch ($Type) {
        'entra-role-revoke' {
            $rid = "$($p.roleDefinitionId)".Trim(); if ($rid.Contains('/')) { $rid = $rid.Substring($rid.LastIndexOf('/') + 1) }
            if (-not $rid) { return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; detail='entra-role-revoke (eligible) has no roleDefinitionId' } }
            $dsid = if ("$($p.directoryScopeId)".Trim()) { "$($p.directoryScopeId)".Trim() } else { '/' }
            $body = @{ action='adminRemove'; principalId=$prin; roleDefinitionId=$rid; directoryScopeId=$dsid; justification=$just }
            try { & $Graph 'POST' '/roleManagement/directory/roleEligibilityScheduleRequests' $body | Out-Null }
            catch { if (-not (& $isAbsent $_.Exception.Message)) { throw } }
            $still = @(& $Graph 'GET' ("/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$prin' and roleDefinitionId eq '$rid'") $null $true)
            if ($null -eq $still) { return [pscustomobject]@{ ok=$true; verification='indeterminate'; detail='eligible removal issued; the read-back could not be performed' } }
            $left = @(@($still) | Where-Object { $_ -and ("$($_.directoryScopeId)".Trim() -eq '' -or "$($_.directoryScopeId)" -eq $dsid) })
            if ($left.Count -eq 0) { return [pscustomobject]@{ ok=$true; verification='verified'; detail='eligible assignment is gone' } }
            return [pscustomobject]@{ ok=$false; verification='indeterminate'; detail='eligible assignment still present on read-back (directory may not have caught up)' }
        }
        'group-assignment-revoke' {
            $gid = "$($p.groupId)".Trim()
            if (-not $gid) { return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; detail='group-assignment-revoke (eligible) has no groupId' } }
            $acc = if ("$($p.accessId)".Trim()) { "$($p.accessId)".Trim() } else { 'member' }
            $body = @{ action='adminRemove'; principalId=$prin; groupId=$gid; accessId=$acc; justification=$just }
            try { & $Graph 'POST' '/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests' $body | Out-Null }
            catch { if (-not (& $isAbsent $_.Exception.Message)) { throw } }
            $still = @(& $Graph 'GET' ("/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$gid' and principalId eq '$prin'") $null $true)
            if ($null -eq $still) { return [pscustomobject]@{ ok=$true; verification='indeterminate'; detail='eligible removal issued; the read-back could not be performed' } }
            $left = @(@($still) | Where-Object { $_ -and ("$($_.accessId)".Trim() -eq '' -or "$($_.accessId)" -ieq $acc) })
            if ($left.Count -eq 0) { return [pscustomobject]@{ ok=$true; verification='verified'; detail='eligible group assignment is gone' } }
            return [pscustomobject]@{ ok=$false; verification='indeterminate'; detail='eligible group assignment still present on read-back' }
        }
        'azure-rbac-revoke' {
            $scope = "$($p.scope)".TrimEnd('/')
            $rdef = "$($p.roleDefinitionId)".Trim()
            if (-not $scope -or -not $rdef) { return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; detail='azure-rbac-revoke (eligible) needs scope and roleDefinitionId -- cannot address the eligibility to remove' } }
            if (-not $rdef.Contains('/')) { $rdef = "$scope/providers/Microsoft.Authorization/roleDefinitions/$rdef" }
            $guidPart = $rdef.Substring($rdef.LastIndexOf('/') + 1)
            $body = @{ properties = @{ principalId=$prin; roleDefinitionId=$rdef; requestType='AdminRemove'; justification=$just } }
            try { & $Arm 'PUT' ("$scope/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/$([guid]::NewGuid().ToString())?api-version=2020-10-01-preview") $body | Out-Null }
            catch { if (-not (& $isAbsent $_.Exception.Message)) { throw } }
            $res = & $Arm 'GET' ("$scope/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01-preview&`$filter=principalId eq '$prin'") $null
            if ($null -eq $res) { return [pscustomobject]@{ ok=$true; verification='verified'; detail='eligible Azure assignment is gone' } }
            $items = if ($res.PSObject.Properties['value']) { @($res.value) } else { @($res) }
            $left = @($items | Where-Object { $_ -and "$($_.properties.roleDefinitionId)" -match [regex]::Escape($guidPart) -and ("$($_.properties.scope)".TrimEnd('/') -eq '' -or "$($_.properties.scope)".TrimEnd('/') -ieq $scope) })
            if ($left.Count -eq 0) { return [pscustomobject]@{ ok=$true; verification='verified'; detail='eligible Azure assignment is gone' } }
            return [pscustomobject]@{ ok=$false; verification='indeterminate'; detail='eligible Azure assignment still present on read-back' }
        }
    }
    return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; detail="no eligible revoke for '$Type'" }
}

function Get-PimQueueActionBreakGlassTypes {
    # The action types that take access AWAY from a principal. A break-glass account must never lose it
    # through the queue. (tap-reset issues a credential and guest-invite creates an account -- neither
    # removes access, so neither is gated here.)
    @('entra-role-revoke','group-assignment-revoke','azure-rbac-revoke','session-revoke')
}

function Get-PimQueueActionBreakGlassRefusal {
    <#
      🔴 §33.28 (integration): the Manager checked break-glass only when the item was QUEUED. The engine
      executed whatever was committed -- so an account added to the break-glass list after the revoke was
      queued (the exact moment an operator reaches for that list: an incident) was still revoked, and a
      queue row written by anything other than the Manager's guarded path was never checked at all.
      This is the EXECUTION-time check, against the same SQL list the engine guards read.

      Returns $null when the action may proceed, otherwise the refusal result (the Invoke-PimQueueAction shape):
        break-glass target          -> ok=$false, terminal=$true   (retrying cannot make it safe)
        list UNREADABLE / no reader -> ok=$false, NOT terminal     (fail safe: nothing is executed; the next
                                                                    drain tries again once the list is readable)
        target's UPN unresolvable   -> ok=$false, NOT terminal     (an id-only payload against a UPN list
                                                                    cannot be proven safe)
      Nothing in the directory is changed on any refusal.
    #>
    param([Parameter(Mandatory)][object]$Payload, [string]$ConnectionString, [scriptblock]$Graph)
    $p = $Payload
    $type = "$($p.type)".Trim()
    if ($type -notin (Get-PimQueueActionBreakGlassTypes)) { return $null }
    $refuse = { param($terminal, $why) [pscustomobject]@{ ok=$false; terminal=[bool]$terminal; verification='none'; breakGlass=$true
        detail="$type REFUSED at execution -- nothing was changed: $why" } }

    if (-not (Get-Command Get-PimBreakGlassAccountStatus -ErrorAction SilentlyContinue)) {
        return (& $refuse $false 'the break-glass account library (PIM-BreakGlassAccounts.ps1) is not loaded in this engine, so the target cannot be proven NOT to be a break-glass account. It will be retried.')
    }
    $st = $null
    # -NoCache: an account added to the list a moment ago (mid-incident) must protect the very next drain.
    try { $st = Get-PimBreakGlassAccountStatus -ConnectionString "$ConnectionString" -NoCache } catch { $st = $null }
    if (-not $st) { return (& $refuse $false 'the break-glass account list could not be read. It will be retried.') }
    if ($st.storeConfigured -and -not $st.storeOk) {
        Write-Warning "  [queue] $type REFUSED: the break-glass account list is UNREADABLE ($($st.error)) -- nothing is revoked until it can be read."
        return (& $refuse $false "the break-glass account list is UNREADABLE ($($st.error)), so the target cannot be proven NOT to be a break-glass account. It will be retried.")
    }
    $ids = @(@($st.accounts) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    if ($ids.Count -eq 0) { return $null }

    # Every identifier the payload carries for its TARGET (never the queue entry's own id).
    $cand = New-Object System.Collections.Generic.List[string]
    foreach ($k in 'principalId','userId','principal','principalUpn','principalName','userPrincipalName','upn') {
        $pp = $p.PSObject.Properties[$k]
        if (-not $pp) { continue }
        $v = "$($pp.Value)".Trim()
        if (-not $v) { continue }
        $cand.Add($v.ToLowerInvariant())
        # principalName is stored as "Display Name (upn)" -- the UPN inside the brackets is the identifier.
        if ($v -match '\(([^()\s]+@[^()\s]+)\)\s*$') { $cand.Add($Matches[1].ToLowerInvariant()) }
    }
    foreach ($c in $cand) {
        if ($ids -contains $c) {
            Write-Warning "  [queue] $type REFUSED: '$c' is a BREAK-GLASS account."
            return (& $refuse $true "'$c' is a BREAK-GLASS account (pim.Settings BreakGlassAccounts). Break-glass accounts are never revoked by PIM -- remove it from the break-glass list first if this is really intended, then queue it again.")
        }
    }

    # The list names accounts by UPN, the payload by object id only (an entry queued before names were
    # stored, or one whose label is a display name): resolve the id's UPN before acting. A principal that
    # is not a user (a group -- 404) cannot be a break-glass ACCOUNT; any other failure cannot be proven safe.
    $guidRx = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    $listHasUpn = @($ids | Where-Object { $_ -notmatch $guidRx }).Count -gt 0
    $haveUpn    = @($cand | Where-Object { $_ -match '@' }).Count -gt 0
    $objId = "$($p.principalId)".Trim(); if (-not $objId) { $objId = "$($p.userId)".Trim() }
    if ($listHasUpn -and -not $haveUpn -and $objId) {
        if (-not $Graph) { return (& $refuse $false "the target '$objId' carries no UPN and there is no Graph client to resolve it against the break-glass list. It will be retried.") }
        $u = $null; $notUser = $false
        try { $u = & $Graph 'GET' ("/users/$objId`?`$select=id,userPrincipalName") $null }
        catch {
            if ("$($_.Exception.Message)" -match '(?i)Request_ResourceNotFound|ResourceNotFound|\b404\b|does not exist|not\s*found') { $notUser = $true }
            else { return (& $refuse $false "the target '$objId' could not be resolved to a UPN to check it against the break-glass list ($($_.Exception.Message)). It will be retried.") }
        }
        if (-not $notUser) {
            $upn = "$($u.userPrincipalName)".Trim().ToLowerInvariant()
            if (-not $upn) {
                if ($null -eq $u) { $notUser = $true }
                else { return (& $refuse $false "the target '$objId' resolved without a UPN, so it cannot be checked against the break-glass list. It will be retried.") }
            } elseif ($ids -contains $upn) {
                Write-Warning "  [queue] $type REFUSED: '$objId' is the BREAK-GLASS account '$upn'."
                return (& $refuse $true "'$upn' ($objId) is a BREAK-GLASS account (pim.Settings BreakGlassAccounts). Break-glass accounts are never revoked by PIM -- remove it from the break-glass list first if this is really intended, then queue it again.")
            }
        }
    }
    return $null
}

function Invoke-PimQueueAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Entry,
        [scriptblock]$GraphInvoker,
        [scriptblock]$ArmInvoker,
        [scriptblock]$MailInvoker,
        # The store the break-glass list is read from (the drain passes its own). Empty = the process's
        # configured store (Resolve-PimBreakGlassStore), which is what a bare call gets.
        [string]$ConnectionString = ''
    )
    $p = $Entry.payload
    $type = "$($p.type)".Trim()
    $meta = Get-PimQueueActionType -Type $type
    if (-not $meta) {
        # 🔴 An unknown action type is a CONFIGURATION error, and it must not look like an empty
        # result -- that is BUG-134 exactly (an unserved scope returned "nothing to do"). It is also
        # not retryable: waiting cannot teach the engine a type it does not implement.
        return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'
            detail="unknown action type '$type' -- no applier is registered for it" }
    }

    # REQ-Y (operator 2026-09-19: "revoke is pro", hard): a queued revoke of a current delegation needs a Pro licence at
    # EXECUTION too (the Manager refuses to queue one without it; this covers an entry queued before). Refused before any
    # directory call -- nothing changes -- and terminal: waiting does not produce a licence; re-queue once licensed.
    if ($type -in @('entra-role-revoke', 'azure-rbac-revoke', 'group-assignment-revoke') -and (Get-Command Test-PimFeatureProLicence -ErrorAction SilentlyContinue)) {
        $plRev = Test-PimFeatureProLicence -Key 'revoke.current'
        if ($plRev.required -and -not $plRev.ok) {
            return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; licence=$true
                detail="$type REFUSED -- nothing was changed: $($plRev.message)" }
        }
    }

    # 🪤 THE 4th PARAMETER IS `-All`, AND IT IS NOT COSMETIC (carried from BUG-66's gate). A paged
    # Graph read without -All can return a WRAPPER that counts as one item, which reads as "there
    # is exactly one TAP" on a user who has none. Every LIST read below passes $true.
    $graph = if ($GraphInvoker) { $GraphInvoker } else {
        {
            param($m,$path,$body,$all)
            if ($all)      { Invoke-PimGraph -All -Path $path }
            elseif ($body) { Invoke-PimGraph -Method $m -Path $path -Body $body }
            else           { Invoke-PimGraph -Method $m -Path $path }
        }
    }
    $arm   = if ($ArmInvoker)   { $ArmInvoker }   else { { param($m,$path,$body,$all) Invoke-PimArm -Method $m -Path $path -Body $body } }

    # 🔒 BREAK-GLASS, RE-CHECKED AT EXECUTION (the Manager's check at queue time is not enough -- see
    # Get-PimQueueActionBreakGlassRefusal). Before ANY directory call; a refusal changes nothing.
    $bgRefusal = $null
    try { $bgRefusal = Get-PimQueueActionBreakGlassRefusal -Payload $p -ConnectionString $ConnectionString -Graph $graph }
    catch { $bgRefusal = [pscustomobject]@{ ok=$false; terminal=$false; verification='none'; breakGlass=$true
                detail="$type REFUSED at execution -- nothing was changed: the break-glass check itself failed ($($_.Exception.Message)). It will be retried." } }
    if ($bgRefusal) { return $bgRefusal }

    # 68.6 row 27 (a): v1's revoker removed ELIGIBLE and ACTIVE assignments for Entra roles, Azure
    # resources and PIM for Groups (engine/PIM-Assignment-Revoker/PIM-Assignment-Revoker.ps1:623-781).
    # The queue only had the ACTIVE half. `assignmentType` on the payload selects the half; absent
    # means Active, so every entry queued before this change is applied exactly as before.
    $revokeType = "$($p.assignmentType)".Trim()
    if (-not $revokeType) { $revokeType = "$($p.memberType)".Trim() }
    $eligible = ($revokeType -ieq 'Eligible' -or $revokeType -ieq 'Eligibility')

    # §70.10: a queued revoke changes live assignments behind the engine's read caches (the group-membership cache
    # now lives 20 minutes in a tick). Drop the affected entries so a later scope in the SAME process reads the
    # tenant, not what was there before the revoke. Nothing in this function reads those caches.
    if (Get-Command Reset-PimAssignmentLiveCaches -ErrorAction SilentlyContinue) { Reset-PimAssignmentLiveCaches -GroupId "$($p.groupId)" }

    try {
        switch ($type) {

            { $eligible -and $_ -in @('entra-role-revoke','group-assignment-revoke','azure-rbac-revoke') } {
                $r = Invoke-PimQueueEligibleRevoke -Type $type -Payload $p -Justification "$($Entry.justification)" -Graph $graph -Arm $arm
                return $r
            }

            'entra-role-revoke' {
                # 🔴 REVOKE FIX (operator 2026-09-19, EFIF: "revoke is not working, remember to differ if delegated with pim or
                # permanent (legacy)"). This always POSTed a PIM adminRemove at the payload's scope (or '/'). That removes ONLY
                # a PIM-managed assignment at exactly that scope; a PERMANENT assignment made outside PIM (v1 / portal / the
                # legacy roleAssignments API) has no PIM schedule to remove, and Graph answers 404 RoleAssignmentDoesNotExist
                # -- the queue entry failed while the Exchange Administrator grant stayed. So READ what is live first:
                #   * held through a GROUP (memberType Inherited/Group)  -> refused: revoke the group membership instead;
                #   * an ACTIVATION of an eligible assignment            -> refused: revoke the eligibility (Eligible) instead;
                #   * PIM-managed, Assigned                              -> adminRemove at its REAL scope;
                #   * and when PIM says it does not exist (permanent / legacy) -> DELETE /roleAssignments/{id}.
                # The detail names the path taken, so the queue shows WHICH kind of assignment it was.
                $pid_ = "$($p.principalId)".Trim(); $rid = "$($p.roleDefinitionId)".Trim()
                $wantScope = "$($p.directoryScopeId)".Trim()
                $inst = @(@(& $graph 'GET' ("/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=principalId eq '$pid_' and roleDefinitionId eq '$rid'") $null $true) | Where-Object { $_ })
                if ($wantScope) { $inst = @($inst | Where-Object { "$($_.directoryScopeId)" -eq $wantScope }) }
                $viaGroup = @($inst | Where-Object { "$($_.memberType)" -in @('Inherited','Group') })
                if ($inst.Count -and $viaGroup.Count -eq $inst.Count) {
                    return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'
                        detail='NOT revoked -- nothing was changed: this principal holds the role THROUGH A GROUP (inherited). Revoke its membership of that group, or the group''s own role assignment.' }
                }
                $activated = @($inst | Where-Object { "$($_.assignmentType)" -eq 'Activated' -and "$($_.memberType)" -notin @('Inherited','Group') })
                if ($inst.Count -and $activated.Count -eq $inst.Count) {
                    return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'
                        detail='NOT revoked -- nothing was changed: this Active role is an ACTIVATION of an eligible PIM assignment. Revoke the eligibility (queue the Eligible half), and the activation ends with it.' }
                }
                $scope = if ($wantScope) { $wantScope } else { "$(@($inst | Where-Object { "$($_.assignmentType)" -ne 'Activated' })[0].directoryScopeId)".Trim() }
                if (-not $scope) { $scope = '/' }
                $path = 'pim'
                try {
                    $body = @{ action='adminRemove'; principalId=$pid_; roleDefinitionId=$rid; directoryScopeId=$scope
                               justification=$(if ("$($Entry.justification)".Trim()) { "$($Entry.justification)" } else { 'revoked via PIM queue' }) }
                    & $graph 'POST' '/roleManagement/directory/roleAssignmentScheduleRequests' $body | Out-Null
                } catch {
                    $em = "$($_.Exception.Message)"
                    if ($em -notmatch 'RoleAssignmentDoesNotExist|HTTP 404') { throw }
                    # PERMANENT (legacy) -- not a PIM schedule. Delete the assignment object itself, at the same scope only.
                    $path = 'legacy'
                    $legacy = @(@(& $graph 'GET' ("/roleManagement/directory/roleAssignments?`$filter=principalId eq '$pid_' and roleDefinitionId eq '$rid'") $null $true) | Where-Object { $_ -and (-not "$($_.directoryScopeId)" -or "$($_.directoryScopeId)" -eq $scope) })
                    if (-not $legacy.Count) {
                        return [pscustomobject]@{ ok=$true; verification='verified'; detail="assignment is gone (neither a PIM schedule nor a permanent assignment exists at scope $scope)" }
                    }
                    foreach ($la in $legacy) { & $graph 'DELETE' ("/roleManagement/directory/roleAssignments/$($la.id)") $null | Out-Null }
                }
                $still = @(@(& $graph 'GET' ("/roleManagement/directory/roleAssignments?`$filter=principalId eq '$pid_' and roleDefinitionId eq '$rid'") $null $true) | Where-Object { $_ -and (-not "$($_.directoryScopeId)" -or "$($_.directoryScopeId)" -eq $scope) })
                $how = if ($path -eq 'legacy') { 'PERMANENT (legacy, not PIM-managed) assignment deleted' } else { 'PIM-managed assignment removed (adminRemove)' }
                if ($null -eq $still) { return [pscustomobject]@{ ok=$true; verification='indeterminate'; detail="$how; the read-back could not be performed" } }
                if (@($still).Count -eq 0) { return [pscustomobject]@{ ok=$true; verification='verified'; detail="$how -- assignment is gone" } }
                return [pscustomobject]@{ ok=$false; verification='indeterminate'; detail="$how, but it is still present on read-back (directory may not have caught up)" }
            }

            'group-assignment-revoke' {
                $body = @{ action='adminRemove'; principalId="$($p.principalId)"; groupId="$($p.groupId)"
                           accessId=$(if ("$($p.accessId)".Trim()) { "$($p.accessId)" } else { 'member' })
                           justification=$(if ("$($Entry.justification)".Trim()) { "$($Entry.justification)" } else { 'revoked via PIM queue' }) }
                & $graph 'POST' '/identityGovernance/privilegedAccess/group/assignmentScheduleRequests' $body | Out-Null
                $still = @(& $graph 'GET' ("/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($p.groupId)' and principalId eq '$($p.principalId)'") $null $true)
                if ($null -eq $still) { return [pscustomobject]@{ ok=$true; verification='indeterminate'; detail='removal issued; the read-back could not be performed' } }
                if (@($still).Count -eq 0) { return [pscustomobject]@{ ok=$true; verification='verified'; detail='group assignment is gone' } }
                return [pscustomobject]@{ ok=$false; verification='indeterminate'; detail='group assignment still present on read-back' }
            }

            'azure-rbac-revoke' {
                $id = "$($p.roleAssignmentId)".Trim()
                if (-not $id) { return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; detail='azure-rbac-revoke has no roleAssignmentId' } }
                & $arm 'DELETE' ("$id`?api-version=2022-04-01") $null | Out-Null
                $still = & $arm 'GET' ("$id`?api-version=2022-04-01") $null
                # 🔑 A 404 on the read-back is the SUCCESS case here, and the invoker signals it by
                # returning $null. "Already gone" is success for a removal -- see the idempotence
                # note at the top: a retry must not turn a completed revoke into a failure.
                if ($null -eq $still) { return [pscustomobject]@{ ok=$true; verification='verified'; detail='role assignment is gone' } }
                return [pscustomobject]@{ ok=$false; verification='indeterminate'; detail='role assignment still present on read-back' }
            }

            'tap-reset' {
                $uid = "$($p.userId)".Trim()
                if (-not $uid) { return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; detail='tap-reset has no userId' } }
                # 🔴 REFUSE BEFORE DESTROYING (the AdminTap provider's BUG-66 guard, which this path
                # never had). The old pass is deleted two lines below; if the new one then cannot be
                # mailed, the account is locked out. So when the real mail path is in use, prove the
                # mail can be delivered FIRST -- a refusal here changes nothing in the directory.
                if (-not $MailInvoker -and (Get-Command Test-PimTapMailReady -ErrorAction SilentlyContinue)) {
                    $rcptPre = Resolve-PimQueuedTapRecipient -Payload $p
                    $ready = Test-PimTapMailReady -Recipient $rcptPre
                    if (-not $ready.ok) {
                        return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'
                            detail="TAP NOT reset -- nothing was changed, the existing pass is untouched: the new pass could not be mailed ($($ready.reason)). Fix mail delivery, then queue the reset again." }
                    }
                }
                # Entra allows exactly ONE TAP per user, so the existing one must go first (BUG-66).
                $existing = @(& $graph 'GET' "/users/$uid/authentication/temporaryAccessPassMethods" $null $true)
                foreach ($e in @($existing)) {
                    if ("$($e.id)".Trim()) { & $graph 'DELETE' "/users/$uid/authentication/temporaryAccessPassMethods/$($e.id)" $null | Out-Null }
                }
                $hrs = [int]"$(if ($p.lifetimeHours) { $p.lifetimeHours } else { 4 })"; if ($hrs -le 0) { $hrs = 4 }
                # s68.6 #21 (2026-09-12): the body follows the TENANT'S TAP POLICY (PIM-TapPolicy.ps1, Invoke-PimTapCreate) -- a one-time-only tenant answered 400 to isUsableOnce=false.
                $tap = if (Get-Command Invoke-PimTapCreate -ErrorAction SilentlyContinue) { Invoke-PimTapCreate -LifetimeMinutes ($hrs*60) -UserLabel "$($p.userPrincipalName)" -PolicyReader { & $graph 'GET' '/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass' $null } -Poster { param($b) & $graph 'POST' "/users/$uid/authentication/temporaryAccessPassMethods" $b } } else { & $graph 'POST' "/users/$uid/authentication/temporaryAccessPassMethods" @{ isUsableOnce=$false; lifetimeInMinutes=($hrs*60) } }
                if (-not "$($tap.temporaryAccessPass)".Trim()) {
                    return [pscustomobject]@{ ok=$false; verification='indeterminate'; detail='TAP create returned no pass' }
                }
                # 🔒 §65.3 -- THE CODE IS DELIVERED BY MAIL ONLY and never returned to a caller or
                # written to the queue row. A time-boxed credential must not sit in the store (or in
                # a log line) where the whole point is that only the recipient sees it.
                $mailed = $false
                if ($MailInvoker) {
                    try { $mailed = [bool](& $MailInvoker $p $tap) } catch { $mailed = $false }
                } else {
                    # No Get-Command gate: a gate on a name that did not exist is exactly how this
                    # silently failed every reset. Send-PimTapMail is defined in THIS file.
                    try { $mailed = [bool](Send-PimTapMail -Payload $p -Tap $tap) } catch { $mailed = $false }
                }
                if (-not $mailed) {
                    # 🔴 A TAP THAT WAS ISSUED BUT NOT DELIVERED IS WORSE THAN ONE NEVER ISSUED: the
                    # old TAP is already destroyed, so the account is locked out and nobody was told.
                    # Reported as a failure so it surfaces -- NOT retried blindly, because retrying
                    # would mint a second pass and destroy this one too.
                    return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'
                        detail='TAP was created but could NOT be mailed -- the previous pass is already gone, so this account needs manual attention' }
                }
                return [pscustomobject]@{ ok=$true; verification='verified'; detail="TAP replaced and mailed (valid ${hrs}h)" }
            }

            'session-revoke' {
                $uid = "$($p.userId)".Trim()
                if (-not $uid) { return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; detail='session-revoke has no userId' } }
                & $graph 'POST' "/users/$uid/revokeSignInSessions" @{} | Out-Null
                # Declared unverifiable in the catalog -- see the header note.
                return [pscustomobject]@{ ok=$true; verification='none'; detail='sign-in sessions revoked (Graph exposes no read-back to confirm this)' }
            }

            'guest-invite' {
                # 🔴 BUG-203 (§33.28) -- guest onboarding had no sender at all: the Manager returned the
                # invitation body and nothing POSTed it. The Manager now QUEUES it; this is the engine half.
                # IDEMPOTENT (§65.8): a retry -- or an operator re-queueing the same person -- must not send a
                # second invitation or turn "the guest already exists" into a failure. So the directory is
                # asked FIRST; an existing account with that mail address is success, and nothing is sent.
                # NEVER CLAIMS UNVERIFIED SUCCESS: success means Graph returned the invited user's object id
                # (and, when the directory has caught up, a read of that user).
                $email = "$($p.invitedUserEmailAddress)".Trim()
                $inv = $p.invitation
                if (-not $email -and $inv) { $email = "$($inv.invitedUserEmailAddress)".Trim() }
                if (-not $email) { return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; detail='guest-invite has no invitedUserEmailAddress' } }
                if (-not $inv) { return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; detail="guest-invite for '$email' carries no invitation body -- re-queue it from the Manager" } }
                if ("$($inv.invitedUserEmailAddress)".Trim() -and "$($inv.invitedUserEmailAddress)".Trim() -ine $email) {
                    return [pscustomobject]@{ ok=$false; terminal=$true; verification='none'; detail="guest-invite payload is inconsistent: '$email' vs invitation '$($inv.invitedUserEmailAddress)' -- nothing sent" }
                }
                $q = [uri]::EscapeDataString($email.Replace("'", "''"))
                $lookup = { @(& $graph 'GET' ("/users?`$filter=mail eq '$q'&`$select=id,userPrincipalName,userType,mail") $null $true) }
                $existing = $null
                try { $existing = & $lookup } catch { $existing = $null }
                $hit = @($existing | Where-Object { $_ -and "$($_.id)".Trim() }) | Select-Object -First 1
                if ($hit) {
                    return [pscustomobject]@{ ok=$true; verification='verified'
                        detail="'$email' already exists in the directory as $("$($hit.userType)".Trim()) $("$($hit.userPrincipalName)".Trim()) (id $($hit.id)) -- no second invitation was sent" }
                }
                $resp = & $graph 'POST' '/invitations' $inv
                $uid = ''
                if ($resp -and $resp.invitedUser) { $uid = "$($resp.invitedUser.id)".Trim() }
                if (-not $uid) {
                    # Retryable: the next attempt looks the user up first, so it cannot double-invite.
                    return [pscustomobject]@{ ok=$false; verification='indeterminate'; detail="the invitation for '$email' returned no invited user id -- not confirmed; retrying looks the user up first" }
                }
                $readBack = $null
                try { $readBack = & $graph 'GET' ("/users/$uid`?`$select=id,userType,mail,externalUserState") $null } catch { $readBack = $null }
                if ($readBack -and "$($readBack.id)".Trim() -eq $uid) {
                    return [pscustomobject]@{ ok=$true; verification='verified'; detail="guest invited: '$email' is user $uid ($("$($readBack.userType)".Trim()), $("$($readBack.externalUserState)".Trim()))" }
                }
                # Graph CREATED the user (it returned the object id) but a read-back is not visible yet (§64.7:
                # the directory is eventually consistent). The id itself is Graph's confirmation, so this is
                # verified by the invitation response -- and says the read-back is pending.
                return [pscustomobject]@{ ok=$true; verification='verified'; detail="guest invited: '$email' is user $uid (confirmed by the invitation response; directory read-back not visible yet)" }
            }
        }
    } catch {
        return [pscustomobject]@{ ok=$false; verification='none'; detail="$($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------------------
# Drain the committed ACTION entries. Mirrors Invoke-PimSqlCommit's contract exactly (§65.8):
# per-entry outcome, conditional claim, bounded retries, failures retained and surfaced.
# ---------------------------------------------------------------------------
function Invoke-PimQueueActionDrain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [int]$MaxAttempts = 3,
        [string]$AppliedBy = '',
        [scriptblock]$GraphInvoker,
        [scriptblock]$ArmInvoker,
        [scriptblock]$MailInvoker
    )
    $committed = @(Get-PimSqlQueue -ConnectionString $ConnectionString -Status 'committed' -Kind 'Action')
    if ($committed.Count -eq 0) {
        return [pscustomobject]@{ applied=0; failed=0; retrying=0; results=@() }
    }
    $who = if ("$AppliedBy".Trim()) { "$AppliedBy" } else { "$env:COMPUTERNAME" }
    $results = New-Object System.Collections.Generic.List[object]
    $applied = 0; $failedN = 0; $retrying = 0

    foreach ($e in @($committed | Sort-Object { "$($_.enqueuedUtc)" })) {
        $id = [guid]"$($e.id)"
        # 🔒 CLAIM BEFORE ACTING. A directory action is not rollback-able, so the claim cannot live
        # in the same transaction as the effect the way a pim.Rows write can. Claiming FIRST means a
        # crash mid-action leaves the entry 'applying' -- visible and attributable -- instead of
        # letting a second drain issue the same revoke concurrently.
        $claimed = Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
UPDATE pim.ChangeQueue
   SET Status='applying', Attempts=Attempts+1, LastAttemptUtc=SYSUTCDATETIME(), AppliedBy=@who
 WHERE Id=@id AND Status='committed';
"@ -Parameters @{ id=$id; who=$who }
        if ([int]$claimed -ne 1) {
            $results.Add([pscustomobject]@{ id="$($e.id)"; outcome='skipped'; detail='claimed by another drain' })
            continue
        }

        $r = Invoke-PimQueueAction -Entry $e -GraphInvoker $GraphInvoker -ArmInvoker $ArmInvoker -MailInvoker $MailInvoker -ConnectionString $ConnectionString
        $attempts = [int]$e.attempts + 1
        # 🔴 §70.15 LOG-03: the Manager audited only the REQUEST ("revoke.active-assignment" ok = QUEUED); the revoke,
        # TAP reset or session revoke the engine then EXECUTED left no audit event at all. One row per executed
        # action: who asked, what was done to whom, how it was verified, and the outcome.
        try {
            $pa = $e.payload
            $what = @('principalUpn','principalName','upn','userPrincipalName','groupName','roleName','roleDefinitionName','scope','directoryScopeId','assignmentType') |
                ForEach-Object { $v = if ($pa -and $pa.PSObject.Properties[$_]) { "$($pa.$_)".Trim() } else { '' }; if ($v) { "$_=$v" } }
            if (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue) {
                Write-PimSqlAuditEvent -ConnectionString $ConnectionString -Actor 'engine' -ActorSource 'engine' `
                    -Action ("queue.action.$("$($pa.type)".Trim()).$(if ($r.ok) { 'applied' } else { 'failed' })") `
                    -Target ("$("$($pa.type)".Trim()): " + (@($what) -join ', ')) `
                    -After ([ordered]@{ queueId = "$($e.id)"; requestedBy = "$($e.requestedBy)$($e.enqueuedBy)"; justification = "$($e.justification)"
                                        payload = $pa; verification = "$($r.verification)"; detail = "$($r.detail)"; attempt = $attempts }) `
                    -Result $(if ($r.ok) { 'ok' } else { 'error' }) -CorrelationId "$($global:PIM_JobCorrelationId)"
            }
        } catch { Write-Warning "  [audit] queued action $($e.id) was NOT recorded: $($_.Exception.Message)" }

        if ($r.ok) {
            [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
UPDATE pim.ChangeQueue
   SET Status='applied', AppliedUtc=SYSUTCDATETIME(), LastError=@v
 WHERE Id=@id AND Status='applying';
"@ -Parameters @{ id=$id; v="verification=$($r.verification): $($r.detail)" })
            $applied++
            # `type` lets the scheduler react to WHAT was applied (§70.1b: an applied revoke queues an active-assignments refresh).
            $results.Add([pscustomobject]@{ id="$($e.id)"; type="$($e.payload.type)"; outcome='applied'; verification="$($r.verification)"; detail="$($r.detail)" })
        } else {
            # `terminal` = retrying cannot help (unknown type, missing field, a TAP that was minted
            # but not delivered). Those go straight to 'failed' rather than burning attempts and
            # delaying the moment a human sees them.
            $next = if ($r.terminal -or $attempts -ge $MaxAttempts) { 'failed' } else { 'committed' }
            [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql @"
UPDATE pim.ChangeQueue SET Status=@st, LastError=@e WHERE Id=@id AND Status='applying';
"@ -Parameters @{ st=$next; e="$($r.detail)"; id=$id })
            if ($next -eq 'failed') { $failedN++ } else { $retrying++ }
            $results.Add([pscustomobject]@{ id="$($e.id)"; type="$($e.payload.type)"; outcome=$next; verification="$($r.verification)"; detail="$($r.detail)" })
        }
    }
    return [pscustomobject]@{ applied=$applied; failed=$failedN; retrying=$retrying; results=@($results.ToArray()) }
}
