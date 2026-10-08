#Requires -Version 5.1
<#
.SYNOPSIS
  PURE decision cores for the mail send right (REQUIREMENTS 65.11). No network, no state.

.DESCRIPTION
  Operator decision 2026-09-13: the HOSTED engine sends as its MANAGED IDENTITY. The scoped
  Exchange 'Application Mail.Send' assignment (Exchange RBAC for Applications, pinned to the
  sender mailbox by a management scope) must therefore name the identity that actually sends --
  the tick job's managed identity, plus the Manager's when it sends alerts -- not only the
  engine SPN. Until now the assignment named the SPN while the container sent as its managed
  identity: two different principals.

  Shared by tools/setup/Initialize-PimMailSender.ps1 (which EXECUTES the plan),
  tools/setup/Invoke-PimDeployAll.ps1 (which resolves the tick job's identity) and
  tools/setup/Test-PimTenantReady.ps1 (which checks no sending identity holds a tenant-wide
  Graph Mail.Send). Dot-sourceable: defines functions only.
#>


function Get-PimJobManagedIdentityPrincipalId {
    <#
      Which managed identity a Container Apps job's engine really authenticates as.
      The engine's token call uses PIM_ManagedIdentityClientId when the job carries it
      (user-assigned) and the system-assigned identity otherwise (PIM-Rest.ps1
      Get-PimManagedIdentityToken). Picking by the same rule is the only way the send right lands
      on the identity that sends.
      Input: the job resource (ARM GET / `az containerapp job show -o json`). Returns
      { principalId; kind = system|user; reason }; reason non-empty = could not decide.
    #>
    [CmdletBinding()] param([object]$Job, [string]$ManagedIdentityClientId = '')
    if ($null -eq $Job) { return [pscustomobject]@{ principalId = ''; kind = ''; reason = 'no job resource was supplied' } }
    $cid = "$ManagedIdentityClientId".Trim()
    if (-not $cid) {
        foreach ($c in @($Job.properties.template.containers)) {
            foreach ($e in @($c.env)) { if ("$($e.name)" -eq 'PIM_ManagedIdentityClientId' -and "$($e.value)".Trim()) { $cid = "$($e.value)".Trim() } }
        }
    }
    $ids = $Job.identity
    $ua = @()
    if ($ids -and $ids.userAssignedIdentities) {
        foreach ($p in $ids.userAssignedIdentities.PSObject.Properties) {
            $ua += [pscustomobject]@{ resourceId = $p.Name; clientId = "$($p.Value.clientId)"; principalId = "$($p.Value.principalId)" }
        }
    }
    if ($cid) {
        $hit = @($ua | Where-Object { $_.clientId -eq $cid })
        if ($hit.Count -eq 1 -and $hit[0].principalId) { return [pscustomobject]@{ principalId = $hit[0].principalId; kind = 'user'; reason = '' } }
        return [pscustomobject]@{ principalId = ''; kind = ''; reason = "the job sets PIM_ManagedIdentityClientId=$cid but carries no user-assigned identity with that client id" }
    }
    if ($ids -and "$($ids.principalId)".Trim()) { return [pscustomobject]@{ principalId = "$($ids.principalId)".Trim(); kind = 'system'; reason = '' } }
    if ($ua.Count -eq 1 -and $ua[0].principalId) {
        # With a user-assigned identity ONLY and no client id, IDENTITY_ENDPOINT issues no token
        # (BUG-76), so the engine cannot send at all -- named, not papered over.
        return [pscustomobject]@{ principalId = ''; kind = ''; reason = "the job has only a user-assigned identity ($($ua[0].clientId)) and no PIM_ManagedIdentityClientId -- the engine gets no managed-identity token (BUG-76); set PIM_ManagedIdentityClientId on the job first" }
    }
    return [pscustomobject]@{ principalId = ''; kind = ''; reason = 'the job has no managed identity' }
}

function Resolve-PimMailSendPrincipals {
    <#
      The identities that RECEIVE the scoped send right, from already-fetched Graph service
      principals. Managed identities first (the hosted senders); the engine SPN only when no
      managed identity was named (a non-hosted topology sends as the SPN).
      A managed-identity object id that resolves to something that is NOT a managed identity is
      REFUSED: the parameter must never become a way to hand a send right to an arbitrary app.
      Returns { principals = @({ kind; appId; objectId; displayName; assignmentName }); reason }.
    #>
    [CmdletBinding()] param([object[]]$ManagedIdentitySps = @(), [object]$EngineSp)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($sp in @($ManagedIdentitySps | Where-Object { $null -ne $_ })) {
        $type = "$($sp.servicePrincipalType)".Trim()
        if ($type -and $type -ne 'ManagedIdentity') {
            return [pscustomobject]@{ principals = @(); reason = "object $($sp.id) is a '$type' service principal, not a managed identity -- refusing to grant it the send right" }
        }
        if (-not "$($sp.appId)".Trim() -or -not "$($sp.id)".Trim()) {
            return [pscustomobject]@{ principals = @(); reason = 'a managed identity service principal without appId/id cannot be registered in Exchange' }
        }
        $oid = "$($sp.id)".Trim()
        $short = $oid.Substring(0, [Math]::Min(8, $oid.Length))
        $out.Add([pscustomobject]@{ kind = 'managed-identity'; appId = "$($sp.appId)".Trim(); objectId = $oid
                                    displayName = ("PIM4EntraPS Engine MI {0}" -f $short)
                                    assignmentName = ("PIM4EntraPS-MI-{0}-MailSend" -f $short) })
    }
    if ($out.Count -eq 0 -and $null -ne $EngineSp -and "$($EngineSp.appId)".Trim()) {
        $out.Add([pscustomobject]@{ kind = 'engine-spn'; appId = "$($EngineSp.appId)".Trim(); objectId = "$($EngineSp.id)".Trim()
                                    displayName = 'PIM4EntraPS Engine'; assignmentName = 'PIM4EntraPS-Engine-MailSend' })
    }
    if ($out.Count -eq 0) {
        return [pscustomobject]@{ principals = @(); reason = 'no sending identity: pass -ManagedIdentityObjectId (hosted: the tick job''s managed identity), -SubscriptionId/-ResourceGroup/-TickJobName to resolve it, or -EngineAppId for a non-hosted engine' }
    }
    return [pscustomobject]@{ principals = $out.ToArray(); reason = '' }
}

function Get-PimExoAssigneeIds {
    # Every string Exchange may use to name one service principal in a role assignment.
    [CmdletBinding()] param([object[]]$ExoServicePrincipals = @(), [string]$AppId, [string]$ObjectId)
    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($AppId, $ObjectId)) { if ("$v".Trim()) { $ids.Add("$v".Trim().ToLowerInvariant()) } }
    foreach ($s in @($ExoServicePrincipals | Where-Object { $null -ne $_ })) {
        if ("$($s.AppId)".Trim().ToLowerInvariant() -ne "$AppId".Trim().ToLowerInvariant()) { continue }
        foreach ($v in @($s.Identity, $s.Name, $s.ObjectId, $s.AppId, $s.DisplayName)) { if ("$v".Trim()) { $ids.Add("$v".Trim().ToLowerInvariant()) } }
    }
    return @($ids | Sort-Object -Unique)
}

function Select-PimExoMailSendAssignment {
    <#
      The scoped send assignments that belong to ONE identity.
      The old idempotency check matched role + scope ONLY, so once the engine SPN held the
      assignment, a managed identity's would have been reported "already present" and never
      created -- the send would then be refused with nothing in the setup log to say why.
      Matched by assignee; the assignment Name is used only when the record names no assignee.
    #>
    [CmdletBinding()] param([object[]]$Assignments = @(), [string]$ScopeName = 'PIM4EntraPS-Sender',
                            [string[]]$AssigneeIds = @(), [string]$AssignmentName = '')
    $want = @($AssigneeIds | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    return @(@($Assignments) | Where-Object {
        $null -ne $_ -and "$($_.Role)" -eq 'Application Mail.Send' -and "$($_.CustomResourceScope)" -eq $ScopeName -and (
            ($want -contains "$($_.RoleAssignee)".Trim().ToLowerInvariant()) -or
            ($want -contains "$($_.RoleAssigneeName)".Trim().ToLowerInvariant()) -or
            (-not "$($_.RoleAssignee)$($_.RoleAssigneeName)".Trim() -and "$AssignmentName".Trim() -and "$($_.Name)" -eq $AssignmentName))
    })
}

function Get-PimMailSenderScopeName {
    <#
      PURE. The Exchange management scope a sender's send right lives in. The DEFAULT mailbox (PIM-Engine@) keeps the
      historic 'PIM4EntraPS-Sender', so every existing tenant is unchanged. Any other mailbox -- a second environment in the
      same tenant (§94: PIM-Engine-r1-pro@) -- gets its own 'PIM4EntraPS-Sender-<mailbox>', because a scope is a tenant
      singleton and sharing one meant sending as the other environment's mailbox.
    #>
    param([Parameter(Mandatory)][string]$Sender)
    $local = ("$Sender" -split '@')[0].Trim()
    if (-not $local -or $local -ieq 'PIM-Engine') { return 'PIM4EntraPS-Sender' }
    return ('PIM4EntraPS-Sender-' + ($local -replace '[^A-Za-z0-9-]', '-'))
}

function New-PimMailSenderExoPlan {
    <#
      WHAT to create in Exchange, given what already exists. Returns an ordered list of
      { cmdlet; parameters; what } -- registrations, then the scope, then assignments, then (only
      when explicitly asked) removal of the engine SPN's older assignment. An empty list means
      everything is in place: running the plan twice writes nothing.
    #>
    [CmdletBinding()]
    param([object[]]$ExoServicePrincipals = @(), [object[]]$Scopes = @(), [object[]]$Assignments = @(),
          [object[]]$Principals = @(), [string]$Sender, [string]$ScopeName = 'PIM4EntraPS-Sender',
          [string]$EngineAppId = '', [string]$EngineObjectId = '', [switch]$RemoveEngineSpnAssignment)
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($Principals)) {
        $known = @(@($ExoServicePrincipals) | Where-Object { $null -ne $_ -and "$($_.AppId)".Trim().ToLowerInvariant() -eq "$($p.appId)".ToLowerInvariant() })
        if (-not $known.Count) {
            $plan.Add([pscustomobject]@{ cmdlet = 'New-ServicePrincipal'; what = "register $($p.kind) $($p.appId) in Exchange"
                                         parameters = @{ AppId = $p.appId; ObjectId = $p.objectId; DisplayName = $p.displayName } })
        }
    }
    $existingScope = @(@($Scopes) | Where-Object { $null -ne $_ -and "$($_.Name)" -eq $ScopeName })[0]
    if (-not $existingScope) {
        $plan.Add([pscustomobject]@{ cmdlet = 'New-ManagementScope'; what = "scope $ScopeName -> $Sender only"
                                     parameters = @{ Name = $ScopeName; RecipientRestrictionFilter = "PrimarySmtpAddress -eq '$Sender'" } })
    } else {
        # §94 (live, internal 2026-10-03): a second environment in the tenant found the FIRST one's scope by name and
        # attached its identities to it -- so it could send only as the OTHER environment's mailbox. A scope that does not
        # name THIS sender is never reused (and never rewritten: that would cut the other environment off).
        $flt = "$($existingScope.RecipientRestrictionFilter)"
        if ($flt.Trim() -and $flt.IndexOf("'$Sender'", [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw ("the Exchange scope '$ScopeName' already exists for ANOTHER mailbox ($flt), not $Sender -- refusing to attach this " +
                   "sender's identities to it. Give this environment its own scope (Initialize-PimMailSender derives '$ScopeName-<mailbox>' " +
                   "for any mailbox other than the default).")
        }
    }
    foreach ($p in @($Principals)) {
        $ids = Get-PimExoAssigneeIds -ExoServicePrincipals $ExoServicePrincipals -AppId $p.appId -ObjectId $p.objectId
        # §94: the same identity's send right on ANOTHER of our sender scopes is the wrong-mailbox grant above -- remove it
        # first (assignment names are tenant-unique, so the right one could not be created beside it).
        foreach ($wrong in @(@($Assignments) | Where-Object { $null -ne $_ -and "$($_.Role)" -eq 'Application Mail.Send' -and
                    "$($_.CustomResourceScope)" -like 'PIM4EntraPS-Sender*' -and "$($_.CustomResourceScope)" -ne $ScopeName } |
                    Where-Object { @(Select-PimExoMailSendAssignment -Assignments @($_) -ScopeName "$($_.CustomResourceScope)" -AssigneeIds $ids -AssignmentName $p.assignmentName).Count })) {
            $idn = if ("$($wrong.Identity)".Trim()) { "$($wrong.Identity)".Trim() } else { "$($wrong.Name)".Trim() }
            $plan.Add([pscustomobject]@{ cmdlet = 'Remove-ManagementRoleAssignment'; what = "remove $($p.kind) $($p.appId)'s send right on the OTHER scope $($wrong.CustomResourceScope) ($idn)"
                                         parameters = @{ Identity = $idn; Confirm = $false } })
        }
        if (-not @(Select-PimExoMailSendAssignment -Assignments $Assignments -ScopeName $ScopeName -AssigneeIds $ids -AssignmentName $p.assignmentName).Count) {
            $plan.Add([pscustomobject]@{ cmdlet = 'New-ManagementRoleAssignment'; what = "scoped send right for $($p.kind) $($p.appId)"
                                         parameters = @{ App = $p.appId; Role = 'Application Mail.Send'; CustomResourceScope = $ScopeName; Name = $p.assignmentName } })
        }
    }
    # Removal of the SPN's assignment is OPT-IN, and never when the SPN is itself a sender.
    if ($RemoveEngineSpnAssignment -and "$EngineAppId".Trim() -and -not @(@($Principals) | Where-Object { "$($_.appId)" -eq "$EngineAppId".Trim() }).Count) {
        $eIds = Get-PimExoAssigneeIds -ExoServicePrincipals $ExoServicePrincipals -AppId $EngineAppId -ObjectId $EngineObjectId
        foreach ($a in @(Select-PimExoMailSendAssignment -Assignments $Assignments -ScopeName $ScopeName -AssigneeIds $eIds)) {
            $idn = if ("$($a.Identity)".Trim()) { "$($a.Identity)".Trim() } else { "$($a.Name)".Trim() }
            $plan.Add([pscustomobject]@{ cmdlet = 'Remove-ManagementRoleAssignment'; what = "remove the engine SPN's send right $idn (explicitly requested)"
                                         parameters = @{ Identity = $idn; Confirm = $false } })
        }
    }
    return $plan.ToArray()
}

# =============================================================================================
# 2026-09-18 (REQUIREMENTS §33.25 BUG-166 / BUG-167, §33.23 IMP-31). The same script failed partway on
# BOTH EFIF and RIDE, three times, from ONE pattern: a transient failure on a READ silently became a
# wrong PLAN. The decisions below separate "absent" from "could not read" and "already there" from
# "failed", so the script can be idempotent by construction and the rules are provable offline.
# =============================================================================================

function ConvertTo-PimObjectIdList {
    <#
      BUG-167 -- `-ManagedIdentityObjectId` under `pwsh -File`. An array written as 'a','b' arrives as
      ONE literal string ("'a','b'"), and the script then reported "managed identity service principal
      ''a','b'' not found: 400" -- which reads as a directory problem and is a parameter-marshalling
      one. Accept an array, a comma/semicolon-separated string, or any mix; strip whitespace and quotes;
      require every value to be a GUID; de-duplicate (case-insensitive, first spelling kept).
      Returns { ids; reason } -- reason non-empty = refuse, naming the marshalling cause.
    #>
    [CmdletBinding()] param([AllowNull()][AllowEmptyCollection()][string[]]$Value)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($Value)) {
        foreach ($part in ("$v" -split '[,;]')) {
            $t = $part.Trim().Trim("'", '"', ' ', '@', '(', ')').Trim()
            if (-not $t) { continue }
            if ($t -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                return [pscustomobject]@{ ids = @(); reason = ("'{0}' is not an object id (GUID). Under 'pwsh -File' an array argument arrives as ONE literal string -- pass the ids comma-separated with no quotes or spaces: -ManagedIdentityObjectId <id1>,<id2>" -f $t) }
            }
            if (-not @($out | Where-Object { $_ -ieq $t }).Count) { $out.Add($t) }
        }
    }
    return [pscustomobject]@{ ids = $out.ToArray(); reason = '' }
}

function Test-PimAlreadyExistsError {
    <#
      "It is already there" -- which, for an idempotent step, is SUCCESS. Graph answers a duplicate
      app-role assignment with 400 "Permission being assigned already exists on the object"; Exchange
      answers a duplicate create with ADObjectAlreadyExistsException / "already exists".
      PURE: the caller passes the error text (message + ErrorDetails).
    #>
    [CmdletBinding()] param([AllowEmptyString()][AllowNull()][string]$Text)
    return ("$Text" -match '(?i)ADObjectAlreadyExistsException|already exists|Permission being assigned already exists|is already assigned|already been assigned')
}

function Test-PimExoNotFoundError {
    <# Exchange's "no such object" -- the ONLY error a single-object lookup may read as "absent". #>
    [CmdletBinding()] param([AllowEmptyString()][AllowNull()][string]$Text)
    return ("$Text" -match "(?i)ManagementObjectNotFoundException|couldn't be found|could not be found|was not found|\bnot found\b|\b404\b")
}

function Test-PimTransientReadError {
    <#
      A read that failed for a reason that passes: role propagation (401/403 while the Exchange
      Administrator grant is still arriving -- measured on EFIF/RIDE, this is exactly how
      Get-ManagementScope "failed"), throttling, a server hiccup. Worth a bounded retry; never worth
      treating as "absent".
    #>
    [CmdletBinding()] param([AllowEmptyString()][AllowNull()][string]$Text)
    return ("$Text" -match '(?i)\b(401|403|408|429|500|502|503|504)\b|Unauthorized|Forbidden|Too ?Many ?Requests|timed? ?out|temporarily|ServiceUnavailable|Bad Gateway')
}

function Resolve-PimExoLookupOutcome {
    <#
      A SINGLE-OBJECT lookup (Get-Mailbox -Identity X) failed. Returns 'absent' only for a genuine
      not-found; anything else is 'unreadable' and the caller must REFUSE rather than plan a create.
      The old code read EVERY failure as "not there", so a 401 during propagation planned a create
      that then 400'd ADObjectAlreadyExistsException.
    #>
    [CmdletBinding()] param([AllowEmptyString()][AllowNull()][string]$ErrorText)
    if (Test-PimExoNotFoundError -Text $ErrorText) { return 'absent' }
    return 'unreadable'
}

function Resolve-PimExoCreateOutcome {
    <#
      An Exchange CREATE failed. What does that mean for an idempotent run?
        'exists'     -- it is already there: success
        'dehydrated' -- the org is not customisable yet: wait (Invoke-ExoWhenHydrated's existing loop)
        'retry'      -- New-ManagementRoleAssignment right after New-ServicePrincipal: Exchange has not
                        MATERIALISED the service principal yet and answers 404 / not found (measured on
                        EFIF and RIDE). Bounded retry.
        'fail'       -- a real failure, reported at once
    #>
    [CmdletBinding()] param([string]$Cmdlet, [AllowEmptyString()][AllowNull()][string]$ErrorText)
    if (Test-PimAlreadyExistsError -Text $ErrorText) { return 'exists' }
    if ("$ErrorText" -like '*InvalidOperationInDehydratedContextException*') { return 'dehydrated' }
    if ("$Cmdlet" -eq 'New-ManagementRoleAssignment' -and (Test-PimExoNotFoundError -Text $ErrorText)) { return 'retry' }
    return 'fail'
}

function Test-PimAssignmentDuration {
    <#
      IMP-31 -- the Exchange Administrator grant is TIME-BOUND. Accept an ISO 8601 duration of
      minutes/hours between 15 minutes and 24 hours (PT15M .. PT24H). A day-plus grant is exactly
      the standing privilege this change removes, so it is refused, not clamped.
      Returns { ok; minutes; reason }.
    #>
    [CmdletBinding()] param([AllowEmptyString()][AllowNull()][string]$Duration)
    $d = "$Duration".Trim().ToUpperInvariant()
    $m = [regex]::Match($d, '^PT(?:(\d+)H)?(?:(\d+)M)?$')
    if (-not $m.Success -or -not ($m.Groups[1].Success -or $m.Groups[2].Success)) {
        return [pscustomobject]@{ ok = $false; minutes = 0; reason = "'$Duration' is not an ISO 8601 duration in hours/minutes (e.g. PT4H, PT90M)" }
    }
    $mins = 0
    if ($m.Groups[1].Success) { $mins += 60 * [int]$m.Groups[1].Value }
    if ($m.Groups[2].Success) { $mins += [int]$m.Groups[2].Value }
    if ($mins -lt 15 -or $mins -gt 1440) {
        return [pscustomobject]@{ ok = $false; minutes = $mins; reason = "'$Duration' is outside PT15M..PT24H -- the Exchange Administrator grant is deliberately short-lived" }
    }
    return [pscustomobject]@{ ok = $true; minutes = $mins; reason = '' }
}

function New-PimRoleScheduleRequestBody {
    <#
      IMP-31 -- the body for POST roleManagement/directory/roleAssignmentScheduleRequests: an ACTIVE,
      TIME-BOUND assignment made THROUGH PIM (action adminAssign, expiration afterDuration).
      Why: the script used to POST roleManagement/directory/roleAssignments -- a PERMANENT active
      assignment outside PIM -- and measured live 2026-09-18 the SPN that received it CANNOT remove it
      again (Graph 400 "Removing self from ... built-in role is not allowed"). The tenants' own
      alerting flagged it as "assigned outside of PIM". A schedule that expires needs no removal.
      PURE: -Now is injectable.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PrincipalId, [Parameter(Mandatory)][string]$RoleDefinitionId,
          [string]$Duration = 'PT4H', [string]$Justification = 'PIM4EntraPS mail-sender setup (Initialize-PimMailSender.ps1): transient Exchange administration',
          [datetime]$Now = [datetime]::UtcNow)
    return [ordered]@{
        action           = 'adminAssign'
        principalId      = $PrincipalId
        roleDefinitionId = $RoleDefinitionId
        directoryScopeId = '/'
        justification    = $Justification
        scheduleInfo     = [ordered]@{
            startDateTime = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            expiration    = [ordered]@{ type = 'afterDuration'; duration = "$Duration".Trim().ToUpperInvariant() }
        }
    }
}

function Select-PimActiveRoleGrant {
    <#
      IMP-31 -- is the principal ALREADY active in the role, and how? Input: roleAssignmentScheduleInstances
      (and/or plain roleAssignments) already fetched. Returns { active; kind = permanent|time-bound|'';
      endDateTime; id }. A permanent one is REUSED (and reported loudly as standing privilege); a
      time-bound one still valid at -Now is reused; an expired one is ignored.
    #>
    [CmdletBinding()]
    param([object[]]$Instances = @(), [string]$PrincipalId, [string]$RoleDefinitionId, [datetime]$Now = [datetime]::UtcNow)
    $best = $null
    foreach ($i in @($Instances | Where-Object { $null -ne $_ })) {
        if ("$($i.principalId)" -ne "$PrincipalId" -or "$($i.roleDefinitionId)" -ne "$RoleDefinitionId") { continue }
        if ($i.PSObject.Properties['directoryScopeId'] -and "$($i.directoryScopeId)".Trim() -and "$($i.directoryScopeId)" -ne '/') { continue }
        $end = $null
        if ($i.PSObject.Properties['endDateTime'] -and "$($i.endDateTime)".Trim()) {
            try { $end = ([datetime]::Parse("$($i.endDateTime)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)) } catch { $end = $null }
            if ($null -eq $end) { continue }
            if ($end -le $Now.ToUniversalTime()) { continue }
        }
        $cand = [pscustomobject]@{ active = $true; kind = $(if ($null -eq $end) { 'permanent' } else { 'time-bound' }); endDateTime = $end; id = "$($i.id)" }
        # prefer a permanent record (it is the one that must be reported), else the latest-ending
        if ($null -eq $best -or $cand.kind -eq 'permanent' -or ($best.kind -ne 'permanent' -and $cand.endDateTime -gt $best.endDateTime)) { $best = $cand }
    }
    if ($best) { return $best }
    return [pscustomobject]@{ active = $false; kind = ''; endDateTime = $null; id = '' }
}

function Test-PimGrantOverlong {
    <#
      BUG-248 (§73.9, a customer build 2026-09-23) -- a reused time-bound grant that ends LATER than -Duration from now is
      standing privilege in all but name. A manual portal assignment defaulted to ONE YEAR and the script
      reused it as "time-bound". Returns { overlong; limitUtc; reason }. A permanent or inactive grant is not
      judged here (permanent is already reported on its own). 5 minutes of slack for clock skew.
    #>
    [CmdletBinding()]
    param([object]$Grant, [Parameter(Mandatory)][string]$Duration, [datetime]$Now = [datetime]::UtcNow)
    $out = [pscustomobject]@{ overlong = $false; limitUtc = $null; reason = '' }
    if (-not $Grant -or -not $Grant.active -or "$($Grant.kind)" -ne 'time-bound' -or $null -eq $Grant.endDateTime) { return $out }
    try { $span = [System.Xml.XmlConvert]::ToTimeSpan($Duration) } catch { $out.reason = "duration '$Duration' unreadable"; return $out }
    $out.limitUtc = $Now.ToUniversalTime().Add($span).AddMinutes(5)
    if (([datetime]$Grant.endDateTime).ToUniversalTime() -gt $out.limitUtc) {
        $out.overlong = $true
        $out.reason = "ends $(([datetime]$Grant.endDateTime).ToUniversalTime().ToString('u')), later than the requested $Duration allows ($($out.limitUtc.ToString('u')))"
    }
    return $out
}

function Select-PimTenantWideMailSend {
    # appRoleAssignments on one service principal that are the TENANT-WIDE Graph Mail.Send.
    [CmdletBinding()] param([object[]]$Assignments = @(), [string]$GraphSpId, [string]$MailSendRoleId)
    return @(@($Assignments) | Where-Object { $null -ne $_ -and "$($_.resourceId)" -eq "$GraphSpId" -and "$($_.appRoleId)" -eq "$MailSendRoleId" })
}

function Get-PimTenantWideMailSendVerdict {
    <#
      Readiness verdict over EVERY identity that can send (engine SPN, tick job managed identity,
      the host's own managed identity). Targets: @({ label; spId; assignments }). No target =
      NOT EVALUATED (ok=$false with the reason) -- "did not look" is never "fine".
    #>
    [CmdletBinding()] param([object[]]$Targets = @(), [string]$GraphSpId, [string]$MailSendRoleId)
    $t = @($Targets | Where-Object { $null -ne $_ -and "$($_.spId)".Trim() })
    if (-not $t.Count) { return [pscustomobject]@{ ok = $false; held = @(); detail = 'engine identity unknown -- neither an engine client id nor a managed identity could be resolved, so cannot tell whether a tenant-wide send right is held (this is "did not look", not "it is fine")' } }
    if (-not "$MailSendRoleId".Trim()) { return [pscustomobject]@{ ok = $false; held = @(); detail = 'could not resolve the Graph Mail.Send app role -- unable to evaluate' } }
    $held = @($t | Where-Object { @(Select-PimTenantWideMailSend -Assignments @($_.assignments) -GraphSpId $GraphSpId -MailSendRoleId $MailSendRoleId).Count } | ForEach-Object { "$($_.label)" })
    if ($held.Count) {
        return [pscustomobject]@{ ok = $false; held = $held; detail = ("TENANT-WIDE Graph Mail.Send held by: {0} -- the per-mailbox Exchange RBAC scope is defeated by it (measured: with this consent an out-of-scope send is ACCEPTED). Revoke it; the scoped grant is what should carry sending." -f ($held -join '; ')) }
    }
    return [pscustomobject]@{ ok = $true; held = @(); detail = ("no tenant-wide Graph Mail.Send on {0} (sending is carried by the per-mailbox Exchange RBAC scope)" -f ((@($t | ForEach-Object { "$($_.label)" })) -join '; ')) }
}

function New-PimMailSenderCommand {
    <#
      MAIL-1 (framework 12.3 (b)-(d), owner 2026-10-08): the command that sets up the shared mailbox AFTERWARDS -- the
      published download plus a browser sign-in call (no certificate, no secret), with every value of this environment
      that is known filled in and a <placeholder> for the rest. PURE. Returns the lines (download, run).
    #>
    [CmdletBinding()] param([string]$TenantId, [string[]]$ManagedIdentityObjectId = @(), [string]$SubscriptionId, [string]$ResourceGroup,
                            [string]$TickJobName, [string]$ManagerAppName, [string]$SqlServerFqdn)
    $v = { param($x, $ph) if ("$x".Trim()) { "$x".Trim() } else { $ph } }
    $run = '.\Initialize-PimMailSender.ps1 -TenantId ' + (& $v $TenantId '<tenant id>')
    $mi = @(@($ManagedIdentityObjectId) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if ($mi.Count) { $run += ' -ManagedIdentityObjectId ' + ($mi -join ',') }
    if ("$SubscriptionId".Trim() -and "$ResourceGroup".Trim() -and ("$TickJobName".Trim() -or "$ManagerAppName".Trim())) {
        $run += " -SubscriptionId $("$SubscriptionId".Trim()) -ResourceGroup $("$ResourceGroup".Trim())"
        if ("$TickJobName".Trim()) { $run += " -TickJobName $("$TickJobName".Trim())" }
        if ("$ManagerAppName".Trim()) { $run += " -ManagerAppName $("$ManagerAppName".Trim())" }
    } elseif (-not $mi.Count) { $run += ' -ManagedIdentityObjectId <manager identity object id>,<engine job identity object id>' }
    $run += ' -SqlServerFqdn ' + (& $v $SqlServerFqdn '<server>.database.windows.net')
    return @('Invoke-WebRequest https://invardia.com/support/pim/Initialize-PimMailSender.ps1 -OutFile Initialize-PimMailSender.ps1', $run)
}

function Resolve-PimDeployMailSignedIn {
    <#
      MAIL-1 (framework 12.3 (a)): in a SIGNED-IN deploy, may the mail-sender step run? PURE over `az account show`.
        * the signed-in principal is an APPLICATION (user.type servicePrincipal -- the Invardia Support app) in the
          deploy's tenant -> run = $true, appId = user.name: Initialize-PimMailSender -UseSignedInAccount -AdminAppId
          <appId> activates its own time-boxed Exchange Administrator through PIM and creates the mailbox now;
        * a PERSON (user.type user) -> run = $false: loud and not fatal, and `lines` say exactly how to finish it
          afterwards (PIM Manager > Get Started > Mail sender, or the published script, browser sign-in);
        * no / another tenant's account -> run = $false with that reason.
      Returns @{ run; appId; why; lines }.
    #>
    [CmdletBinding()] param([object]$Account, [string]$TenantId, [string[]]$ManagedIdentityObjectId = @(), [string]$SubscriptionId, [string]$ResourceGroup,
                            [string]$TickJobName, [string]$ManagerAppName, [string]$SqlServerFqdn)
    $cmd = New-PimMailSenderCommand -TenantId $TenantId -ManagedIdentityObjectId $ManagedIdentityObjectId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup `
               -TickJobName $TickJobName -ManagerAppName $ManagerAppName -SqlServerFqdn $SqlServerFqdn
    $after = @(
        '  DO IT AFTERWARDS (no certificate): PIM Manager > Get Started > Mail sender -- choose Shared mailbox (it prints this',
        '  command with the values filled in: an Exchange or Global Administrator runs it and signs in in the browser) or SMTP relay:',
        "    $($cmd[0])",
        "    $($cmd[1])")
    $type = "$($Account.user.type)".Trim()
    $name = "$($Account.user.name)".Trim()
    $tid  = "$($Account.tenantId)".Trim()
    if (-not $Account -or -not $name) {
        return @{ run = $false; appId = ''; why = 'no signed-in az account'; lines = @('mail sender: NOT RUN -- no signed-in az account could be read.') + $after }
    }
    if ("$TenantId".Trim() -and $tid -and $tid -ine "$TenantId".Trim()) {
        return @{ run = $false; appId = ''; why = 'signed in to another tenant'; lines = @("mail sender: NOT RUN -- the signed-in az account is in tenant $tid, not $TenantId.") + $after }
    }
    if ($type -ieq 'servicePrincipal' -and $name -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        return @{ run = $true; appId = $name; why = 'signed-in application'; lines = @() }
    }
    return @{ run = $false; appId = ''; why = 'signed-in deploy is a person'
              lines = @("mail sender: NOT RUN -- this deploy is signed in as a person ($name). Creating the shared mailbox needs Exchange administration this run does not",
                        '  hold (an app identity with a time-boxed Exchange Administrator, or an administrator''s own browser sign-in). The environment is MAIL-MUTE until then.') + $after }
}
