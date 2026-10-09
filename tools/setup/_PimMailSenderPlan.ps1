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
# 12.7 / 12.10 item 11: the command for the person (New-PimMailSenderCommand) is the save-verify-preview-run form with the
# documentation link -- built by _PimScriptDoc.ps1, loaded here so EVERY loader of this file has it (Confirm-PimInstall,
# Invoke-PimDeployAll, Install-PimEngineAppRegistration, Test-PimTenantReady, the mail scripts).
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')


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
    # MAIL-NAMING (100.14, owner 2026-10-09: "companies have their own naming"): the Exchange names follow the company's
    # mailbox -- -AssignmentNamePrefix (default: the mailbox name) -> '<prefix>-<short id>-MailSend'. The names earlier
    # releases forced on every tenant ('PIM4EntraPS-MI-<short id>-MailSend', 'PIM4EntraPS-Engine-MailSend') travel along
    # as legacyAssignmentNames, so an existing assignment is RECOGNISED (adopted), never duplicated.
    [CmdletBinding()] param([object[]]$ManagedIdentitySps = @(), [object]$EngineSp, [string]$AssignmentNamePrefix = 'PIM-Engine')
    $pfx = ConvertTo-PimExoNamePart -Value $AssignmentNamePrefix
    if (-not $pfx) { $pfx = 'PIM-Engine' }
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
                                    displayName = ("{0} sender {1}" -f $pfx, $short)
                                    assignmentName = ("{0}-{1}-MailSend" -f $pfx, $short)
                                    legacyAssignmentNames = @(("PIM4EntraPS-MI-{0}-MailSend" -f $short)) })
    }
    if ($out.Count -eq 0 -and $null -ne $EngineSp -and "$($EngineSp.appId)".Trim()) {
        $out.Add([pscustomobject]@{ kind = 'engine-spn'; appId = "$($EngineSp.appId)".Trim(); objectId = "$($EngineSp.id)".Trim()
                                    displayName = ("{0} sender (engine app)" -f $pfx); assignmentName = ("{0}-App-MailSend" -f $pfx)
                                    legacyAssignmentNames = @('PIM4EntraPS-Engine-MailSend') })
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
    # -AlternateNames (MAIL-NAMING 100.14): the names earlier releases gave the same assignment -- matched like
    # -AssignmentName, so a legacy-named assignment is adopted rather than created a second time.
    [CmdletBinding()] param([object[]]$Assignments = @(), [string]$ScopeName = 'PIM-Engine-SendScope',
                            [string[]]$AssigneeIds = @(), [string]$AssignmentName = '', [string[]]$AlternateNames = @())
    $want = @($AssigneeIds | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    $names = @(@($AssignmentName) + @($AlternateNames) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    return @(@($Assignments) | Where-Object {
        $null -ne $_ -and "$($_.Role)" -eq 'Application Mail.Send' -and "$($_.CustomResourceScope)" -eq $ScopeName -and (
            ($want -contains "$($_.RoleAssignee)".Trim().ToLowerInvariant()) -or
            ($want -contains "$($_.RoleAssigneeName)".Trim().ToLowerInvariant()) -or
            (-not "$($_.RoleAssignee)$($_.RoleAssigneeName)".Trim() -and $names.Count -and ($names -contains "$($_.Name)".Trim().ToLowerInvariant())))
    })
}

function ConvertTo-PimExoNamePart {
    # PURE. A mailbox name (or a company-given prefix) as a safe part of an Exchange object name: letters, digits, '-'.
    param([AllowEmptyString()][AllowNull()][string]$Value)
    return (("$Value".Trim() -replace '[^A-Za-z0-9-]', '-') -replace '-{2,}', '-').Trim('-')
}

function Test-PimExoObjectName {
    <# PURE. MAIL-NAMING: a company-given Exchange object name (-ScopeName / -AssignmentNamePrefix). Returns '' or the reason. #>
    param([AllowEmptyString()][AllowNull()][string]$Value, [string]$What = 'name')
    $v = "$Value".Trim()
    if (-not $v) { return '' }
    if ($v -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$') { return "$What '$v' is not usable as an Exchange object name (letters, digits, space, '.', '_' and '-'; at most 64 characters, starting with a letter or digit)" }
    return ''
}

function Test-PimMailboxLocalPart {
    <# PURE. MAIL-NAMING: the mailbox name the company chose (the part before the @). Returns '' or the reason. #>
    param([AllowEmptyString()][AllowNull()][string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return 'no mailbox name was given' }
    if ($v -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$' -or $v -match '\.\.') { return "'$v' is not usable as a mailbox name (letters, digits, '.', '_' and '-'; at most 64 characters, not starting or ending with '.', '_' or '-')" }
    return ''
}

function Get-PimMailSenderScopeName {
    <#
      PURE. MAIL-NAMING (100.14, owner 2026-10-09): the DEFAULT name of the Exchange management scope for a NEW sender --
      neutral and following the company's mailbox name: '<mailbox>-SendScope' (PIM-Engine@ -> 'PIM-Engine-SendScope').
      Per mailbox, because a scope is a tenant singleton (§94: sharing one meant sending as another environment's mailbox).
      An existing tenant's scope is ADOPTED by Resolve-PimMailSenderScope, never renamed or duplicated.
    #>
    param([Parameter(Mandatory)][string]$Sender)
    $local = ConvertTo-PimExoNamePart -Value (("$Sender" -split '@')[0])
    if (-not $local) { $local = 'PIM-Engine' }
    return ($local + '-SendScope')
}

function Test-PimLegacyMailSenderScopeName {
    # PURE. The names earlier releases gave the scope ('PIM4EntraPS-Sender', 'PIM4EntraPS-Sender-<mailbox>').
    param([AllowEmptyString()][AllowNull()][string]$Name)
    return ("$Name" -match '^(?i)PIM4EntraPS-Sender(-.+)?$')
}

function Resolve-PimMailSenderScope {
    <#
      PURE. MAIL-NAMING (100.14): WHICH scope this sender's send right lives in, given the scopes that already exist.
        1. a scope that already restricts to EXACTLY this sender is ADOPTED, whatever it is called (a legacy
           'PIM4EntraPS-Sender*' first) -- a re-run, or an install from before 2.4.538, keeps its scope and assignments;
        2. else the company's -ScopeName;
        3. else the neutral default '<mailbox>-SendScope'.
      Returns @{ name; adopted; note }.
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Sender, [string]$ScopeName = '', [object[]]$Scopes = @())
    $mine = @(@($Scopes) | Where-Object { $null -ne $_ -and "$($_.Name)".Trim() -and "$($_.RecipientRestrictionFilter)".IndexOf("'$Sender'", [StringComparison]::OrdinalIgnoreCase) -ge 0 })
    if ($mine.Count) {
        $pick = @($mine | Where-Object { Test-PimLegacyMailSenderScopeName -Name $_.Name }) + @($mine | Where-Object { -not (Test-PimLegacyMailSenderScopeName -Name $_.Name) })
        $n = "$($pick[0].Name)".Trim()
        $note = if ("$ScopeName".Trim() -and "$ScopeName".Trim() -ne $n) { "the existing scope '$n' already restricts to $Sender -- kept (not renamed to '$("$ScopeName".Trim())', never a second scope)" } else { "the existing scope '$n' (restricts to $Sender) is reused" }
        return [pscustomobject]@{ name = $n; adopted = $true; note = $note }
    }
    if ("$ScopeName".Trim()) { return [pscustomobject]@{ name = "$ScopeName".Trim(); adopted = $false; note = '' } }
    return [pscustomobject]@{ name = (Get-PimMailSenderScopeName -Sender $Sender); adopted = $false; note = '' }
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
          [object[]]$Principals = @(), [string]$Sender, [string]$ScopeName = '',
          [string]$EngineAppId = '', [string]$EngineObjectId = '', [switch]$RemoveEngineSpnAssignment)
    # MAIL-NAMING (100.14): no -ScopeName = the scope that already restricts to this sender (adopted), else the neutral
    # '<mailbox>-SendScope' (Resolve-PimMailSenderScope).
    if (-not "$ScopeName".Trim()) { $ScopeName = (Resolve-PimMailSenderScope -Sender $Sender -Scopes $Scopes).name }
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
                   "sender's identities to it. Give this environment its own scope (-ScopeName, or leave it out: the default is '<mailbox>-SendScope').")
        }
    }
    foreach ($p in @($Principals)) {
        $ids = Get-PimExoAssigneeIds -ExoServicePrincipals $ExoServicePrincipals -AppId $p.appId -ObjectId $p.objectId
        # §94: the same identity's send right on ANOTHER of our sender scopes is the wrong-mailbox grant above -- remove it
        # first (assignment names are tenant-unique, so the right one could not be created beside it).
        foreach ($wrong in @(@($Assignments) | Where-Object { $null -ne $_ -and "$($_.Role)" -eq 'Application Mail.Send' -and
                    "$($_.CustomResourceScope)" -ne $ScopeName -and ((Test-PimLegacyMailSenderScopeName -Name "$($_.CustomResourceScope)") -or "$($_.CustomResourceScope)" -like '*-SendScope') } |
                    Where-Object { @(Select-PimExoMailSendAssignment -Assignments @($_) -ScopeName "$($_.CustomResourceScope)" -AssigneeIds $ids -AssignmentName $p.assignmentName -AlternateNames @($p.legacyAssignmentNames)).Count })) {
            $idn = if ("$($wrong.Identity)".Trim()) { "$($wrong.Identity)".Trim() } else { "$($wrong.Name)".Trim() }
            $plan.Add([pscustomobject]@{ cmdlet = 'Remove-ManagementRoleAssignment'; what = "remove $($p.kind) $($p.appId)'s send right on the OTHER scope $($wrong.CustomResourceScope) ($idn)"
                                         parameters = @{ Identity = $idn; Confirm = $false } })
        }
        if (-not @(Select-PimExoMailSendAssignment -Assignments $Assignments -ScopeName $ScopeName -AssigneeIds $ids -AssignmentName $p.assignmentName -AlternateNames @($p.legacyAssignmentNames)).Count) {
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
# TWO customer tenants, three times, from ONE pattern: a transient failure on a READ silently became a
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
      Administrator grant is still arriving -- measured on two customer tenants, this is exactly how
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
                        two customer tenants). Bounded retry.
        'fail'       -- a real failure, reported at once
    #>
    [CmdletBinding()] param([string]$Cmdlet, [AllowEmptyString()][AllowNull()][string]$ErrorText)
    if (Test-PimAlreadyExistsError -Text $ErrorText) { return 'exists' }
    if ("$ErrorText" -like '*InvalidOperationInDehydratedContextException*') { return 'dehydrated' }
    # INSTALL-HARDEN-1 item 4 (2026-10-08, two new tenants): right after the organization was hydrated, Exchange answered
    # New-ManagementRoleAssignment with 400 "You don't have access to create, change, or remove the ... management role
    # assignment. You must be assigned a delegating role assignment ..." for ~40-60 minutes -- and then the same call
    # worked. It is Exchange finishing the new organization's RBAC, not a missing right: a bounded wait, never a failure.
    if (Test-PimExoNotReadyError -Text $ErrorText) { return 'notready' }
    if ("$Cmdlet" -eq 'New-ManagementRoleAssignment' -and (Test-PimExoNotFoundError -Text $ErrorText)) { return 'retry' }
    return 'fail'
}

function Test-PimExoNotReadyError {
    <# Exchange's "the new organization's RBAC is not ready yet" answer (INSTALL-HARDEN-1 item 4). #>
    [CmdletBinding()] param([AllowEmptyString()][AllowNull()][string]$Text)
    return ("$Text" -match "(?i)must be assigned a delegating role assignment|don.t have access to create, change, or remove the .{0,200}management role assignment")
}

function Get-PimExoNotReadyWait {
    <#
      PURE. INSTALL-HARDEN-1 item 4 -- one decision of the bounded wait for a not-ready Exchange organization.
      Returns @{ wait; sleepSeconds; message }: wait = $false once -ElapsedSeconds reaches -BoundSeconds (default 75 min);
      the message is the plain progress line (or, past the bound, the one sentence the install fails with).
    #>
    [CmdletBinding()] param([int]$Attempt = 1, [double]$ElapsedSeconds = 0, [int]$BoundSeconds = 4500, [int]$IntervalSeconds = 150, [string]$What = 'the send right')
    if ($ElapsedSeconds -ge $BoundSeconds) {
        return @{ wait = $false; sleepSeconds = 0
                  message = "Exchange has not finished preparing the new organization -- re-run in an hour (waited $([int]($ElapsedSeconds / 60)) minutes for $What)" }
    }
    $left = [Math]::Max(1, [int][Math]::Ceiling(($BoundSeconds - $ElapsedSeconds) / 60))
    return @{ wait = $true; sleepSeconds = [int][Math]::Min($IntervalSeconds, [Math]::Max(1, $BoundSeconds - $ElapsedSeconds))
              message = "Exchange is still preparing the new organization ($What, attempt $Attempt, $([int]($ElapsedSeconds / 60)) min waited, up to $left min more) -- this is normal for a new tenant" }
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

function New-PimMailSenderSetupCheck {
    <#
      PURE (MAIL-STEP-PROOF, owner 2026-10-09: "why dont you trigger somehing or accept that we just did a test mail"). The
      record Initialize-PimMailSender stores in pim.Settings 'MailSenderSetupCheck' when its step [3] read-back CONFIRMED the
      scoped Application Mail.Send assignment for every sending identity, in ONE management scope on THIS mailbox. PIM Manager
      reads it: with its own successful test mail on the same mailbox the engine job's row is "granted -- confirmed by the
      setup check and the test mail". -Confirmed $false (not read back) or no identity -> $null: nothing is stored, never a guess.
    #>
    param([bool]$Confirmed, [string]$Sender, [string]$ScopeName, [object[]]$Principals = @(), [string]$By = '', [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not $Confirmed -or -not "$Sender".Trim() -or -not "$ScopeName".Trim()) { return $null }
    $ids = @(@($Principals) | Where-Object { $_ -and ("$($_.objectId)".Trim() -or "$($_.appId)".Trim()) } | ForEach-Object { [ordered]@{ kind = "$($_.kind)"; appId = "$($_.appId)".Trim(); objectId = "$($_.objectId)".Trim() } })
    if (-not $ids.Count) { return $null }
    return [ordered]@{ ok = $true; scopedMailSend = 'confirmed'; sender = "$Sender".Trim(); scope = "$ScopeName".Trim(); identities = $ids
                       at = $NowUtc.ToUniversalTime().ToString('o'); by = "$By".Trim(); source = 'Initialize-PimMailSender' }
}

function New-PimMailSenderAddressRecord {
    <#
      PURE (INSTALL-FIX-EVIDA, REQUIREMENTS 100.25 item 4). The record Initialize-PimMailSender stores in pim.Settings
      'MailSenderAddress': the mailbox's PRIMARY SMTP address -- what the customer chose (name@their domain) -- next to the
      MailSender it belongs to (the mailbox's UPN, BUG-296: what Microsoft Graph sends by, often on the initial domain).
      PIM Manager and the end-of-install check SHOW the address with the UPN as detail, and only while 'sender' is still
      the stored MailSender (a later change of sender makes the record stale, never wrong). No address -> $null.
    #>
    param([string]$Sender, [string]$Address, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not "$Sender".Trim() -or -not "$Address".Trim()) { return $null }
    return [ordered]@{ sender = "$Sender".Trim(); address = "$Address".Trim(); at = $NowUtc.ToUniversalTime().ToString('o'); source = 'Initialize-PimMailSender' }
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
      that is known filled in and a <placeholder> for the rest. PURE. Returns the lines of Get-PimSupportScriptCommand
      (12.7 / 12.10 item 11): the download, the checksum check, the signature status, the documentation link (with the
      -WhatIf hint), then the run line (always the LAST line).
    #>
    # MAIL-NAMING (100.14, owner 2026-10-09: "it must be possible to define as parameter on the scripts"): the company's
    # mailbox name, domain and display name travel in the command (-MailboxName / -MailDomain / -DisplayName) whenever
    # they are known -- the script's own defaults otherwise.
    [CmdletBinding()] param([string]$TenantId, [string[]]$ManagedIdentityObjectId = @(), [string]$SubscriptionId, [string]$ResourceGroup,
                            [string]$TickJobName, [string]$ManagerAppName, [string]$SqlServerFqdn,
                            [string]$MailboxName, [string]$MailDomain, [string]$DisplayName)
    $v = { param($x, $ph) if ("$x".Trim()) { "$x".Trim() } else { $ph } }
    $q = { param($x) $t = "$x".Trim(); if ($t -match '^[A-Za-z0-9._@-]+$') { $t } else { "'" + $t.Replace("'", "''") + "'" } }
    $run = '.\Initialize-PimMailSender.ps1 -TenantId ' + (& $v $TenantId '<tenant id>')
    if ("$MailboxName".Trim()) { $run += ' -MailboxName ' + (& $q $MailboxName) }
    if ("$MailDomain".Trim())  { $run += ' -MailDomain ' + (& $q $MailDomain) }
    if ("$DisplayName".Trim()) { $run += ' -DisplayName ' + (& $q $DisplayName) }
    $mi = @(@($ManagedIdentityObjectId) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
    if ($mi.Count) { $run += ' -ManagedIdentityObjectId ' + ($mi -join ',') }
    if ("$SubscriptionId".Trim() -and "$ResourceGroup".Trim() -and ("$TickJobName".Trim() -or "$ManagerAppName".Trim())) {
        $run += " -SubscriptionId $("$SubscriptionId".Trim()) -ResourceGroup $("$ResourceGroup".Trim())"
        if ("$TickJobName".Trim()) { $run += " -TickJobName $("$TickJobName".Trim())" }
        if ("$ManagerAppName".Trim()) { $run += " -ManagerAppName $("$ManagerAppName".Trim())" }
    } elseif (-not $mi.Count) { $run += ' -ManagedIdentityObjectId <manager identity object id>,<engine job identity object id>' }
    $run += ' -SqlServerFqdn ' + (& $v $SqlServerFqdn '<server>.database.windows.net')
    return @(Get-PimSupportScriptCommand -Script 'Initialize-PimMailSender' -Run @($run))
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
    # INSTALL-HARDEN-1 (owner 2026-10-08, the trial runs in the customer's Cloud Shell as a PERSON): a signed-in person who
    # holds an ACTIVE Exchange Administrator or Global Administrator role (-PersonRoleTemplateIds: the 'wids' of their token,
    # or their directory roles) AND for whom az mints an Exchange Online token (-PersonExoToken) runs it too: run = $true,
    # person = $true, appId = '' -> Initialize-PimMailSender -UseSignedInAccount with no -AdminAppId (their own role; no app
    # is granted anything). Anyone else stays the loud, non-fatal skip with the Get Started follow-up.
    [CmdletBinding()] param([object]$Account, [string]$TenantId, [string[]]$ManagedIdentityObjectId = @(), [string]$SubscriptionId, [string]$ResourceGroup,
                            [string]$TickJobName, [string]$ManagerAppName, [string]$SqlServerFqdn,
                            [string[]]$PersonRoleTemplateIds = @(), [bool]$PersonExoToken = $false)
    $cmd = New-PimMailSenderCommand -TenantId $TenantId -ManagedIdentityObjectId $ManagedIdentityObjectId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup `
               -TickJobName $TickJobName -ManagerAppName $ManagerAppName -SqlServerFqdn $SqlServerFqdn
    $after = @(
        '  DO IT AFTERWARDS (no certificate): PIM Manager > Get Started > Mail sender -- choose Shared mailbox (it prints this',
        '  command with the values filled in: an Exchange or Global Administrator runs it and signs in in the browser) or SMTP relay:') +
        @(@($cmd) | ForEach-Object { "    $_" })
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
        return @{ run = $true; appId = $name; why = 'signed-in application'; lines = @(); person = $false }
    }
    $exoRoles = @('29232cdf-9323-42fd-ade2-1d097af3e4de', '62e90394-69f5-4237-9190-012177145e10')   # Exchange Administrator, Global Administrator
    $held = @(@($PersonRoleTemplateIds) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ -in $exoRoles })
    if ($held.Count -and $PersonExoToken) {
        return @{ run = $true; appId = ''; person = $true; why = 'signed-in person with an active Exchange role'; lines = @() }
    }
    $whyPerson = if (-not $held.Count) { 'no ACTIVE Exchange Administrator or Global Administrator role' } else { 'no Exchange Online token from the signed-in session' }
    return @{ run = $false; appId = ''; person = $true; why = "signed-in deploy is a person ($whyPerson)"
              lines = @("mail sender: NOT RUN -- this deploy is signed in as a person ($name). Creating the shared mailbox needs Exchange administration this run does not",
                        '  hold (an app identity with a time-boxed Exchange Administrator, or an administrator''s own browser sign-in). The environment is MAIL-MUTE until then.') + $after }
}

# =============================================================================================
# MAIL-NAMING 100.14 item 5 (owner 2026-10-09): the store write from a customer PC fails at the Azure SQL firewall
# ("Client with IP address ... is not allowed"). Default: no firewall change, a short message, PIM Manager finishes it.
# Opt-in -AllowThisIpTemporarily: a temporary rule for exactly that IP, the write, and the rule ALWAYS removed (finally).
# =============================================================================================
function Get-PimSqlFirewallBlockedIp {
    # PURE. The IP Azure SQL refused (error 40615), or '' when the error is not the firewall.
    param([AllowEmptyString()][AllowNull()][string]$Text)
    $m = [regex]::Match("$Text", "(?i)Client with IP address '(?<ip>[0-9a-fA-F:.]+)' is not allowed")
    if ($m.Success) { return $m.Groups['ip'].Value }
    return ''
}

function New-PimSqlTempFirewallRuleName {
    # PURE. A rule name that says what it is and when it was made (removed again by the same run).
    param([Parameter(Mandatory)][string]$Ip, [datetime]$Now = [datetime]::UtcNow)
    return ('PimSetupTemp-' + ($Ip -replace '[^0-9A-Za-z]', '-') + '-' + $Now.ToUniversalTime().ToString('yyyyMMddHHmmss'))
}

function Invoke-PimSqlWriteWithTemporaryFirewall {
    <#
      The write, and -- only with -AllowThisIpTemporarily, only when the write was refused by the SQL firewall, and only
      when -ShouldProcess agrees (-WhatIf = no) -- one temporary rule for the refused IP, the write retried while the rule
      takes effect, and the rule REMOVED in finally whether the write worked or not. The calls are injected
      (-Write / -AddRule param($ip) -> handle / -RemoveRule param($handle) / -ShouldProcess param($ip) -> bool / -Sleep),
      so the whole decision is tested offline.
      Returns @{ ok; firewall; ip; whatIf; ruleAdded; ruleRemoved; rule; error; removeError }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][scriptblock]$Write, [switch]$AllowThisIpTemporarily, [scriptblock]$AddRule, [scriptblock]$RemoveRule,
          [scriptblock]$ShouldProcess, [int]$Attempts = 9, [int]$DelaySeconds = 20, [scriptblock]$Sleep)
    $r = [ordered]@{ ok = $false; firewall = $false; ip = ''; whatIf = $false; ruleAdded = $false; ruleRemoved = $false; rule = $null; error = ''; removeError = '' }
    $txt = { param($e) ("$($e.Exception.Message) $($e.ErrorDetails.Message)" -replace '\s+', ' ').Trim() }
    try { & $Write; $r.ok = $true; return $r } catch { $r.error = & $txt $_ }
    $r.ip = Get-PimSqlFirewallBlockedIp -Text $r.error
    if (-not $r.ip) { return $r }
    $r.firewall = $true
    if (-not $AllowThisIpTemporarily -or -not $AddRule -or -not $RemoveRule) { return $r }
    if ($ShouldProcess -and -not (& $ShouldProcess $r.ip)) { $r.whatIf = $true; return $r }
    try {
        try { $r.rule = & $AddRule $r.ip; $r.ruleAdded = $true }
        catch { $r.error = "could not add the temporary firewall rule: $(& $txt $_)"; return $r }
        for ($i = 1; $i -le [Math]::Max(1, $Attempts); $i++) {
            if ($Sleep) { & $Sleep $DelaySeconds } else { Start-Sleep -Seconds $DelaySeconds }   # a new rule takes a moment to apply
            try { & $Write; $r.ok = $true; $r.error = ''; break }
            catch { $r.error = & $txt $_; if (-not (Get-PimSqlFirewallBlockedIp -Text $r.error)) { break } }
        }
    } finally {
        if ($r.ruleAdded) {
            try { & $RemoveRule $r.rule; $r.ruleRemoved = $true } catch { $r.removeError = & $txt $_ }
        }
    }
    return $r
}
