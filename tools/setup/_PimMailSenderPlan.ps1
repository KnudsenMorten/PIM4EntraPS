#Requires -Version 5.1
<#
.SYNOPSIS
  PURE decision cores for the mail send right (REQUIREMENTS 65.11). No network, no state.

.DESCRIPTION
  Operator decision 2026-09-13: the HOSTED engine sends as its MANAGED IDENTITY. The scoped
  Exchange 'Application Mail.Send' assignment (Exchange RBAC for Applications, pinned to the
  sender mailbox by a management scope) must therefore name the identity that actually sends --
  the tick job's managed identity -- not only the engine SPN. (SECURE-WEB-1, 3.1.26 / MAIL-WEB-RIGHTS-1: the web app,
  PIM Manager, sends NO mail; its identity is never a sending identity and never gets this assignment.) Until now the assignment named the SPN while the container sent as its managed
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
      Input: the job resource (ARM GET of the Container Apps job). Returns
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
    # ONE-SENDER-1 point B (Invardia 2026-11-25): -Roles @{ <objectId> = 'engine' | 'rfa' } names WHICH component each managed
    # identity sends for (the tick job = engine, the RFA broker ca-pim-rfa = rfa); an identity not named = 'engine'.
    [CmdletBinding()] param([object[]]$ManagedIdentitySps = @(), [object]$EngineSp, [string]$AssignmentNamePrefix = 'PIM-Engine', [hashtable]$Roles = @{})
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
        # 3.1.69 review: a value may be a LIST -- one identity can send for the engine AND the broker; 'roles' keeps all of them
        # (the retire decision checks every role's probe), 'role' is the first ('engine' when it is one of them)
        $roleList = @()
        if ($Roles) { foreach ($rk in @($Roles.Keys)) { if ("$rk".Trim() -ieq $oid) { $roleList += @(@($Roles[$rk]) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ }) } } }
        $roleList = @($roleList | Select-Object -Unique); if (-not $roleList.Count) { $roleList = @('engine') }
        $role = if ($roleList -contains 'engine') { 'engine' } else { $roleList[0] }
        $out.Add([pscustomobject]@{ kind = 'managed-identity'; role = $role; roles = $roleList; appId = "$($sp.appId)".Trim(); objectId = $oid
                                    displayName = ("{0} sender {1}" -f $pfx, $short)
                                    assignmentName = ("{0}-{1}-MailSend" -f $pfx, $short)
                                    legacyAssignmentNames = @(("PIM4EntraPS-MI-{0}-MailSend" -f $short)) })
    }
    if ($out.Count -eq 0 -and $null -ne $EngineSp -and "$($EngineSp.appId)".Trim()) {
        $out.Add([pscustomobject]@{ kind = 'engine-spn'; role = 'engine'; roles = @('engine'); appId = "$($EngineSp.appId)".Trim(); objectId = "$($EngineSp.id)".Trim()
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

function Get-PimExoDuplicateScopeName {
    <#
      PURE. Exchange refuses a New-ManagementScope whose filter equals an existing scope's: "The <name> management scope has
      the same RecipientRoot, RecipientFilter, ... property values that you specified. Use the existing management scope".
      Returns that existing scope's name ('' for any other answer). A customer install, 2026-10-21: the scope read came back
      empty right after the Exchange Administrator role was activated, so the plan did not adopt 'PIM4EntraPS-Sender' and
      the create was refused -- the run now adopts the scope Exchange names instead of failing.
    #>
    [CmdletBinding()] param([AllowEmptyString()][AllowNull()][string]$Text)
    $m = [regex]::Match("$Text", '(?i)The (?<n>[^\s|"]+) management scope has the same')
    if ($m.Success) { return $m.Groups['n'].Value }
    return ''
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

# =============================================================================================
# MAIL-SCOPE-SMTP (2026-11-11, found live at a customer). The scope filtered on PrimarySmtpAddress = the address the script was
# GIVEN; that mailbox's UPN was the custom domain but its PRIMARY SMTP the initial (onmicrosoft) one, so the scope matched NO
# mailbox and every scoped send was DENIED for days -- while the read-back said "verified" because the objects existed.
# The filter is now built from the mailbox's REAL primary SMTP (Get-Mailbox), an existing scope with exactly that filter is
# reused (Exchange refuses a second one), a scope of ours that pins another address of this mailbox is repaired, and the
# read-back is Exchange's own Test-ServicePrincipalAuthorization: InScope = True for every sending identity, or FAILED.
# =============================================================================================

function Get-PimMailSenderScopeFilter {
    # PURE. The one filter a sender scope carries: the mailbox's PRIMARY SMTP address (never the UPN, never an alias).
    param([Parameter(Mandatory)][string]$PrimarySmtp)
    return "PrimarySmtpAddress -eq '$("$PrimarySmtp".Trim())'"
}

function Get-PimExoScopeFilterText {
    # PURE. A management scope's filter as Exchange's REST API answers it (RecipientRestrictionFilter or RecipientFilter).
    param([AllowNull()]$Scope)
    if ($null -eq $Scope) { return '' }
    foreach ($n in 'RecipientRestrictionFilter', 'RecipientFilter') {
        $v = if ($Scope -is [System.Collections.IDictionary]) { $Scope[$n] } elseif ($Scope.PSObject.Properties[$n]) { $Scope.$n } else { $null }
        if ("$v".Trim()) { return "$v".Trim() }
    }
    return ''
}

function Get-PimExoScopeFilterAddress {
    # PURE. The ONE address a "PrimarySmtpAddress -eq '<a>'" filter pins (lower case), '' for any other filter.
    param([AllowEmptyString()][AllowNull()][string]$Filter)
    $m = [regex]::Match("$Filter", '^\s*\(?\s*PrimarySmtpAddress\s+-eq\s+[''"](?<a>[^''"]+)[''"]\s*\)?\s*$', 'IgnoreCase')
    if ($m.Success) { return $m.Groups['a'].Value.Trim().ToLowerInvariant() }
    return ''
}

function Get-PimMailboxAddressSet {
    # PURE. Every address that names this mailbox (lower case): primary SMTP, UPN, WindowsEmailAddress, each smtp: proxy, plus -Extra.
    param([AllowNull()]$Mailbox, [string[]]$Extra = @())
    $out = New-Object System.Collections.Generic.List[string]
    $add = { param($v) $t = "$v".Trim().ToLowerInvariant(); if ($t -and $t -match '@' -and -not $out.Contains($t)) { $out.Add($t) } }
    if ($Mailbox) {
        foreach ($n in 'PrimarySmtpAddress', 'UserPrincipalName', 'WindowsEmailAddress') { if ($Mailbox.PSObject.Properties[$n]) { & $add $Mailbox.$n } }
        if ($Mailbox.PSObject.Properties['EmailAddresses']) {
            foreach ($e in @($Mailbox.EmailAddresses)) { $s = "$e".Trim(); if ($s -match '^(?i)smtp:(.+)$') { & $add $Matches[1] } elseif ($s -notmatch ':') { & $add $s } }
        }
    }
    foreach ($x in @($Extra)) { & $add $x }
    return @($out.ToArray())
}

function Resolve-PimMailSenderScopeRepair {
    <#
      PURE (MAIL-SCOPE-SMTP). Given the mailbox's REAL primary SMTP, the other addresses of the same mailbox and what exists:
        * twin   -- a scope whose filter is exactly PrimarySmtpAddress -eq '<primary>' exists (any name): it is REUSED (Exchange
                    refuses a second scope with the same filter). Our scopes that pin ANOTHER address of this mailbox (they
                    match no mailbox at all) have their 'Application Mail.Send' assignments MOVED to it
                    (Set-ManagementRoleAssignment -CustomResourceScope);
        * repair -- no twin, but our scope pins another address of this mailbox: its filter is CORRECTED to the primary SMTP
                    (Set-ManagementScope -RecipientRestrictionFilter) -- still exactly one mailbox, widens nothing. Refused when
                    that scope also carries a role other than 'Application Mail.Send' (correcting it would widen that role);
        * none   -- nothing to repair; the normal plan creates or adopts the scope.
      "Ours" = named -ScopeName / -OwnNames, a legacy 'PIM4EntraPS-Sender*', '*-SendScope', or carrying an Application Mail.Send.
      Returns { kind; scopeName; filter; actions = @({ cmdlet; parameters; what }); scopes; assignments; note; reason } --
      scopes / assignments are the inputs AS THEY WILL BE after the actions, for New-PimMailSenderExoPlan.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PrimarySmtp, [string[]]$MailboxAddresses = @(), [object[]]$Scopes = @(), [object[]]$Assignments = @(),
          [string]$ScopeName = '', [string[]]$OwnNames = @())
    $p = "$PrimarySmtp".Trim().ToLowerInvariant()
    $want = Get-PimMailSenderScopeFilter -PrimarySmtp "$PrimarySmtp".Trim()
    $others = @(@($MailboxAddresses) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ -and $_ -ne $p })
    $names = @(@($ScopeName) + @($OwnNames) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    $sc = @(@($Scopes) | Where-Object { $null -ne $_ -and "$($_.Name)".Trim() })
    $asg = @(@($Assignments) | Where-Object { $null -ne $_ })
    $onScope = { param($n) @($asg | Where-Object { "$($_.CustomResourceScope)" -eq "$n" }) }
    $isMailSend = { param($a) "$($a.Role)" -eq 'Application Mail.Send' }
    $ours = { param($s) $n = "$($s.Name)".Trim()
        ($names -contains $n.ToLowerInvariant()) -or (Test-PimLegacyMailSenderScopeName -Name $n) -or $n -like '*-SendScope' -or
        @(& $onScope $n | Where-Object { & $isMailSend $_ }).Count }
    $rank = { param($list) @($list | Where-Object { $names -contains "$($_.Name)".Trim().ToLowerInvariant() }) + @($list | Where-Object { $names -notcontains "$($_.Name)".Trim().ToLowerInvariant() -and (Test-PimLegacyMailSenderScopeName -Name $_.Name) }) +
                                    @($list | Where-Object { $names -notcontains "$($_.Name)".Trim().ToLowerInvariant() -and -not (Test-PimLegacyMailSenderScopeName -Name $_.Name) }) }
    $twins = @(& $rank @($sc | Where-Object { (Get-PimExoScopeFilterAddress -Filter (Get-PimExoScopeFilterText $_)) -eq $p }))
    $broken = @(& $rank @($sc | Where-Object { $a = Get-PimExoScopeFilterAddress -Filter (Get-PimExoScopeFilterText $_); $a -and $others -contains $a -and (& $ours $_) }))
    $out = [ordered]@{ kind = 'none'; scopeName = ''; filter = $want; actions = @(); scopes = $sc; assignments = $asg; note = ''; reason = '' }
    if (-not $twins.Count -and -not $broken.Count) { return [pscustomobject]$out }
    $actions = New-Object System.Collections.Generic.List[object]
    $moveTo = { param($fromNames, $target)
        foreach ($a in @($asg | Where-Object { $fromNames -contains "$($_.CustomResourceScope)" -and (& $isMailSend $_) })) {
            $idn = if ("$($a.Identity)".Trim()) { "$($a.Identity)".Trim() } else { "$($a.Name)".Trim() }
            $actions.Add([pscustomobject]@{ cmdlet = 'Set-ManagementRoleAssignment'; what = "move send right $idn from scope $($a.CustomResourceScope) (it matches no mailbox) to $target"
                                            parameters = @{ Identity = $idn; CustomResourceScope = $target }
                                            # ONE-SENDER-1 point C: the move, recorded so it can be put back
                                            previous = [ordered]@{ kind = 'move'; identity = $idn; fromScope = "$($a.CustomResourceScope)"; toScope = $target } })
        }
        # the inputs as they will be: the moved assignments now live in $target
        @($asg | ForEach-Object { if ($fromNames -contains "$($_.CustomResourceScope)" -and (& $isMailSend $_)) { $c = $_.PSObject.Copy(); $c.CustomResourceScope = $target; $c } else { $_ } })
    }
    if ($twins.Count) {
        $t = "$($twins[0].Name)".Trim()
        $from = @($broken | ForEach-Object { "$($_.Name)".Trim() } | Where-Object { $_ -ne $t })
        $out.kind = 'twin'; $out.scopeName = $t
        $out.assignments = @(& $moveTo $from $t)
        $out.actions = $actions.ToArray()
        $out.note = "the existing scope '$t' already restricts to the mailbox's primary SMTP address $PrimarySmtp -- reused (Exchange refuses a second scope with the same filter)" +
                    $(if ($from.Count) { "; send rights in $($from -join ', ') (they match no mailbox) are moved to it" } else { '' })
        return [pscustomobject]$out
    }
    $b = $broken[0]; $bn = "$($b.Name)".Trim()
    $foreign = @(& $onScope $bn | Where-Object { -not (& $isMailSend $_) })
    if ($foreign.Count) {
        $out.kind = 'refuse'; $out.scopeName = $bn
        $out.reason = "the scope '$bn' filters on $(Get-PimExoScopeFilterAddress -Filter (Get-PimExoScopeFilterText $b)) (not the mailbox's primary SMTP address $PrimarySmtp, so it matches no mailbox) and also carries other roles ($(@($foreign | ForEach-Object { "$($_.Role)" } | Sort-Object -Unique) -join ', ')) -- correcting its filter would widen them. Give this sender its own scope (-ScopeName)."
        return [pscustomobject]$out
    }
    $actions.Add([pscustomobject]@{ cmdlet = 'Set-ManagementScope'; what = "correct scope $bn to the mailbox's primary SMTP address $PrimarySmtp (it filtered on $(Get-PimExoScopeFilterAddress -Filter (Get-PimExoScopeFilterText $b)) and matched no mailbox)"
                                    parameters = @{ Identity = $bn; RecipientRestrictionFilter = $want } })
    $from = @($broken | Select-Object -Skip 1 | ForEach-Object { "$($_.Name)".Trim() })
    $out.kind = 'repair'; $out.scopeName = $bn
    $out.assignments = @(& $moveTo $from $bn)
    $out.actions = $actions.ToArray()
    $out.scopes = @($sc | ForEach-Object { if ("$($_.Name)".Trim() -eq $bn) { [pscustomobject]@{ Name = $bn; RecipientRestrictionFilter = $want } } else { $_ } })
    $out.note = "the scope '$bn' filtered on another address of this mailbox and matched no mailbox -- its filter is corrected to the primary SMTP address $PrimarySmtp"
    return [pscustomobject]$out
}

function Get-PimMailSendAuthVerdict {
    <#
      PURE (MAIL-SCOPE-SMTP). Exchange's Test-ServicePrincipalAuthorization answer (rows: RoleName, GrantedPermissions, InScope,
      ScopeName) for ONE identity and the mailbox -> @{ inScope; detail }. Only an 'Application Mail.Send' row with
      InScope = True proves the identity may send as that mailbox; an assignment that merely EXISTS proves nothing.
    #>
    param([object[]]$Rows = @(), [string]$Resource = '')
    $ms = @(@($Rows) | Where-Object { $null -ne $_ -and "$($_.RoleName)" -eq 'Application Mail.Send' })
    if (-not $ms.Count) { return @{ inScope = $false; detail = "no 'Application Mail.Send' role assignment answers for $Resource" } }
    $in = @($ms | Where-Object { "$($_.InScope)" -match '^(?i)true$' })
    if ($in.Count) { return @{ inScope = $true; detail = "InScope=True for $Resource (scope $(@($in | ForEach-Object { "$($_.ScopeName)" } | Where-Object { $_ } | Sort-Object -Unique) -join ', '))" } }
    return @{ inScope = $false; detail = "'Application Mail.Send' is assigned (scope $(@($ms | ForEach-Object { "$($_.ScopeName)" } | Where-Object { $_ } | Sort-Object -Unique) -join ', ')) but InScope=False for $Resource -- the scope does not cover this mailbox" }
}

function Confirm-PimMailSendInScope {
    <#
      MAIL-SCOPE-SMTP read-back: Test-ServicePrincipalAuthorization -Identity <appId> -Resource <primary SMTP> for EVERY sending
      identity, retried while Exchange replicates (default 120 s, every 15 s). -Invoke param($appId, $resource) -> rows
      (injected: the script passes its Exchange call, the tests a stub); -Sleep param($s) injectable.
      Returns @{ ok; attempts; identities = @({ kind; appId; objectId; inScope; detail }); reason }.
    #>
    [CmdletBinding()]
    param([object[]]$Principals = @(), [Parameter(Mandatory)][string]$Resource, [Parameter(Mandatory)][scriptblock]$Invoke,
          [int]$Seconds = 120, [int]$IntervalSeconds = 15, [scriptblock]$Sleep)
    $ids = @(@($Principals) | Where-Object { $_ -and "$($_.appId)".Trim() } | ForEach-Object {
        [pscustomobject]@{ kind = "$($_.kind)"; appId = "$($_.appId)".Trim(); objectId = "$($_.objectId)".Trim(); inScope = $false; detail = 'not checked' } })
    if (-not $ids.Count) { return @{ ok = $false; attempts = 0; identities = @(); reason = 'no sending identity to check' } }
    $max = 1 + [Math]::Max(0, [int][Math]::Floor($Seconds / [Math]::Max(1, $IntervalSeconds)))
    $n = 0
    while ($true) {
        $n++
        foreach ($i in @($ids | Where-Object { -not $_.inScope })) {
            try { $v = Get-PimMailSendAuthVerdict -Rows @(& $Invoke $i.appId $Resource) -Resource $Resource; $i.inScope = [bool]$v.inScope; $i.detail = $v.detail }
            catch { $i.inScope = $false; $i.detail = "Test-ServicePrincipalAuthorization failed: $((("$($_.Exception.Message) $($_.ErrorDetails.Message)") -replace '\s+', ' ').Trim())" }
        }
        $bad = @($ids | Where-Object { -not $_.inScope })
        if (-not $bad.Count) { return @{ ok = $true; attempts = $n; identities = $ids; reason = '' } }
        if ($n -ge $max) {
            return @{ ok = $false; attempts = $n; identities = $ids
                      reason = (@($bad | ForEach-Object { "$($_.kind) $($_.appId): $($_.detail)" }) -join '; ') }
        }
        if ($Sleep) { & $Sleep $IntervalSeconds } else { Start-Sleep -Seconds $IntervalSeconds }
    }
}

function Resolve-PimMailInScopeOutcome {
    <#
      PURE (MAIL-SCOPE-SMTP, coordinator decision 2026-11-11). What the in-scope read-back means for the run:
        'verified' -- Exchange said InScope=True for every sending identity;
        'pending'  -- not in scope after the wait, but THIS run created or changed the Exchange objects: Exchange app RBAC can
                      take up to ~2 h on a new tenant, so the run ends PENDING (exit 3), the setup check stays NOT confirmed;
        'failed'   -- not in scope and nothing was changed in this run (the objects already existed): the configuration is
                      wrong (the customer's state of 2026-11-11), so FAILED -- waiting would not help.
    #>
    param([bool]$InScope, [bool]$ChangedThisRun)
    if ($InScope) { return 'verified' }
    if ($ChangedThisRun) { return 'pending' }
    return 'failed'
}

function Get-PimMailInScopePendingText {
    # PURE. The one sentence a PENDING run ends with (coordinator decision 2026-11-11).
    return 'Exchange has not applied the send right yet (it can take up to 2 hours) -- re-run this script later; nothing more to change'
}

# =============================================================================================
# ONE-SENDER-1 (Invardia 2026-11-25, framework ONE-SENDER-1 points B + C). Found on internal 2026-11-25: the RFA broker
# signed in as id-pim-requests, which held NO Exchange Application Mail.Send -- the mail-sender script only ever knew the
# tick job. B: ONE run covers EVERY sending identity (the tick job AND, where ca-pim-rfa is deployed, the broker's
# identity -- found the same way as the tick job, never by a separate run). C, TIGHTENED (owner via Invardia 2026-11-26):
# a sender change KEEPS the old sender's right in the granting run (the run ends PENDING with both in place); a LATER run
# (a re-run or -Cleanup) retires the old assignments, then the old scope when nothing is left on it, ONLY when every sending
# identity's own Graph probe (PIM-MailSenderProbe.ps1) is verified for the NEW sender after the change -- Exchange's
# Test-ServicePrincipalAuthorization InScope is not enough (EPS: it said in-scope before sending really worked).
# =============================================================================================

function Get-PimRfaBrokerDefaultAppName { 'ca-pim-rfa' }

function Resolve-PimRfaBrokerSendIdentity {
    <#
      PURE (ONE-SENDER-1 point B). Is the RFA broker (container app ca-pim-rfa) deployed in the resource group, and which
      identity does it SEND as? -App = the ARM GET of the container app ($null when the read failed), -ErrorText = the read's
      error. The broker's Graph token follows the same rule as the engine's (PIM_ManagedIdentityClientId -> that user-assigned
      identity, e.g. id-pim-requests; else its system identity), so Get-PimJobManagedIdentityPrincipalId decides it.
      Returns @{ deployed = $true | $false | $null (could not tell); principalId; kind; reason }:
        404 / not found -> deployed $false (no broker = nothing to grant, not an error);
        another read error -> deployed $null + the reason (the run says so -- it never guesses that there is no broker);
        deployed but no usable identity -> deployed $true, principalId '' + the reason.
    #>
    [CmdletBinding()] param([object]$App, [AllowEmptyString()][AllowNull()][string]$ErrorText = '', [string]$AppName = 'ca-pim-rfa')
    if ($null -eq $App) {
        if (-not "$ErrorText".Trim() -or "$ErrorText" -match '(?i)\b404\b|ResourceNotFound|was not found|could not be found|NotFound') {
            return [pscustomobject]@{ deployed = $false; principalId = ''; kind = ''; reason = "no RFA broker ($AppName) in this resource group" }
        }
        return [pscustomobject]@{ deployed = $null; principalId = ''; kind = ''; reason = "the RFA broker ($AppName) could not be read: $((("$ErrorText") -split "`n")[0].Trim())" }
    }
    $pick = Get-PimJobManagedIdentityPrincipalId -Job $App
    if ($pick.reason) { return [pscustomobject]@{ deployed = $true; principalId = ''; kind = ''; reason = "RFA broker ${AppName}: $($pick.reason)" } }
    return [pscustomobject]@{ deployed = $true; principalId = "$($pick.principalId)"; kind = "$($pick.kind)"; reason = '' }
}

function Get-PimMailSenderRetireList {
    <#
      PURE (ONE-SENDER-1 point C, tightened 2026-11-26). The OLD sender's rights a sender change leaves behind: each sending
      identity's 'Application Mail.Send' on ANOTHER of our sender scopes (a legacy 'PIM4EntraPS-Sender*' or '*-SendScope') whose
      filter is READ and names another mailbox (§94). NOTHING is removed here -- the list is what a LATER run retires once every
      identity's own probe passes for the new sender.
      2026-10-31 (EntraPolicySuite, internal): Exchange's REST Get-ManagementScope can answer an EMPTY RecipientRestrictionFilter
      -- an unread filter (or an unlisted scope) may be this sender's own scope under an older name, so it is never listed.
      Returns @({ identity; name; role; app; principalRole; scope }).
    #>
    [CmdletBinding()] param([object[]]$ExoServicePrincipals = @(), [object[]]$Scopes = @(), [object[]]$Assignments = @(), [object[]]$Principals = @(),
                            [string]$Sender = '', [string]$ScopeName = '')
    $out = New-Object System.Collections.Generic.List[object]
    $otherMailbox = { param($n) $sc = @(@($Scopes) | Where-Object { $null -ne $_ -and "$($_.Name)" -eq "$n" })[0]
        $f = "$(if ($sc) { $sc.RecipientRestrictionFilter })"; ($f.Trim() -and $f.IndexOf("'$Sender'", [StringComparison]::OrdinalIgnoreCase) -lt 0) }
    foreach ($p in @($Principals | Where-Object { $_ })) {
        $ids = Get-PimExoAssigneeIds -ExoServicePrincipals $ExoServicePrincipals -AppId $p.appId -ObjectId $p.objectId
        foreach ($wrong in @(@($Assignments) | Where-Object { $null -ne $_ -and "$($_.Role)" -eq 'Application Mail.Send' -and
                    "$($_.CustomResourceScope)" -ne $ScopeName -and ((Test-PimLegacyMailSenderScopeName -Name "$($_.CustomResourceScope)") -or "$($_.CustomResourceScope)" -like '*-SendScope') -and
                    (& $otherMailbox "$($_.CustomResourceScope)") } |
                    Where-Object { @(Select-PimExoMailSendAssignment -Assignments @($_) -ScopeName "$($_.CustomResourceScope)" -AssigneeIds $ids -AssignmentName $p.assignmentName -AlternateNames @($p.legacyAssignmentNames)).Count })) {
            $idn = if ("$($wrong.Identity)".Trim()) { "$($wrong.Identity)".Trim() } else { "$($wrong.Name)".Trim() }
            $out.Add([pscustomobject][ordered]@{ identity = $idn; name = $(if ("$($wrong.Name)".Trim()) { "$($wrong.Name)".Trim() } else { $idn }); role = 'Application Mail.Send'
                                                 app = "$($p.appId)"; principalRole = "$(if ($p.PSObject.Properties['role'] -and "$($p.role)".Trim()) { $p.role } else { 'engine' })"; scope = "$($wrong.CustomResourceScope)" })
        }
    }
    return @($out.ToArray())
}

function Get-PimMailSendAssignmentNameBeside {
    <#
      PURE (ONE-SENDER-1 point C). Exchange role-assignment names are tenant-unique. While the OLD right is kept under -Name on
      another scope, the new one is created as '<name without -MailSend>-<scope>-MailSend' (at most 64 characters); otherwise
      -Name as it is.
    #>
    param([Parameter(Mandatory)][string]$Name, [string]$ScopeName = '', [object[]]$Assignments = @())
    $taken = @(@($Assignments) | Where-Object { $null -ne $_ -and "$($_.Name)" -ieq $Name -and "$($_.CustomResourceScope)" -ine "$ScopeName" }).Count
    if (-not $taken) { return $Name }
    $base = ($Name -replace '-MailSend$', '')
    $sc = ConvertTo-PimExoNamePart -Value $ScopeName
    $n = "$base-$sc"
    if ($n.Length -gt 55) { $n = $n.Substring(0, 55).TrimEnd('-') }
    return "$n-MailSend"
}

function Resolve-PimMailSenderRetireDecision {
    <#
      PURE (ONE-SENDER-1 point C, owner via Invardia 2026-11-26: "keep the old sender and its right until EVERY sending
      identity's own Graph probe passes for the NEW sender" -- Exchange's InScope is NOT enough, it said in-scope before
      sending really worked). May the OLD rights (-Retire) go now?
        -ProbeRead @{ ok; probe (pim.Settings MailSenderProbe); rfa (pim.Settings MailSenderProbeRfa); error }
        -Sender     the NEW sender (pim.Settings MailSender); -Roles the sending identities' roles (engine, rfa);
        -ChangedAtUtc when the new right was granted (the recorded state's 'at'); unknown -> the probe must be < 24 h old.
      'retire' only when the record is READ, is FOR THE NEW SENDER, and EVERY role is verified (sender allowed + the probe
      mailbox denied) by a probe taken AFTER the change. Anything else 'keep' (never removes blind); no old right -> 'none'.
      Returns @{ action; reason; checks = @({ role; ok; why }) }.
    #>
    param([object[]]$Retire = @(), [AllowNull()][hashtable]$ProbeRead, [string]$Sender = '', [string[]]$Roles = @('engine'), [AllowNull()][object]$ChangedAtUtc, [datetime]$NowUtc = [datetime]::UtcNow)
    $g = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $toUtc = { param($v) if ($v -is [datetime]) { $v.ToUniversalTime() } elseif ("$v".Trim()) { try { [datetime]::Parse("$v", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $null } } else { $null } }
    $keep = { param($why, $checks = @()) @{ action = 'keep'; reason = "the OLD send right is KEPT: $why"; checks = @($checks) } }
    if (-not @($Retire | Where-Object { $_ }).Count) { return @{ action = 'none'; reason = 'no old send right to retire'; checks = @() } }
    if ($null -eq $ProbeRead -or -not $ProbeRead.ok) { return (& $keep "the probe record could not be read$(if ($ProbeRead -and "$($ProbeRead.error)".Trim()) { " ($($ProbeRead.error))" }) -- nothing is removed blind") }
    $pr = $ProbeRead.probe; if ($pr -is [string]) { try { $pr = $pr | ConvertFrom-Json } catch { $pr = $null } }
    $rf = $ProbeRead.rfa; if ($rf -is [string]) { try { $rf = $rf | ConvertFrom-Json } catch { $rf = $null } }
    if ($null -eq $pr) { return (& $keep 'there is no probe record yet (pim.Settings MailSenderProbe) -- the daily probe or the first send writes it') }
    $s = "$Sender".Trim().Trim('"')
    $ps = "$(& $g $pr 'sender')".Trim()
    if (-not $s -or $ps -ine $s) { return (& $keep "the probe record is for '$ps', not the new sender '$s'") }
    $chg = & $toUtc $ChangedAtUtc
    $fresh = { param($at) $t = & $toUtc $at; if ($null -eq $t) { return $false }; if ($chg) { return ($t -gt $chg) }; return (($NowUtc.ToUniversalTime() - $t).TotalHours -lt 24) }
    $checks = New-Object System.Collections.Generic.List[object]
    foreach ($role in @(@($Roles) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)) {
        $ok = $false; $why = ''
        if ($role -eq 'rfa' -and $rf) {
            # the broker's own answer (it alone signs in as its identity)
            $rs = "$(& $g $rf 'sender')".Trim()
            if ($rs -ine $s) { $why = "the broker's probe is for '$rs', not '$s'" }
            elseif ("$(& $g $rf 'senderVerdict')" -ne 'allowed' -or "$(& $g $rf 'probeVerdict')" -ne 'denied') { $why = "the broker's probe is not verified (sender $(& $g $rf 'senderVerdict'), another mailbox $(& $g $rf 'probeVerdict'))" }
            elseif (-not (& $fresh (& $g $rf 'at'))) { $why = "the broker's probe is from before the change" }
            else { $ok = $true; $why = 'verified for the new sender after the change' }
        } else {
            $row = @(@(& $g $pr 'identities') | Where-Object { "$(& $g $_ 'role')" -ieq $role })[0]
            if (-not $row) { $why = "no probe of the $role identity" }
            elseif ("$(& $g $row 'restriction')" -ne 'verified') { $why = "the $role identity's probe is '$(& $g $row 'restriction')', not verified" }
            elseif ("$(& $g $row 'sender')".Trim() -and "$(& $g $row 'sender')".Trim() -ine $s) { $why = "the $role identity's probe is for '$(& $g $row 'sender')'" }
            elseif (-not (& $fresh $(if ("$(& $g $row 'at')".Trim() -or (& $g $row 'at') -is [datetime]) { & $g $row 'at' } else { & $g $pr 'at' }))) { $why = "the $role identity's probe is from before the change" }
            else { $ok = $true; $why = 'verified for the new sender after the change' }
        }
        $checks.Add([pscustomobject]@{ role = $role; ok = $ok; why = $why })
    }
    $bad = @($checks | Where-Object { -not $_.ok })
    if ($bad.Count -or -not $checks.Count) { return (& $keep ((@($bad | ForEach-Object { "$($_.role): $($_.why)" }) -join '; ')) $checks.ToArray()) }
    return @{ action = 'retire'; reason = 'every sending identity''s own probe passes for the new sender (after the change) -- the old send right is retired'; checks = $checks.ToArray() }
}

function New-PimMailSenderRetirePlan {
    <#
      PURE (ONE-SENDER-1 point C). The retire steps from a FRESH read: each listed old assignment still there ->
      Remove-ManagementRoleAssignment; then each old scope (never the current one) with NO role assignment of any kind left after
      those removals -> Remove-ManagementScope. Returns @{ actions; kept = @({ name; remaining }); removedScopes }.
    #>
    param([object[]]$Retire = @(), [object[]]$Assignments = @(), [object[]]$Scopes = @(), [Parameter(Mandatory)][string]$CurrentScopeName)
    $actions = New-Object System.Collections.Generic.List[object]
    $gone = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Retire | Where-Object { $_ })) {
        $hit = @(@($Assignments) | Where-Object { $null -ne $_ -and "$($_.CustomResourceScope)" -ieq "$($r.scope)" -and ("$($_.Identity)" -ieq "$($r.identity)" -or "$($_.Name)" -ieq "$($r.name)") })[0]
        if (-not $hit) { continue }
        $gone.Add($hit)
        $idn = if ("$($hit.Identity)".Trim()) { "$($hit.Identity)".Trim() } else { "$($hit.Name)".Trim() }
        $actions.Add([pscustomobject]@{ cmdlet = 'Remove-ManagementRoleAssignment'; what = "retire the OLD sender's send right $idn ($($r.app) on scope $($r.scope))"; parameters = @{ Identity = $idn; Confirm = $false } })
    }
    $left = @(@($Assignments) | Where-Object { $null -ne $_ -and -not $gone.Contains($_) })
    $cl = New-PimMailSenderOldScopeCleanupPlan -OldScopeNames @(@($Retire) | ForEach-Object { "$($_.scope)" }) -CurrentScopeName $CurrentScopeName -Scopes $Scopes -Assignments $left
    foreach ($a in @($cl.actions)) { $actions.Add($a) }
    return [pscustomobject]@{ actions = $actions.ToArray(); kept = @($cl.kept); removedScopes = @(@($cl.actions) | ForEach-Object { "$($_.parameters.Identity)" }) }
}

function Resolve-PimMailSenderChangeTime {
    <#
      PURE (ONE-SENDER-1, 3.1.69 review). The time of the sender change when THIS run did not make it and this computer has no
      state file (a re-run from another computer): the stored pim.Settings 'MailSenderSetupCheck' -- its 'retire'.at, else its
      'pendingSince' -- when it is for the same new sender (retire.sender = -ScopeSender, or the check's sender = -Sender).
      This run changed something / a local state exists / nothing usable stored -> '' (keep what the caller has).
    #>
    param([AllowNull()][object]$StoredSetupCheck, [string]$Sender = '', [string]$ScopeSender = '', [bool]$ChangedThisRun = $false, [bool]$HaveLocalState = $false)
    if ($ChangedThisRun -or $HaveLocalState -or $null -eq $StoredSetupCheck) { return '' }
    $sc = $StoredSetupCheck; if ($sc -is [string]) { try { $sc = $sc | ConvertFrom-Json } catch { return '' } }
    $g = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    $iso = { param($v) if ($v -is [datetime]) { $v.ToUniversalTime().ToString('o') } else { "$v".Trim() } }
    $rt = & $g $sc 'retire'
    if ($rt -and "$(& $g $rt 'sender')".Trim() -ieq "$ScopeSender".Trim() -and (& $iso (& $g $rt 'at'))) { return (& $iso (& $g $rt 'at')) }
    if ("$(& $g $sc 'sender')".Trim() -ieq "$Sender".Trim() -and (& $iso (& $g $sc 'pendingSince'))) { return (& $iso (& $g $sc 'pendingSince')) }
    return ''
}

function Test-PimMailSenderRetireReadBack {
    # PURE (ONE-SENDER-1 point C). After the retire: none of the retired assignments and none of the removed scopes may still be listed.
    param([object[]]$Retire = @(), [string[]]$RemovedScopes = @(), [object[]]$Assignments = @(), [object[]]$Scopes = @())
    $left = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Retire | Where-Object { $_ })) { if (@(@($Assignments) | Where-Object { $null -ne $_ -and "$($_.CustomResourceScope)" -ieq "$($r.scope)" -and ("$($_.Identity)" -ieq "$($r.identity)" -or "$($_.Name)" -ieq "$($r.name)") }).Count) { $left.Add("assignment $($r.name) on $($r.scope)") } }
    foreach ($n in @($RemovedScopes | Where-Object { "$_".Trim() })) { if (@(@($Scopes) | Where-Object { $null -ne $_ -and "$($_.Name)" -ieq $n }).Count) { $left.Add("scope $n") } }
    return @{ ok = ($left.Count -eq 0); leftovers = @($left.ToArray()) }
}

function New-PimMailSenderPreviousState {
    <#
      PURE (ONE-SENDER-1 point C). The state a sender change leaves for later runs: the OLD rights to retire (-Retire,
      Get-PimMailSenderRetireList -- KEPT until every identity's probe passes for the new sender), what this run's plan MOVES
      (a repair of a scope that matched no mailbox), and the old scopes' filters (for a -Restore). -ChangedAtUtc keeps the
      time of the change an earlier run recorded (a re-run that changes nothing must not reset it). Nothing to retire or move
      -> $null. Returns @{ at; sender; newScope; retire; assignments (removed -- none since 2026-11-26, kept for older states);
      moves; scopes = @({ name; filter }) }.
    #>
    [CmdletBinding()] param([object[]]$Plan = @(), [object[]]$Retire = @(), [object[]]$Scopes = @(), [string]$Sender = '', [string]$NewScope = '', [datetime]$NowUtc = [datetime]::UtcNow, [AllowNull()][object]$ChangedAtUtc)
    $asg = @(@($Plan) | Where-Object { $_ -and $_.PSObject.Properties['previous'] -and $_.previous -and "$($_.previous.kind)" -eq 'assignment' } | ForEach-Object {
        [ordered]@{ name = "$($_.previous.name)"; role = "$($_.previous.role)"; app = "$($_.previous.app)"; scope = "$($_.previous.scope)" } })
    $mv = @(@($Plan) | Where-Object { $_ -and $_.PSObject.Properties['previous'] -and $_.previous -and "$($_.previous.kind)" -eq 'move' } | ForEach-Object {
        [ordered]@{ identity = "$($_.previous.identity)"; fromScope = "$($_.previous.fromScope)"; toScope = "$($_.previous.toScope)" } })
    $rt = @(@($Retire) | Where-Object { $_ } | ForEach-Object { [ordered]@{ identity = "$($_.identity)"; name = "$($_.name)"; role = "$($_.role)"; app = "$($_.app)"; principalRole = "$($_.principalRole)"; scope = "$($_.scope)" } })
    if (-not $asg.Count -and -not $mv.Count -and -not $rt.Count) { return $null }
    $names = @(@($asg | ForEach-Object { $_.scope }) + @($mv | ForEach-Object { $_.fromScope }) + @($rt | ForEach-Object { $_.scope }) | Where-Object { "$_".Trim() } | Sort-Object -Unique)
    $sc = @(foreach ($n in $names) {
        $s = @(@($Scopes) | Where-Object { $null -ne $_ -and "$($_.Name)" -eq $n })[0]
        [ordered]@{ name = $n; filter = (Get-PimExoScopeFilterText $s) } })
    $at = if ($ChangedAtUtc -is [datetime]) { $ChangedAtUtc.ToUniversalTime().ToString('o') } elseif ("$ChangedAtUtc".Trim()) { "$ChangedAtUtc".Trim() } else { $NowUtc.ToUniversalTime().ToString('o') }
    return [ordered]@{ at = $at; sender = "$Sender".Trim(); newScope = "$NewScope".Trim(); retire = $rt; assignments = $asg; moves = $mv; scopes = $sc }
}

function New-PimMailSenderOldScopeCleanupPlan {
    <#
      PURE (ONE-SENDER-1 point C). AFTER the new scope read back InScope for every sending identity: which OLD scopes go.
      -OldScopeNames = the scopes this run (or the recorded earlier run) took send rights from; -Assignments = a FRESH read of
      Get-ManagementRoleAssignment (every assignee type -- a person's or another app's assignment on the scope keeps it);
      -Scopes = a fresh Get-ManagementScope. A scope is removed ONLY when it exists, is not the current one, and NO role
      assignment of any kind is left on it. Returns @{ actions = @({ cmdlet = 'Remove-ManagementScope'; parameters; what });
      kept = @({ name; remaining }) }.
    #>
    [CmdletBinding()] param([string[]]$OldScopeNames = @(), [Parameter(Mandatory)][string]$CurrentScopeName, [object[]]$Scopes = @(), [object[]]$Assignments = @())
    $actions = New-Object System.Collections.Generic.List[object]; $kept = New-Object System.Collections.Generic.List[object]
    foreach ($n in @(@($OldScopeNames) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Sort-Object -Unique)) {
        if ($n -ieq "$CurrentScopeName".Trim()) { continue }
        if (-not @(@($Scopes) | Where-Object { $null -ne $_ -and "$($_.Name)" -ieq $n }).Count) { continue }   # already gone
        $left = @(@($Assignments) | Where-Object { $null -ne $_ -and "$($_.CustomResourceScope)" -ieq $n })
        if ($left.Count) { $kept.Add([pscustomobject]@{ name = $n; remaining = $left.Count }); continue }
        $actions.Add([pscustomobject]@{ cmdlet = 'Remove-ManagementScope'; what = "remove the OLD scope $n (no role assignment is left on it; the new scope $CurrentScopeName reads back InScope)"
                                        parameters = @{ Identity = $n; Confirm = $false } })
    }
    return [pscustomobject]@{ actions = $actions.ToArray(); kept = $kept.ToArray() }
}

function New-PimMailSenderRestorePlan {
    <#
      PURE (ONE-SENDER-1 point C). Put the OLD send right back from -Previous (New-PimMailSenderPreviousState), given what
      exists NOW: the old scope again when it is gone (its recorded filter -- refused when none was recorded), each removed
      assignment that is not there (New-ManagementRoleAssignment, same name, same app, same scope), each moved assignment
      back to its old scope. Returns @{ actions; reason } (reason = cannot restore).
    #>
    [CmdletBinding()] param([AllowNull()][object]$Previous, [object[]]$Scopes = @(), [object[]]$Assignments = @())
    $g = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    if ($Previous -is [string]) { try { $Previous = $Previous | ConvertFrom-Json } catch { $Previous = $null } }
    if ($null -eq $Previous) { return [pscustomobject]@{ actions = @(); reason = 'no previous state was recorded -- nothing to put back' } }
    $actions = New-Object System.Collections.Generic.List[object]
    # ONE-SENDER-1 (2026-11-26): the old rights are KEPT now ('retire', never removed before the probe passes) -- a restore
    # normally finds them all in place and does nothing; one that is gone anyway (by hand) is put back like a removed one
    $toKeep = @(@(& $g $Previous 'assignments') + @(& $g $Previous 'retire') | Where-Object { $_ })
    $need = @(@($toKeep | ForEach-Object { "$(& $g $_ 'scope')" }) + @(@(& $g $Previous 'moves') | ForEach-Object { "$(& $g $_ 'fromScope')" }) | Where-Object { "$_".Trim() } | Sort-Object -Unique)
    foreach ($n in $need) {
        if (@(@($Scopes) | Where-Object { $null -ne $_ -and "$($_.Name)" -ieq $n }).Count) { continue }
        $rec = @(@(& $g $Previous 'scopes') | Where-Object { "$(& $g $_ 'name')" -ieq $n })[0]
        $flt = "$(& $g $rec 'filter')".Trim()
        if (-not $flt) { return [pscustomobject]@{ actions = @(); reason = "the old scope $n is gone and its filter was not recorded -- it cannot be put back safely" } }
        $actions.Add([pscustomobject]@{ cmdlet = 'New-ManagementScope'; what = "put the old scope $n back ($flt)"; parameters = @{ Name = $n; RecipientRestrictionFilter = $flt } })
    }
    foreach ($a in $toKeep) {
        $nm = "$(& $g $a 'name')".Trim(); $sc = "$(& $g $a 'scope')".Trim(); $app = "$(& $g $a 'app')".Trim()
        if (-not $nm -or -not $sc -or -not $app) { continue }
        if (@(@($Assignments) | Where-Object { $null -ne $_ -and "$($_.Name)" -ieq $nm -and "$($_.CustomResourceScope)" -ieq $sc }).Count) { continue }
        $actions.Add([pscustomobject]@{ cmdlet = 'New-ManagementRoleAssignment'; what = "put the old send right $nm back ($app on scope $sc)"
                                        parameters = @{ App = $app; Role = $(if ("$(& $g $a 'role')".Trim()) { "$(& $g $a 'role')".Trim() } else { 'Application Mail.Send' }); CustomResourceScope = $sc; Name = $nm } })
    }
    foreach ($m in @(& $g $Previous 'moves')) {
        $idn = "$(& $g $m 'identity')".Trim(); $from = "$(& $g $m 'fromScope')".Trim()
        if (-not $idn -or -not $from) { continue }
        $now = @(@($Assignments) | Where-Object { $null -ne $_ -and ("$($_.Identity)" -ieq $idn -or "$($_.Name)" -ieq $idn) })[0]
        if ($now -and "$($now.CustomResourceScope)" -ieq $from) { continue }
        $actions.Add([pscustomobject]@{ cmdlet = 'Set-ManagementRoleAssignment'; what = "move send right $idn back to its old scope $from"; parameters = @{ Identity = $idn; CustomResourceScope = $from } })
    }
    return [pscustomobject]@{ actions = $actions.ToArray(); reason = '' }
}

function Get-PimMailSenderPendingHours { 2 }

function Resolve-PimMailSenderRestoreDecision {
    <#
      PURE (ONE-SENDER-1 point C, tightened 2026-11-26). What a run does with a recorded previous state, given today's in-scope
      answer. The OLD right is never removed before every identity's probe passes (Resolve-PimMailSenderRetireDecision decides
      THAT), so "restore" mostly means: keep the old right, check it is still all there, and tell Invardia.
        'ok'      -- the new scope reads back InScope (whether the old right may go is the probe's decision, not this one);
        'restore' -- NOT in scope and the change is older than the PENDING window (2 h), or -Restore was asked: make sure the
                     old right is complete (New-PimMailSenderRestorePlan -- normally nothing to do) and tell Invardia;
        'wait'    -- NOT in scope, still inside the window: PENDING, Exchange may still be applying it;
        'none'    -- no previous state recorded.
      Returns @{ action; reason; pendingSince; ageMinutes }.
    #>
    [CmdletBinding()] param([AllowNull()][object]$Previous, [bool]$InScope, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$Restore, [double]$PendingHours = 2)
    $g = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$n] } elseif ($o.PSObject.Properties[$n]) { $o.$n } else { $null } }
    if ($Previous -is [string]) { try { $Previous = $Previous | ConvertFrom-Json } catch { $Previous = $null } }
    if ($null -eq $Previous) {
        if ($Restore) { return @{ action = 'none'; reason = '-Restore was asked, but no previous state is recorded -- nothing to put back'; pendingSince = ''; ageMinutes = 0 } }
        return @{ action = 'none'; reason = 'no previous state recorded'; pendingSince = ''; ageMinutes = 0 }
    }
    $atRaw = & $g $Previous 'at'
    # a state read back from JSON carries 'at' as a [datetime] already (ConvertFrom-Json)
    $at = if ($atRaw -is [datetime]) { $atRaw.ToUniversalTime().ToString('o') } else { "$atRaw".Trim() }
    $since = $null
    if ($at) { try { $since = [datetime]::Parse($at, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $since = $null } }
    $age = if ($since) { [Math]::Round(($NowUtc.ToUniversalTime() - $since).TotalMinutes, 0) } else { [double]::PositiveInfinity }
    if ($Restore) { return @{ action = 'restore'; reason = '-Restore was asked: the old send right is kept (anything of it that is gone is put back)'; pendingSince = $at; ageMinutes = $age } }
    if ($InScope) { return @{ action = 'ok'; reason = 'the new scope reads back InScope -- the old right stays until every identity''s probe passes for the new sender'; pendingSince = $at; ageMinutes = $age } }
    if ($age -ge ($PendingHours * 60)) { return @{ action = 'restore'; reason = "the new scope has not read back InScope within $PendingHours h of the change ($at) -- the old send right stays in place (nothing was removed)"; pendingSince = $at; ageMinutes = $age } }
    return @{ action = 'wait'; reason = "the new scope has not read back InScope yet ($age min since the change, the window is $PendingHours h)"; pendingSince = $at; ageMinutes = $age }
}

function New-PimMailSenderPendingCheck {
    <#
      PURE (ONE-SENDER-1 point C). The record a PENDING run stores in pim.Settings 'MailSenderSetupCheck': NOT confirmed (ok
      $false -- Get-PimMailSetupCheckVerdict never grants on it), inScope 'pending', when the change was made, and the
      PREVIOUS state a re-run uses to put the old send right back if the new scope does not read back within 2 h.
    #>
    param([string]$Sender, [string]$ScopeName, [object[]]$Principals = @(), [AllowNull()][object]$Previous, [string]$By = '', [string]$InScopeResource = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $ids = @(@($Principals) | Where-Object { $_ -and ("$($_.objectId)".Trim() -or "$($_.appId)".Trim()) } | ForEach-Object { [ordered]@{ kind = "$($_.kind)"; role = "$(if ($_.PSObject.Properties['role']) { $_.role } else { 'engine' })"; appId = "$($_.appId)".Trim(); objectId = "$($_.objectId)".Trim() } })
    return [ordered]@{ ok = $false; scopedMailSend = 'pending'; inScope = 'pending'; inScopeResource = "$InScopeResource".Trim(); sender = "$Sender".Trim(); scope = "$ScopeName".Trim(); identities = $ids
                       pendingSince = $(if ($Previous -and "$($Previous.at)".Trim()) { "$($Previous.at)" } else { $NowUtc.ToUniversalTime().ToString('o') })
                       previous = $Previous; at = $NowUtc.ToUniversalTime().ToString('o'); by = "$By".Trim(); source = 'Initialize-PimMailSender' }
}

function Get-PimMailSenderPreviousStatePath {
    # ONE-SENDER-1 point C: where a run keeps the previous state on THIS computer (next to its transcripts), per tenant
    # cross-platform (the Linux runner, Cloud Shell): [IO.Path] only -- Join-Path resolves PowerShell drives, and a 'C:' root
    # does not exist there; the temp folder comes from .NET ($env:TEMP / TMPDIR / /tmp)
    param([Parameter(Mandatory)][string]$TenantId, [string]$Root = '')
    $tmp = [IO.Path]::GetTempPath(); if (-not "$tmp".Trim()) { $tmp = "$env:TEMP" }
    $base = if ("$Root".Trim()) { "$Root".Trim() } else { [IO.Path]::Combine($tmp, 'pim-manager-logs') }
    return [IO.Path]::Combine($base, ("Initialize-PimMailSender-previous-{0}.json" -f (("$TenantId".Trim()) -replace '[^0-9A-Za-z-]', '')))
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
    # ONE-SENDER-1 point C, TIGHTENED (owner via Invardia 2026-11-26): the same identity's send right on ANOTHER of our sender
    # scopes (an OLD sender -- §94's wrong-mailbox grant) is NO LONGER removed here. The run that grants the new right KEEPS
    # the old one; it is retired by a LATER run, only when every sending identity's own Graph probe passes for the NEW sender
    # (Get-PimMailSenderRetireList -> Resolve-PimMailSenderRetireDecision -> New-PimMailSenderRetirePlan).
    $retire = @(Get-PimMailSenderRetireList -ExoServicePrincipals $ExoServicePrincipals -Scopes $Scopes -Assignments $Assignments -Principals $Principals -Sender $Sender -ScopeName $ScopeName)
    foreach ($p in @($Principals)) {
        $ids = Get-PimExoAssigneeIds -ExoServicePrincipals $ExoServicePrincipals -AppId $p.appId -ObjectId $p.objectId
        if (-not @(Select-PimExoMailSendAssignment -Assignments $Assignments -ScopeName $ScopeName -AssigneeIds $ids -AssignmentName $p.assignmentName -AlternateNames @($p.legacyAssignmentNames)).Count) {
            # assignment names are tenant-unique: while the old right is KEPT under the same name, the new one gets the scope in
            # its name (Get-PimMailSendAssignmentNameBeside)
            $nm = Get-PimMailSendAssignmentNameBeside -Name $p.assignmentName -ScopeName $ScopeName -Assignments $Assignments
            $plan.Add([pscustomobject]@{ cmdlet = 'New-ManagementRoleAssignment'; what = "scoped send right for $($p.kind) $($p.appId)$(if (@($retire | Where-Object { $_.app -eq $p.appId }).Count) { ' (the OLD sender''s right is kept until the probe passes)' })"
                                         parameters = @{ App = $p.appId; Role = 'Application Mail.Send'; CustomResourceScope = $ScopeName; Name = $nm } })
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
    # MAIL-SCOPE-SMTP (2026-11-11): -Confirmed means Exchange's Test-ServicePrincipalAuthorization answered InScope = True for
    # every sending identity on -InScopeResource (the mailbox's primary SMTP). No -InScopeResource -> $null: an assignment
    # that merely exists is not a proof (a customer's scope matched NO mailbox while every object existed).
    param([bool]$Confirmed, [string]$Sender, [string]$ScopeName, [object[]]$Principals = @(), [string]$By = '', [string]$InScopeResource = '', [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not $Confirmed -or -not "$Sender".Trim() -or -not "$ScopeName".Trim() -or -not "$InScopeResource".Trim()) { return $null }
    # ONE-SENDER-1 point B: + role (engine | rfa) -- the check lists EVERY sending identity, the RFA broker's too
    $ids = @(@($Principals) | Where-Object { $_ -and ("$($_.objectId)".Trim() -or "$($_.appId)".Trim()) } | ForEach-Object { [ordered]@{ kind = "$($_.kind)"; role = "$(if ($_.PSObject.Properties['role'] -and "$($_.role)".Trim()) { $_.role } else { 'engine' })"
                                                                                                                                  roles = @(if ($_.PSObject.Properties['roles'] -and @($_.roles).Count) { @($_.roles) } else { @("$(if ($_.PSObject.Properties['role'] -and "$($_.role)".Trim()) { $_.role } else { 'engine' })") })
                                                                                                                                  appId = "$($_.appId)".Trim(); objectId = "$($_.objectId)".Trim() } })
    if (-not $ids.Count) { return $null }
    return [ordered]@{ ok = $true; scopedMailSend = 'confirmed'; inScope = 'confirmed'; inScopeResource = "$InScopeResource".Trim(); sender = "$Sender".Trim(); scope = "$ScopeName".Trim(); identities = $ids
                       at = $NowUtc.ToUniversalTime().ToString('o'); by = "$By".Trim(); source = 'Initialize-PimMailSender' }
}

function New-PimMailSenderAddressRecord {
    <#
      PURE (INSTALL-FIX, REQUIREMENTS 100.25 item 4). The record Initialize-PimMailSender stores in pim.Settings
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
    # 🔒 SECURE-WEB-1 / MAIL-WEB-RIGHTS-1: the command names the ENGINE job only. -ManagerAppName is still accepted from
    # old callers but never printed -- the web app sends no mail, so its identity is never given a send right.
    if ("$SubscriptionId".Trim() -and "$ResourceGroup".Trim() -and "$TickJobName".Trim()) {
        $run += " -SubscriptionId $("$SubscriptionId".Trim()) -ResourceGroup $("$ResourceGroup".Trim()) -TickJobName $("$TickJobName".Trim())"
    } elseif (-not $mi.Count) { $run += ' -ManagedIdentityObjectId <engine job identity object id>' }
    $run += ' -SqlServerFqdn ' + (& $v $SqlServerFqdn '<server>.database.windows.net')
    return @(Get-PimSupportScriptCommand -Script 'Initialize-PimMailSender' -Run @($run))
}

function Resolve-PimDeployMailSignedIn {
    <#
      MAIL-1 (framework 12.3 (a)): in a SIGNED-IN deploy, may the mail-sender step run? PURE over the signed-in account (Get-PimSetupAccount: { tenantId; user = { name; type } }).
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
    # or their directory roles) AND for whom the signed-in session mints an Exchange Online token (-PersonExoToken) runs it too: run = $true,
    # person = $true, appId = '' -> Initialize-PimMailSender -UseSignedInAccount with no -AdminAppId (their own role; no app
    # is granted anything). Anyone else stays the loud, non-fatal skip with the Get Started follow-up.
    [CmdletBinding()] param([object]$Account, [string]$TenantId, [string[]]$ManagedIdentityObjectId = @(), [string]$SubscriptionId, [string]$ResourceGroup,
                            [string]$TickJobName, [string]$ManagerAppName, [string]$SqlServerFqdn,
                            [string[]]$PersonRoleTemplateIds = @(), [bool]$PersonExoToken = $false)
    $cmd = New-PimMailSenderCommand -TenantId $TenantId -ManagedIdentityObjectId $ManagedIdentityObjectId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup `
               -TickJobName $TickJobName -ManagerAppName $ManagerAppName -SqlServerFqdn $SqlServerFqdn
    # REQUIREMENTS 100.77: plain text (this window / the install log) -- the doc page is ONE line UNDER the two command lines.
    $after = @(
        '  DO IT AFTERWARDS (no certificate): PIM Manager > Get Started > Mail sender -- choose Shared mailbox (it prints this',
        '  command with the values filled in: an Exchange or Global Administrator runs it and signs in in the browser) or SMTP relay:') +
        @(@($cmd) | ForEach-Object { "    $_" }) + @("    $(Get-PimSupportScriptDocLine -Script 'Initialize-PimMailSender')")
    $type = "$($Account.user.type)".Trim()
    $name = "$($Account.user.name)".Trim()
    $tid  = "$($Account.tenantId)".Trim()
    if (-not $Account -or -not $name) {
        return @{ run = $false; appId = ''; why = 'no signed-in account'; lines = @('mail sender: NOT RUN -- no signed-in account could be read.') + $after }
    }
    if ("$TenantId".Trim() -and $tid -and $tid -ine "$TenantId".Trim()) {
        return @{ run = $false; appId = ''; why = 'signed in to another tenant'; lines = @("mail sender: NOT RUN -- the signed-in account is in tenant $tid, not $TenantId.") + $after }
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
