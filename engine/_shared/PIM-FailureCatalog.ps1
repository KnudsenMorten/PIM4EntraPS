#Requires -Version 5.1
<#
.SYNOPSIS
    Engine item failures, CLASSIFIED: what failed, why, what to do -- and, where the data is the
    problem, a fix the operator can stage with one click.

.DESCRIPTION
    WHY THIS EXISTS (operator, 2026-09-12: "the eror msg was useless, as you have more details here.
    improve my ability to solve this with auto-fix capability"). A failed job said only
        "17 item(s) FAILED to apply in [AzRes:errors=17] ... see the [x] lines above"
    and the [x] lines lived in a container log nobody can reach from the Manager. Diagnosing those 17
    took a read-only investigation of Log Analytics, ARM, Graph and SQL. Every fact that investigation
    found is a fact the engine already HAD at the moment the item failed -- it just threw it away.

    Three pieces:
      * Get-PimFailureClassification -- PURE. Raw error text + the row -> a stable code, a plain title,
        the cause, the remedy, whether retrying can help, and the fixes that apply to this row.
      * Update-PimEngineItemFailures -- the CURRENTLY FAILING set per scope, persisted in SQL
        (pim.Settings['EngineItemFailures']; v2 has no files), with first-seen / last-seen / count so
        "new today" and "failing since August" are different facts on screen.
      * Format-PimFailureSummary -- the one-line job result, grouped by cause instead of "see above".

    AUTO-FIX NEVER WRITES. The Manager is read-only (REQUIREMENTS 65): a fix is STAGED into Pending changes as an
    ordinary row edit or removal, and an operator commits it. Fixes are offered only where the change
    is unambiguous from the row itself; everything else carries a remedy, not a button.
#>

$script:PimFailureRules = @(
    # ---- safety holds: FIRST, because a hold message quotes counts, hashes and rule names that the
    #      generic rules below would otherwise match (a "500" in a count is not a service error) -------
    @{ code = 'AZ-POLICY-MASS-HOLD'
       match = { param($m, $row) $m -match '(?i)AZ-POLICY-MASS-HOLD' }
       title = 'Azure PIM policy changes HELD by the mass-change circuit breaker'
       cause = 'This run would have changed more Azure resource PIM policies than the breaker allows at once (too many policies, too large a share of those checked, or too many WEAKENING changes: MFA/justification/ticketing removed from activation, a longer maximum duration, expiration no longer required, a notification recipient or default notifications removed; admin-path enablement aligned to the template is counted as a change but not as weakening, because the engine identity can never present MFA). A mass change is what a wrong template or a wrong template link looks like, so the engine wrote NOTHING and recorded the plan. The item lists the counts, the plan hash, the largest policies and every weakening change.'
       remedy = 'Review the plan (Get-PimAzResPolicyMassHold). If it is intended, approve exactly that plan hash (Approve-PimAzResPolicyMassChange -PlanHash <hash> -By <you>; valid 24 hours) and the next run applies it. If it is not intended, fix the template or the rows instead. Any change to the plan changes the hash and needs a new approval.'
       retryable = $false; severity = 'policy'
       fixes = @() }

    # The same breaker on the two GRAPH policy providers (operator, 2026-09-13). Own codes, own hold and
    # approval records: an approval of one provider's plan never covers another's.
    @{ code = 'GROUP-POLICY-MASS-HOLD'
       match = { param($m, $row) $m -match '(?i)GROUP-POLICY-MASS-HOLD' }
       title = 'PIM for Groups policy changes HELD by the mass-change circuit breaker'
       cause = 'This run would have changed more PIM for Groups policies (member and owner) than the breaker allows at once: too many policies, too large a share of those checked, or too many WEAKENING changes (MFA/justification/ticketing removed from activation, a longer maximum duration, expiration no longer required, a named notification recipient removed, approval turned off). Admin-path enablement and notification defaults aligned to the template count as changes, not as weakening. A mass change is what a wrong template or a wrong template link looks like, so the engine wrote NOTHING and recorded the plan.'
       remedy = 'Review the plan in Jobs > Engine logs & errors (or Get-PimPolicyMassHold -Provider GroupsPolicies). If it is intended, approve exactly that plan hash (Approve-PimPolicyMassChange -Provider GroupsPolicies -PlanHash <hash> -By <you>; valid 24 hours) and the next run applies it. If not, fix the template or the rows. Any change to the plan changes the hash and needs a new approval.'
       retryable = $false; severity = 'policy'
       fixes = @() }
    @{ code = 'ENTRA-POLICY-MASS-HOLD'
       match = { param($m, $row) $m -match '(?i)ENTRA-POLICY-MASS-HOLD' }
       title = 'Entra role policy changes HELD by the mass-change circuit breaker'
       cause = 'This run would have changed more Entra directory role PIM policies than the breaker allows at once: too many policies, too large a share of those checked, or too many WEAKENING changes (MFA/justification/ticketing removed from activation, a longer maximum duration, expiration no longer required, a named notification recipient removed, approval turned off). Admin-path enablement and notification defaults aligned to the template count as changes, not as weakening. A mass change is what a wrong template or a wrong template link looks like, so the engine wrote NOTHING and recorded the plan.'
       remedy = 'Review the plan in Jobs > Engine logs & errors (or Get-PimPolicyMassHold -Provider EntraRolePolicies). If it is intended, approve exactly that plan hash (Approve-PimPolicyMassChange -Provider EntraRolePolicies -PlanHash <hash> -By <you>; valid 24 hours) and the next run applies it. If not, fix the template or the rows. Any change to the plan changes the hash and needs a new approval.'
       retryable = $false; severity = 'policy'
       fixes = @() }

    # One or more per-rule PATCHes on an Azure resource PIM policy did not apply. Ahead of the generic
    # rules because the message quotes ARM's raw per-rule errors, which may contain any of their words.
    @{ code = 'AZ-POLICY-RULE-FAILED'
       match = { param($m, $row) $m -match '(?i)AZ-POLICY-RULE-FAILED' }
       title = 'Azure PIM policy rule(s) did not apply'
       cause = 'The engine PATCHes each differing rule of an Azure resource PIM policy in its own request (as v1 did), so one refused rule never blocks the others. The rules named in the message were refused by Azure, or were accepted but did not read back with the template value; the message carries Azure''s raw error for each rule, and lists the rules that did apply.'
       remedy = 'Read the raw Azure error per rule. The item is retried on every run; a permission error means the engine identity needs roleManagementPolicies/write at that scope.'
       retryable = $true; severity = 'policy'
       fixes = @() }

    # ---- data problems: the row can never apply as written -----------------------------------
    @{ code = 'AZ-SUB-PLACEHOLDER'
       match = { param($m, $row) ($m + ' ' + "$($row.AzScope)") -match '(?i)/subscriptions/0{8}-0{4}-0{4}-0{4}-0{12}' }
       title = 'Placeholder subscription -- this row was never filled in'
       cause = 'The scope is the all-zeros subscription from the shipped template. No such subscription exists, so Azure answers "subscription not found" on every run.'
       remedy = 'Remove the row, or replace the subscription id in AzScope with a real one.'
       retryable = $false; severity = 'data'
       fixes = @(@{ id = 'delete-row'; label = 'Remove this row'; kind = 'delete-row' }) }

    @{ code = 'AZ-SUB-NOT-FOUND'
       match = { param($m, $row) $m -match '(?i)SubscriptionNotFound|subscription .* (could not be found|was not found)' }
       title = 'Subscription not found'
       cause = 'The subscription in AzScope does not exist, was deleted, or is in a different tenant.'
       remedy = 'Correct the subscription id in AzScope, or remove the row if the subscription is gone.'
       retryable = $false; severity = 'data'
       fixes = @(@{ id = 'delete-row'; label = 'Remove this row'; kind = 'delete-row' }) }

    @{ code = 'AZ-POLICY-NO-APPROVER'
       match = { param($m, $row) $m -match '(?i)AZ-POLICY-NO-APPROVER' }
       title = 'Azure PIM policy template requires approval, but no approver resolved'
       cause = 'The policy template linked to this Azure role requires approval, and no approver could be resolved (the assignment row''s ApproverUpns, else the owners of the assigned groups: Owners, SponsorUpn, then the Department''s owners). The engine never writes a policy half-configured, so NOTHING was written to it.'
       remedy = 'Set Owners (or SponsorUpn, or the Department''s owners) on the group definition the assignment names, or link a template without approval. The next run then applies the whole template.'
       retryable = $false; severity = 'data'
       fixes = @() }

    @{ code = 'AZ-POLICY-APPROVAL'
       match = { param($m, $row) $m -match '(?i)AZ-POLICY-APPROVAL' }
       title = 'Azure PIM policy approval kept (not in the template)'
       cause = 'The Azure role has approval switched on, and its policy template does not declare approval. The engine never removes an approval (that would silently lower security), so it is KEPT. Informational: shown on the verification report, not a failed item.'
       remedy = 'Nothing to do if the approval is intended. To make the template say so, link the assignment to an approval template.'
       retryable = $false; severity = 'info'
       fixes = @() }

    @{ code = 'AZ-POLICY-MAX-DURATION'
       match = { param($m, $row) $m -match '(?i)ExpirationRule|greater than (the )?maximum allowed duration' }
       title = 'Azure PIM policy rejects the assignment duration'
       cause = 'The PIM policy for this role at this scope allows a shorter ACTIVE assignment than the row requests. Measured on internal: these policies were only partly written (11 rules, no admin-assignment expiration rule), so Azure applies a short default.'
       remedy = 'Make the assignment Eligible (activated on demand), shorten it, or repair the role''s PIM policy at that scope so it allows the duration.'
       retryable = $false; severity = 'policy'
       fixes = @(@{ id = 'make-eligible'; label = 'Make it Eligible'; kind = 'set'; set = @{ AssignmentType = 'Eligible' } }) }

    @{ code = 'AZ-POLICY-MFA'
       match = { param($m, $row) $m -match '(?i)MfaRule|Multi-?factor authentication is required' }
       title = 'Azure PIM policy requires MFA -- the engine can never satisfy it'
       cause = 'The PIM policy requires multi-factor authentication for an ACTIVE assignment. The engine runs as a managed identity, which cannot perform MFA.'
       remedy = 'Make the assignment Eligible (the person does MFA when activating), or remove the MFA requirement on active assignment in that policy.'
       retryable = $false; severity = 'policy'
       fixes = @(@{ id = 'make-eligible'; label = 'Make it Eligible'; kind = 'set'; set = @{ AssignmentType = 'Eligible' } }) }

    @{ code = 'ARM-ROLE-NOT-FOUND'
       match = { param($m, $row) $m -match "(?i)ARM role '([^']+)' not found" }
       title = 'Azure role name does not exist at this scope'
       cause = 'No Azure role definition with this name exists at the scope. Common causes: a misspelt or invented name (e.g. "Sentinel Operator" -- the real roles are "Microsoft Sentinel Contributor / Responder / Reader"), or a custom role not assignable at that scope.'
       remedy = 'Correct AzScopePermission to an existing role name, or remove the row.'
       retryable = $false; severity = 'data'
       fixes = @(@{ id = 'delete-row'; label = 'Remove this row'; kind = 'delete-row' }) }

    @{ code = 'ENTRA-ROLE-UNRESOLVED'
       match = { param($m, $row) $m -match '(?i)unresolved group/role' }
       title = 'Entra group or role could not be resolved'
       cause = 'Either the group for this GroupTag does not exist yet, or the role name is not in the tenant''s role catalog. (Before 2026-09-12 this also appeared for EVERY role because the scheduler never loaded the role catalog.)'
       remedy = 'Check that the group exists (it is created by the Groups job) and that RoleDefinitionName matches an Entra role exactly.'
       retryable = $true; severity = 'data'
       fixes = @() }

    # §70.19 (2026-09-13, measured live on internal): Entra refuses an ACTIVE membership of a group in a
    # role-assignable group. The engine used to count this as "skipped" with a console line only, so the
    # operator's delegation never deployed while the Manager showed nothing failing.
    @{ code = 'ENTRA-NESTING-ROLE-ASSIGNABLE'
       match = { param($m, $row) $m -match '(?i)Nesting is currently not supported' }
       title = 'Active group nesting into a role-assignable group -- Entra refuses it'
       cause = 'The row makes a group an ACTIVE member of a role-assignable group. Entra ID does not support that (a role-assignable group cannot have groups as active members), so it can never apply as written. The same delegation as Eligible is supported: members activate it just-in-time.'
       remedy = 'Make the nesting Eligible (the delegation wizards now always write Eligible here), or remove the row.'
       retryable = $false; severity = 'data'
       fixes = @(@{ id = 'make-eligible'; label = 'Make it Eligible'; kind = 'set'; set = @{ AssignmentType = 'Eligible' } }) }

    # A group the row needs does not exist (yet). Almost always ORDER, not data: the Groups job creates the
    # group, and every item that names it fails until then -- or for good, when the create itself failed
    # (measured 2026-09-13: a 403 on creating PIM-ROLE-test1 surfaced as 5 "Unrecognised failure" items).
    @{ code = 'GROUP-NOT-CREATED-YET'
       match = { param($m, $row) $m -match "(?i)unresolved target/source|unresolved principal/group|group '[^']+' not found" }
       title = 'The group this item needs does not exist yet'
       cause = 'The item names a group that is not in Entra ID. New groups are created by the Groups job (delta-groups-deploy); until that has run, every membership, policy and assignment naming the group waits. If the group''s own create failed, this item keeps failing until that is fixed -- look for a failed Groups item for the same group (for example "The engine identity lacks a permission").'
       remedy = 'Nothing to do if the group was committed moments ago: the next group-deploy creates it and this item applies on the run after. If it persists, fix the failing Groups item for that group first, or check that the GroupTag / Username in the row is spelled as defined.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    # ---- workload bindings (PIM-Assignments-Workloads, WorkloadConnectors scope) ----------------
    # The provider prefixes its data problems with these codes, so they are matched exactly and never
    # confused with a permission or service error in the same message.
    @{ code = 'WORKLOAD-CONNECTOR-UNKNOWN'
       match = { param($m, $row) $m -match 'WORKLOAD-CONNECTOR-UNKNOWN' }
       title = 'Workload row names a connector that does not exist'
       cause = 'The Workload column must be the id of a shipped workload connector (the error lists the supported ids). The row is not applied at all.'
       remedy = 'Correct the Workload column to a supported connector id, or remove the row.'
       retryable = $false; severity = 'data'
       fixes = @(@{ id = 'delete-row'; label = 'Remove this row'; kind = 'delete-row' }) }

    @{ code = 'WORKLOAD-ROLE-NOT-FOUND'
       match = { param($m, $row) $m -match 'WORKLOAD-ROLE-NOT-FOUND' }
       title = 'Workload role name does not exist'
       cause = 'The workload has no role with this RoleName (the error lists the roles it does have). For Defender XDR a custom role must be created first; roles are matched by exact name.'
       remedy = 'Correct RoleName to an existing role, create the custom role in the workload, or remove the row.'
       retryable = $true; severity = 'data'
       fixes = @(@{ id = 'delete-row'; label = 'Remove this row'; kind = 'delete-row' }) }

    @{ code = 'WORKLOAD-GROUP-UNRESOLVED'
       match = { param($m, $row) $m -match 'WORKLOAD-GROUP-UNRESOLVED' }
       title = 'Workload row names a group that does not exist'
       cause = 'The GroupTag did not resolve to an Entra group (by its defined group name, by name, or as PIM-<tag>).'
       remedy = 'Check that the group exists (it is created by the Groups job) and that GroupTag matches it.'
       retryable = $true; severity = 'data'
       fixes = @() }

    @{ code = 'WORKLOAD-RESOURCE-MISSING'
       match = { param($m, $row) $m -match 'WORKLOAD-RESOURCE-MISSING' }
       title = 'Workload row is missing its Resource'
       cause = 'This connector works per target (an app, an environment, an organisation) and the row does not say which.'
       remedy = 'Fill in the Resource column as the connector''s prerequisites describe, or remove the row.'
       retryable = $false; severity = 'data'
       fixes = @(@{ id = 'delete-row'; label = 'Remove this row'; kind = 'delete-row' }) }

    @{ code = 'WORKLOAD-CONTAINER-MISSING'
       match = { param($m, $row) $m -match 'WORKLOAD-CONTAINER-MISSING' }
       title = 'The group is not provisioned in the workload yet'
       cause = 'Dataverse, Business Central and Azure DevOps grant roles to a container that represents the Entra group (a group team, a security group, a subject). It does not exist yet, so there is nothing to attach the role to.'
       remedy = 'Provision the group in the workload once (the connector''s prerequisites say how); the next run attaches the role.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    @{ code = 'WORKLOAD-ACTION-UNKNOWN'
       match = { param($m, $row) $m -match 'WORKLOAD-ACTION-UNKNOWN|WORKLOAD-CONNECTOR-AUTH' }
       title = 'Workload row cannot be applied as written'
       cause = 'Either the Action is not Assign or Remove, or the connector uses an authentication adapter this engine cannot request a token for.'
       remedy = 'Set Action to Assign or Remove. For an adapter error, the connector definition needs a supported auth value.'
       retryable = $false; severity = 'data'
       fixes = @() }

    # ---- Temporary Access Pass (s68.6 #21, measured live on internal 2026-09-12) --------------
    # Ahead of the generic rules: the TAP refusal is an HTTP 400 whose text is the whole diagnosis.
    @{ code = 'TAP-TENANT-POLICY'
       match = { param($m, $row) $m -match '(?i)Tenant Policy does not allow|Invalid IsUsableOnce' }
       title = 'The tenant TAP policy refused the Temporary Access Pass request'
       cause = 'The tenant''s Temporary Access Pass policy (Authentication methods > Temporary Access Pass) does not allow what was requested -- typically a MULTI-use pass on a tenant that only allows one-time passes, or a lifetime outside its minimum/maximum. The engine conforms the request to that policy when it can read it, and retries once as one-time use on this exact refusal; this item means the request still did not fit.'
       remedy = 'Grant Policy.Read.All to the engine identity so it reads the TAP policy up front, or align the policy (one-time use, lifetime range) with the admin row''s TAPLifetimeHours. Nothing in the row itself is wrong.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    @{ code = 'TAP-NO-RECIPIENT'
       match = { param($m, $row) $m -match '(?i)nowhere to deliver the TAP|no forwarding address \(MailForwardAddress\) and no ManagerEmail|no recipient \(office user email' }
       title = 'No one to send the Temporary Access Pass to'
       cause = 'No recipient resolved for this admin. An admin''s mail (its TAP included) goes to the owners of its SPONSOR DEPARTMENT (71.19); a per-admin office-user email (ForwardMailsToContact + MailForwardAddress) overrides that. Neither resolved. A TAP is a sign-in credential and is delivered by mail only, so it is refused BEFORE anything is created -- nothing was changed.'
       remedy = 'Set the admin''s Department and set Owners on that department (PIM-Definitions-Departments) -- or set an office user email with Edit on the admin (Access > Admin accounts) -- commit, and the next run issues the TAP.'
       retryable = $false; severity = 'data'
       fixes = @() }

    # SEC-30 (ss33.28): the engine REFUSES an AU-scoped role that sits in the tenant-wide entity.
    @{ code = 'AU-SCOPE-REFUSED'
       match = { param($m, $row) $m -match '(?i)AU-SCOPE-REFUSED' }
       title = 'An AU-scoped role row is in the tenant-wide role entity -- refused'
       cause = 'The row in PIM-Assignments-Roles-Groups carries PermissionScope ''AU:<name>''. That entity assigns roles over the WHOLE tenant, so applying it would have granted the role tenant-wide instead of over the administrative unit. Nothing was changed.'
       remedy = 'Move the grant to PIM-Assignments-Roles-AUs (same GroupTag and role, AdministrativeUnitTag = the AU) and delete this row, then commit.'
       retryable = $false; severity = 'data'
       fixes = @() }

    # ---- REQ-U wave 2: Defender XDR custom roles (DefenderXdrRoles, PIM-WorkloadRoles.ps1) -----------
    @{ code = 'DEFENDER-PERMISSION-PREREQUISITE'
       match = { param($m, $row) $m -match '(?i)DEFENDER-PERMISSION-PREREQUISITE' }
       title = 'Defender XDR refused a permission its prerequisite is missing for'
       cause = 'The tenant would not store the custom role with these permissions ("not a valid permission for storage"). A permission group whose prerequisite is not in place is refused -- Data Operations needs a Microsoft Sentinel workspace onboarded to Defender XDR. Nothing was created for this row.'
       remedy = 'Run tools\setup\Initialize-PimWorkloadPrereqs.ps1 -Workload DefenderXdr (it checks the prerequisite and says what to fix); the next run creates the role and its assignment.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    @{ code = 'DEFENDER-ROLE-AMBIGUOUS'
       match = { param($m, $row) $m -match '(?i)DEFENDER-ROLE-AMBIGUOUS' }
       title = 'Two Defender XDR roles share this name -- PIM will not pick one'
       cause = 'The row binds a Defender XDR role by name and more than one live role carries that name. Binding either could grant the wrong permissions, so nothing was assigned.'
       remedy = 'Rename or delete the extra role in the Defender portal (Settings > Permissions > Roles); the next run binds the one that is left.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    @{ code = 'DEFENDER-ASSIGNMENT-SHARED'
       match = { param($m, $row) $m -match '(?i)DEFENDER-ASSIGNMENT-SHARED' }
       title = 'The Defender XDR assignment is shared with other principals'
       cause = 'The group''s role assignment has the wrong data sources, but the same assignment also holds other principals. Re-creating it with the right data sources would remove their access, so nothing was changed.'
       remedy = 'Give the group its own assignment (or split the shared one) in the Defender portal; the next run sets its data sources.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    # ---- environment problems: nothing in the row to fix ---------------------------------------
    @{ code = 'REMOVE-BUDGET-HELD'
       match = { param($m, $row) $m -match '(?i)REMOVE-BUDGET-HELD' }
       title = 'Removals held -- more than the per-run removal budget in one scope'
       cause = 'This run would remove more assignments in one scope than the per-run removal budget allows (Remove rows plus assignment-type changes), so the engine removed NOTHING in that scope. The budget exists so a data mistake cannot strip access in bulk.'
       remedy = 'Check that the Remove rows and type changes for this scope are intended, then apply them in batches no larger than the budget (commit a batch, let the engine run, commit the next).'
       retryable = $false; severity = 'data'
       fixes = @() }

    @{ code = 'PERMISSION-DENIED'
       match = { param($m, $row) $m -match '(?i)\b403\b|Forbidden|AuthorizationFailed|InsufficientPermissions|Authorization_RequestDenied' }
       title = 'The engine identity lacks a permission'
       cause = 'Azure or Graph refused the request for the identity the engine runs as.'
       remedy = 'Grant the missing permission to the engine''s runtime identity (the scheduled job''s managed identity). The raw error names the action that was denied.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    @{ code = 'THROTTLED'
       match = { param($m, $row) $m -match '(?i)\b429\b|TooManyRequests|throttl' }
       title = 'Throttled by Microsoft'
       cause = 'The service rate-limited the engine and the retry budget ran out.'
       remedy = 'Nothing to change -- the item is retried on the next run. If it persists, spread the job cadence.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    @{ code = 'SERVICE-ERROR'
       match = { param($m, $row) $m -match '(?i)\bHTTP 5\d\d\b|\b50[0234]\b|An error has occurred|InternalServerError|ServiceUnavailable' }
       title = 'Microsoft service error'
       cause = 'Azure or Graph returned a server error. If it repeats for the SAME scope every run, the object on the Microsoft side is likely broken (measured on internal: even a plain read of that policy returned 500).'
       remedy = 'Retried automatically. If it keeps failing, open a Microsoft support case for that scope, or remove the row.'
       retryable = $true; severity = 'environment'
       fixes = @() }
)

function Get-PimFailureClassification {
    <# PURE. First matching rule wins (rules are ordered specific -> general). #>
    [CmdletBinding()]
    param([string]$Message, [AllowNull()][object]$Row)
    $m = "$Message"
    foreach ($r in $script:PimFailureRules) {
        $hit = $false
        try { $hit = [bool](& $r.match $m $Row) } catch { $hit = $false }
        if ($hit) {
            return [pscustomobject]@{
                code = $r.code; title = $r.title; cause = $r.cause; remedy = $r.remedy
                retryable = [bool]$r.retryable; severity = $r.severity; fixes = @($r.fixes)
            }
        }
    }
    return [pscustomobject]@{
        code = 'UNCLASSIFIED'; title = 'Unrecognised failure'; cause = 'The engine has no explanation for this error yet -- the raw message is shown below.'
        remedy = 'Read the raw error. If it recurs, it should be added to the failure catalog.'
        retryable = $true; severity = 'unknown'; fixes = @()
    }
}

function ConvertTo-PimFailureRowSnapshot {
    # The row as plain strings, so it survives JSON and can be matched against the Manager's grid.
    param([AllowNull()][object]$Row)
    $o = [ordered]@{}
    if ($null -eq $Row) { return $o }
    $props = if ($Row -is [System.Collections.IDictionary]) { @($Row.Keys) } else { @($Row.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($k in $props) {
        if ("$k" -match '^(pim|_)') { continue }
        $v = if ($Row -is [System.Collections.IDictionary]) { $Row[$k] } else { $Row.$k }
        if ($v -is [string] -or $v -is [ValueType] -or $null -eq $v) { $o["$k"] = "$v" }
    }
    return $o
}

function Format-PimAzureScopeLabel {
    <# PURE. '/providers/Microsoft.Management/managementGroups/mg-x' -> 'management group mg-x', etc. #>
    param([string]$Scope)
    $s = "$Scope".Trim()
    if (-not $s) { return '' }
    if ($s -match '(?i)/resourceGroups/([^/]+)/providers/.+/([^/]+)$') { return "resource $($Matches[2]) (resource group $($Matches[1]))" }
    if ($s -match '(?i)/resourceGroups/([^/]+)$') { return "resource group $($Matches[1])" }
    if ($s -match '(?i)managementGroups/([^/]+)$') { return "management group $($Matches[1])" }
    if ($s -match '(?i)^/subscriptions/([^/]+)$') { return "subscription $($Matches[1])" }
    return $s
}

function Get-PimFailureItemLabel {
    <#
      PURE. One readable sentence for a failing item: who gets what, where. Operator, 2026-09-13, on an
      AZ-POLICY-MFA item whose only identifier was '891857a0-…|/providers/…|rid:acdd72a7-…|active':
      "could be nice to see which role this is, so i can delete the policy". The row the item came from
      already names the group, role, scope and type; the key stays available as the technical id.
    #>
    param([string]$Key, [AllowNull()][object]$Row)
    $g = { param($n) if ($null -eq $Row) { return '' }; $v = if ($Row -is [System.Collections.IDictionary]) { $Row[$n] } else { $p = $Row.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }; "$v".Trim() }
    $type = & $g 'AssignmentType'
    $t = if ($type) { " ($type)" } else { '' }
    $grp = { param($tag) if (-not $tag) { return '' }; if ($tag -match '(?i)^PIM-') { $tag } else { "PIM-$tag" } }
    $tgt = & $g 'TargetGroupTag'; $src = & $g 'SourceGroupTag'
    if ($tgt -and $src) { return "group $(& $grp $tgt) -> member of group $(& $grp $src)$t" }
    $user = & $g 'Username'; $gt = & $g 'GroupTag'
    $gname = & $g 'GroupName'; $gdisp = if ($gname) { $gname } else { & $grp $gt }
    if ($user -and $gt) { return "$user -> member of group $gdisp$t" }
    # A LIVE membership row (a drift 'extra' carries the live row, not a desired one) has no Username or
    # TargetGroupTag -- only principalId + groupId + GroupTag. Operator, 2026-09-14, on the Drift page:
    # "i cannot see what that guid is". The drift snapshot stamps PrincipalName/PrincipalKind/GroupName
    # (Add-PimDriftPayloadNames, PIM-DriftSnapshot.ps1) because this function stays PURE.
    $pName = & $g 'PrincipalName'
    if ($pName -and ($gt -or $gname)) {
        $who = if ((& $g 'PrincipalKind') -ieq 'group') { "group $pName" } else { $pName }
        return "$who -> member of group $gdisp$t"
    }
    $prin = & $g 'principalId'
    if ($prin -and (& $g 'groupId') -and ($gt -or $gname) -and -not (& $g 'RoleDefinitionName') -and -not (& $g 'AzScope')) {
        return "unresolved principal $prin -> member of group $gdisp$t"
    }
    $azPerm = & $g 'AzScopePermission'; $azScope = & $g 'AzScope'
    # POLICY rows (measured on internal 2.4.348: an AzResPolicies item rendered "group  -> Azure role '' at ..."):
    # an Azure policy row carries RoleName + AzScope + TemplateId; a group policy row GroupName + PolicyRole.
    $polRole = & $g 'RoleName'; $tplId = & $g 'TemplateId'
    if ($azScope -and $polRole -and -not $azPerm) {
        return "PIM policy for Azure role '$polRole' at $(Format-PimAzureScopeLabel $azScope)$(if ($tplId) { " (template $tplId)" })"
    }
    $pRole = & $g 'PolicyRole'
    if ($gname -and $pRole) { return "PIM for Groups $pRole policy of group $gname$(if ($tplId) { " (template $tplId)" })" }
    if ($azPerm -or $azScope) { return "group $gdisp -> Azure role '$azPerm' at $(Format-PimAzureScopeLabel $azScope)$t" }
    $role = & $g 'RoleDefinitionName'
    if ($role) {
        # REQ-U wave 2: a WORKLOAD binding (Defender XDR / Intune rows carry RoleDefinitionName + Workload) is not an
        # Entra role -- it read "group X -> Entra role 'Security Operator'" on the Drift page.
        $wlr = & $g 'Workload'
        if ($wlr) { return "group $gdisp -> $wlr role '$role'$t" }
        $au = & $g 'AdministrativeUnitTag'
        return "group $gdisp -> Entra role '$role'$(if ($au) { " in administrative unit $au" })$t"
    }
    $wl = & $g 'Workload'; $wrole = & $g 'RoleName'
    if ($wl -and $wrole) { return "group $gdisp -> $wl role '$wrole'$t" }
    if ($gname) { return "group $gname" }
    # Policy items carry no row: the key is '<scope>|<role name>[|owner]'.
    $parts = @("$Key" -split '\|')
    if ($parts.Count -ge 2 -and $parts[0] -match '^/(providers|subscriptions)/') {
        $rn = (Get-Culture).TextInfo.ToTitleCase($parts[1])
        return "PIM policy for Azure role '$rn' at $(Format-PimAzureScopeLabel $parts[0])"
    }
    if ($parts.Count -ge 1 -and $parts[0] -match '^pim-' -and $parts.Count -le 2) {
        return "PIM for Groups policy of group $($parts[0])$(if ($parts.Count -eq 2) { " ($($parts[1]))" })"
    }
    return ''
}

function New-PimEngineItemFailure {
    param([string]$Scope, [string]$Entity, [string]$Op, [string]$Key, [string]$Message, [AllowNull()][object]$Row)
    $c = Get-PimFailureClassification -Message $Message -Row $Row
    $label = ''
    try { $label = Get-PimFailureItemLabel -Key $Key -Row $Row } catch { $label = '' }
    [pscustomobject]@{
        scope = $Scope; entity = $Entity; op = $Op; key = $Key; label = $label
        code = $c.code; title = $c.title; cause = $c.cause; remedy = $c.remedy
        retryable = $c.retryable; severity = $c.severity; fixes = @($c.fixes)
        message = $Message; row = (ConvertTo-PimFailureRowSnapshot -Row $Row)
    }
}

function Format-PimFailureSummary {
    <# "17 item(s) failed: 10x Azure PIM policy rejects the assignment duration [AZ-POLICY-MAX-DURATION]; 4x ..." #>
    param([object[]]$Failures)
    $f = @($Failures | Where-Object { $_ })
    if (-not $f.Count) { return '' }
    $groups = @($f | Group-Object code | Sort-Object Count -Descending)
    $parts = foreach ($g in $groups) {
        $t = "$($g.Group[0].title)"
        $fixable = @($g.Group | Where-Object { @($_.fixes).Count }).Count
        "{0}x {1} [{2}]{3}" -f $g.Count, $t, $g.Name, $(if ($fixable) { ' -- auto-fix available' } else { '' })
    }
    return ("{0} item(s) failed: {1}. Open Jobs > Engine logs & errors for each item, its cause and the fix." -f $f.Count, ($parts -join '; '))
}

function ConvertTo-PimFailureStamp {
    # PS 7's ConvertFrom-Json turns an ISO-8601 string into a LOCAL [datetime]; "$value" then renders
    # it in the host culture ("12-09-2026 12:00:00") and first-seen silently loses its zone and format
    # on the very next write. Normalise every stamp back to round-trip UTC.
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    $s = "$Value".Trim(); if (-not $s) { return '' }
    try { return ([datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)).ToUniversalTime().ToString('o') } catch { return $s }
}

function Update-PimEngineItemFailures {
    <#
      Replace ONE scope's slice of the currently-failing set with this run's failures, keeping
      first-seen and the occurrence count for items that were already failing. Items of this scope that
      did not fail this run are dropped -- they applied, or are no longer in the diff. Other scopes are
      untouched. Persisted in SQL (pim.Settings['EngineItemFailures']). Never throws: losing the
      failure list must not fail the run it describes.
    #>
    param([Parameter(Mandatory)][string]$Scope, [object[]]$Failures = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) -or -not (Get-Command Set-PimSetting -ErrorAction SilentlyContinue)) { return $false }
    try {
        $now = $NowUtc.ToUniversalTime().ToString('o')
        $existing = @()
        try { $raw = Get-PimSetting -Name 'EngineItemFailures'; if ($raw) { $tmp = if ($raw -is [string]) { $raw | ConvertFrom-Json } else { $raw }; $existing = @($tmp) } } catch { $existing = @() }
        $prevByKey = @{}
        foreach ($e in @($existing | Where-Object { $_ -and "$($_.scope)" -eq $Scope })) { $prevByKey["$($e.key)"] = $e }
        $keep = New-Object System.Collections.Generic.List[object]
        foreach ($e in @($existing | Where-Object { $_ -and "$($_.scope)" -ne $Scope })) {
            foreach ($sf in @('firstSeenUtc', 'lastSeenUtc')) { if ($e.PSObject.Properties[$sf]) { $e.$sf = ConvertTo-PimFailureStamp $e.$sf } }
            $keep.Add($e)
        }
        foreach ($f in @($Failures | Where-Object { $_ })) {
            $prev = $prevByKey["$($f.key)"]
            $rec = [ordered]@{}
            foreach ($p in $f.PSObject.Properties) { $rec[$p.Name] = $p.Value }
            $rec['firstSeenUtc'] = if ($prev -and "$($prev.firstSeenUtc)") { ConvertTo-PimFailureStamp $prev.firstSeenUtc } else { $now }
            $rec['lastSeenUtc']  = $now
            $rec['count']        = if ($prev) { [int]$prev.count + 1 } else { 1 }
            $keep.Add([pscustomobject]$rec)
        }
        $json = ConvertTo-Json -InputObject @($keep.ToArray()) -Depth 8 -Compress
        Set-PimSetting -Name 'EngineItemFailures' -Value $json
        return $true
    } catch {
        Write-Warning "  [engine] could not record the failing items for '$Scope': $($_.Exception.Message)"
        return $false
    }
}

function Get-PimEngineItemFailures {
    param()
    if (-not (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { return @() }
    try {
        $raw = Get-PimSetting -Name 'EngineItemFailures'
        if (-not $raw) { return @() }
        $tmp = if ($raw -is [string]) { $raw | ConvertFrom-Json } else { $raw }
        $list = @(@($tmp) | Where-Object { $_ })
        foreach ($e in $list) { foreach ($sf in @('firstSeenUtc', 'lastSeenUtc')) { if ($e.PSObject.Properties[$sf]) { $e.$sf = ConvertTo-PimFailureStamp $e.$sf } } }
        return $list
    } catch { return @() }
}

# ---------------------------------------------------------------------------------------------
# HELD FOR APPROVAL is its own outcome (REQUIREMENTS 71.13, operator 2026-09-15: "fix 1-3").
#
# A policy mass-change circuit breaker that HOLDS a plan is the safety net working: the engine wrote
# nothing and recorded exactly what needs an operator's approval. Measured on RIDE 2026-09-15: every
# pull of a freshly onboarded tenant ended "downlink JOB FAILED", and the tick's delta-policies job
# was red, while the only "error" was the hold itself. A red FAILED teaches operators to ignore red.
# A green would hide the approval. So: its own outcome -- ok, ran, 'held', amber, needs attention --
# and a REAL item failure in the same run still fails the job.
# ---------------------------------------------------------------------------------------------
function Get-PimApprovalHoldProvider {
    # PURE. The breaker provider a hold code belongs to, or '' when the code is not an approval hold.
    param([string]$Code)
    switch -Regex ("$Code".Trim().ToUpperInvariant()) {
        '^GROUP-POLICY-MASS-HOLD$' { return 'GroupsPolicies' }
        '^ENTRA-POLICY-MASS-HOLD$' { return 'EntraRolePolicies' }
        '^AZ-POLICY-MASS-HOLD$'    { return 'AzResPolicies' }
    }
    return ''
}

function Test-PimEngineFailureIsApprovalHold {
    # PURE. $true for an item the policy mass-change breaker HELD (awaiting an approval), never for a real failure.
    param([AllowNull()][object]$Failure)
    if ($null -eq $Failure) { return $false }
    $code = if ($Failure -is [System.Collections.IDictionary]) { "$($Failure['code'])" } else { "$($Failure.code)" }
    return [bool](Get-PimApprovalHoldProvider -Code $code)
}

function Get-PimEngineRunOutcome {
    <#
      PURE. Classify one engine run (the per-scope results of Invoke-PimEngine / Invoke-PimEngineScope, or
      the perScope array of the engine summary) as:
        ok     -- every scope ok
        held   -- the ONLY errors are approval holds (policy mass-change breaker)
        failed -- any real item failure, or a scope bound to no provider (even when holds are also present)
      Returns @{ outcome; heldCount; failedCount; unboundCount; holds = @(@{ scope; provider; code; planHash;
      changes; approve }); detail }. A scope result without a failures list counts every error as real
      (fail closed: an unclassified error is never softened into a hold).
    #>
    param([AllowEmptyCollection()][object[]]$Results = @())
    $held = New-Object System.Collections.Generic.List[object]
    $failed = 0; $unbound = 0
    foreach ($r in @($Results | Where-Object { $null -ne $_ })) {
        $okProp = $r.PSObject.Properties['ok']
        if (-not $okProp -or [bool]$r.ok) { continue }
        if ("$($r.detail)" -match 'no provider for scope') { $unbound++; continue }
        $errors = 0; try { $errors = [int]$r.errors } catch { $errors = 0 }
        $items = @()
        if ($r.PSObject.Properties['failures']) { $items = @(@($r.failures) | Where-Object { $null -ne $_ }) }
        $holdItems = @($items | Where-Object { Test-PimEngineFailureIsApprovalHold $_ })
        $real = [Math]::Max(0, $errors - $holdItems.Count)
        # ok=$false with no counted error at all is not something we can call held
        if ($errors -le 0 -and -not $holdItems.Count) { $real = 1 }
        $failed += $real
        foreach ($h in $holdItems) {
            $msg = "$($h.message)"
            $prov = Get-PimApprovalHoldProvider -Code "$($h.code)"
            $hash = ''; $m = [regex]::Match($msg, 'planHash=([0-9a-fA-F]{64})'); if ($m.Success) { $hash = $m.Groups[1].Value.ToLowerInvariant() }
            $n = 0; $m2 = [regex]::Match($msg, 'N=(\d+) polic'); if ($m2.Success) { $n = [int]$m2.Groups[1].Value }
            if (@($held | Where-Object { $_.provider -eq $prov -and $_.planHash -eq $hash }).Count) { continue }
            $held.Add([pscustomobject]@{ scope = "$($r.scope)"; provider = $prov; code = "$($h.code)"; planHash = $hash; changes = $n
                approve = ("Approve-PimPolicyMassChange -Provider {0} -PlanHash {1} -By <you>" -f $prov, $(if ($hash) { $hash } else { '<hash>' })) }) | Out-Null
        }
    }
    $holds = @($held.ToArray())
    $outcome = if ($failed -gt 0 -or $unbound -gt 0) { 'failed' } elseif ($holds.Count) { 'held' } else { 'ok' }
    $detail = ''
    if ($holds.Count) {
        $detail = 'HELD for approval (the engine wrote nothing for these): ' + ((@($holds | ForEach-Object {
            "{0} -- {1} polic(ies) to change; {2}" -f $_.provider, $_.changes, $_.approve })) -join ' | ')
    }
    return [pscustomobject]@{ outcome = $outcome; heldCount = $holds.Count; failedCount = $failed; unboundCount = $unbound; holds = $holds; detail = $detail }
}
