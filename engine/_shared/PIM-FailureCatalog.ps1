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

    STABLE ERROR CODES (framework DOCS/REQUIREMENTS.md 8.16 UPLINK-CAUSES; PIM REQUIREMENTS 100.167; owner 2026-10-15:
    "or define errorcodes"). Every class above has ONE public code pim-<area>-<nnnn> + a CauseClass + who acts
    (Get-PimFailureCodeTable). A code is NEVER changed or reused once released -- tests/pim-error-codes.freeze.txt pins
    every released one (Test-PimErrorCodes). New causes get the next free number of their area.
      area   what                                             numbers
      eng    the engine job itself (memory, run record,       0101.. ; 0201 the convergence check
             permission, throttling, Microsoft errors)
      grd    a safety guard holds a change for approval       0101..
      az     Azure resources, subscriptions, Azure PIM policy 0101..
      entra  Entra ID roles, administrative units, objects    0101..
      grp    groups and PIM for Groups                        0101..
      def    Defender XDR roles and assignments               0101..
      pbi    Power BI workspaces                              0101..
      wl     workload connectors (custom workloads)           0101..
      tap    accounts and Temporary Access Pass               0101..
      ad     hybrid Active Directory (the hybrid worker)      0101..
      upd    the in-cloud updater (ca-pim-update)             0101..
      gen    the GENERIC code of each CauseClass: a failure    0001..
             that has no own class yet (UNCLASSIFIED = 0001)
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

    # PIM 100.143 (Invardia fix-request watcher 2026-10-14, a customer production environment on 2.4.622): "the execution
    # 'ca-pim-tick-<n>' finished without recording this run's result" went up as UNCLASSIFIED. The execution SUCCEEDED; only
    # the run's record was lost (the run-history write lost every compare-and-set to an overlapping execution -- handed over
    # and retried since 100.143). Transient: the next turn runs the job again; nothing for the customer. Ahead of the
    # data / environment rules: the text quotes an execution name, never an HTTP status.
    @{ code = 'RUN-NO-RESULT'
       match = { param($m, $row) $m -match '(?i)\[RUN-NO-RESULT\]|finished without recording this run''s result' }
       title = 'The run ended without recording its result'
       cause = 'The scheduled execution finished normally, but the record of this run did not reach the store before it ended (another execution was writing the run history at the same moment). The job itself did its work; only its result is missing.'
       remedy = 'Nothing to do -- the job runs again on its next turn. One such run is not a failure; two in a row show as failing.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    # 2.4.653 (Invardia report 87315, internal 2026-10-19 06:24Z, filed under 4aa736f5 as UNCLASSIFIED): "interrupted: the
    # execution 'ca-pim-tick-<n>' ended in Failed while this run ... was in progress" (PIM-JobLanes, cause 'crashed'). Measured:
    # the platform scheduled the first replica, it never started, a second one did and ran; the execution hit its backoff limit
    # and the job cleanup stopped the running replica. Azure's side, not the job's: transient, nobody acts. Ahead of
    # ENGINE-OUT-OF-MEMORY, which deliberately does not read this text's "out of memory or a crash" guess.
    @{ code = 'RUN-EXECUTION-FAILED'
       match = { param($m, $row) $m -match '(?i)ended in Failed while this run' }
       title = 'The scheduled execution stopped while the job was running'
       cause = 'Azure ended the scheduled execution while this job was still running -- for example a replica that did not start, or the container stopping. The job did not finish this time; nothing it had not written yet was changed.'
       remedy = 'Nothing to do -- the job runs again on its next turn. If it happens on many turns in a row, contact Invardia support.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    # MI-TOKEN-TRANSIENT (SUP-2026-00323, internal rfa-sync 2026-10-27 02:16Z, filed as pim-gen-0001): the container's identity
    # endpoint did not issue one token ("PIM-Rest: could not acquire a token for 'https://storage.azure.com'"); every other
    # token of that window was issued and the next runs were green. PIM-Rest now retries the endpoint, so this text means it
    # failed on every try. Ahead of SERVICE-ERROR / PERMISSION-DENIED: the endpoint's own answer is appended to the text and
    # may carry a 5xx or a 400, but the cause is the token, not the call that needed it.
    @{ code = 'MI-TOKEN-UNAVAILABLE'
       match = { param($m, $row) $m -match '(?i)could not acquire a token for ' }
       title = 'The job could not sign in this time'
       cause = 'The job asks Azure for a sign-in token for its own managed identity before it reads or writes anything. Azure did not issue the token, also after a retry, so this job did nothing that needed it this time. Usually a short fault on Azure''s side.'
       remedy = 'Nothing to do at first: the job runs again on its next turn. If it repeats on several turns in a row, check that the job still has its managed identity, or contact Invardia support.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    # The updater's own outcomes (update-job-entry.ps1 Send-PimUpdateOutcome). Invardia fix request 4aa736f5 (2026-10-18):
    # both went up as UNCLASSIFIED and were merged under one request.
    @{ code = 'UPDATE-ROLL-INCOMPLETE'
       match = { param($m, $row) $m -match '(?i)still on the previous build' }
       title = 'The update did not reach every part of PIM Manager'
       cause = 'The update rolled the new version, but one or more apps or jobs (named in the message) were still running the previous version when the updater checked. Usually Azure had not finished starting the new version yet, or a request to Azure did not get through.'
       remedy = 'Nothing to do at first: the next update run checks again and finishes the roll. If the same app is still named after two runs, contact Invardia support.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    # UPDATER-ACR-PUSH-RETRY (2026-10-23, SUP-2026-00290, filed as pim-gen-0001): the build succeeded and the push to the
    # install's own registry failed ("connection refused"). The updater retries once; a second failure says so in these words.
    @{ code = 'UPDATE-REGISTRY-PUSH-FAILED'
       match = { param($m, $row) $m -match '(?i)the push to the registry failed' }
       title = 'The new version was built, but the registry did not accept it'
       cause = 'The update built the new version of PIM Manager in this installation''s container registry, but the registry refused or dropped the upload of the finished image (a network fault or a temporary error on Azure''s side). The updater tried a second time and that failed too. Nothing was rolled: PIM Manager keeps running on its current version.'
       remedy = 'Nothing to do at first: the next update run builds again. If the same failure is reported on several runs in a row, contact Invardia support.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    @{ code = 'UPDATE-NO-LICENCE'
       match = { param($m, $row) $m -match '(?i)no licence is installed -- Pro updates need' }
       title = 'No Pro licence is installed, so the Pro update was not fetched'
       cause = 'Pro updates come from Invardia and need the Pro licence that Invardia issues. This installation has none stored (or it could not be read this time), so nothing was fetched and nothing changed.'
       remedy = 'If you have a Pro subscription, contact Invardia support to have the licence installed. If the message appears only once, it was a read that failed; the next run tries again.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    # 100.31 SNAPSHOT-OOM (2026-10-09, live on a production tenant of ~10.8k identity objects, ca-pim-tick at 0.5 CPU /
    # 1 GiB): the active-assignments-snapshot job died with "Exception of type 'System.OutOfMemoryException' was thrown."
    # and telemetry filed it UNCLASSIFIED. Ahead of every data / environment rule: an out-of-memory job is the cause, and
    # whatever HTTP status or Graph text the same message happens to quote is not. The interrupted-execution text
    # ("out of memory or a crash", PIM-JobLanes) is a guess, not evidence, and is deliberately NOT matched.
    @{ code = 'ENGINE-OUT-OF-MEMORY'
       match = { param($m, $row) $m -match '(?i)System\.OutOfMemoryException|OutOfMemoryException|Insufficient memory to continue|\bOOMKilled\b|exit code 137\b' }
       title = 'The engine job ran out of memory'
       cause = 'The scheduled engine job (ca-pim-tick) ran out of memory while it ran, so it was stopped and its work is not done. A tenant of 5,000 or more users, groups and service principals needs more than the 0.5 CPU / 1 GiB a small tenant''s job gets. The next update raises the job one size by itself (it reads this failure); the command below does it now.'
       remedy = 'the engine job ran out of memory -- raise ca-pim-tick to the next size (2 CPU / 4 GiB; 4 CPU / 8 GiB from 15,000 objects; the run limit stays 7 days): az containerapp job update -g <resource group> -n ca-pim-tick --cpu 2.0 --memory 4Gi --replica-timeout 604800'
       retryable = $false; severity = 'environment'
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

    # BUG-234 (77.3, EFIF 2026-09-21): a row names an Entra role this tenant does not have. It was UNCLASSIFIED in
    # EntraRolePolicies and "unresolved group/role" in EntraRoles, and failed every run for two days. Ahead of the
    # generic rule below, which still covers a missing GROUP.
    @{ code = 'ENTRA-ROLE-NOT-IN-TENANT'
       match = { param($m, $row) $m -match "(?i)Entra has no role named '|directory role '[^']+' not found in this tenant" }
       title = 'The row names an Entra role this tenant does not have'
       cause = 'No Entra directory role with this display name exists in this tenant. Role display names are not the same everywhere -- Microsoft renames roles and tenants can show the old or the new name (e.g. "Office Apps Administrator" vs "Microsoft 365 Apps Administrator"). The error names the closest real role when there is one.'
       remedy = 'Change RoleDefinitionName on the row to the role name this tenant uses (the suggestion in the error), or remove the row. Nothing is assigned until then.'
       retryable = $false; severity = 'data'
       fixes = @(@{ id = 'delete-row'; label = 'Remove this row'; kind = 'delete-row' }) }

    # §95.2o (a customer, 2026-10-07): Entra refuses an Entra ROLE on a group that is not role-assignable -- shown as
    # "Unrecognised failure". The flag is fixed when the group is created and cannot be changed afterwards.
    @{ code = 'ENTRA-GROUP-NOT-ROLE-ASSIGNABLE'
       # AZRES-NOTRA-LABEL (SUP-2026-00250, 3.0.5): an Entra cause only. Azure's "InvalidRoleAssignmentRequest" (ARM) is not
       # this -- an Azure role never needs a role-assignable group; that answer is ARM-REQUEST-REFUSED-ONCE below.
       match = { param($m, $row) $m -notmatch '(?i)management\.azure\.com' -and $m -match '(?i)InvalidRoleAssignment\b|not role[- ]assignable|isAssignableToRole' }
       title = 'The group is not role-assignable, so Entra refuses the role'
       cause = 'An Entra role can be given to a group only when the group was CREATED as role-assignable. This group exists without that flag (it was created outside PIM Manager, or before IsRoleAssignable was set on its definition), and the flag cannot be added to an existing group.'
       remedy = 'Set IsRoleAssignable = TRUE on the group''s definition; the daily reconcile then recreates the group role-assignable and the role applies on the next run. Or give the role to another, role-assignable group.'
       retryable = $false; severity = 'data'
       fixes = @() }

    # ---- 100.122 F6 (owner 2026-10-13): two live objects carry ONE defined name -- the engine touches neither ----------
    # AHEAD of the "unresolved / not found / not created yet" rules: the engine resolves a duplicated name to nothing
    # (Resolve-PimLiveGroupIdByName / Resolve-PimLiveAuIdByName, PIM-EngineProviders.ps1), so the item that names it fails
    # with one of THOSE messages -- and "nothing to do, it is created on the next run" would be the wrong thing to tell
    # the customer.
    # REVIEW FIXES 2026-10-13: matched ONLY on a message that carries the literal class id. These two rules also matched
    # on the row's name / tag, or on a message that merely quoted the name, of a duplicate the run had registered -- so a
    # 403 or a throttle on a row that happens to name such a group was classed "duplicate" (wrong cause, wrong step for
    # the customer). The orchestrator holds every row that names a registered duplicate itself
    # (Split-PimDuplicateNameItems, PIM-EngineProviders.ps1) with a message that STARTS with the class id, and the
    # resolver's warning carries it too; any other failure keeps its own class.
    @{ code = 'DUPLICATE-GROUP-NAME'
       match = { param($m, $row) "$m" -match '(?i)(^|[^A-Za-z0-9-])DUPLICATE-GROUP-NAME([^A-Za-z0-9-]|$)' }
       title = 'Two groups in Entra ID carry the same name -- PIM Manager touches neither'
       cause = 'PIM Manager finds a group by the name its definition carries, and two live groups have that name. Choosing one would put owners, policy, members or roles on a group by chance, so the name is resolved to nothing and every item that names the group waits. Nothing was changed on either group.'
       remedy = 'In the Microsoft Entra admin center, rename or delete the group that is NOT the one PIM Manager should manage (the job log names both object ids). The next run finds the one that is left and applies the waiting items.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    # ADOPT-BY-NAME-SQUAT (owner 2026-10-23 "Hold for approval"): a group of a defined name that PIM Manager did not create
    # and no administrator adopted is held -- never used, never given a role (PIM-EngineProviders Test-PimGroupAdoption).
    @{ code = 'GROUP-ADOPT-HELD'
       match = { param($m, $row) "$m" -match '(?i)(^|[^A-Za-z0-9-])GROUP-ADOPT-HELD([^A-Za-z0-9-]|$)' }
       title = 'A group with a defined name exists, but PIM Manager did not create it -- it waits for an administrator'
       cause = 'PIM Manager finds a group by the name its definition carries. A group of that name exists in Entra ID that PIM Manager did not create and that no administrator has adopted (or it is not the group PIM Manager manages under that name). Using it would give a group someone else made the roles of the definition, so it is held: nothing is given to it and nothing was changed on it.'
       remedy = 'If it is the right group, adopt it in PIM Manager on Jobs > Engine logs & errors (Groups waiting for adoption). If it is not, rename or delete it in the Microsoft Entra admin center; PIM Manager then creates its own group on the next run.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    @{ code = 'DUPLICATE-AU-NAME'
       match = { param($m, $row) "$m" -match '(?i)(^|[^A-Za-z0-9-])DUPLICATE-AU-NAME([^A-Za-z0-9-]|$)' }
       title = 'Two administrative units in Entra ID carry the same name -- PIM Manager touches neither'
       cause = 'PIM Manager finds an administrative unit by the name its definition carries, and two live administrative units have that name. Choosing one would scope a role or place a group by chance, so the name is resolved to nothing and every item that names the unit waits. Nothing was changed on either unit.'
       remedy = 'In the Microsoft Entra admin center, rename or delete the administrative unit that is NOT the one PIM Manager should use (the job log names both object ids). The next run finds the one that is left and applies the waiting items.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    @{ code = 'ENTRA-ROLE-UNRESOLVED'
       # 2026-10-07 (Invardia fix request 7429f13c, a customer): RolesAUs says "unresolved group/AU/role" -- the same failure
       # with the administrative unit as a third part; it fell through to UNCLASSIFIED.
       match = { param($m, $row) $m -match '(?i)unresolved group/(AU/)?role' }
       title = 'Entra group, administrative unit or role could not be resolved'
       cause = 'Either the group for this GroupTag does not exist yet (or was deleted and is not recreated yet), the administrative unit does not exist, or the role name is not in the tenant''s role catalog. (Before 2026-09-12 this also appeared for EVERY role because the scheduler never loaded the role catalog.)'
       remedy = 'Check that the group exists (it is created by the Groups job), that the administrative unit exists, and that RoleDefinitionName matches an Entra role exactly. A group recreated by the full reconcile resolves on the next run.'
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

    # BUG-253 (§78 live E2E, 2026-09-24): an account (or group) the SAME run just created is not yet visible to the PIM
    # role service, which answers 404 SubjectNotFound. Measured: a DIRECT role on a user created seconds earlier in the
    # run -- UNCLASSIFIED, and the whole run recorded FAILED; the next run applied it. Replication lag, not data.
    @{ code = 'PRINCIPAL-NOT-REPLICATED-YET'
       # 2026-09-26 (§78 live, ig798): the same lag also answers a plain 404 ResourceNotFound on the schedule-request POST
       # ("POST .../roleEligibilityScheduleRequests -> HTTP 404 : ResourceNotFound"); the next run applied it. Only the
       # role SCHEDULE-REQUEST endpoints -- a ResourceNotFound anywhere else is not this.
       # BUG-276 (§78 GUI live, ig798 2026-10-01): the PIM-for-Groups schedule-request POST answers the same 404 for a group
       # created seconds earlier ("POST .../privilegedAccess/group/eligibilityScheduleRequests -> HTTP 404 : ResourceNotFound");
       # the run was recorded FAILED and the next one, two minutes later, applied both items. Same lag, so the same code.
       # BUG-279 (§78 live, ig798 2026-10-01 13:47; also internal 2026-09-29 13:06, §33.31): the FIRST eligibility of a
       # role-assignable group created moments earlier answers "HTTP 400 : ArgumentNullException -- Value cannot be null.
       # Parameter name: action" -- the run was recorded FAILED and the next run applied it. Only on the schedule-request POSTs;
       # a body that is really malformed keeps failing and is escalated by the waiting-window rule hours later.
       match = { param($m, $row) $m -match '(?i)SubjectNotFound|The subject is not found|(role(Eligibility|Assignment)|privilegedAccess/group/(eligibility|assignment))ScheduleRequests\S*\s*->\s*HTTP (404\b.{0,20}ResourceNotFound|400\b.{0,10}ArgumentNullException.{0,60}Parameter name: action)' }
       title = 'The account or group was created moments ago and PIM cannot see it yet'
       cause = 'Entra replicates a new user or group to the PIM service within minutes. An assignment made in the same run that created the principal is refused with "SubjectNotFound" until then.'
       remedy = 'Nothing to do: the next run applies it. If it persists for hours, check that the account or group in the row still exists.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    # 2026-09-26 (§78 MSP live, RIDE): a PIM-for-Groups policy rule PATCH on a group the engine created minutes earlier
    # answered 400 "InvalidPolicyRule -- The policy rule is invalid." and the pull recorded FAILED; the next run applied it.
    # Recorded three times before (§68.4, RIDE 2026-09-15, EFIF 2.4.392) and it converged every time. A still-failing item
    # hours later is escalated back to a real failure by the waiting-window rule, so a genuinely invalid rule still surfaces.
    # §97.3 (Invardia fleet watch 2026-10-08, a freshly built MSP managing tenant on 2.4.532): the RE-READ of a new group's
    # owner policy answered "not found" before PIM had materialised it, and the item was "Unrecognised failure" beside a
    # WAITING rule PATCH on the same group. The provider (Get-PimGroupPolicyRereadFailureMessage) now tags such a re-read
    # [GROUP-POLICY-NOT-READY] -- ONLY when the group is new (created within Get-PimTransientWaitWindowMinutes) and the
    # answer is one Test-PimGroupPolicyNotReadyAnswer lists -- so it lands HERE, on this one rule, not on a second copy.
    @{ code = 'GROUP-POLICY-NOT-READY'
       match = { param($m, $row) $m -match '(?i)\[GROUP-POLICY-NOT-READY\]|GroupsPolicies\b.*rule PATCH.*InvalidPolicyRule -- The policy rule is invalid' }
       title = 'The new group''s PIM policy is not ready for this rule yet'
       cause = 'PIM creates the policy of a new group in the background. For a few minutes after the group is created, a single rule update can be refused as "InvalidPolicyRule" even though the value is valid; the next run applies it.'
       remedy = 'Nothing to do if the group is new: the next run applies the rule. If it keeps failing for hours, the rule value itself is refused -- compare the rule in the message with the template.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    # 2026-09-26: a Defender custom role whose create was answered (redirect) but is not listed yet -- the engine does NOT post
    # it again (that is how RIDE got two roles of one name); the next run binds it once Defender lists it.
    @{ code = 'DEFENDER-ROLE-CREATE-PENDING'
       match = { param($m, $row) $m -match '(?i)DEFENDER-ROLE-CREATE-PENDING' }
       title = 'The Defender XDR role was created and is not listed yet'
       cause = 'Defender XDR answers the create of a custom role with a redirect and lists the new role only after a delay. The engine waits instead of creating it a second time.'
       remedy = 'Nothing to do: the next run binds the role once Defender lists it. If it is still waiting after 30 minutes, the engine tries the create again.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    # BUG-257 (§78 live run 7, 2026-09-24): the TAP job (delta-admin-tap, every 10 min) and the account job (delta-admins,
    # every 5 min) run apart, so an admin that became due between them reaches AdminTap before the account exists -- the
    # run was recorded FAILED "Unrecognised failure" and the next run issued the pass as normal. Ordering, not a fault.
    @{ code = 'ADMIN-NOT-CREATED-YET'
       match = { param($m, $row) $m -match "(?i)AdminTap: user '[^']+' not found" }
       title = 'The admin account is not created yet, so its Temporary Access Pass waits'
       cause = 'The pass is issued by the TAP job and the account is created by the Admin accounts job; they run on their own schedules. An admin that has just become due (a new row, or a scheduled ProvisionDate that has passed) reaches the TAP job before its account exists.'
       remedy = 'Nothing to do: once the Admin accounts job has created the account, the next TAP run issues the pass. If it persists for hours, look for a failed Admin accounts item for the same person.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    # 100.125 (a customer, 2.4.615, 2026-10-13; Invardia fix request e37ce115): the run created a group and, 20 seconds
    # later, the add of that group to its administrative unit answered "HTTP 404 : Request_ResourceNotFound -- Resource
    # '<the new group id>' does not exist" -- "Unrecognised failure", the run FAILED, and the next run added it. The
    # orchestrator (Invoke-PimEngineScope) now tries such a step again within the run, and tags what still does not go
    # through [NEW-OBJECT-NOT-VISIBLE-YET] -- ONLY when the "not found" answer names an object THIS RUN created
    # (Get-PimNewObjectIdInMessage); a "not found" for anything else is never tagged. Matched on the tag alone, and AFTER
    # the older lag classes above, so a message they already own keeps its class.
    @{ code = 'NEW-OBJECT-NOT-VISIBLE-YET'
       match = { param($m, $row) $m -match '\[NEW-OBJECT-NOT-VISIBLE-YET\]' }
       title = 'An object this run created is not visible to Microsoft Entra yet, so the step that uses it waits'
       cause = 'The same run created a group, an administrative unit or an account, and a following step that uses it (an administrative unit membership, an owner, a membership, a role assignment or a policy) was answered "not found" for that new object. Microsoft Entra serves a new object to its other services only after a short while. The engine tried the step again within the run before it left it waiting.'
       remedy = 'Nothing to do: the next run applies it, and the status turns OK by itself. If it still waits after two hours it is shown as a failure -- then check that the object named in the message still exists.'
       retryable = $true; severity = 'transient'
       fixes = @() }

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
    # 🔴 100.27 REMOVE-NEVER-APPLIED: a Remove row that lacks the data its removal needs, for a binding PIM Manager DID
    # apply (or could not prove it never did). FIRST of the workload rules: the message quotes the original
    # WORKLOAD-RESOURCE-MISSING / -ROLE-NOT-FOUND / ... cause, which would otherwise win. (A never-applied one is no
    # failure at all -- the engine completes it without calling the workload.)
    # PIM 100.135 (internal 2026-10-13, 6 PIM-Assignments-Workloads rows for Power BI workspace roles): listing the
    # workspace's users answered "HTTP 404 : PowerBIEntityNotFound" -- the workspace in the row does not exist, or PIM
    # Manager's identity is not a member/admin of it (Power BI answers the same for both). It was UNCLASSIFIED. Ahead of
    # every generic rule: a 404 here is neither a replication delay nor a missing Entra object.
    # PIM 100.142 (owner 2026-10-13: "Admin API, no membership"): the powerbi connector calls ONLY the Power BI ADMIN api
    # (/v1.0/myorg/admin/groups/{workspace}/users). A 401 / 403 there -- or Power BI's own "PowerBINotAuthorized" / "API is not
    # accessible for application" answer -- means PIM Manager's identity is not a Fabric Administrator yet, or the Fabric
    # tenant settings do not let service principals use the admin APIs. The connector tags it POWERBI-ADMIN-NOT-GRANTED
    # (Invoke-PimPowerBiAdminRequest, PIM-WorkloadConnectors.ps1); the raw admin-api answer is matched too (discovery reads
    # /admin/groups). Ahead of POWERBI-WORKSPACE-NOT-FOUND and of the generic PERMISSION-DENIED: the cause is one grant.
    # PIM 100.142b (owner 2026-10-14, "One script run"): the powerbi connector ADDS the PIM group through the Fabric workspace
    # api (POST api.fabric.microsoft.com/v1/workspaces/{ws}/roleAssignments), which only a member/admin of the workspace may
    # call. A 401 / 403 there = PIM Manager's identity is not in that workspace yet. The connector tags it
    # POWERBI-ENGINE-NOT-IN-WORKSPACE (Invoke-PimFabricWorkspaceRequest); the raw Fabric answer is matched too. FIRST of the
    # Power BI rules and ahead of the generic PERMISSION-DENIED: the cause is one script run by the customer.
    @{ code = 'POWERBI-ENGINE-NOT-IN-WORKSPACE'
       match = { param($m, $row) ($m -match 'POWERBI-ENGINE-NOT-IN-WORKSPACE') -or
                 (($m -match '(?i)api\.fabric\.microsoft\.com/v1/workspaces/[^/\s]+/roleAssignments') -and ($m -match '(?i)HTTP 40[13]\b|InsufficientPrivileges')) }
       title = 'PIM Manager is not in this Power BI workspace yet'
       cause = 'PIM Manager gives Power BI workspace roles through the Fabric workspace API, which only a member or admin of the workspace may call. PIM Manager''s identity is not in this workspace yet, so nothing was given in Power BI for this row.'
       remedy = 'A Fabric administrator runs the workload prerequisites script once (two lines: Initialize-PimWorkloadPrereqs.ps1 -Workload PowerBI -AddEngineToWorkspaces; PIM Manager shows them with this tenant''s values and the workspaces), signed in in the browser as a person. It adds PIM Manager''s identity as Admin of each workspace. The next run applies the row. Run it again when a new workspace is added.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    @{ code = 'POWERBI-ADMIN-NOT-GRANTED'
       match = { param($m, $row) ($m -match 'POWERBI-ADMIN-NOT-GRANTED') -or
                 (($m -match '(?i)api\.powerbi\.com/v1\.0/myorg/admin/') -and ($m -match '(?i)HTTP 40[13]\b|PowerBINotAuthorized|API is not accessible for application')) }
       title = 'PIM Manager cannot use the Power BI admin API yet'
       cause = 'PIM Manager''s identity is not a Fabric Administrator yet, or Fabric does not let it use the admin API. PIM Manager gives Power BI workspace roles through the Power BI admin API only, so nothing was given or taken away in Power BI for this row.'
       remedy = 'Run the workload prerequisites script once as a Global Administrator (two lines: Initialize-PimWorkloadPrereqs.ps1 -Workload PowerBI -GrantFabricAdministrator; PIM Manager shows them with this tenant''s values) -- it makes the identity a Fabric Administrator. Then in the Fabric admin portal, Tenant settings > Admin API settings, switch on "Service principals can access read-only admin APIs" and "Service principals can access admin APIs used for updates" for a security group the identity is in. The next run applies the row.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    # PIM 100.142b: a Fabric workspace-api 404 (WorkspaceNotFound / EntityNotFound) on the ADD is the same class.
    @{ code = 'POWERBI-WORKSPACE-NOT-FOUND'
       match = { param($m, $row) ($m -match '(?i)PowerBIEntityNotFound') -or
                 (($m -match '(?i)api\.fabric\.microsoft\.com/v1/workspaces/[^/\s]+/roleAssignments') -and ($m -match '(?i)HTTP 404\b')) }
       title = 'The Power BI workspace was not found'
       cause = 'Power BI answered PowerBIEntityNotFound for the workspace in this row. Through the admin API (PIM 100.142) that means no workspace has that id -- it was deleted, or the row names a wrong id. Nothing was assigned for this row.'
       remedy = 'Check the workspace id on the Workloads row and correct it, or take the row out when the workspace is gone. The next run assigns the role.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    @{ code = 'WORKLOAD-REMOVE-NEEDS-DATA'
       match = { param($m, $row) $m -match 'WORKLOAD-REMOVE-NEEDS-DATA' }
       title = 'Removing this workload binding needs data the row does not have'
       cause = 'PIM Manager applied this binding, so taking it away has to call the workload, and the row lacks what that call needs (the message says which: the Resource, the role, the group or the connector).'
       remedy = 'Fill in what the message names with the value the binding was applied with and commit -- the next run removes it. Or remove the access in the workload yourself, then stop managing the binding (delete the row).'
       retryable = $false; severity = 'data'
       fixes = @(@{ id = 'delete-row'; label = 'Stop managing this binding (delete the row)'; kind = 'delete-row' }) }

    @{ code = 'WORKLOAD-CONNECTOR-UNKNOWN'
       match = { param($m, $row) $m -match 'WORKLOAD-CONNECTOR-UNKNOWN' }
       title = 'Workload row names a connector that does not exist'
       cause = 'The Workload column must be the id of a shipped workload connector (the error lists the supported ids). The row is not applied at all.'
       remedy = 'Correct the Workload column to a supported connector id, or stop managing the binding (delete the row -- a binding that was never applied is deleted outright).'
       retryable = $false; severity = 'data'
       fixes = @(@{ id = 'delete-row'; label = 'Stop managing this binding (delete the row)'; kind = 'delete-row' }) }

    @{ code = 'WORKLOAD-ROLE-NOT-FOUND'
       match = { param($m, $row) $m -match 'WORKLOAD-ROLE-NOT-FOUND' }
       title = 'Workload role name does not exist'
       cause = 'The workload has no role with this RoleName (the error lists the roles it does have). For Defender XDR a custom role must be created first; roles are matched by exact name.'
       remedy = 'Correct RoleName to an existing role, create the custom role in the workload, or stop managing the binding (delete the row).'
       retryable = $true; severity = 'data'
       fixes = @(@{ id = 'delete-row'; label = 'Stop managing this binding (delete the row)'; kind = 'delete-row' }) }

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
       remedy = 'Fill in the Resource column as the connector''s prerequisites describe (the delegation wizard now asks for it), or stop managing the binding (delete the row -- one that was never applied is deleted outright, nothing is called in the workload).'
       retryable = $false; severity = 'data'
       fixes = @(@{ id = 'delete-row'; label = 'Stop managing this binding (delete the row)'; kind = 'delete-row' }) }

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

    # 100.122 F5 (owner 2026-10-13): a Defender role is changed only when it is PIM Manager's own.
    @{ code = 'DEFENDER-ROLE-NOT-OWN'
       match = { param($m, $row) $m -match '(?i)DEFENDER-ROLE-NOT-OWN' }
       title = 'A Defender XDR role of this name exists and was not created by PIM Manager -- not changed'
       cause = 'The workload template names a custom Defender XDR role, and a live role already has that name with other permissions. It was not created by PIM Manager (it is built-in, or does not carry PIM Manager''s description), so its permissions were not replaced.'
       remedy = 'Rename or delete that role in the Defender portal (Settings > Permissions > Roles) so PIM Manager creates its own, or set the template to the permissions the role already has.'
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

    # PIM 100.123 known gap (lane handover, 2026-10-13): the reviewed AD clean-up is refused by Active Directory because the
    # hybrid worker's permission group lacks "Delete Group objects" on the groups OU -- every install made before 2.4.618.
    # The worker's own sentence (engine/hybrid-ad/PIM-HybridAdCleanup.ps1) names the right; ahead of PERMISSION-DENIED so an
    # "Access is denied" / 0x80070005 from AD keeps THIS class. The customer runs the command; PIM never grants it itself.
    @{ code = 'AD-CLEANUP-RIGHT-MISSING'
       match = { param($m, $row) $m -match "(?i)AD-CLEANUP-RIGHT-MISSING|may not delete groups in that OU|'Delete Group objects'" }
       title = 'The hybrid worker may not delete groups in Active Directory'
       cause = 'A SuperAdmin approved the deletion of old PIM groups in Active Directory, and Active Directory refused it: the hybrid worker''s permission group has no "Delete Group objects" right on the OU for new AD groups. Installs made before this right existed do not have it. Nothing was deleted.'
       remedy = 'On a domain controller, as a domain administrator, run the published Initialize-PimHybridWorkerAd.ps1 again with -AllowGroupCleanup and the values used at the install (Settings > Hybrid Active Directory in PIM Manager shows the command with this install''s OU). The worker deletes the approved groups at its next run.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    # §97 (owner 2026-10-08, live on a production managing tenant): Discovery's LIST of management groups (or
    # subscriptions) refused with 403 is not "a change that is not being deployed" -- it is the engine not being able to
    # SEE Azure, because it holds Reader on its hosting subscription only. Ahead of PERMISSION-DENIED so it gets its own
    # code; the Manager shows it AMBER while no Azure resource delegation is defined and RED once one is.
    @{ code = 'AZURE-NOT-VISIBLE'
       match = { param($m, $row) ($m -match '(?i)\b403\b|Forbidden|AuthorizationFailed') -and
                 ($m -match '(?i)/providers/Microsoft\.Management/managementGroups(\?|\s|$)' -or $m -match '(?i)(^|\s)/subscriptions(\?|\s|$)' -or $m -match '(?i)management\.azure\.com/subscriptions(\?|\s|$)') }
       title = 'Discovery: Azure not visible'
       cause = 'Azure refused to LIST the management groups or subscriptions for the engine identity. It holds no Reader at the tenant root management group, so Discovery cannot see Azure (management groups, subscriptions and everything below them).'
       remedy = 'Grant the engine identity Reader (read-only) at the tenant root management group /providers/Microsoft.Management/managementGroups/<tenant id>. The install does this by default; when the installing account could not, a Global Administrator runs the published Grant-PimEnginePermissions.ps1 with -AzureRoleAssignments ''Reader@/providers/Microsoft.Management/managementGroups/<tenant id>'' (Get Started > Engine permissions shows it with your values).'
       retryable = $true; severity = 'environment'
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

    # §97.3: the re-read of an ESTABLISHED group's policy failed (or the group's age could not be read). LAST on purpose:
    # a 403 / 429 / 5xx in the same message keeps its own, more precise class above; only what is otherwise unexplained
    # lands here instead of UNCLASSIFIED. Not transient: an old group's policy that cannot be read is a real failure.
    @{ code = 'GROUP-POLICY-UNREADABLE'
       match = { param($m, $row) $m -match "(?i)GroupsPolicies: the \w+ policy of '[^']*' could not be re-read" }
       title = 'The group''s PIM policy could not be read, so nothing was written'
       cause = 'Before it changes a PIM for Groups policy the engine reads it again, and writes nothing when that read fails. The group is not new (or its creation time could not be read), so this is not the few minutes PIM needs to create a new group''s policy. A "not found" answer usually means the policy id the engine had is stale or the group is no longer onboarded to PIM for Groups.'
       remedy = 'Read the raw Graph error. The engine forgets the policy id it had and looks it up again on the next run. If it keeps failing, open the group in Entra ID > PIM for Groups and check that its policy exists and the engine identity can read it.'
       retryable = $true; severity = 'environment'
       fixes = @() }

    # 2.4.646 (Invardia fix request f016ea51, internal 2026-10-16 16:22Z, one hit): "AzRes: could not look up ARM role 'Owner'
    # at /providers/Microsoft.Management/managementGroups/mg-lz-corp: GET ..." came out UNCLASSIFIED. The management group
    # exists and the same lookup answers today (read back 2026-10-18), so ARM's answer was a one-off. LAST on purpose: a
    # 403 / 404 subscription / 429 / 5xx in the same message keeps its own class above; only an otherwise unexplained lookup
    # failure lands here -- the item is retried on the next run (the lookup is cached per run only).
    @{ code = 'ARM-ROLE-LOOKUP-FAILED'
       match = { param($m, $row) $m -match "(?i)could not look up ARM role '[^']+' at " }
       title = 'Azure did not answer the role lookup'
       cause = 'Before it assigns an Azure role the engine looks the role name up at the scope. Azure answered that lookup with an error the engine does not recognise, so this assignment was not written in this run. Everything else was applied.'
       remedy = 'Nothing to do when it happens once: the next run looks the role up again. If it repeats for the same scope, read the raw Azure error -- it names what Azure refused.'
       retryable = $true; severity = 'transient'
       fixes = @() }

    # AZRES-NOTRA-LABEL (SUP-2026-00250, internal 21/23/27 Oct 2026, 3.0.5): re-creating an Azure role assignment that had been
    # there for days answered "PUT .../providers/Microsoft.Authorization/roleAssignmentScheduleRequests/... -> HTTP 400 :
    # InvalidRoleAssignmentRequest -- Request body is invalid" once, and the next run applied the same body. It was labelled
    # ENTRA-GROUP-NOT-ROLE-ASSIGNABLE (wrong cause, wrong fix). Only on ARM's schedule-request PUTs; a body that is really
    # invalid keeps failing and is escalated by the waiting-window rule, so it still surfaces.
    @{ code = 'ARM-REQUEST-REFUSED-ONCE'
       match = { param($m, $row) $m -match '(?i)management\.azure\.com\S*/role(Assignment|Eligibility)ScheduleRequests\S*\s*->\s*HTTP 400\b.{0,10}InvalidRoleAssignmentRequest' }
       title = 'Azure refused the role assignment request once'
       cause = 'Azure answered the request to give this Azure role with "Request body is invalid". The same request is normally accepted on the next run, so Azure was not ready for it yet (for example while it was still removing an earlier assignment at that scope). The group and the row are fine.'
       remedy = 'Nothing to do when it happens once: the next run sends it again. If it repeats for the same scope for hours, read the raw Azure error and check the role and the scope in the row.'
       retryable = $true; severity = 'transient'
       fixes = @() }
)

# 100.34 UPLINK-ERRORCLASS: what a code means for Invardia's fix-request triage. customer-config = the customer's data,
# policy or environment is what has to change (auto-fix / "fix the data" / grant a permission) -- support shows it, no
# product fix request. product-defect = PIM itself must change (an unexplained failure, an engine that does not converge,
# a Microsoft-side error PIM should absorb). A rule may override its severity's default with fixKind; these three do.
$script:PimFailureFixKindOverrides = @{ 'SERVICE-ERROR' = 'product-defect'; 'THROTTLED' = 'product-defect'; 'GROUP-POLICY-UNREADABLE' = 'product-defect' }

function Test-PimFailureNamesDuplicate {
    <#
      100.122 F6. Does this failing item name a group / administrative unit the RUN found twice under one name
      ($global:PIM_DuplicateLiveNames, written by Register-PimDuplicateLiveName in PIM-EngineProviders.ps1)? TRUE when the
      row carries the duplicated name (GroupName / AUDisplayName), a tag that maps to it (GroupTag / TargetGroupTag /
      SourceGroupTag / AdministrativeUnitTag), or the message quotes the name. No register (no duplicate seen, or another
      process) = FALSE at once.
      REVIEW FIXES 2026-10-13: NO catalog rule calls this any more -- the two DUPLICATE-* classes match on the class id
      in the message only (a 403 or a throttle on a row naming a registered duplicate must keep its own class). Kept as
      a pure question about the register ("does this item name a duplicate the run saw?"); never use it to classify.
    #>
    param([ValidateSet('group', 'administrativeUnit')][string]$Kind = 'group', [string]$Message = '', [AllowNull()][object]$Row)
    $reg = $global:PIM_DuplicateLiveNames
    if (-not ($reg -is [hashtable]) -or -not ($reg[$Kind] -is [hashtable]) -or -not $reg[$Kind].Count) { return $false }
    $get = { param($n) if ($null -eq $Row) { '' } elseif ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { "$($Row[$n])".Trim().ToLowerInvariant() } else { '' } } elseif ($Row.PSObject.Properties[$n]) { "$($Row.$n)".Trim().ToLowerInvariant() } else { '' } }
    $nameCols = if ($Kind -eq 'group') { @('GroupName') } else { @('AUDisplayName') }
    $tagCols = if ($Kind -eq 'group') { @('GroupTag', 'TargetGroupTag', 'SourceGroupTag') } else { @('AdministrativeUnitTag') }
    $rowNames = @($nameCols | ForEach-Object { & $get $_ } | Where-Object { $_ })
    $rowTags = @($tagCols | ForEach-Object { & $get $_ } | Where-Object { $_ })
    $msg = "$Message".ToLowerInvariant()
    foreach ($k in @($reg[$Kind].Keys)) {
        $e = $reg[$Kind][$k]
        if ($rowNames -contains "$k") { return $true }
        foreach ($t in @($e.tags)) { if ("$t" -and $rowTags -contains "$t") { return $true } }
        if ($msg -and "$k".Length -ge 3 -and $msg.Contains("'$k'")) { return $true }
    }
    return $false
}

function Get-PimFailureCatalogCodes {
    <# PURE. Every code the catalog can give (UNCLASSIFIED included), upper-case. #>
    return @(@($script:PimFailureRules | ForEach-Object { "$($_.code)" }) + 'UNCLASSIFIED')
}

function Get-PimFailureFixKind {
    <#
      PURE. 100.34: a catalog code -> 'customer-config' | 'product-defect'. A rule's severity data / policy / environment is
      customer-config (the fix is in the customer's rows, Azure policy or tenant); transient / info / unknown, UNCLASSIFIED,
      CONVERGENCE and any code the catalog does not know are product-defect (absent = product-defect at Invardia too).
    #>
    param([string]$Code)
    $c = "$Code".Trim().ToUpperInvariant()
    if (-not $c) { return 'product-defect' }
    if ($script:PimFailureFixKindOverrides.ContainsKey($c)) { return $script:PimFailureFixKindOverrides[$c] }
    $rule = @($script:PimFailureRules | Where-Object { "$($_.code)" -eq $c }) | Select-Object -First 1
    if (-not $rule) { return 'product-defect' }
    if ("$($rule.severity)" -in @('data', 'policy', 'environment')) { return 'customer-config' }
    return 'product-defect'
}

# ---------------------------------------------------------------------------------------------
# PIM 100.167 / framework 8.16 UPLINK-CAUSES: the STABLE public error code of every class (the area table is in the file
# header). One row per class: class -> code | causeClass | whoActs | fixedIn | since. A FUNCTION returning literals (the
# BUG-79-6b trap: no $script: table read from a child script). Released codes are pinned by tests/pim-error-codes.freeze.txt:
# never change or reuse one; add new causes with the next free number of their area.
#   causeClass  framework 8.16 list + PIM's additions: customer-config, target-missing, replication-delay, throttled,
#               upstream-error, held-for-approval (NOT a failure, never an alert), not-converged, permission,
#               platform-timeout, too-large, missing-licence, no-data-source, settings-unreachable; 'unclassified' only
#               for the generic code of a failure nobody has classified yet (itself a PIM defect, framework 8.16).
#   whoActs     customer | support | product | nobody
#   fixedIn     the PIM version that fixes a PRODUCT cause ('' = none known); it makes the Action 'fixed-in'.
# ---------------------------------------------------------------------------------------------
function Get-PimFailureCodeTable {
    <# PURE. Ordered rows @{ class; code; causeClass; whoActs; fixedIn; since }: every catalog class, CONVERGENCE and the generic codes. #>
    $rows = @(
        # class                               code              causeClass           whoActs     fixedIn  since
        ,@('ENGINE-OUT-OF-MEMORY',             'pim-eng-0101',   'too-large',         'support',  '',      '2.4.638')
        ,@('RUN-NO-RESULT',                    'pim-eng-0102',   'settings-unreachable', 'nobody', '',     '2.4.638')
        ,@('PERMISSION-DENIED',                'pim-eng-0103',   'permission',        'customer', '',      '2.4.638')
        ,@('THROTTLED',                        'pim-eng-0104',   'throttled',         'nobody',   '',      '2.4.638')
        ,@('SERVICE-ERROR',                    'pim-eng-0105',   'upstream-error',    'nobody',   '',      '2.4.638')
        ,@('RUN-EXECUTION-FAILED',             'pim-eng-0106',   'platform-timeout',  'nobody',   '',      '2.4.653')
        ,@('MI-TOKEN-UNAVAILABLE',             'pim-eng-0107',   'upstream-error',    'nobody',   '',      '2.4.674')
        ,@('CONVERGENCE',                      'pim-eng-0201',   'not-converged',     'product',  '',      '2.4.638')
        ,@('AZ-POLICY-MASS-HOLD',              'pim-grd-0101',   'held-for-approval', 'customer', '',      '2.4.638')
        ,@('GROUP-POLICY-MASS-HOLD',           'pim-grd-0102',   'held-for-approval', 'customer', '',      '2.4.638')
        ,@('ENTRA-POLICY-MASS-HOLD',           'pim-grd-0103',   'held-for-approval', 'customer', '',      '2.4.638')
        ,@('REMOVE-BUDGET-HELD',               'pim-grd-0104',   'held-for-approval', 'customer', '',      '2.4.638')
        ,@('AZ-POLICY-RULE-FAILED',            'pim-az-0101',    'customer-config',   'customer', '',      '2.4.638')
        ,@('AZ-SUB-PLACEHOLDER',               'pim-az-0102',    'customer-config',   'customer', '',      '2.4.638')
        ,@('AZ-SUB-NOT-FOUND',                 'pim-az-0103',    'target-missing',    'customer', '',      '2.4.638')
        ,@('AZ-POLICY-NO-APPROVER',            'pim-az-0104',    'customer-config',   'customer', '',      '2.4.638')
        ,@('AZ-POLICY-APPROVAL',               'pim-az-0105',    'customer-config',   'nobody',   '',      '2.4.638')
        ,@('AZ-POLICY-MAX-DURATION',           'pim-az-0106',    'customer-config',   'customer', '',      '2.4.638')
        ,@('AZ-POLICY-MFA',                    'pim-az-0107',    'customer-config',   'customer', '',      '2.4.638')
        ,@('ARM-ROLE-NOT-FOUND',               'pim-az-0108',    'target-missing',    'customer', '',      '2.4.638')
        ,@('AZURE-NOT-VISIBLE',                'pim-az-0109',    'permission',        'customer', '',      '2.4.638')
        ,@('ARM-ROLE-LOOKUP-FAILED',           'pim-az-0110',    'upstream-error',    'nobody',   '',      '2.4.646')
        ,@('ARM-REQUEST-REFUSED-ONCE',         'pim-az-0111',    'upstream-error',    'nobody',   '',      '3.0.5')
        ,@('ENTRA-ROLE-NOT-IN-TENANT',         'pim-entra-0101', 'target-missing',    'customer', '',      '2.4.638')
        ,@('ENTRA-GROUP-NOT-ROLE-ASSIGNABLE',  'pim-entra-0102', 'customer-config',   'customer', '',      '2.4.638')
        ,@('DUPLICATE-AU-NAME',                'pim-entra-0103', 'customer-config',   'customer', '',      '2.4.638')
        ,@('ENTRA-ROLE-UNRESOLVED',            'pim-entra-0104', 'target-missing',    'customer', '',      '2.4.638')
        ,@('ENTRA-NESTING-ROLE-ASSIGNABLE',    'pim-entra-0105', 'customer-config',   'customer', '',      '2.4.638')
        ,@('PRINCIPAL-NOT-REPLICATED-YET',     'pim-entra-0106', 'replication-delay', 'nobody',   '',      '2.4.638')
        ,@('NEW-OBJECT-NOT-VISIBLE-YET',       'pim-entra-0107', 'replication-delay', 'nobody',   '',      '2.4.638')
        ,@('AU-SCOPE-REFUSED',                 'pim-entra-0108', 'customer-config',   'customer', '',      '2.4.638')
        ,@('DUPLICATE-GROUP-NAME',             'pim-grp-0101',   'customer-config',   'customer', '',      '2.4.638')
        ,@('GROUP-POLICY-NOT-READY',           'pim-grp-0102',   'replication-delay', 'nobody',   '',      '2.4.638')
        ,@('GROUP-NOT-CREATED-YET',            'pim-grp-0103',   'replication-delay', 'nobody',   '',      '2.4.638')
        ,@('GROUP-POLICY-UNREADABLE',          'pim-grp-0104',   'upstream-error',    'product',  '',      '2.4.638')
        ,@('GROUP-ADOPT-HELD',                 'pim-grp-0105',   'customer-config',   'customer', '',      '2.4.672')
        ,@('DEFENDER-ROLE-CREATE-PENDING',     'pim-def-0101',   'replication-delay', 'nobody',   '',      '2.4.638')
        ,@('DEFENDER-PERMISSION-PREREQUISITE', 'pim-def-0102',   'customer-config',   'customer', '',      '2.4.638')
        ,@('DEFENDER-ROLE-AMBIGUOUS',          'pim-def-0103',   'customer-config',   'customer', '',      '2.4.638')
        ,@('DEFENDER-ROLE-NOT-OWN',            'pim-def-0104',   'customer-config',   'customer', '',      '2.4.638')
        ,@('DEFENDER-ASSIGNMENT-SHARED',       'pim-def-0105',   'customer-config',   'customer', '',      '2.4.638')
        ,@('POWERBI-ENGINE-NOT-IN-WORKSPACE',  'pim-pbi-0101',   'permission',        'customer', '',      '2.4.638')
        ,@('POWERBI-ADMIN-NOT-GRANTED',        'pim-pbi-0102',   'permission',        'customer', '',      '2.4.638')
        ,@('POWERBI-WORKSPACE-NOT-FOUND',      'pim-pbi-0103',   'target-missing',    'customer', '',      '2.4.638')
        ,@('WORKLOAD-REMOVE-NEEDS-DATA',       'pim-wl-0101',    'customer-config',   'customer', '',      '2.4.638')
        ,@('WORKLOAD-CONNECTOR-UNKNOWN',       'pim-wl-0102',    'customer-config',   'customer', '',      '2.4.638')
        ,@('WORKLOAD-ROLE-NOT-FOUND',          'pim-wl-0103',    'target-missing',    'customer', '',      '2.4.638')
        ,@('WORKLOAD-GROUP-UNRESOLVED',        'pim-wl-0104',    'target-missing',    'customer', '',      '2.4.638')
        ,@('WORKLOAD-RESOURCE-MISSING',        'pim-wl-0105',    'customer-config',   'customer', '',      '2.4.638')
        ,@('WORKLOAD-CONTAINER-MISSING',       'pim-wl-0106',    'replication-delay', 'nobody',   '',      '2.4.638')
        ,@('WORKLOAD-ACTION-UNKNOWN',          'pim-wl-0107',    'customer-config',   'customer', '',      '2.4.638')
        ,@('ADMIN-NOT-CREATED-YET',            'pim-tap-0101',   'replication-delay', 'nobody',   '',      '2.4.638')
        ,@('TAP-TENANT-POLICY',                'pim-tap-0102',   'customer-config',   'customer', '',      '2.4.638')
        ,@('TAP-NO-RECIPIENT',                 'pim-tap-0103',   'customer-config',   'customer', '',      '2.4.638')
        ,@('AD-CLEANUP-RIGHT-MISSING',         'pim-ad-0101',    'permission',        'customer', '',      '2.4.638')
        ,@('UPDATE-ROLL-INCOMPLETE',           'pim-upd-0101',   'platform-timeout',  'nobody',   '',      '2.4.652')
        ,@('UPDATE-NO-LICENCE',                'pim-upd-0102',   'customer-config',   'support',  '',      '2.4.652')
        ,@('UPDATE-REGISTRY-PUSH-FAILED',      'pim-upd-0103',   'upstream-error',    'nobody',   '',      '2.4.671')
        # the generic code of each CauseClass (framework 8.16: "an unknown failure gets the generic code of its CauseClass")
        ,@('UNCLASSIFIED',                     'pim-gen-0001',   'unclassified',      'product',  '',      '2.4.638')
        ,@('GENERIC:customer-config',          'pim-gen-0002',   'customer-config',   'customer', '',      '2.4.638')
        ,@('GENERIC:target-missing',           'pim-gen-0003',   'target-missing',    'customer', '',      '2.4.638')
        ,@('GENERIC:replication-delay',        'pim-gen-0004',   'replication-delay', 'nobody',   '',      '2.4.638')
        ,@('GENERIC:throttled',                'pim-gen-0005',   'throttled',         'nobody',   '',      '2.4.638')
        ,@('GENERIC:upstream-error',           'pim-gen-0006',   'upstream-error',    'nobody',   '',      '2.4.638')
        ,@('GENERIC:held-for-approval',        'pim-gen-0007',   'held-for-approval', 'customer', '',      '2.4.638')
        ,@('GENERIC:not-converged',            'pim-gen-0008',   'not-converged',     'product',  '',      '2.4.638')
        ,@('GENERIC:permission',               'pim-gen-0009',   'permission',        'customer', '',      '2.4.638')
        ,@('GENERIC:platform-timeout',         'pim-gen-0010',   'platform-timeout',  'nobody',   '',      '2.4.638')
        ,@('GENERIC:too-large',                'pim-gen-0011',   'too-large',         'support',  '',      '2.4.638')
        ,@('GENERIC:missing-licence',          'pim-gen-0012',   'missing-licence',   'nobody',   '',      '2.4.638')
        ,@('GENERIC:no-data-source',           'pim-gen-0013',   'no-data-source',    'nobody',   '',      '2.4.638')
        ,@('GENERIC:settings-unreachable',     'pim-gen-0014',   'settings-unreachable', 'support', '',    '2.4.638')
    )
    foreach ($r in $rows) { [pscustomobject][ordered]@{ class = $r[0]; code = $r[1]; causeClass = $r[2]; whoActs = $r[3]; fixedIn = $r[4]; since = $r[5] } }
}

function Get-PimFailureCodeInfo {
    <#
      PURE. framework 8.16: a catalog class (any case; CONVERGENCE, UNCLASSIFIED) -> its row of Get-PimFailureCodeTable
      plus Action (none | fixed-in | support | customer). An unknown class -> the generic code of -CauseClass when given,
      else UNCLASSIFIED's (a failure is never sent without a code). Action: fixedIn known -> fixed-in; whoActs customer ->
      customer; support / product -> support; nobody -> none.
    #>
    param([string]$Class, [string]$CauseClass = '')
    $c = "$Class".Trim().ToUpperInvariant()
    $all = @(Get-PimFailureCodeTable)
    $row = $null
    if ($c) { $row = @($all | Where-Object { $_.class -eq $c }) | Select-Object -First 1 }
    if (-not $row -and "$CauseClass".Trim()) { $row = @($all | Where-Object { $_.class -eq ('GENERIC:' + "$CauseClass".Trim().ToLowerInvariant()) }) | Select-Object -First 1 }
    if (-not $row) { $row = @($all | Where-Object { $_.class -eq 'UNCLASSIFIED' }) | Select-Object -First 1 }
    $action = if ("$($row.fixedIn)".Trim()) { 'fixed-in' } elseif ($row.whoActs -eq 'customer') { 'customer' } elseif ($row.whoActs -in @('support', 'product')) { 'support' } else { 'none' }
    return [pscustomobject][ordered]@{ class = $row.class; code = $row.code; causeClass = $row.causeClass; whoActs = $row.whoActs; fixedIn = "$($row.fixedIn)"; since = $row.since; action = $action; known = [bool]($c -and $row.class -eq $c) }
}

function Get-PimErrorDefaultText {
    <#
      PURE. framework 8.16: the customer sentence + the step of a code WITHOUT a customer-ready solution, by its cause class.
      @( customerText, stepText ). ONE source for errors.json (tools/setup/New-PimErrorsJson.ps1) and the customer alert
      mail (PIM-JobAlert.ps1), so the mail and Invardia's page per code say the same words.
    #>
    param([string]$CauseClass, [string]$WhoActs)
    $next = 'It runs again on the next run by itself.'
    switch ("$CauseClass") {
        'replication-delay'    { return @("Microsoft has not finished creating an object PIM Manager needs, so this step waits. $next", 'Nothing to do.') }
        'throttled'            { return @("Microsoft asked PIM Manager to slow down, so this step waits. $next", 'Nothing to do.') }
        'upstream-error'       { return @("A Microsoft service answered with an error, so this step was not done. $next", $(if ($WhoActs -eq 'nobody') { 'Nothing to do.' } else { 'Nothing to do for you: Invardia support looks at it.' })) }
        'held-for-approval'    { return @('A safety check held a large change for approval. Nothing was changed; an approver in your tenant decides.', 'Open Jobs > Engine logs & errors in PIM Manager, review the held change and approve it, or correct what caused it and commit in Pending changes.') }
        'not-converged'        { return @('A change you committed is not in place in your tenant yet. PIM Manager tries again on every run, and Invardia support looks at why.', 'Nothing to do for you: Invardia support looks at it.') }
        'unclassified'         { return @('PIM Manager met a problem it does not recognise yet. Nothing was changed wrongly; Invardia support looks at it.', 'Nothing to do for you: Invardia support looks at it.') }
        'too-large'            { return @('The engine job needs more resources for this tenant, so part of its work is not done yet.', 'Nothing to do when updates are on: the next update gives the job more resources. Invardia support can do it with you now.') }
        'settings-unreachable' { return @("PIM Manager could not save the result of one run in its own database. $next", $(if ($WhoActs -eq 'nobody') { 'Nothing to do.' } else { 'Nothing to do for you: Invardia support looks at it.' })) }
        'platform-timeout'     { return @("The run was stopped before it finished. $next", 'Nothing to do.') }
        'permission'           { return @('PIM Manager is not allowed to do this step in your tenant.', 'Open Get Started > Engine permissions in PIM Manager and run the shown command as a Global Administrator.') }
        'target-missing'       { return @('A row names something that does not exist in your tenant (any more), so that row is not applied. Everything else is applied.', 'Open Jobs > Engine logs & errors in PIM Manager; the item shows what to correct or remove, then commit in Pending changes.') }
        'customer-config'      { return @('A row or setting cannot be applied as it is written. Everything else is applied.', 'Open Jobs > Engine logs & errors in PIM Manager; the item shows what to change, then commit in Pending changes.') }
        'missing-licence'      { return @('Your tenant does not have the Microsoft service this step needs, so the step does not apply. Nothing is wrong.', 'Nothing to do. If you add the service later, the step starts on its own.') }
        'no-data-source'       { return @('Your tenant does not have the data this step reads, so the step does not apply. Nothing is wrong.', 'Nothing to do.') }
    }
    return @('PIM Manager met a problem. Invardia support looks at it.', 'Nothing to do for you: Invardia support looks at it.')
}

function Get-PimFailureCustomerText {
    <#
      PURE. framework 8.16: a catalog class -> its stable code (Get-PimFailureCodeInfo) and the ONE customer sentence of that
      code -- the customer-ready solution's 'what' + 'affected' when the class has one (Get-PimFailureSolutionCatalog), else
      the default sentence of its cause class. errors.json's customerText and the customer alert mail both come from here.
      @{ class; code; causeClass; whoActs; fixedIn; action; customerText }.
    #>
    param([string]$Class, [string]$CauseClass = '')
    $info = Get-PimFailureCodeInfo -Class $Class -CauseClass $CauseClass
    $def = Get-PimErrorDefaultText -CauseClass "$($info.causeClass)" -WhoActs "$($info.whoActs)"
    $customer = "$($def[0])"
    $sol = Get-PimFailureSolutionCatalog
    if ("$($info.class)" -and $sol.ContainsKey("$($info.class)")) {
        $s = $sol["$($info.class)"]
        $customer = ("$($s.what)".Replace(': {item}', '').Replace('{item}', 'one or more items').Trim() + ' ' + "$($s.affected)".Trim()).Trim()
    }
    return [pscustomobject][ordered]@{ class = "$($info.class)"; code = "$($info.code)"; causeClass = "$($info.causeClass)"; whoActs = "$($info.whoActs)"
                                       fixedIn = "$($info.fixedIn)"; action = "$($info.action)"; customerText = $customer }
}

# ---------------------------------------------------------------------------------------------
# PIM 100.115 (owner 2026-10-12: "ask invardia to send email to [the customer's admin] and explain the solution. learn
# from this so future of this are solved from this lessons learned"). EVERY class whose FixKind is customer-config
# carries a CUSTOMER-READY solution: what is wrong (one sentence, {item} = the item's own names, filled in by the
# reporter), is anything affected, the one or two ways to solve it as steps with the page names of the product, and
# what happens afterwards. It travels with the run report (PIM-Uplink.ps1, field Solution), so a ticket or a mail to the
# customer is written from the report without anybody reading a log first.
# !! The class ids are KEYS at Invardia (solved cases are stored per class): never rename or split one here. A class
#    solved by hand gets its solution HERE in the same release (the lessons-learned loop).
# A FUNCTION returning literals, not a $script: table (the BUG-79-6b trap: a $script: default read from a child script).
# Test-PimEngineFailures pins: every customer-config class has one, every page named below is a page of the Manager.
# ---------------------------------------------------------------------------------------------
function Get-PimFailureSolutionPages {
    <# PURE. The Manager page names the solutions use -- exactly as the pages are called in pim-manager.html. #>
    return @('Engine logs & errors', 'Pending changes', 'Advanced View (grid)', 'Accounts & TAP', 'Departments & owners',
             'Policy templates', 'Policy settings', 'Guards', 'Get Started', 'Workload templates', 'Custom workloads', 'Role Lookup', 'Jobs',
             'Engine logs & errors')
}

function Get-PimFailureSolutionCatalog {
    <#
      PURE. code -> @{ short; what; affected; steps; after }.
        short     the cause in a few plain words (the convergence sentence: "1 assignment cannot be made: <short>")
        what      what is wrong, one sentence; {item} = the item's own names
        affected  is anything affected
        steps     one or two ways to solve it, each a step with the page name
        after     what happens afterwards
    #>
    $next = 'It turns OK by itself on the next run. Nothing has to be acknowledged.'
    $hold = 'Nothing was changed. The policies stay as they are until the change set is approved or withdrawn.'
    $holdSteps = @('If the change is intended: open Jobs > Engine logs & errors, review the held change set and approve it (a SuperAdmin of your tenant approves; the approval is valid for 24 hours).',
                   'If it is not intended: correct the policy template (Policy templates) or the choice in Policy settings, and commit in Pending changes.')
    $eligible = 'Open Jobs > Engine logs & errors, press "Make it Eligible" on the item and commit in Pending changes.'
    $stop = 'Or press "Stop managing this binding (delete the row)" on the item in Jobs > Engine logs & errors and commit in Pending changes.'
    $removeRow = 'Or press "Remove this row" on the item in Jobs > Engine logs & errors and commit in Pending changes.'
    return @{
        'AZ-POLICY-MASS-HOLD' = @{ short = 'a change to many Azure role policies at once waits for approval'
            what = 'A change to many Azure role policies at once is held for approval: {item}.'; affected = $hold; steps = $holdSteps; after = 'After the approval the next run makes exactly those changes and the status turns OK by itself.' }
        'GROUP-POLICY-MASS-HOLD' = @{ short = 'a change to many PIM for Groups policies at once waits for approval'
            what = 'A change to many PIM for Groups policies at once is held for approval: {item}.'; affected = $hold; steps = $holdSteps; after = 'After the approval the next run makes exactly those changes and the status turns OK by itself.' }
        'ENTRA-POLICY-MASS-HOLD' = @{ short = 'a change to many Entra role policies at once waits for approval'
            what = 'A change to many Entra role policies at once is held for approval: {item}.'; affected = $hold; steps = $holdSteps; after = 'After the approval the next run makes exactly those changes and the status turns OK by itself.' }
        'ENGINE-OUT-OF-MEMORY' = @{ short = 'the engine job ran out of memory'
            what = 'The engine job ran out of memory, so its work is not done: {item}.'
            affected = 'Committed changes are not applied until the job has more memory. Nothing was changed wrongly.'
            steps = @('Nothing to do when updates are on: the next update gives the job more memory by itself.',
                      'To do it now: your Azure administrator raises the job ca-pim-tick to 2 CPU / 4 GiB in the resource group of PIM Manager (Invardia support can do it with you).')
            after = $next }
        'AZ-POLICY-RULE-FAILED' = @{ short = 'Azure refused one or more settings of a PIM policy'
            what = 'Azure refused one or more settings of a PIM policy: {item}.'
            affected = 'The other settings of that policy were applied. The refused ones keep the value they had.'
            steps = @('Open Jobs > Engine logs & errors and read Azure''s answer per setting on the item.',
                      'When the answer is about a permission: open Get Started > Engine permissions and run the shown command, so the engine identity may write role management policies at that scope.')
            after = $next }
        'AZ-SUB-PLACEHOLDER' = @{ short = 'the assignment still points at the example subscription of the template'
            what = 'An assignment still points at the example subscription of the template: {item}.'
            affected = 'Nothing is assigned by this row. Everything else is applied.'
            steps = @('Open Jobs > Engine logs & errors, press "Remove this row" on the item and commit in Pending changes.',
                      'Or open Advanced View (grid), put the real subscription id in AzScope on that row and commit.')
            after = $next }
        'AZ-SUB-NOT-FOUND' = @{ short = 'the Azure subscription it names does not exist in this tenant'
            what = 'An assignment names an Azure subscription that does not exist in this tenant (any more): {item}.'
            affected = 'Nothing is assigned by this row. Everything else is applied.'
            steps = @('Open Advanced View (grid), correct the subscription id in AzScope on that row and commit.', $removeRow)
            after = $next }
        'AZ-POLICY-NO-APPROVER' = @{ short = 'the policy requires approval and nobody could be found to approve'
            what = 'The policy template of an Azure role requires approval, and nobody could be found to approve: {item}.'
            affected = 'Nothing was written to that policy. The assignment itself is not affected.'
            steps = @('Open Departments & owners, set the owners of the department of the assigned group (they become the approvers) and commit.',
                      'Or link the assignment to a policy template without approval in Policy templates and commit.')
            after = $next }
        'AZ-POLICY-MAX-DURATION' = @{ short = 'Azure refuses the length of the active assignment'
            what = 'Azure refuses the length of an active assignment: {item}.'
            affected = 'Only this assignment: it is not made. Everything else is applied.'
            steps = @($eligible, 'Or shorten the assignment in Advanced View (grid), or allow a longer active assignment in the policy of that role (Policy templates), and commit.')
            after = $next }
        'AZ-POLICY-MFA' = @{ short = 'the policy requires multifactor authentication for an active assignment, which the engine cannot do'
            what = 'The PIM policy of an Azure role requires multifactor authentication for an active assignment, which the engine can never do: {item}.'
            affected = 'Only this assignment: it is not made. Everything else is applied.'
            steps = @($eligible, 'Or take the multifactor requirement for active assignment out of the policy of that role (Policy templates) and commit.')
            after = $next }
        'ARM-ROLE-NOT-FOUND' = @{ short = 'the Azure role it names does not exist at that scope'
            what = 'An assignment names an Azure role that does not exist at that scope: {item}.'
            affected = 'Only this assignment: it is not made. Everything else is applied.'
            steps = @('Open Advanced View (grid), correct the role name in AzScopePermission on that row (Role Lookup shows the real names) and commit.', $removeRow)
            after = $next }
        'ENTRA-ROLE-NOT-IN-TENANT' = @{ short = 'the Entra role it names does not exist under that name in this tenant'
            what = 'An assignment names an Entra role this tenant does not have under that name: {item}.'
            affected = 'Only this assignment: nobody gets the role through it. Everything else is applied.'
            steps = @('Open Advanced View (grid), change RoleDefinitionName on that row to the name your tenant uses (the item in Jobs > Engine logs & errors shows the closest real role) and commit.', $removeRow)
            after = $next }
        'ENTRA-GROUP-NOT-ROLE-ASSIGNABLE' = @{ short = 'the group was not created as role-assignable, so Entra refuses the role'
            what = 'An Entra role is given to a group that was not created as role-assignable, which Entra refuses: {item}.'
            affected = 'Only this assignment: nobody gets the role through it. Everything else is applied.'
            steps = @('Open Advanced View (grid), set IsRoleAssignable to TRUE on the definition of that group and commit; the daily run creates the group again as role-assignable.',
                      'Or give the role to another group that is role-assignable, and commit.')
            after = 'The role is applied on the run after the group exists as role-assignable, and the status turns OK by itself.' }
        'ENTRA-ROLE-UNRESOLVED' = @{ short = 'the role is assigned to a group that no longer exists (or it names a role or an administrative unit the tenant does not have)'
            what = 'An Entra role assignment cannot be made, because the group it is given to no longer exists or is being retired (or the role or the administrative unit it names is not in the tenant): {item}.'
            affected = 'Only this assignment: nobody gets the role through it. Nothing was changed in the tenant, and everything else is applied.'
            steps = @('If the assignment is no longer wanted: open Advanced View (grid), set Action to Remove on that role assignment (or delete the row) and commit in Pending changes.',
                      'If it is wanted: open Advanced View (grid), take the definition of that group out of Lifecycle "Retire" (or correct the group, role or administrative unit name on the row) and commit; the group is created again and the role is applied on the run after.')
            after = $next }
        'ENTRA-NESTING-ROLE-ASSIGNABLE' = @{ short = 'a group cannot be an active member of a role-assignable group'
            what = 'A group is made an active member of a role-assignable group, which Entra does not support: {item}.'
            affected = 'Only this membership: it is not made. Everything else is applied.'
            steps = @($eligible, $removeRow)
            after = $next }
        'WORKLOAD-REMOVE-NEEDS-DATA' = @{ short = 'removing the workload access needs information the row no longer has'
            what = 'Removing a workload access needs information the row no longer has: {item}.'
            affected = 'The access is still there in the workload until it is removed.'
            steps = @('Open Advanced View (grid), fill in what the item names (the resource, the role, the group or the connector) with the value the access was applied with, and commit.',
                      'Or remove the access in the workload yourself, then press "Stop managing this binding (delete the row)" on the item in Jobs > Engine logs & errors and commit.')
            after = $next }
        'WORKLOAD-CONNECTOR-UNKNOWN' = @{ short = 'the row names a workload PIM Manager does not know'
            what = 'A workload access names a workload PIM Manager does not know: {item}.'
            affected = 'Nothing is applied by this row. Everything else is applied.'
            steps = @('Open Advanced View (grid), correct the Workload column on that row (Workload templates lists the workloads) and commit.', $stop)
            after = $next }
        'WORKLOAD-ROLE-NOT-FOUND' = @{ short = 'the workload has no role with that name'
            what = 'A workload access names a role the workload does not have: {item}.'
            affected = 'Only this access: it is not given. Everything else is applied.'
            steps = @('Open Advanced View (grid), correct RoleName on that row (the item in Jobs > Engine logs & errors lists the roles the workload has), or create the role in the workload, and commit.', $stop)
            after = $next }
        'WORKLOAD-GROUP-UNRESOLVED' = @{ short = 'the group the workload access names does not exist'
            what = 'A workload access names a group that does not exist: {item}.'
            affected = 'Only this access: it is not given. Everything else is applied.'
            steps = @('Open Advanced View (grid) and check that GroupTag on that row is the tag of a defined group; correct it and commit.',
                      'If the group was defined moments ago there is nothing to do: it is created on the next run.')
            after = $next }
        'WORKLOAD-RESOURCE-MISSING' = @{ short = 'the workload access does not say which resource it is for'
            what = 'A workload access does not say which resource it is for: {item}.'
            affected = 'Nothing is applied by this row. Everything else is applied.'
            steps = @('Open Advanced View (grid), fill in the Resource column on that row (Workload templates shows what the workload expects) and commit.', $stop)
            after = $next }
        'UPDATE-NO-LICENCE' = @{ short = 'no Pro licence is installed'
            what = 'The Pro update was not fetched: this installation has no Pro licence from Invardia stored, or it could not be read this time: {item}.'
            affected = 'Only the update: nothing was fetched and nothing changed. PIM Manager keeps running on its current version.'
            steps = @('If the message appears only once, nothing is needed: a licence read failed and the next update run tries again.',
                      'If it stays, contact Invardia support (invardia.com/support) to have the Pro licence installed for this installation.')
            after = 'The next update run fetches the Pro update, and the status turns OK by itself. Nothing has to be acknowledged.' }
        'POWERBI-ENGINE-NOT-IN-WORKSPACE' = @{ short = 'PIM Manager is not in the Power BI workspace yet'
            what = 'PIM Manager cannot give the Power BI workspace role yet, because its identity is not in that workspace: {item}.'
            affected = 'Only these Power BI workspace roles: nothing was given or taken away in Power BI. Everything else is applied.'
            steps = @('A Fabric administrator runs the workload prerequisites script once, signed in in the browser as a person -- the two lines PIM Manager shows next to the Power BI rows (Initialize-PimWorkloadPrereqs.ps1 -Workload PowerBI -AddEngineToWorkspaces, with the workspaces listed). It adds PIM Manager''s identity as Admin of each workspace and removes nobody.',
                      'When a new Power BI workspace gets a Workloads row later, run the same two lines again.')
            after = 'The next run gives the workspace roles, and the status turns OK by itself. Nothing has to be acknowledged.' }
        'POWERBI-ADMIN-NOT-GRANTED' = @{ short = 'PIM Manager''s identity is not a Fabric Administrator yet, or Fabric does not let it use the admin API'
            what = 'PIM Manager cannot reach Power BI yet: its identity is not a Fabric Administrator yet, or Fabric does not let it use the admin API: {item}.'
            affected = 'Only these Power BI workspace roles: nothing was given or taken away in Power BI. Everything else is applied.'
            steps = @('A Global Administrator runs the workload prerequisites script once -- the two lines PIM Manager shows next to the Power BI rows (Initialize-PimWorkloadPrereqs.ps1 -Workload PowerBI -GrantFabricAdministrator). It makes PIM Manager''s identity a Fabric Administrator.',
                      'In the Fabric admin portal, Tenant settings > Admin API settings: switch on "Service principals can access read-only admin APIs" and "Service principals can access admin APIs used for updates" for Specific security groups, with a group PIM Manager''s identity is in.')
            after = 'The next run gives the workspace roles, and the status turns OK by itself. A Fabric setting can take about 15 minutes to apply.' }
        'POWERBI-WORKSPACE-NOT-FOUND' = @{ short = 'the Power BI workspace was not found'
            what = 'Power BI does not have the workspace a workload access names: {item}.'
            affected = 'Only these workspace roles: they are not given. Nothing was changed in Power BI, and everything else is applied.'
            steps = @('Open Advanced View (grid) and check the workspace id on the Workloads row; correct it and commit in Pending changes.',
                      'If the workspace was deleted: take the row out in Advanced View (grid) and commit in Pending changes.')
            after = $next }
        'WORKLOAD-CONTAINER-MISSING' = @{ short = 'the group is not set up inside the workload yet'
            what = 'The group is not set up inside the workload yet, so the role cannot be attached: {item}.'
            affected = 'Only this access: it is not given. Everything else is applied.'
            steps = @('Set the group up in the workload once (Workload templates shows the prerequisites of each workload).')
            after = 'The next run attaches the role and the status turns OK by itself.' }
        'WORKLOAD-ACTION-UNKNOWN' = @{ short = 'the workload access cannot be applied as it is written'
            what = 'A workload access cannot be applied as it is written: {item}.'
            affected = 'Nothing is applied by this row. Everything else is applied.'
            steps = @('Open Advanced View (grid), set Action on that row to Assign or Remove and commit.',
                      'If the item names the sign-in of a custom workload: correct the definition of that workload in Custom workloads.')
            after = $next }
        'TAP-TENANT-POLICY' = @{ short = 'the Temporary Access Pass policy of the tenant refused the pass'
            what = 'The Temporary Access Pass policy of your tenant refused the pass that was requested: {item}.'
            affected = 'The admin has no Temporary Access Pass yet. The account itself is not affected.'
            steps = @('In the Microsoft Entra admin center open Authentication methods > Temporary Access Pass and allow one-time use and a lifetime that includes the hours set on the admin.',
                      'Or open Get Started > Engine permissions and give the engine identity Policy.Read.All, so it reads the policy first and asks for a pass that fits.')
            after = 'The next run issues the pass and the status turns OK by itself.' }
        'TAP-NO-RECIPIENT' = @{ short = 'there is nobody to send the Temporary Access Pass to'
            what = 'There is nobody to send the Temporary Access Pass of an admin to: {item}.'
            affected = 'Nothing was created: the pass is not issued until it can be delivered.'
            steps = @('Open Departments & owners, set an owner on the department of that admin (the owners receive the pass) and commit.',
                      'Or open Accounts & TAP, press Edit on the admin, set the office user email address and commit.')
            after = 'The next run issues the pass and the status turns OK by itself.' }
        'AU-SCOPE-REFUSED' = @{ short = 'a role limited to an administrative unit was put among the tenant-wide roles'
            what = 'A role limited to an administrative unit was put among the tenant-wide roles, so it was refused: {item}.'
            affected = 'Nothing was changed. The role was NOT given over the whole tenant.'
            steps = @('Open Advanced View (grid): add the same group and role to PIM-Assignments-Roles-AUs with the administrative unit, delete the row in PIM-Assignments-Roles-Groups, and commit in Pending changes.')
            after = $next }
        'DEFENDER-PERMISSION-PREREQUISITE' = @{ short = 'Defender XDR refused a permission because what it depends on is not in place'
            what = 'Defender XDR refused a permission of a custom role, because what it depends on is not in place: {item}.'
            affected = 'Nothing was created for this row. Everything else is applied.'
            steps = @('Onboard a Microsoft Sentinel workspace to Defender XDR (the Data Operations permissions need it).',
                      'Or take that permission out of the role in Workload templates and commit.')
            after = 'The next run creates the role and its assignment, and the status turns OK by itself.' }
        'DEFENDER-ROLE-AMBIGUOUS' = @{ short = 'two Defender XDR roles have the same name'
            what = 'Two Defender XDR roles have the same name, so PIM Manager does not choose one: {item}.'
            affected = 'Nothing was assigned for this row. Everything else is applied.'
            steps = @('In the Defender portal open Settings > Permissions > Roles and rename or delete the extra role.')
            after = 'The next run uses the role that is left, and the status turns OK by itself.' }
        'DEFENDER-ROLE-NOT-OWN' = @{ short = 'a Defender XDR role of that name exists and was not created by PIM Manager'
            what = 'A Defender XDR role with the name of the workload template already exists and was not created by PIM Manager, so its permissions were not changed: {item}.'
            affected = 'The role keeps the permissions it had. Nothing was changed, and everything else is applied.'
            steps = @('In the Defender portal open Settings > Permissions > Roles and rename or delete that role, so PIM Manager creates its own.',
                      'Or set the permissions of the role in Workload templates to the ones the existing role has, and commit in Pending changes.')
            after = $next }
        'DUPLICATE-GROUP-NAME' = @{ short = 'two groups in Entra ID have the same name, so PIM Manager touches neither'
            what = 'Two groups in Entra ID have the same name, so PIM Manager does not choose one and touches neither: {item}.'
            affected = 'Nothing was changed on either group. Every item that names the group waits; everything else is applied.'
            steps = @('In the Microsoft Entra admin center, rename or delete the group that is not the one PIM Manager should manage (Jobs > Engine logs & errors names both object ids).')
            after = 'The next run finds the group that is left, applies the waiting items, and the status turns OK by itself.' }
        'GROUP-ADOPT-HELD' = @{ short = 'a group with a defined name exists that PIM Manager did not create'
            what = 'A group with a name PIM Manager defines exists in Entra ID, but PIM Manager did not create it and no administrator has adopted it, so PIM Manager does not use it: {item}.'
            affected = 'Nothing was given to that group and nothing was changed on it. Every item that names the group waits; everything else is applied.'
            steps = @('If it is the right group, open Engine logs & errors and adopt it under Groups waiting for adoption.',
                      'If it is not, rename or delete it in the Microsoft Entra admin center; PIM Manager then creates its own group on the next run.')
            after = 'The next run uses the adopted group (or creates its own), applies the waiting items, and the status turns OK by itself.' }
        'DUPLICATE-AU-NAME' = @{ short = 'two administrative units in Entra ID have the same name, so PIM Manager touches neither'
            what = 'Two administrative units in Entra ID have the same name, so PIM Manager does not choose one and touches neither: {item}.'
            affected = 'Nothing was changed on either administrative unit. Every item that names it waits; everything else is applied.'
            steps = @('In the Microsoft Entra admin center, rename or delete the administrative unit that is not the one PIM Manager should use (Jobs > Engine logs & errors names both object ids).')
            after = 'The next run finds the administrative unit that is left, applies the waiting items, and the status turns OK by itself.' }
        'DEFENDER-ASSIGNMENT-SHARED' = @{ short = 'the Defender XDR assignment is shared with others, so it was not changed'
            what = 'A Defender XDR role assignment is shared with other people or groups, so it was not changed: {item}.'
            affected = 'Nothing was changed, so nobody lost access. The group keeps the data sources it had.'
            steps = @('In the Defender portal give the group its own assignment (or split the shared one).')
            after = 'The next run sets the data sources of that assignment, and the status turns OK by itself.' }
        'REMOVE-BUDGET-HELD' = @{ short = 'more removals than the safety limit allows in one run were held back'
            what = 'More removals than the safety limit allows in one run were held back: {item}.'
            affected = 'Nothing was removed in that area. The access is still there.'
            steps = @('If the removals are intended: open Guards and release the held run (a SuperAdmin), or commit the removals in smaller batches.',
                      'If they are not intended: undo the Remove rows in Advanced View (grid) and commit in Pending changes.')
            after = 'After the release the next run removes them and the status turns OK by itself.' }
        'AD-CLEANUP-RIGHT-MISSING' = @{ short = 'the hybrid worker may not delete groups in Active Directory yet'
            what = 'Active Directory refused the approved deletion of old PIM groups, because the hybrid worker may not delete groups in the OU for new AD groups yet: {item}.'
            affected = 'Nothing was deleted in Active Directory. The groups and their members stay as they are; everything else the worker does keeps working.'
            steps = @('On a domain controller, as a domain administrator, run these two lines with the values used at the install (Settings > Hybrid Active Directory in PIM Manager shows them with your OU filled in): Invoke-WebRequest https://invardia.com/support/pim/Initialize-PimHybridWorkerAd.ps1 -OutFile Initialize-PimHybridWorkerAd.ps1 -- then -- .\Initialize-PimHybridWorkerAd.ps1 -WorkerComputerName <worker> -ComputerOu ''<OU of the worker computer>'' -GmsaOu ''<OU of the gMSA>'' -GroupsOu ''<OU for new AD groups>'' -AllowGroupCleanup. It grants the one right "Delete Group objects" on that OU and changes nothing else.')
            after = 'The worker deletes the approved groups at its next run (about hourly) and the status turns OK by itself. An approval that expired meanwhile is approved again on the same page.' }
        'AZURE-NOT-VISIBLE' = @{ short = 'PIM Manager cannot see the Azure management groups and subscriptions'
            what = 'PIM Manager cannot see your Azure management groups and subscriptions: {item}.'
            affected = 'Discovery shows nothing for Azure. Access that is already defined keeps working.'
            steps = @('Open Get Started > Engine permissions and run the shown command as a Global Administrator: it gives the engine identity Reader (read-only) at the tenant root management group.')
            after = 'Azure is read on the next discovery run and the status turns OK by itself.' }
        'PERMISSION-DENIED' = @{ short = 'the engine identity lacks a permission'
            what = 'Microsoft refused a change because the engine identity lacks a permission: {item}.'
            affected = 'That change is not made. Everything the identity is allowed to do is applied.'
            steps = @('Open Get Started > Engine permissions, see which permission is missing and run the shown command as a Global Administrator.',
                      'A new permission can take about 30 minutes before Microsoft honours it; nothing more is needed after that.')
            after = $next }
    }
}

function Get-PimFailureSolution {
    <#
      PURE. PIM 100.115. The customer-ready solution of a class, the item's own names filled in:
        @{ code; short; what; affected; steps; after; text } -- or $null for a class without one (every customer-config
        class has one; a product-defect / transient class has none: nothing for the customer to do).
      -Items  the failing items' own names (Get-PimFailureItemLabel, else their key): the first three are named, then
              "and N more". None known = "the item is named in Jobs > Engine logs & errors".
      text = the four parts in one paragraph, at most -MaxLength characters (the run report's Solution, 2000).
    #>
    param([string]$Code, [string[]]$Items = @(), [int]$MaxLength = 2000)
    $c = "$Code".Trim().ToUpperInvariant()
    if (-not $c) { return $null }
    $cat = Get-PimFailureSolutionCatalog
    if (-not $cat.ContainsKey($c)) { return $null }
    $s = $cat[$c]
    $names = @(@($Items) | ForEach-Object { ("$_" -replace '\s+', ' ').Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $item = 'the item is named in Jobs > Engine logs & errors'
    if ($names.Count) {
        $show = @($names | Select-Object -First 3 | ForEach-Object { if ($_.Length -gt 160) { $_.Substring(0, 157) + '...' } else { $_ } })
        $item = ($show -join '; ')
        if ($names.Count -gt 3) { $item += " and $($names.Count - 3) more" }
    }
    $what = "$($s.what)".Replace('{item}', $item)
    $steps = @(@($s.steps) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $n = 0
    $stepText = (@($steps | ForEach-Object { $n++; "($n) $_" }) -join ' ')
    $text = "WHAT IS WRONG: $what IS ANYTHING AFFECTED: $($s.affected) HOW TO SOLVE IT: $stepText AFTERWARDS: $($s.after)"
    if ($MaxLength -le 0 -or $MaxLength -gt 2000) { $MaxLength = 2000 }   # literal ceiling (the report's limit)
    if ($text.Length -gt $MaxLength) { $text = $text.Substring(0, $MaxLength - 3) + '...' }
    return [pscustomobject]@{ code = $c; short = "$($s.short)"; what = $what; affected = "$($s.affected)"; steps = $steps; after = "$($s.after)"; text = $text }
}

function Get-PimConvergenceCause {
    <#
      PURE. PIM 100.113 (owner 2026-10-12, on a status row "CONVERGENCE" owned by the product team: "why is this still an
      error"). The convergence check finds "exists in the Manager but NOT in the tenant" by a plan-only read; it does not
      know WHY. The engine does: every item whose apply fails is in the currently-failing set (pim.Settings
      'EngineItemFailures', Update-PimEngineItemFailures) with its class -- and a convergence key is '<scope>|<item key>',
      the same scope and key the failing item carries. So NO new tenant read is needed.
        -Unconverged  the keys the check would fail on ('<scope>|<item key>')
        -Failures     the currently-failing items (Get-PimEngineItemFailures)
      Returns @{ customerConfig; code; fixKind; count; sentence; items; codes; unmatched }:
        customerConfig  $true ONLY when there is at least one key and EVERY key is a failing item (same scope + key) whose
                        class is customer-config (Get-PimFailureFixKind). One key with no failing item, a product-defect
                        class, a transient class or UNCLASSIFIED = $false (mixed or unknown causes stay as they were).
        code            the class of the largest group (ties: alphabetical)      fixKind  'customer-config' | ''
        sentence        "1 assignment cannot be made: the role is assigned to a group that no longer exists ..." -- per class,
                        largest first, joined with '; '
        items           the items' own names (label, else the key)
    #>
    param([string[]]$Unconverged = @(), [AllowNull()][object[]]$Failures = @())
    $out = [ordered]@{ customerConfig = $false; code = ''; fixKind = ''; count = 0; sentence = ''; items = @(); codes = @(); unmatched = 0 }
    $keys = @(@($Unconverged) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $out.count = $keys.Count
    if (-not $keys.Count) { return [pscustomobject]$out }
    $by = @{}
    foreach ($f in @(@($Failures) | Where-Object { $null -ne $_ })) {
        $fs = "$($f.scope)".Trim(); $fk = "$($f.key)".Trim()
        if ($fs -and $fk) { $by["$fs|$fk".ToLowerInvariant()] = $f }
    }
    $groups = @{}; $names = New-Object System.Collections.Generic.List[string]; $unmatched = 0; $other = 0
    foreach ($k in $keys) {
        $f = $by[$k.ToLowerInvariant()]
        if ($null -eq $f) { $unmatched++; continue }
        $code = "$($f.code)".Trim().ToUpperInvariant()
        if (-not $code -or $code -eq 'UNCLASSIFIED' -or (Get-PimFailureFixKind -Code $code) -ne 'customer-config') { $other++; continue }
        if (-not $groups.ContainsKey($code)) { $groups[$code] = 0 }
        $groups[$code] = [int]$groups[$code] + 1
        $lab = "$($f.label)".Trim(); if (-not $lab) { $lab = "$($f.key)".Trim() }
        $names.Add($lab)
    }
    $out.unmatched = $unmatched
    $order = @($groups.Keys | Sort-Object @{ Expression = { -[int]$groups[$_] } }, @{ Expression = { "$_" } })
    $out.codes = @($order)
    if ($unmatched -gt 0 -or $other -gt 0 -or -not $order.Count) { return [pscustomobject]$out }
    $parts = foreach ($c in $order) {
        $n = [int]$groups[$c]
        $sol = Get-PimFailureSolution -Code $c
        $short = if ($sol -and "$($sol.short)".Trim()) { "$($sol.short)" } else { "$c" }
        "{0} assignment{1} cannot be made: {2} [{3}]" -f $n, $(if ($n -eq 1) { '' } else { 's' }), $short, $c
    }
    $out.customerConfig = $true
    $out.code = "$($order[0])"; $out.fixKind = 'customer-config'
    $out.sentence = (@($parts) -join '; ')
    $out.items = @($names.ToArray())
    return [pscustomobject]$out
}

function Get-PimTransientWaitWindowMinutes {
    <# PURE. How long a transient item may wait before it counts as a real failure again (Test-PimEngineFailuresAreAllTransient),
       and -- the same window -- how young a group must be for its unreadable policy to count as "not ready yet" (§97.3). #>
    return 120
}

function Test-PimGroupPolicyNotReadyAnswer {
    <#
      PURE. §97.3: TRUE when a Graph error is one of the answers PIM gives for a group whose policy it has not materialised
      yet: 404 / NotFound / ResourceNotFound, a 400 saying the policy "does not exist" / is "not found", or the rule PATCH's
      "InvalidPolicyRule -- The policy rule is invalid" (the GROUP-POLICY-NOT-READY catalog rule's measured answer).
      The ONE list of not-ready answers. It says nothing about the group's age -- the caller must prove the group is new.
      A 403, 429 or 5xx is never "not ready".
    #>
    param([string]$Message)
    $m = "$Message"
    if (-not $m.Trim()) { return $false }
    if ($m -match '(?i)HTTP (401|403|429|5\d\d)\b') { return $false }
    return [bool]($m -match '(?i)HTTP 404\b|\bNotFound\b|ResourceNotFound|InvalidPolicyRule -- The policy rule is invalid|HTTP 400\b.{0,300}(does not exist|not found)')
}

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
    if ($azPerm -or $azScope) {
        # 2026-09-26 (EFIF drift mail, 7x): a LIVE Azure assignment the store does not define (a drift 'extra') carries no
        # GroupTag and no AzScopePermission -- it read "group  -> Azure role '' at management group ...". Name what the live
        # row does carry (principal name / id, role definition id) instead of printing blanks.
        $whoAz = if ($gdisp) { "group $gdisp" } elseif ($pName) { $pName } elseif ($prin) { "principal $prin" } else { 'an unnamed principal' }
        $rdId = & $g 'roleDefinitionId'
        $roleAz = if ($azPerm) { $azPerm } elseif ($rdId) { "role id $(("$rdId" -split '/')[-1])" } else { 'an unnamed role' }
        return "$whoAz -> Azure role '$roleAz' at $(Format-PimAzureScopeLabel $azScope)$t"
    }
    $role = & $g 'RoleDefinitionName'
    if ($role) {
        # REQ-U wave 2: a WORKLOAD binding (Defender XDR / Intune rows carry RoleDefinitionName + Workload) is not an
        # Entra role -- it read "group X -> Entra role 'Security Operator'" on the Drift page.
        $wlr = & $g 'Workload'
        if ($wlr) { return "group $gdisp -> $wlr role '$role'$t" }
        $au = & $g 'AdministrativeUnitTag'
        # A DIRECT role row (PIM-Assignments-Roles-Direct) names a USER, not a group -- it read "group  -> Entra role
        # 'Reports Reader'" with an empty group (§78 live E2E, 2026-09-24).
        $dUpn = & $g 'UserPrincipalName'; if (-not $dUpn) { $dUpn = & $g 'Username' }
        if ($dUpn -and -not $gt -and -not $gname) { return "user $dUpn -> Entra role '$role' (direct)$t" }
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

# §100.45 (owner 2026-10-10, after an alert mail for 'delta-pim-entra' whose only cause was HTTP 429 on the role schedule
# preload: "did you not fix this across all jobs" / "maybe even have a throttle category ... it is not to alert me about,
# except if you cannot handle it, but this is normal"). ONE rule for every job: a failed run whose every cause is Microsoft
# throttling or a Microsoft-side outage, and which applied nothing, is THROTTLED -- retried on the next run, never mailed.
$script:PimRunTransientCodes = @('THROTTLED', 'SERVICE-ERROR')
$script:PimRunTransientSignal = '(?i)\b429\b|Too ?Many ?Requests|throttl|\bHTTP 5\d\d\b|\b50[0234]\b|Service ?Unavailable|Bad ?Gateway|Gateway ?Time-?out|InternalServerError|timed out|\btimeout\b|TaskCanceledException|A task was canceled'
# Anything here means a cause that is NOT throttling: a permission, a bad request / missing object, a code fault, a hold,
# an unbound scope. Deliberately broad -- a doubt keeps the run FAILED (an alert too many beats a silent failure).
$script:PimRunNonTransientSignal = '(?i)\bHTTP 4(?!29)\d\d\b|->\s*4(?!29)\d\d\b|\b40[13]\b|Forbidden|Unauthori[sz]ed|AuthorizationFailed|Authorization_RequestDenied|InsufficientPermissions|Insufficient privileges|BadRequest|\bNotFound\b|ResourceNotFound|no provider for scope|NEEDS APPROVAL|MASS-HOLD|REMOVE-BUDGET-HELD|OutOfMemory|NullReference|null-valued expression|Cannot index into|cannot be found|is not recognized|ParameterBinding|Exception calling'

function Test-PimRunFailureTransient {
    <#
      PURE. §100.45. TRUE when a failed run is THROTTLED: every failing cause is HTTP 429 / "Too Many Requests" / throttling,
      an HTTP 5xx / service unavailable / gateway error, or a timeout -- including the engine's "the live state could not be
      read ... preload was INCOMPLETE (... -> HTTP 429 | ... -> HTTP 503)" -- AND the run applied nothing.
        -Text   the run's failure text (the job detail / the thrown error).
        -Items  the classified failing items (New-PimEngineItemFailure), when the caller has them.
      FALSE when: any cause is something else (403, bad data, a code fault, a hold, an unknown catalog code); a cause of the
      preload list ("<what> -> <answer>") carries no throttling signal; the run applied something ("applied=N", N > 0: a
      PARTIAL apply is a real failure); or there is no throttling signal at all.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Text = '', [object[]]$Items = @())
    $t = "$Text"
    $its = @(@($Items) | Where-Object { $_ })
    if (-not $t.Trim() -and -not $its.Count) { return $false }
    foreach ($x in $its) {
        $c = "$($x.code)".Trim().ToUpperInvariant()
        if ($c) { if ($c -notin $script:PimRunTransientCodes) { return $false }; continue }
        $m = "$($x.message)"
        if (-not ($m -match $script:PimRunTransientSignal) -or $m -match $script:PimRunNonTransientSignal) { return $false }
    }
    if (-not $t.Trim()) { return $true }
    # A partial apply is not "nothing happened": the engine (and queue-apply) state how much they applied.
    if ($t -match '(?i)\bapplied\s*[=:]\s*[1-9]\d*') { return $false }
    if ($t -match $script:PimRunNonTransientSignal) { return $false }
    # Every catalog code the summary names must be a throttling / service code (UNCLASSIFIED included as "not").
    $known = @{}; foreach ($k in @(Get-PimFailureCatalogCodes)) { $known["$k"] = $true }
    foreach ($mm in [regex]::Matches($t, '\[([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*)\]')) {   # single-word codes too: THROTTLED, UNCLASSIFIED
        $code = $mm.Groups[1].Value
        if ($known.ContainsKey($code) -and $code -notin $script:PimRunTransientCodes) { return $false }
    }
    # Each listed cause ("<request> -> <answer>", separated by ' | ' or '; ') must itself be throttling / service-side.
    foreach ($seg in @($t -split '\s\|\s|;\s')) {
        if ($seg -match '->' -and -not ($seg -match $script:PimRunTransientSignal)) { return $false }
    }
    return [bool]($t -match $script:PimRunTransientSignal)
}

function Test-PimEngineFailuresAreAllTransient {
    <#
      PURE. TRUE when every failed item in a run is a transient, retryable one -- today that is
      GROUP-NOT-CREATED-YET and its kind: the item names something another job creates in the same
      cycle, so it applies on the next run without anybody doing anything.
      🔴 Operator, 2026-09-22, on an alert for 'delta-admins' (1x "The group this item needs does not
      exist yet"): "bug". A run whose ONLY problem is ordering was recorded FAILED and raised a
      failure alert every cycle, which is how a real failure stops being noticed.
      🔒 It is NOT "ignore transient items": with no failures at all the caller reports ok and SAYS
      how many are waiting, and an item still waiting after `-MaxAgeMinutes` (its first-seen stamp)
      is treated as a real failure again -- something it needs is never coming.
    #>
    param([object[]]$Failures, [int]$MaxAgeMinutes = (Get-PimTransientWaitWindowMinutes), [datetime]$NowUtc = [datetime]::UtcNow)
    $all = @($Failures | Where-Object { $_ })
    if (-not $all.Count) { return $false }
    foreach ($x in $all) {
        if (Test-PimEngineFailureIsApprovalHold $x) { continue }          # holds have their own path
        if (-not ("$($x.severity)" -eq 'transient' -and $x.retryable)) { return $false }
        # Outlived its cause? The item carries firstSeenUtc once the failure store has seen it before.
        $seen = $null
        try { if ($x.PSObject.Properties['firstSeenUtc'] -and "$($x.firstSeenUtc)".Trim()) { $seen = [datetime]::Parse("$($x.firstSeenUtc)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal') } } catch { $seen = $null }
        if ($seen -and ($NowUtc.ToUniversalTime() - $seen).TotalMinutes -gt $MaxAgeMinutes) { return $false }
    }
    return $true
}

function Format-PimFailureSummary {
    <# "17 item(s) failed: 10x Azure PIM policy rejects the assignment duration [AZ-POLICY-MAX-DURATION]; 4x ..." #>
    param([object[]]$Failures)
    $all = @($Failures | Where-Object { $_ })
    if (-not $all.Count) { return '' }
    # BUG-233 (77.2, EFIF 2026-09-21): a breaker HOLD is not a failure. It used to be counted as "1x ... HELD"
    # among the failures, so one unrelated error turned the whole job into "2 item(s) failed" and the approval the
    # run was waiting for was never stated. Holds are reported on their own, after the real failures.
    $holds = @($all | Where-Object { Test-PimEngineFailureIsApprovalHold $_ })
    $rest  = @($all | Where-Object { -not (Test-PimEngineFailureIsApprovalHold $_) })
    # 🔴 WAITING IS NOT FAILING (operator, 2026-09-22, on an alert for 'delta-admins': "[AdminMembers]
    # 1 item(s) failed: 1x The group this item needs does not exist yet [GROUP-NOT-CREATED-YET]" --
    # "bug"). That item is ORDER, not error: the Groups job creates the group and the membership
    # applies on the next run. The catalogue already calls it transient + retryable, but the run was
    # still recorded FAILED and it raised a failure alert -- every cycle, for a condition that fixes
    # itself. Same treatment as a breaker HOLD (BUG-233): reported on its own line, never counted
    # among the failures. A transient item that OUTLIVES its cause is a real failure and is escalated
    # by the caller (Test-PimEngineFailuresAreAllTransient + the first-seen age), not by hiding it.
    $waiting = @($rest | Where-Object { "$($_.severity)" -eq 'transient' -and $_.retryable })
    $f = @($rest | Where-Object { -not ("$($_.severity)" -eq 'transient' -and $_.retryable) })
    $out = @()
    if ($f.Count) {
        $groups = @($f | Group-Object code | Sort-Object Count -Descending)
        $parts = foreach ($g in $groups) {
            $t = "$($g.Group[0].title)"
            $fixable = @($g.Group | Where-Object { @($_.fixes).Count }).Count
            # BUG-234 (77.3): "Unrecognised failure" says nothing. With no catalogued explanation, the raw error IS
            # the explanation -- show it (first item, trimmed), not only the word "unrecognised".
            $raw = if ("$($g.Name)" -eq 'UNCLASSIFIED') {
                $m = ("$($g.Group[0].message)" -replace '\s+', ' ').Trim()
                if ($m.Length -gt 220) { $m = $m.Substring(0, 217) + '...' }
                if ($m) { ": $m" } else { '' }
            } else { '' }
            "{0}x {1} [{2}]{3}{4}" -f $g.Count, $t, $g.Name, $raw, $(if ($fixable) { ' -- auto-fix available' } else { '' })
        }
        $out += ("{0} item(s) failed: {1}. Open Jobs > Engine logs & errors for each item, its cause and the fix." -f $f.Count, ($parts -join '; '))
    }
    if ($waiting.Count) {
        $wg = @($waiting | Group-Object code | Sort-Object Count -Descending)
        $wp = foreach ($g in $wg) { "{0}x {1} [{2}]" -f $g.Count, "$($g.Group[0].title)", $g.Name }
        $out += ("{0} item(s) WAITING (not failed -- they apply on a later run once what they need exists): {1}" -f $waiting.Count, ($wp -join '; '))
    }
    if ($holds.Count) {
        $h = @($holds | ForEach-Object {
            $msg = "$($_.message)"; $prov = Get-PimApprovalHoldProvider -Code "$($_.code)"
            $hash = ''; $m = [regex]::Match($msg, 'planHash=([0-9a-fA-F]{64})'); if ($m.Success) { $hash = $m.Groups[1].Value.ToLowerInvariant() }
            $n = ''; $m2 = [regex]::Match($msg, 'N=(\d+) polic'); if ($m2.Success) { $n = $m2.Groups[1].Value }
            "{0}: {1} polic(ies) would change -- review the WhatIf and approve in Jobs > Engine logs & errors (Approve-PimPolicyMassChange -Provider {0} -PlanHash {2} -By <you>)" -f $prov, $(if ($n) { $n } else { '?' }), $(if ($hash) { $hash } else { '<hash>' })
        } | Select-Object -Unique)
        $out += ($(if ($f.Count) { 'ALSO NEEDS APPROVAL (nothing written for these): ' } else { 'NEEDS APPROVAL (nothing written for these): ' }) + ($h -join ' | '))
    }
    return ($out -join ' ')
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
