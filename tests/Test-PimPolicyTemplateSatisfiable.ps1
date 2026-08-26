#Requires -Version 5.1
<#
.SYNOPSIS
    BUG-21 -- a shipped policy template must never impose a rule the ENGINE itself cannot
    satisfy, and must never quietly drop the one that protects activation.

    What happened: default.policytemplate.json -- applied to the member policy of EVERY
    managed group -- set

        "Enablement": { "Admin_Eligibility": ["MultiFactorAuthentication", "Justification"] }

    The 'admin' who makes that request is the engine's own app-only certificate SPN. An
    app-only token can never carry an MFA claim, so the rule was unsatisfiable BY ANYONE:
    the engine wrote a policy onto each group it created and was then refused by that same
    policy when it tried to assign to the group --

        HTTP 400 RoleAssignmentRequestPolicyValidationFailed
        "The following policy rules failed: MfaRule - Multi-factor authentication is required"

    -- on every run, forever. It removed no risk (nobody could satisfy it) and blocked the
    product's core delegation path: an admin made eligible on a PIM group.

    Observed live 2026-08-06 in the TEST-12 scenario matrix, after BUG-20 was fixed and the
    principal finally resolved. Justification is KEPT: the engine does send one, so that
    half is satisfiable and preserves the audit trail.

    The two assertions that matter, and they pull in OPPOSITE directions -- which is the
    point, because the cheap "fix" is to blank the whole Enablement block:
      1. no Admin_* target may require MultiFactorAuthentication (unsatisfiable);
      2. EndUser_Assignment MUST still require it (activation MFA is the real control).

    Offline. Reads the shipped template files.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$tplDir  = Join-Path $solRoot 'templates\policy'

Write-Host "=== BUG-21: every shipped policy template must be satisfiable by an app-only engine ===" -ForegroundColor Cyan

$files = @(Get-ChildItem -LiteralPath $tplDir -Filter '*.policytemplate.json' -ErrorAction SilentlyContinue)
Assert "there are shipped policy templates to check" (@($files).Count -ge 1)

foreach ($f in $files) {
    Write-Host "`n-- $($f.Name) --" -ForegroundColor Yellow
    $j = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert "$($j.id): parses and has an id" ("$($j.id)".Trim() -ne '')

    # ---- BUG-56: never ship an EXPLICIT APPROVER RECIPIENT -- it write-locks the policy ----
    # An Approver notification rule with a NON-EMPTY recipient list puts the whole policy into
    # a state where Entra refuses EVERY subsequent per-rule PATCH with
    # 400 ActivationCustomApproversNotEmpty -- including rules with nothing to do with approval,
    # and including the PATCH that would remove the recipients.
    #
    # MEASURED 2026-08-11 on a throwaway custom role in an isolated test tenant. All four
    # combinations, each on a freshly unlocked policy:
    #     defaults=true  + recipients=[]   -> writeable
    #     defaults=false + recipients=[]   -> writeable
    #     defaults=true  + recipients=[2]  -> LOCKED
    #     defaults=false + recipients=[2]  -> LOCKED
    # So the RECIPIENT LIST ALONE is the trigger and isDefaultRecipientsEnabled is irrelevant.
    # 🪤 An earlier version of this guard asserted the PAIR (defaults=false AND recipients),
    # because the first two data points happened to have defaults=false. That guard would have
    # PASSED the shape that actually caused the outage. The single-variable sweep above is why
    # it now tests the recipients alone -- do not narrow it back.
    #
    # Other measured boundaries: the poisoning PATCH is ACCEPTED (it does not fail loudly); the
    # only way back is PATCH /policies/roleManagementPolicies/{id} with a `rules` collection
    # setting the list empty; and the ADMIN recipientType does NOT lock, which is why
    # EntraIDRoles_Standard's Admin rule may keep both defaults=false and explicit recipients.
    #
    # EntraIDRoles_RequireApproval shipped `recipientsSource: ApproverUpns` until 2026-08-11 --
    # that is what locked a production role's policy and then made it the only role of 96 that
    # could not receive template updates.
    foreach ($n in @($j.rules.Notification)) {
        if (-not $n) { continue }
        if ("$($n.recipientType)" -ne 'Approver') { continue }
        # 🪤 @($null).Count is 1, not 0 -- a template with NO `recipients` property would look
        # like it had one. Filter the blanks out before counting.
        $explicitList = @($n.recipients | Where-Object { "$_".Trim() })
        $hasExplicit  = ("$($n.recipientsSource)".Trim() -ne '') -or ($explicitList.Count -gt 0)
        Assert "$($j.id): Approver notification declares NO explicit recipients -- any list write-locks the policy (BUG-56)" `
            (-not $hasExplicit)
    }

    $en = $j.rules.Enablement
    if (-not $en) { Write-Host "     (no Enablement block -- inherits)" -ForegroundColor DarkGray; continue }

    foreach ($p in $en.PSObject.Properties) {
        $target = $p.Name
        $rules  = @($p.Value)
        if ($target -like 'Admin_*') {
            # THE regression: an admin-side rule the app-only engine cannot meet.
            Assert "$($j.id).$target does NOT require MFA (app-only cannot present one)" (-not ($rules -contains 'MultiFactorAuthentication'))
        }
    }

    # ...and the other direction: activation MFA must survive. Blanking the whole
    # Enablement block would satisfy the assertion above and silently weaken the product.
    if ($en.PSObject.Properties['EndUser_Assignment']) {
        Assert "$($j.id).EndUser_Assignment STILL requires MFA (activation is the real control)" (@($en.EndUser_Assignment) -contains 'MultiFactorAuthentication')
    }
    # Admin_Eligibility: pinned to the OPERATOR'S DECISION (2026-08-11), and it now DIFFERS BY
    # TEMPLATE FAMILY -- so this asserts per template rather than one value for all four.
    #
    #   STANDARD  (default, EntraIDRoles_Standard)              -> []              EMPTY
    #   APPROVAL  (approval-required, EntraIDRoles_RequireApproval) -> [Justification]
    #
    # OPERATOR 2026-08-11: *"admin eligible is blank, no justification or mfa. app must be able to
    # work"*. That supersedes the 2026-08-10 decision which had briefly put Justification on all
    # four. The rationale for the split: on a STANDARD scope every grant is made by the engine's
    # app-only SPN, and a justification rule there is not a control at all (measured: a request
    # that OMITS a justification is still ACCEPTED app-only) -- it only adds a rule that must be
    # kept converged. On an APPROVAL scope a human is in the loop by definition, and there the
    # rule IS enforced by the portal, so it earns its place.
    #
    # HISTORY, because this value has now oscillated three times and the REASON matters far more
    # than the value: ["Justification"] -> [] (2026-08-06, "match the production reference") ->
    # ["Justification"] (2026-08-10) -> [] on standard only (2026-08-11). None of the 2026-08-10
    # value ever reached the tenant, so production never moved and stays converged at [].
    #
    # 🔴 THE LOAD-BEARING GUARD IS THE MFA ONE ABOVE, NOT THIS VALUE. Whatever Admin_Eligibility
    # becomes next, it must NEVER contain MultiFactorAuthentication (BUG-21): A/B tested in test
    # tenant test1intr2ig798 on BOTH the group path and the directory-role path (different
    # endpoints, tested separately) -- MFA+Justification fails every eligibility create with
    # 400 RoleAssignmentRequestPolicyValidationFailed / MfaRule, because an app-only token carries
    # no MFA claim and no permission grant can change that.
    # 🪤 The directory-role arm needed the estate onboarding SPN granted RoleManagementPolicy
    # .ReadWrite.Directory first: it is a GLOBAL ADMINISTRATOR (confirmed in the token's `wids`
    # claim) and STILL got 403, because an app-only token is authorised by its `roles` claim
    # (application permissions), which held none of them. GA covered the GROUP policy path but not
    # this one. Third variant of the recurring lesson in framework §10.0b.
    $standardTemplates = @('default','EntraIDRoles_Standard')
    if ($en.PSObject.Properties['Admin_Eligibility']) {
        $isStandard = ($standardTemplates -contains "$($j.id)")
        $wantElig = if ($isStandard) { @() } else { @('Justification') }
        $haveElig = @($en.Admin_Eligibility)
        $label = if ($wantElig.Count) { "['$($wantElig -join "','")']" } else { 'EMPTY' }
        $family = if ($isStandard) { 'STANDARD' } else { 'APPROVAL' }
        Assert "$($j.id).Admin_Eligibility is $label -- $family family (operator decision 2026-08-11)" `
            ((@($haveElig | Sort-Object) -join ',') -eq (@($wantElig | Sort-Object) -join ','))
    }
}

Write-Host "`n=== $pass passed / $fail failed ===" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
