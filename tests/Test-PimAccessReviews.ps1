<#
  Offline tests for the Access Review OVERVIEW data layer
  (engine/_shared/PIM-AccessReviews.ps1). Covers the PURE normalization/shaping:
  scope/target derivation, reviewer flattening, recurrence cadence, decision
  tallies, and the full definition -> table-ready row contract. No network, no
  live calls (the live wrapper Get-PimAccessReviewOverview is exercised live in a
  tenant smoke, not here). Fixtures mirror the Graph accessReview definition shape.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-AccessReviews.ps1"

$pass=0; $fail=0
function Assert($n,$c){ if($c){ $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

Write-Host "=== PIM-AccessReviews (overview data layer) tests ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Scope/target derivation
# ---------------------------------------------------------------------------
Write-Host "-- scope/target --" -ForegroundColor DarkCyan
$grp = Get-PimAccessReviewScopeTarget -Scope ([pscustomobject]@{ query = '/groups/abc-123/transitiveMembers'; queryType = 'MicrosoftGraph' })
Assert "group scope -> kind=group + id"        ($grp.kind -eq 'group' -and $grp.id -eq 'abc-123' -and $grp.display -eq 'Group: abc-123')
$rol = Get-PimAccessReviewScopeTarget -Scope ([pscustomobject]@{ query = "/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=roleDefinitionId eq 'ROLE9'" })
Assert "role scope -> kind=role + roleDefId"   ($rol.kind -eq 'role' -and $rol.id -eq 'ROLE9')
$oth = Get-PimAccessReviewScopeTarget -Scope ([pscustomobject]@{ query = '/servicePrincipals' })
Assert "other scope -> kind=other + raw query" ($oth.kind -eq 'other' -and $oth.display -eq '/servicePrincipals')
$non = Get-PimAccessReviewScopeTarget -Scope ([pscustomobject]@{ query = '' })
Assert "empty scope -> kind=unknown"           ($non.kind -eq 'unknown')

# ---------------------------------------------------------------------------
# 2. Reviewer flattening
# ---------------------------------------------------------------------------
Write-Host "-- reviewers --" -ForegroundColor DarkCyan
$rev = @(Get-PimAccessReviewReviewers -Reviewers @(
    [pscustomobject]@{ query = '/users/u1'; queryType = 'MicrosoftGraph' }
    [pscustomobject]@{ query = '/groups/g1'; queryType = 'MicrosoftGraph' }
    [pscustomobject]@{ query = '' }
))
Assert "user reviewer flattened to id"         ($rev -contains 'u1')
Assert "group reviewer prefixed"               ($rev -contains 'group:g1')
Assert "empty reviewer -> self placeholder"    (($rev | Where-Object { $_ -like '*self*' }).Count -eq 1)
Assert "no reviewers -> empty array"           (@(Get-PimAccessReviewReviewers -Reviewers @()).Count -eq 0)

# ---------------------------------------------------------------------------
# 2b. Reviewers JSON-array shape (the GUI dead-tab fix). A single-reviewer review
#     must STILL serialize as a JSON LIST, not a scalar string, or the GUI's
#     reviewers()/search .filter()/.join() throw and the tab spins forever.
#     ConvertTo-PimJsonArray forces this; the normalizer applies it to .Reviewers.
# ---------------------------------------------------------------------------
Write-Host "-- reviewers JSON-array coercion (GUI dead-tab fix) --" -ForegroundColor DarkCyan
$one  = ConvertTo-PimJsonArray -Value 'solo-reviewer'
Assert "scalar -> single-element array"         ($one -is [System.Array] -and $one.Count -eq 1 -and $one[0] -eq 'solo-reviewer')
$nul  = ConvertTo-PimJsonArray -Value $null
Assert "null -> empty array (not null)"         ($nul -is [System.Array] -and $nul.Count -eq 0)
$many = ConvertTo-PimJsonArray -Value @('a','b')
Assert "array stays a 2-element array"           ($many -is [System.Array] -and $many.Count -eq 2)
# Single-reviewer review through the FULL normalizer must keep Reviewers an array...
$defSolo = [pscustomobject]@{
    id = 'def-solo'
    displayName = 'PIM4EntraPS review - PIM-Solo'
    scope = [pscustomobject]@{ query = '/groups/grp-solo/transitiveMembers'; queryType = 'MicrosoftGraph' }
    reviewers = @([pscustomobject]@{ query = '/users/only-one'; queryType = 'MicrosoftGraph' })
    settings = [pscustomobject]@{}
}
$rowSolo = ConvertTo-PimAccessReviewOverviewRow -Definition $defSolo
Assert "1-reviewer row .Reviewers is an array"   ($rowSolo.Reviewers -is [System.Array] -and @($rowSolo.Reviewers).Count -eq 1 -and $rowSolo.Reviewers[0] -eq 'only-one')
# ...and (the real regression) survives JSON round-trip as a JSON array, so the
# browser receives ["only-one"] and never a bare "only-one" string. We assert on
# both the compiled Manager serializer AND the ConvertTo-Json fallback shape.
$jsonRow = $rowSolo | ConvertTo-Json -Depth 12 -Compress
$back    = $jsonRow | ConvertFrom-Json
$backRev = $back.Reviewers
Assert "JSON round-trip keeps Reviewers a LIST"  (($backRev -is [System.Array]) -or ($backRev -is [System.Collections.IEnumerable] -and -not ($backRev -is [string])))
Assert "JSON round-trip preserves the reviewer"  (@($backRev).Count -eq 1 -and @($backRev)[0] -eq 'only-one')
# Zero-reviewer review must yield an EMPTY array (renders honest empty state, not a spin).
$defNone = [pscustomobject]@{ id='def-none'; displayName='No-reviewer review'; scope=[pscustomobject]@{ query='/servicePrincipals' }; reviewers=@(); settings=[pscustomobject]@{} }
$rowNone = ConvertTo-PimAccessReviewOverviewRow -Definition $defNone
Assert "0-reviewer row .Reviewers is empty array" ($rowNone.Reviewers -is [System.Array] -and @($rowNone.Reviewers).Count -eq 0)

# ---------------------------------------------------------------------------
# 3. Recurrence cadence
# ---------------------------------------------------------------------------
Write-Host "-- recurrence --" -ForegroundColor DarkCyan
$mk = { param($type,$interval) [pscustomobject]@{ recurrence = [pscustomobject]@{ pattern = [pscustomobject]@{ type=$type; interval=$interval }; range = [pscustomobject]@{ type='noEnd' } } } }
Assert "monthly interval 1 -> Monthly"         ((Get-PimAccessReviewRecurrence -Settings (& $mk 'absoluteMonthly' 1)).cadence -eq 'Monthly')
Assert "monthly interval 3 -> Quarterly"       ((Get-PimAccessReviewRecurrence -Settings (& $mk 'absoluteMonthly' 3)).cadence -eq 'Quarterly')
Assert "weekly -> Weekly + isRecurring"        ((Get-PimAccessReviewRecurrence -Settings (& $mk 'weekly' 1)).isRecurring)
Assert "yearly -> Annually"                    ((Get-PimAccessReviewRecurrence -Settings (& $mk 'absoluteYearly' 1)).cadence -eq 'Annually')
Assert "no recurrence -> One-time, not recurring" (((Get-PimAccessReviewRecurrence -Settings ([pscustomobject]@{})).isRecurring) -eq $false)

# ---------------------------------------------------------------------------
# 4. Decision tallies
# ---------------------------------------------------------------------------
Write-Host "-- decision counts --" -ForegroundColor DarkCyan
$dec = @(
    [pscustomobject]@{ decision='Approve' }
    [pscustomobject]@{ decision='Approve' }
    [pscustomobject]@{ decision='Deny' }
    [pscustomobject]@{ decision='DontKnow' }
    [pscustomobject]@{ decision='NotReviewed' }
    [pscustomobject]@{ decision='NotNotified' }
)
$c = Get-PimAccessReviewDecisionCounts -Decisions $dec
Assert "total counted"                         ($c.total -eq 6)
Assert "approved tallied"                      ($c.approved -eq 2)
Assert "denied tallied"                        ($c.denied -eq 1)
Assert "dontKnow tallied"                      ($c.dontKnow -eq 1)
Assert "pending = NotReviewed + NotNotified"   ($c.pending -eq 2)
$empty = Get-PimAccessReviewDecisionCounts -Decisions @()
Assert "empty decisions -> all zero"           ($empty.total -eq 0 -and $empty.pending -eq 0)

# ---------------------------------------------------------------------------
# 5. Full normalizer -> table-ready row (engine-managed review, with instance)
# ---------------------------------------------------------------------------
Write-Host "-- normalizer (PIM-managed) --" -ForegroundColor DarkCyan
$def = [pscustomobject]@{
    id = 'def-1'
    displayName = 'PIM4EntraPS review - PIM-Entra-ID-UserAdmin-L1-T0-CP-ID'
    scope = [pscustomobject]@{ query = '/groups/grp-9/transitiveMembers'; queryType = 'MicrosoftGraph' }
    reviewers = @([pscustomobject]@{ query = '/users/owner1'; queryType = 'MicrosoftGraph' })
    status = 'NotStarted'
    settings = [pscustomobject]@{
        autoApplyDecisionsEnabled = $false
        recurrence = [pscustomobject]@{ pattern = [pscustomobject]@{ type='absoluteMonthly'; interval=3 }; range = [pscustomobject]@{ type='noEnd' } }
    }
}
$inst = [pscustomobject]@{ id='inst-1'; status='InProgress'; startDateTime='2026-06-01T00:00:00Z'; endDateTime='2026-06-15T00:00:00Z' }
$row = ConvertTo-PimAccessReviewOverviewRow -Definition $def -CurrentInstance $inst -Decisions $dec

Assert "row carries definition id"             ($row.Id -eq 'def-1')
Assert "row flagged IsPimManaged"              ($row.IsPimManaged -eq $true)
Assert "row extracts GroupName from name"      ($row.GroupName -eq 'PIM-Entra-ID-UserAdmin-L1-T0-CP-ID')
Assert "row scope = group + id"                ($row.ScopeKind -eq 'group' -and $row.ScopeId -eq 'grp-9')
Assert "row reviewer flattened + counted"      ($row.ReviewerCount -eq 1 -and ($row.Reviewers -contains 'owner1'))
Assert "row recurrence = Quarterly"            ($row.Recurrence -eq 'Quarterly' -and $row.IsRecurring)
Assert "row status from INSTANCE not def"      ($row.Status -eq 'InProgress')
Assert "row start/due from instance"           ($row.StartDate -eq '2026-06-01T00:00:00Z' -and $row.DueDate -eq '2026-06-15T00:00:00Z')
Assert "row decision counts wired through"     ($row.DecisionsTotal -eq 6 -and $row.DecisionsApproved -eq 2 -and $row.DecisionsDenied -eq 1)
Assert "row AutoApply reflects settings"       ($row.AutoApply -eq $false)

# ---------------------------------------------------------------------------
# 6. Normalizer fallback -- non-PIM review, no instance, no decisions
# ---------------------------------------------------------------------------
Write-Host "-- normalizer (non-managed, no instance) --" -ForegroundColor DarkCyan
$def2 = [pscustomobject]@{
    id = 'def-2'
    displayName = 'Quarterly guest review'
    scope = [pscustomobject]@{ query = '/servicePrincipals' }
    reviewers = @()
    status = 'NotStarted'
    settings = [pscustomobject]@{}
}
$row2 = ConvertTo-PimAccessReviewOverviewRow -Definition $def2
Assert "non-managed -> IsPimManaged false"     ($row2.IsPimManaged -eq $false)
Assert "non-managed -> GroupName blank"         ($row2.GroupName -eq '')
Assert "no instance -> status from definition"  ($row2.Status -eq 'NotStarted')
Assert "no recurrence -> One-time"              ($row2.Recurrence -eq 'One-time' -and -not $row2.IsRecurring)
Assert "no decisions -> zero counts"            ($row2.DecisionsTotal -eq 0 -and $row2.DecisionsPending -eq 0)
Assert "scope other -> ScopeKind other"         ($row2.ScopeKind -eq 'other')

# ---------------------------------------------------------------------------
# 7. Seed rows -- the GUI "Access Reviews" tab renders these when the live
#    tenant returns nothing (no grant / no reviews / offline). They MUST be
#    produced by the real normalizer so the schema + logic match live data.
# ---------------------------------------------------------------------------
Write-Host "-- seed rows (GUI fallback) --" -ForegroundColor DarkCyan
$seed = @(Get-PimAccessReviewSeedRows)
Assert "seed returns multiple rows"             ($seed.Count -ge 4)
Assert "seed rows carry the normalizer schema"  ($null -ne $seed[0].PSObject.Properties['DecisionsApproved'] -and $null -ne $seed[0].PSObject.Properties['ScopeTarget'] -and $null -ne $seed[0].PSObject.Properties['Recurrence'])
Assert "seed has a PIM-managed group review"    (@($seed | Where-Object { $_.IsPimManaged -and $_.ScopeKind -eq 'group' }).Count -ge 1)
Assert "seed has a role-scoped review"          (@($seed | Where-Object { $_.ScopeKind -eq 'role' }).Count -ge 1)
Assert "seed has a non-PIM tenant review"       (@($seed | Where-Object { -not $_.IsPimManaged }).Count -ge 1)
Assert "seed has an in-progress review"         (@($seed | Where-Object { $_.Status -eq 'InProgress' }).Count -ge 1)
Assert "seed decision counts are populated"     ((@($seed | Where-Object { $_.DecisionsTotal -gt 0 }).Count -ge 1) -and (@($seed | ForEach-Object { $_.DecisionsApproved }) -join '' -match '\d'))
$mgr = @($seed | Where-Object { $_.IsPimManaged })[0]
Assert "seed PIM review extracts GroupName"     ($mgr.GroupName -and $mgr.GroupName -notlike 'PIM4EntraPS review*')
$onetime = @($seed | Where-Object { -not $_.IsRecurring })
Assert "seed includes a one-time review"        ($onetime.Count -ge 1 -and $onetime[0].Recurrence -eq 'One-time')

# ---------------------------------------------------------------------------
# 8. ATTESTATION -- decision value resolution + PATCH body + idempotency
#    (REQUIREMENTS § H7 -- the WRITE layer; pure, offline fixtures, no network).
# ---------------------------------------------------------------------------
Write-Host "-- attestation: decision resolution --" -ForegroundColor DarkCyan
Assert "approve synonyms -> Approve"            ((Resolve-PimReviewDecisionValue -Outcome 'certify') -eq 'Approve' -and (Resolve-PimReviewDecisionValue -Outcome 'recertify') -eq 'Approve' -and (Resolve-PimReviewDecisionValue -Outcome 'approved') -eq 'Approve')
Assert "deny synonyms -> Deny"                  ((Resolve-PimReviewDecisionValue -Outcome 'revoke') -eq 'Deny' -and (Resolve-PimReviewDecisionValue -Outcome 'reject') -eq 'Deny' -and (Resolve-PimReviewDecisionValue -Outcome 'remove') -eq 'Deny')
Assert "dontknow synonyms -> DontKnow"          ((Resolve-PimReviewDecisionValue -Outcome 'unsure') -eq 'DontKnow' -and (Resolve-PimReviewDecisionValue -Outcome "dont know") -eq 'DontKnow')
$threw = $false; try { Resolve-PimReviewDecisionValue -Outcome 'maybe-later' | Out-Null } catch { $threw = $true }
Assert "unknown outcome throws (fail-closed)"   ($threw)

Write-Host "-- attestation: PATCH body + audit --" -ForegroundColor DarkCyan
$now = [datetime]'2026-06-15T12:00:00Z'
$p = New-PimReviewDecisionPatch -Outcome 'deny' -Justification 'Left the team' -NowUtc $now -DecidedBy 'owner@x'
Assert "patch body has exact Graph decision"    ($p.body.decision -eq 'Deny')
Assert "patch body carries justification"       ($p.body.justification -eq 'Left the team')
Assert "patch audit records who/what/when"      ($p.audit.decision -eq 'Deny' -and $p.audit.decidedBy -eq 'owner@x' -and $p.audit.action -eq 'access-review.decision' -and $p.audit.decidedUtc -match '^2026-06-15')
$threwJ = $false; try { New-PimReviewDecisionPatch -Outcome 'approve' -Justification '   ' -NowUtc $now | Out-Null } catch { $threwJ = $true }
Assert "blank justification throws"             ($threwJ)
# PATCH body must serialize to valid JSON the Graph endpoint accepts.
$json = $p.body | ConvertTo-Json -Compress
Assert "patch body serializes to JSON"          ($json -match '"decision"\s*:\s*"Deny"' -and $json -match '"justification"')

Write-Host "-- attestation: idempotency --" -ForegroundColor DarkCyan
Assert "same outcome is idempotent"             (Test-PimReviewDecisionIdempotent -Outcome 'approve' -Existing 'Approve')
Assert "synonym maps then idempotent"           (Test-PimReviewDecisionIdempotent -Outcome 'certify' -Existing 'Approve')
Assert "different outcome NOT idempotent"        (-not (Test-PimReviewDecisionIdempotent -Outcome 'deny' -Existing 'Approve'))
Assert "over NotReviewed NOT idempotent"        (-not (Test-PimReviewDecisionIdempotent -Outcome 'approve' -Existing 'NotReviewed'))
Assert "over blank NOT idempotent"              (-not (Test-PimReviewDecisionIdempotent -Outcome 'approve' -Existing ''))

# Set-PimAccessReviewDecision -WhatIf must NOT call the network and must return the
# resolved decision + audit record (explicit, no bulk, ShouldProcess-gated write).
Write-Host "-- attestation: Set-PimAccessReviewDecision -WhatIf (no network) --" -ForegroundColor DarkCyan
$wi = $null; $err = $null
try { $wi = Set-PimAccessReviewDecision -DefinitionId 'd1' -InstanceId 'i1' -DecisionId 'dec1' -Outcome 'approve' -Justification 'ok' -Force -WhatIf } catch { $err = $_ }
Assert "WhatIf returns skipped-whatif, no throw" ($null -eq $err -and $wi.status -eq 'skipped-whatif' -and $wi.decision -eq 'Approve' -and $wi.audit.decision -eq 'Approve')
Assert "no bulk auto-approve helper exists"      ($null -eq (Get-Command -Name 'Set-PimAccessReviewDecisionsBulk','Approve-PimAllAccessReviews' -ErrorAction SilentlyContinue))

# ---------------------------------------------------------------------------
# 9. OVERDUE / EXPIRY surfacing (the GUI "needs attention" list). Clock injected.
# ---------------------------------------------------------------------------
Write-Host "-- overdue surfacing --" -ForegroundColor DarkCyan
$ref = [datetime]'2026-06-15T00:00:00Z'
Assert "days remaining computed"                ((Get-PimReviewItemDays -DueDateTime '2026-06-20T00:00:00Z' -NowUtc $ref) -eq 5)
Assert "days overdue is negative"               ((Get-PimReviewItemDays -DueDateTime '2026-06-10T00:00:00Z' -NowUtc $ref) -eq -5)
Assert "blank due -> null"                       ($null -eq (Get-PimReviewItemDays -DueDateTime '' -NowUtc $ref))

$defA = [pscustomobject]@{ id='dA'; displayName='PIM4EntraPS review - PIM-Grp'; scope=[pscustomobject]@{ query='/groups/gA/transitiveMembers' } }
$ovr  = ConvertTo-PimReviewOverdueRow -Instance ([pscustomobject]@{ id='iA'; status='InProgress'; endDateTime='2026-06-10T00:00:00Z' }) -Definition $defA -Decisions @([pscustomobject]@{decision='NotReviewed'}) -NowUtc $ref
Assert "past-due in-progress -> overdue"        ($ovr.IsOverdue -and $ovr.Urgency -eq 'overdue' -and $ovr.DueInDays -lt 0 -and $ovr.PendingCount -eq 1)
$soon = ConvertTo-PimReviewOverdueRow -Instance ([pscustomobject]@{ id='iB'; status='InProgress'; endDateTime='2026-06-17T00:00:00Z' }) -Definition $defA -Decisions @() -NowUtc $ref -SoonDays 3
Assert "within SoonDays -> dueSoon (not overdue)" ($soon.IsDueSoon -and -not $soon.IsOverdue -and $soon.Urgency -eq 'dueSoon')
$done = ConvertTo-PimReviewOverdueRow -Instance ([pscustomobject]@{ id='iC'; status='Completed'; endDateTime='2026-06-01T00:00:00Z' }) -Definition $defA -Decisions @() -NowUtc $ref
Assert "completed past-due -> completed not overdue" (-not $done.IsOverdue -and $done.Urgency -eq 'completed')
$far = ConvertTo-PimReviewOverdueRow -Instance ([pscustomobject]@{ id='iD'; status='InProgress'; endDateTime='2026-07-30T00:00:00Z' }) -Definition $defA -Decisions @() -NowUtc $ref
Assert "far-future -> urgency none"             ($far.Urgency -eq 'none' -and -not $far.IsOverdue -and -not $far.IsDueSoon)

# ---------------------------------------------------------------------------
# 10. EVIDENCE shaping (the exportable audit artefact the GUI exports).
# ---------------------------------------------------------------------------
Write-Host "-- evidence shaping --" -ForegroundColor DarkCyan
$evDi = [pscustomobject]@{ id='dec-x'; decision='Approve'; justification='still needed'
    principal=[pscustomobject]@{ id='u9'; displayName='Dana Dev'; userPrincipalName='dana@x.test' }
    resource=[pscustomobject]@{ id='g9'; displayName='PIM-Grp' }
    reviewedBy=[pscustomobject]@{ displayName='Owner Z' }; reviewedDateTime='2026-06-12T09:00:00Z'; recommendation='Approve' }
$item = ConvertTo-PimReviewEvidenceItem -DecisionItem $evDi
Assert "evidence item pulls principal id+name" ($item.PrincipalId -eq 'u9' -and $item.PrincipalName -eq 'Dana Dev' -and $item.PrincipalUpn -eq 'dana@x.test')
Assert "evidence item pulls decision+just+by"  ($item.Decision -eq 'Approve' -and $item.Justification -eq 'still needed' -and $item.ReviewedBy -eq 'Owner Z' -and $item.Recommendation -eq 'Approve')
$evMissing = ConvertTo-PimReviewEvidenceItem -DecisionItem ([pscustomobject]@{ id='dec-y'; principal=[pscustomobject]@{ id='u0' } })
Assert "evidence item null-tolerant -> NotReviewed default" ($evMissing.Decision -eq 'NotReviewed' -and $evMissing.PrincipalId -eq 'u0')

$pkg = ConvertTo-PimReviewEvidencePackage -Definition ([pscustomobject]@{ id='dA'; displayName='PIM4EntraPS review - PIM-Grp'; scope=[pscustomobject]@{ query='/groups/gA/transitiveMembers' } }) `
        -Instance ([pscustomobject]@{ id='iA'; status='InProgress'; startDateTime='2026-06-01T00:00:00Z'; endDateTime='2026-06-15T00:00:00Z' }) `
        -Decisions @($evDi, ([pscustomobject]@{ id='dec-z'; decision='Deny'; principal=[pscustomobject]@{ id='u8' } })) -NowUtc $ref
Assert "evidence header carries scope+managed" ($pkg.Header.IsPimManaged -and $pkg.Header.ScopeKind -eq 'group' -and $pkg.Header.DisplayName -eq 'PIM4EntraPS review - PIM-Grp')
Assert "evidence header stamps GeneratedUtc"    ($pkg.Header.GeneratedUtc -match '^2026-06-15')
Assert "evidence package has per-principal items" (@($pkg.Items).Count -eq 2 -and $pkg.Items[0].PrincipalId -eq 'u9')
Assert "evidence summary tallies decisions"      ($pkg.Summary.Total -eq 2 -and $pkg.Summary.Approved -eq 1 -and $pkg.Summary.Denied -eq 1)
# Whole package must JSON round-trip (export shape).
$pkgJson = $pkg | ConvertTo-Json -Depth 12
Assert "evidence package serializes to JSON"     ($pkgJson -match '"Header"' -and $pkgJson -match '"Items"' -and $pkgJson -match '"Summary"')

# ---------------------------------------------------------------------------
# 11. Attestation SEED (GUI offline fallback for overdue + evidence). Real shapers.
# ---------------------------------------------------------------------------
Write-Host "-- attestation seed (GUI fallback) --" -ForegroundColor DarkCyan
$attSeed = Get-PimAccessReviewAttestationSeed
Assert "seed has overdue + evidence"            ($null -ne $attSeed.Overdue -and $null -ne $attSeed.Evidence)
Assert "seed includes an overdue review"        (@($attSeed.Overdue | Where-Object { $_.Urgency -eq 'overdue' }).Count -ge 1)
Assert "seed includes a due-soon review"        (@($attSeed.Overdue | Where-Object { $_.Urgency -eq 'dueSoon' }).Count -ge 1)
Assert "seed includes a completed review"        (@($attSeed.Overdue | Where-Object { $_.Urgency -eq 'completed' }).Count -ge 1)
Assert "seed evidence has mixed decisions"       ($attSeed.Evidence.Summary.Approved -ge 1 -and $attSeed.Evidence.Summary.Denied -ge 1 -and $attSeed.Evidence.Summary.Pending -ge 1)
Assert "seed evidence items carry principals"    (@($attSeed.Evidence.Items | Where-Object { $_.PrincipalName }).Count -ge 1)

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass,$fail) -ForegroundColor ($(if($fail){'Red'}else{'Green'}))
if ($fail) { exit 1 }
