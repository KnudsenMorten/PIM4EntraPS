#requires -Version 5.1
<#
  PIM-PolicyImpact.ps1 -- REQ-WHATIF (REQUIREMENTS 77.1, operator 2026-09-21: "we need to change that so you run
  a whatif first, that shows the actual impact" / "you need to compare the current policies with new policies to
  show any change").

  The mass-change breaker already compares every CURRENT policy rule with the NEW rule the template wants, as the
  normalised facet strings the providers diff on:
      exp|dur=P180D|req=True            enablement:  en|rules=Justification,MultiFactorAuthentication
      notify|lvl=All|def=True|recips=a@x approval:   appr|required=true|approvers=<id>,<id>
  It then showed an approver only the RULE IDS. These PURE functions turn each current -> new pair into the
  settings a person recognises ("Activation: maximum duration 8 hours -> 4 hours"), mark each one as
  tightens / loosens / neutral, and group policies that receive the IDENTICAL change set, so 114 policies with
  the same six changes read as one line. Used by the hold record (engine), its message, and the Manager panel.

  ASCII only on purpose: this file has no BOM, and Windows PowerShell 5.1 would read non-ASCII as CP1252.
#>

function ConvertFrom-PimPolicyFacet {
    # PURE. A facet string -> @{ kind; <field> = value }. '(absent)' / '' -> @{ kind = 'absent' }.
    param([AllowNull()][AllowEmptyString()][string]$Facet)
    $f = "$Facet".Trim()
    if (-not $f -or $f -eq '(absent)') { return @{ kind = 'absent' } }
    $parts = $f -split '\|'
    $o = @{ kind = $parts[0] }
    foreach ($p in @($parts | Select-Object -Skip 1)) {
        $i = $p.IndexOf('=')
        if ($i -lt 0) { continue }
        $o[$p.Substring(0, $i)] = $p.Substring($i + 1)
    }
    $o
}

function Get-PimPolicyRuleContext {
    # PURE. A rule id -> what it governs, in words. Unknown ids come back unchanged (never dropped).
    param([Parameter(Mandatory)][string]$RuleId)
    $what = @{ 'Admin_Eligibility' = 'Eligible assignment'; 'Admin_Assignment' = 'Active assignment'; 'EndUser_Assignment' = 'Activation' }
    if ($RuleId -match '^(Expiration|Enablement|Approval)_(Admin_Eligibility|Admin_Assignment|EndUser_Assignment)$') {
        return $what[$Matches[2]]
    }
    if ($RuleId -match '^Notification_(Admin|Approver|Requestor)_(Admin_Eligibility|Admin_Assignment|EndUser_Assignment)$') {
        $who = @{ 'Admin' = 'admins'; 'Approver' = 'approvers'; 'Requestor' = 'the member' }[$Matches[1]]
        $when = @{ 'Admin_Eligibility' = 'someone is made eligible'; 'Admin_Assignment' = 'someone is assigned active'; 'EndUser_Assignment' = 'someone activates' }[$Matches[2]]
        return "Notify $who when $when"
    }
    $RuleId
}

function ConvertTo-PimPolicyImpactDuration {
    # PURE. ISO-8601 duration -> "180 days" / "8 hours" / "1 day 4 hours"; '' -> 'not set'.
    param([AllowNull()][AllowEmptyString()][string]$Iso)
    $s = "$Iso".Trim()
    if (-not $s) { return 'not set' }
    try { $ts = [System.Xml.XmlConvert]::ToTimeSpan($s) } catch { return $s }
    $parts = @()
    if ($ts.Days) { $parts += ('{0} day{1}' -f $ts.Days, $(if ($ts.Days -eq 1) { '' } else { 's' })) }
    if ($ts.Hours) { $parts += ('{0} hour{1}' -f $ts.Hours, $(if ($ts.Hours -eq 1) { '' } else { 's' })) }
    if ($ts.Minutes) { $parts += ('{0} minute{1}' -f $ts.Minutes, $(if ($ts.Minutes -eq 1) { '' } else { 's' })) }
    if (-not $parts.Count) { return '0' }
    $parts -join ' '
}

function Get-PimPolicyDurationSeconds {
    param([AllowNull()][AllowEmptyString()][string]$Iso)
    $s = "$Iso".Trim(); if (-not $s) { return $null }
    try { return [System.Xml.XmlConvert]::ToTimeSpan($s).TotalSeconds } catch { return $null }
}

function Get-PimPolicyRuleImpact {
    <#
      PURE. ONE rule's current facet vs new facet -> the settings that change, each
        [pscustomobject]@{ ruleId; setting; before; after; direction = tightens|loosens|neutral }
      Direction is about the policy's control, not about the breaker's W count: fewer requirements, a longer
      duration, expiry no longer required, approval off, fewer notification recipients = loosens.
    #>
    param([Parameter(Mandatory)][string]$RuleId, [AllowNull()][AllowEmptyString()][string]$Live, [AllowNull()][AllowEmptyString()][string]$Target)
    $ctx = Get-PimPolicyRuleContext -RuleId $RuleId
    $b = ConvertFrom-PimPolicyFacet $Live; $a = ConvertFrom-PimPolicyFacet $Target
    $kind = if ($a.kind -ne 'absent') { $a.kind } else { $b.kind }
    $out = New-Object System.Collections.Generic.List[object]
    $add = { param($setting, $before, $after, $dir) $out.Add([pscustomobject]@{ ruleId = $RuleId; setting = $setting; before = "$before"; after = "$after"; direction = $dir }) }
    $yn = { param($v) if ("$v" -match '^(?i)true$') { 'yes' } elseif ("$v" -match '^(?i)false$') { 'no' } else { 'not set' } }
    switch ($kind) {
        'exp' {
            if ("$($b['dur'])" -ne "$($a['dur'])") {
                $bs = Get-PimPolicyDurationSeconds $b['dur']; $as = Get-PimPolicyDurationSeconds $a['dur']
                $dir = if ($null -eq $bs -or $null -eq $as) { 'neutral' } elseif ($as -gt $bs) { 'loosens' } elseif ($as -lt $bs) { 'tightens' } else { 'neutral' }
                & $add "${ctx}: maximum duration" (ConvertTo-PimPolicyImpactDuration $b['dur']) (ConvertTo-PimPolicyImpactDuration $a['dur']) $dir
            }
            if ("$($b['req'])" -ne "$($a['req'])") {
                $dir = if ("$($a['req'])" -match '^(?i)true$') { 'tightens' } elseif ("$($b['req'])" -match '^(?i)true$') { 'loosens' } else { 'neutral' }
                & $add "${ctx}: must expire" (& $yn $b['req']) (& $yn $a['req']) $dir
            }
        }
        'en' {
            $names = @{ 'MultiFactorAuthentication' = 'MFA'; 'Justification' = 'a justification'; 'Ticketing' = 'a ticket number' }
            $bl = @("$($b['rules'])" -split ',' | Where-Object { $_ }); $al = @("$($a['rules'])" -split ',' | Where-Object { $_ })
            foreach ($r in @(@($bl) + @($al) | Sort-Object -Unique)) {
                $inB = $bl -contains $r; $inA = $al -contains $r
                if ($inB -eq $inA) { continue }
                $label = if ($names.ContainsKey($r)) { $names[$r] } else { $r }
                & $add "${ctx}: requires $label" $(if ($inB) { 'yes' } else { 'no' }) $(if ($inA) { 'yes' } else { 'no' }) $(if ($inA) { 'tightens' } else { 'loosens' })
            }
        }
        'notify' {
            if ("$($b['def'])" -ne "$($a['def'])") {
                $dir = if ("$($a['def'])" -match '^(?i)true$') { 'tightens' } elseif ("$($b['def'])" -match '^(?i)true$') { 'loosens' } else { 'neutral' }
                & $add "${ctx}: default recipients" $(if ("$($b['def'])" -match '^(?i)true$') { 'on' } elseif ($b.kind -eq 'absent') { 'not set' } else { 'off' }) $(if ("$($a['def'])" -match '^(?i)true$') { 'on' } else { 'off' }) $dir
            }
            if ("$($b['lvl'])" -ne "$($a['lvl'])" -and $b.kind -ne 'absent') {
                & $add "${ctx}: which notices" $(if ("$($b['lvl'])" -eq 'Critical') { 'critical only' } else { 'all' }) $(if ("$($a['lvl'])" -eq 'Critical') { 'critical only' } else { 'all' }) 'neutral'
            }
            $br = @("$($b['recips'])" -split ',' | Where-Object { $_ }); $ar = @("$($a['recips'])" -split ',' | Where-Object { $_ })
            if ((($br | Sort-Object) -join ',') -ne (($ar | Sort-Object) -join ',')) {
                $dir = if (@($br | Where-Object { $ar -notcontains $_ }).Count) { 'loosens' } else { 'tightens' }
                & $add "${ctx}: extra recipients" $(if ($br.Count) { $br -join ', ' } else { 'none' }) $(if ($ar.Count) { $ar -join ', ' } else { 'none' }) $dir
            }
        }
        'appr' {
            $breq = "$($b['required'])" -eq 'true'; $areq = "$($a['required'])" -eq 'true'
            if ($breq -ne $areq) { & $add "${ctx}: requires approval" $(if ($breq) { 'yes' } else { 'no' }) $(if ($areq) { 'yes' } else { 'no' }) $(if ($areq) { 'tightens' } else { 'loosens' }) }
            $bp = @("$($b['approvers'])" -split ',' | Where-Object { $_ }); $ap = @("$($a['approvers'])" -split ',' | Where-Object { $_ })
            if ($areq -and ((($bp | Sort-Object) -join ',') -ne (($ap | Sort-Object) -join ','))) {
                $gone = @($bp | Where-Object { $ap -notcontains $_ }).Count; $new = @($ap | Where-Object { $bp -notcontains $_ }).Count
                & $add "${ctx}: approvers" ('{0} approver(s)' -f $bp.Count) ('{0} approver(s) ({1} added, {2} removed)' -f $ap.Count, $new, $gone) 'neutral'
            }
        }
        default { & $add $ctx "$Live" "$Target" 'neutral' }
    }
    # A facet that differs but maps to no setting above (e.g. a format-only difference) must not vanish:
    # the plan will still PATCH it, so the report says so.
    if (-not $out.Count -and "$Live" -ne "$Target") { & $add "${ctx}: rule is rewritten (no visible setting changes)" '' '' 'neutral' }
    $out.ToArray()
}

function Get-PimPolicyImpactReport {
    <#
      PURE. A breaker plan (Get-PimGraphPolicyChangePlan / Get-PimAzResPolicyChangePlan) -> the WhatIf report:
        totals  = { policies; settings; tightens; loosens; neutral; firstApplication }
        groups  = policies with the IDENTICAL change set, largest first:
                  { count; policies[] (names); firstApplication (all at Entra defaults); changes[] (Get-PimPolicyRuleImpact) }
        reasons = why this change set exists, in words
      -MaxNamesPerGroup caps the names carried per group (the count is always exact).
    #>
    param([Parameter(Mandatory)][object]$Plan, [int]$MaxNamesPerGroup = 400)
    $groups = [ordered]@{}
    $tot = @{ policies = 0; settings = 0; tightens = 0; loosens = 0; neutral = 0; firstApplication = 0 }
    foreach ($p in @($Plan.policies)) {
        if ($null -eq $p) { continue }
        $tot.policies++
        $rules = @($p.rules | Sort-Object { "$($_.ruleId)" })
        $sig = ($rules | ForEach-Object { "$($_.ruleId)|$($_.live)|$($_.target)" }) -join "`n"
        $name = if ($p.PSObject.Properties['name'] -and "$($p.name)") { "$($p.name)" } elseif ($p.PSObject.Properties['role']) { "$($p.role) @ $($p.scope)" } else { "$($p.key)" }
        $first = [bool]($p.PSObject.Properties['neverModified'] -and $p.neverModified)
        if ($first) { $tot.firstApplication++ }
        if (-not $groups.Contains($sig)) {
            $changes = @($rules | ForEach-Object { Get-PimPolicyRuleImpact -RuleId "$($_.ruleId)" -Live "$($_.live)" -Target "$($_.target)" })
            $groups[$sig] = [pscustomobject]@{ count = 0; policies = New-Object System.Collections.Generic.List[string]; firstApplication = $true; template = "$($p.template)"; changes = $changes }
        }
        $g = $groups[$sig]
        $g.count++
        if ($g.policies.Count -lt $MaxNamesPerGroup) { $g.policies.Add($name) }
        if (-not $first) { $g.firstApplication = $false }
        foreach ($c in @($g.changes)) { $tot.settings++; $tot[$c.direction]++ }
    }
    $list = @($groups.Values | Sort-Object @{ e = { $_.count }; Descending = $true } | ForEach-Object {
        [pscustomobject]@{ count = $_.count; policies = $_.policies.ToArray(); firstApplication = [bool]$_.firstApplication; template = $_.template; changes = @($_.changes) }
    })
    $reasons = New-Object System.Collections.Generic.List[string]
    if ($tot.firstApplication) { $reasons.Add(("{0} of the {1} policies are still at Entra's defaults (never changed by anyone) -- this is the FIRST time the template is applied to them, typically new groups or roles." -f $tot.firstApplication, $tot.policies)) }
    $nd = @($Plan.notificationDefaultsAligned).Count; if ($nd) { $reasons.Add("$nd notification rule(s) switch Entra's default recipients to what the template says.") }
    $ap = @($Plan.adminPathAligned).Count; if ($ap) { $reasons.Add("$ap admin-assignment rule(s) drop MFA/justification for ADMIN assignments -- the engine assigns with its own identity, which can never present MFA.") }
    if ($tot.policies -and -not $tot.firstApplication -and -not $nd -and -not $ap) { $reasons.Add('These policies differ from their template. If nobody changed the template, someone changed the policies in Entra; if the template was edited, this is that edit reaching every linked policy.') }
    [pscustomobject]@{
        totals  = [pscustomobject]$tot
        groups  = $list
        reasons = $reasons.ToArray()
    }
}

function Format-PimPolicyImpactText {
    # PURE. The report as plain text lines (engine log, alert mail, job detail). Groups and changes are capped.
    param([Parameter(Mandatory)][object]$Report, [int]$MaxGroups = 5, [int]$MaxChanges = 8)
    $t = $Report.totals
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(("WhatIf: {0} policies would change ({1} setting change(s): {2} tighten, {3} loosen, {4} neutral)." -f $t.policies, $t.settings, $t.tightens, $t.loosens, $t.neutral))
    foreach ($r in @($Report.reasons)) { $lines.Add("  Why: $r") }
    $i = 0
    foreach ($g in @($Report.groups)) {
        if ($i -ge $MaxGroups) { $lines.Add(("  ... and {0} more group(s) of policies with a different change set." -f (@($Report.groups).Count - $MaxGroups))); break }
        $i++
        $names = @($g.policies | Select-Object -First 3) -join ', '
        $lines.Add(("  {0} polic{1}{2} ({3}{4}):" -f $g.count, $(if ($g.count -eq 1) { 'y' } else { 'ies' }), $(if ($g.firstApplication) { ' at Entra defaults' } else { '' }), $names, $(if ($g.count -gt 3) { ', ...' } else { '' })))
        $j = 0
        foreach ($c in @($g.changes)) {
            if ($j -ge $MaxChanges) { $lines.Add(("      ... and {0} more change(s)" -f (@($g.changes).Count - $MaxChanges))); break }
            $j++
            $lines.Add(("      [{0}] {1}: {2} -> {3}" -f $c.direction, $c.setting, $(if ("$($c.before)") { $c.before } else { '-' }), $(if ("$($c.after)") { $c.after } else { '-' })))
        }
    }
    $lines.ToArray()
}

function Get-PimPolicyImpactReportSafe {
    # The report, or $null. NEVER throws: a hold is the safe outcome, and a report failure must not turn it into
    # something else (it is logged; the hold still records and still holds).
    param([AllowNull()][object]$Plan)
    if ($null -eq $Plan) { return $null }
    try { return (Get-PimPolicyImpactReport -Plan $Plan) }
    catch { Write-Warning "  [breaker] the WhatIf impact report could not be built: $($_.Exception.Message)"; return $null }
}

function Write-PimPolicyImpactLog {
    # Print the WhatIf into the run log when a provider HOLDS, so the job output itself shows current -> new.
    param([Parameter(Mandatory)][string]$Provider, [AllowNull()][object]$Plan)
    $r = Get-PimPolicyImpactReportSafe -Plan $Plan
    if (-not $r) { return }
    foreach ($line in @(Format-PimPolicyImpactText -Report $r)) { Write-Host ("    [whatif] {0}: {1}" -f $Provider, $line) -ForegroundColor Yellow }
}

function Get-PimPolicyHoldLead {
    # PURE. The first sentence of a hold message: what happened and what to do, before any technical detail.
    param([Parameter(Mandatory)][string]$Noun, [AllowNull()][object]$Impact, [int]$Changes)
    $t = if ($Impact) { $Impact.totals } else { $null }
    $mix = if ($t) { " ({0} setting change(s): {1} tighten, {2} loosen, {3} neutral)" -f $t.settings, $t.tightens, $t.loosens, $t.neutral } else { '' }
    $why = if ($Impact -and @($Impact.reasons).Count) { ' ' + (@($Impact.reasons) -join ' ') } else { '' }
    "NEEDS APPROVAL -- $Changes $Noun(s) would change$mix, which is more than the engine changes at once without a person looking. NOTHING was written.$why Review the WhatIf (current -> new, per setting) on the Approvals page (Reviews & controls > Approvals) and approve it there, or fix the template/rows. --"
}

function ConvertTo-PimMailHtmlText {
    # PURE. Plain text -> HTML-safe text. Mail tokens are inserted RAW into the HTML template, so an unencoded
    # '<you>' vanished as a tag (the approve command read '-By type=engine-delta ...', 2026-09-21).
    param([AllowNull()][AllowEmptyString()][string]$Text)
    return [System.Net.WebUtility]::HtmlEncode("$Text")
}

function Format-PimPolicyHoldMail {
    <#
      PURE. A held plan (the hold record: New-PimGraphPolicyMassHold / New-PimAzResPolicyMassHold, with its WhatIf
      'impact') -> the three parts of the alert mail, HTML-safe:
        headline   -- what happened, one sentence
        detailHtml -- WHICH policies and WHAT changes: every group of policies with the identical change set, each
                      setting as current -> new with its effect; why the set exists
        actionHtml -- what to do: approve in the Manager, or the exact command
      Operator 2026-09-21: "this email is impossible to read" / "this email needs more details, which policies and
      what is the change".
    #>
    param([Parameter(Mandatory)][object]$Hold, [string]$Provider, [int]$MaxGroups = 8, [int]$MaxNames = 25)
    $e = { param($t) ConvertTo-PimMailHtmlText $t }
    $prov = if ("$Provider".Trim()) { "$Provider".Trim() } elseif ($Hold.PSObject.Properties['provider'] -and "$($Hold.provider)") { "$($Hold.provider)" } else { 'AzResPolicies' }
    $noun = switch ($prov) { 'GroupsPolicies' { 'PIM for Groups policy' } 'EntraRolePolicies' { 'Entra role policy' } default { 'Azure role policy' } }
    $imp = if ($Hold.PSObject.Properties['impact'] -and $Hold.impact) { $Hold.impact } else { $null }
    if (-not $imp -and (Get-Command Get-PimPolicyImpactReportSafe -ErrorAction SilentlyContinue)) {
        # A hold recorded before 2.4.385 carries no report: build it from the policies it does carry (top 10).
        $imp = Get-PimPolicyImpactReportSafe -Plan ([pscustomobject]@{ policies = @($Hold.policies); notificationDefaultsAligned = @($Hold.notificationDefaultsAligned); adminPathAligned = @($Hold.adminPathAligned) })
    }
    $n = [int]$Hold.changes
    $headline = "$n $(if ($n -eq 1) { $noun } else { $noun -replace 'y$', 'ies' }) would change -- more than PIM changes at once without a person looking, so NOTHING was changed. It needs your approval."
    $sb = New-Object System.Text.StringBuilder
    if ($imp) {
        $t = $imp.totals
        [void]$sb.Append(("<b>{0} setting change(s)</b> across {1} polic{2}: <b>{3} tighten</b>, <b>{4} loosen</b>, {5} neutral.<br>" -f $t.settings, $t.policies, $(if ([int]$t.policies -eq 1) { 'y' } else { 'ies' }), $t.tightens, $t.loosens, $t.neutral))
        foreach ($r in @($imp.reasons)) { [void]$sb.Append('Why: ' + (& $e $r) + '<br>') }
        $gi = 0
        foreach ($g in @($imp.groups)) {
            if ($gi -ge $MaxGroups) { [void]$sb.Append(('<br>... and {0} more group(s) of policies with a different change -- see the Manager.<br>' -f (@($imp.groups).Count - $MaxGroups))); break }
            $gi++
            $names = @($g.policies | ForEach-Object { Format-PimPolicyHoldName $_ })
            $shown = @($names | Select-Object -First $MaxNames)
            [void]$sb.Append(('<br><b>{0} polic{1}{2}:</b> {3}{4}<br>' -f $g.count, $(if ([int]$g.count -eq 1) { 'y' } else { 'ies' }), $(if ($g.firstApplication) { ' (still at the default -- first time the template is applied)' } else { '' }),
                (($shown | ForEach-Object { & $e $_ }) -join ', '), $(if ([int]$g.count -gt $shown.Count) { (', and {0} more' -f ([int]$g.count - $shown.Count)) } else { '' })))
            foreach ($c in @($g.changes)) {
                [void]$sb.Append(('&nbsp;&nbsp;&bull; {0}: {1} &rarr; <b>{2}</b> <i>({3})</i><br>' -f (& $e $c.setting), (& $e $(if ("$($c.before)") { $c.before } else { '-' })), (& $e $(if ("$($c.after)") { $c.after } else { '-' })), (& $e $c.direction)))
            }
        }
    } else {
        [void]$sb.Append((& $e "$($Hold.reason)"))
    }
    $cmd = if ($prov -eq 'AzResPolicies') { "Approve-PimAzResPolicyMassChange -PlanHash $($Hold.planHash) -By <your UPN>" } else { "Approve-PimPolicyMassChange -Provider $prov -PlanHash $($Hold.planHash) -By <your UPN>" }
    # 2026-09-21 (operator: "why can i not approve from gui"): the hash in the mail went stale as soon as the next run
    # planned differently, so the mail now sends you to the Approvals page, which always shows the CURRENT change set.
    # One mail per hold: you are not mailed again while it stands unless it grows weaker (or after 24 hours).
    $action = 'Open the PIM Manager, <b>Reviews &amp; controls &rsaquo; Approvals</b>: <i>Policy changes waiting for your approval</i> shows the change set that is held <b>now</b>, with its WhatIf, and an <b>Approve this change set</b> button (Admin role). ' +
              'If it is not intended, fix the template or the rows instead. You are not mailed again for this hold while it stands, unless it starts weakening more policies. ' +
              'Scripted: <code>' + (& $e $cmd) + '</code> -- valid only while this exact change set is the one held.'
    [pscustomobject]@{ headline = $headline; detailHtml = $sb.ToString(); actionHtml = $action; subject = "$n $(if ($n -eq 1) { $noun } else { $noun -replace 'y$', 'ies' }) held -- needs approval" }
}

function Format-PimPolicyHoldName {
    # PURE. A policy name for a person: an Azure 'role @ /providers/Microsoft.Management/managementGroups/<id>' becomes
    # 'role @ management group <id>' (subscription / resource group likewise). Anything else is returned as it is.
    param([AllowNull()][string]$Name)
    $s = "$Name"
    $m = [regex]::Match($s, '^(?<role>.+?) @ (?<scope>/.+)$')
    if (-not $m.Success) { return $s }
    $sc = $m.Groups['scope'].Value
    $lbl = $sc
    if ($sc -match '(?i)/managementGroups/([^/]+)$') { $lbl = "management group $($Matches[1])" }
    elseif ($sc -match '(?i)/resourceGroups/([^/]+)$') { $lbl = "resource group $($Matches[1])" }
    elseif ($sc -match '(?i)^/subscriptions/([^/]+)$') { $lbl = "subscription $($Matches[1])" }
    return "$($m.Groups['role'].Value) @ $lbl"
}

function Set-PimPolicyHoldMailState {
    <#
      PURE. ONE MAIL PER HOLD, NOT PER RUN (operator 2026-09-21: "i am getting lots of errors now"). A hold is raised again on
      every engine run, and its plan hash changes whenever the planned set does (a new group appears), so mailing per plan
      hash mailed every run. -Previous is the hold still standing from the last run (Get-PimPolicyMassHold: $null once it
      cleared). Mail when there was none, when the last mail is older than 24 hours, or when the hold now WEAKENS more than
      the one mailed. The decision is stamped on -Hold (alertedUtc / alertedWeakening / alertedChanges) so the next run
      carries it. Returns $true when a mail is due.
    #>
    param([AllowNull()][object]$Previous, [Parameter(Mandatory)][object]$Hold, [datetime]$NowUtc = [datetime]::UtcNow)
    $stamp = { param($utc, $w, $c)
        foreach ($p in @(@('alertedUtc', $utc), @('alertedWeakening', $w), @('alertedChanges', $c))) { $Hold | Add-Member -NotePropertyName $p[0] -NotePropertyValue $p[1] -Force } }
    $prevUtc = $null
    if ($Previous -and $Previous.PSObject.Properties['alertedUtc'] -and "$($Previous.alertedUtc)".Trim()) {
        try { $prevUtc = [datetime]::Parse("$($Previous.alertedUtc)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } catch { $prevUtc = $null }
    }
    $prevW = if ($Previous -and $Previous.PSObject.Properties['alertedWeakening']) { [int]"$($Previous.alertedWeakening)" } else { -1 }
    $due = (-not $Previous) -or (-not $prevUtc) -or (($NowUtc.ToUniversalTime() - $prevUtc.ToUniversalTime()).TotalHours -ge 24) -or ([int]"$($Hold.weakening)" -gt $prevW)
    if ($due) { & $stamp $NowUtc.ToUniversalTime().ToString('o') ([int]"$($Hold.weakening)") ([int]"$($Hold.changes)") }
    else { & $stamp "$($Previous.alertedUtc)" $prevW ([int]"$($Previous.alertedChanges)") }
    return [bool]$due
}
